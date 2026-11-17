"""Controlled local processes exercise execution state, cancellation and recovery."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import hunt_integration as integration
import program_rules_gate
from hunt_loop import HuntLoop


def ready():
    loop = HuntLoop()
    loop.add_hypothesis('h')
    return loop


def test_denied_process_stop_is_bounded_and_remains_unconfirmed(monkeypatch):
    import command_lifecycle

    class InaccessibleProcess:
        pid = 12345

        def wait(self, timeout=None):
            assert timeout is not None
            raise subprocess.TimeoutExpired('controlled inaccessible process', timeout)

    def denied(*_args):
        raise PermissionError('controlled policy denial')

    monkeypatch.setattr(command_lifecycle.os, 'killpg', denied)
    assert command_lifecycle.stop_process(InaccessibleProcess(), grace=.001) is False


def terminal(loop):
    return [e for e in loop.events if e['type'] == 'action_finished'][-1]


def test_start_and_running_are_durable_before_cancellation(tmp_path):
    loop, ledger, output = ready(), tmp_path / 'ledger', tmp_path / 'out'
    observed = []

    def cancel():
        restored = HuntLoop.load(ledger)
        observed.append([e['type'] for e in restored.events])
        return output.exists() and 'ready' in output.read_text()

    assert not integration.execute_command(loop, ledger, 'h', 'a',
        [sys.executable, '-u', '-c', 'import time; print("ready"); time.sleep(30)'],
        output, cancel_requested=cancel)
    assert 'action_started' in observed[0]
    assert any('action_running' in snapshot for snapshot in observed)
    end = terminal(HuntLoop.load(ledger))
    assert end['status'] == 'cancelled'
    assert end['returncode'] is not None
    assert end['execution_stop_confirmed'] is True
    assert end['finished_at'] >= loop.events[1]['started_at']
    assert not integration.handoff(loop)['priority']['execution_stop_requires_reconciliation']


def test_timeout_reaps_child_and_retry_keeps_previous_attempt(tmp_path):
    loop, ledger = ready(), tmp_path / 'ledger'
    assert not integration.execute_command(loop, ledger, 'h', 'first',
        [sys.executable, '-c', 'import time; time.sleep(30)'], tmp_path / 'first', timeout=.15)
    end = terminal(loop)
    assert end['status'] == 'timed_out'
    assert end['error'] == 'TimeoutExpired'
    assert end['execution_stop_confirmed']
    assert integration.execute_command(loop, ledger, 'h', 'retry',
        [sys.executable, '-c', 'print("recovered")'], tmp_path / 'retry')
    assert [e['status'] for e in loop.events if e['type'] == 'action_finished'] == ['timed_out', 'completed']
    assert (tmp_path / 'first').exists()


@pytest.mark.parametrize('detached', [False, True])
def test_leader_exit_does_not_leave_late_stdout_writer(tmp_path, detached):
    loop, ledger, output = ready(), tmp_path / 'ledger', tmp_path / 'out'
    child = 'import time; time.sleep(.6); print("late")'
    script = ('import subprocess,sys; '
              f'subprocess.Popen([sys.executable,"-u","-c",{child!r}],start_new_session={detached!r}); '
              'print("early")')
    assert not integration.execute_command(loop, ledger, 'h', 'a',
        [sys.executable, '-u', '-c', script], output)
    end = terminal(loop)
    assert end['status'] == 'failed'
    assert end['error'] == 'DescendantsOutlivedTool'
    if detached:
        assert end['execution_stop_confirmed'] is False
        assert integration.handoff(loop)['priority']['execution_stop_requires_reconciliation']
    before = output.read_bytes()
    assert before == b'early\n'
    time.sleep(.8)
    assert output.read_bytes() == before
    assert integration.handoff(loop)['priority']['evidence_problems'] == []


def test_missing_tool_is_failure_and_secrets_do_not_enter_ledger(tmp_path):
    loop, ledger = ready(), tmp_path / 'ledger'
    secret = 'do-not-persist-this-secret'
    assert not integration.execute_command(loop, ledger, 'h', 'a',
        [str(tmp_path / 'missing-tool'), '--token', secret, f'https://user:{secret}@example.invalid'],
        tmp_path / 'out', command_ref='controlled:command-1', scope_ref='scope:v1')
    assert terminal(loop)['status'] == 'failed'
    assert terminal(loop)['error'] == 'FileNotFoundError'
    assert secret not in ledger.read_text()
    assert loop.capsule()['confirmed'] == {}


def test_keyboard_interrupt_stops_process_and_persists_terminal(tmp_path):
    loop, ledger = ready(), tmp_path / 'ledger'

    def interrupt_after_spawn():
        if any(e['type'] == 'action_running' for e in loop.events):
            raise KeyboardInterrupt()
        return False

    with pytest.raises(KeyboardInterrupt):
        integration.execute_command(loop, ledger, 'h', 'a',
            [sys.executable, '-c', 'import time; time.sleep(30)'], tmp_path / 'out',
            cancel_requested=interrupt_after_spawn)
    end = terminal(HuntLoop.load(ledger))
    assert end['status'] == 'interrupted'
    assert end['execution_stop_confirmed'] is True


def test_recovery_does_not_replay_or_claim_lost_child_stopped(tmp_path):
    owner = subprocess.Popen([sys.executable, '-c', 'pass'])
    owner.wait()
    loop, ledger = ready(), tmp_path / 'ledger'
    loop.append('action_started', action_id='orphan', hyp_id='h',
                owner_host=socket.gethostname(), owner_pid=owner.pid, output_ref=str(tmp_path / 'out'))
    loop.append('action_started', action_id='live', hyp_id='h',
                owner_host=socket.gethostname(), owner_pid=os.getpid())
    loop.append('action_started', action_id='legacy', hyp_id='h')
    result = integration.reconcile_actions(loop, ledger)
    assert result == {'interrupted': ['orphan'], 'requires_reconciliation': ['live', 'legacy']}
    assert terminal(loop)['status'] == 'interrupted'
    assert terminal(loop)['execution_stop_confirmed'] is False
    assert terminal(loop)['sha256'] is None
    assert integration.handoff(loop)['priority']['execution_stop_requires_reconciliation']
    assert integration.reconcile_actions(loop, ledger)['interrupted'] == []
    with pytest.raises(ValueError, match='already recorded'):
        integration.execute_command(loop, ledger, 'h', 'orphan', [sys.executable], tmp_path / 'out')


def test_remote_quoting_preserves_literal_arguments_through_posix_shell(tmp_path):
    marker = tmp_path / 'injected'
    args = [sys.executable, '-c', 'import json,sys; print(json.dumps(sys.argv[1:]))',
            f'x; touch {marker}', '$(whoami)', 'a b', "it's literal", '']
    command = integration.remote_argv('lab-host', args)
    assert command[:3] == ['ssh', '--', 'lab-host']
    # Exercise exactly the command string an SSH server gives its POSIX shell.
    out = subprocess.check_output(['/bin/sh', '-c', command[3]], text=True)
    assert json.loads(out) == args[3:]
    assert not marker.exists()
    with pytest.raises(ValueError):
        integration.remote_argv('-oProxyCommand=bad', ['true'])


def program():
    return {'target': 'fixture', 'hosts': {'lab.example.invalid'}, 'suffixes': {'example.invalid'},
            'registered_ip': '192.0.2.1', 'egress_via': '', 'bbp_header': '', 'start': '',
            'expiry': '', 'weekday': '', 'weekend': '', 'auto_scan': False}


@pytest.mark.parametrize('remote', [False, True])
@pytest.mark.parametrize('scanner', ['nmap', 'nuclei'])
def test_program_gate_blocks_both_transports_before_start(tmp_path, monkeypatch, remote, scanner):
    monkeypatch.setattr(program_rules_gate, 'load_programs', lambda root: [program()])
    loop = ready()
    argv = [scanner, 'lab.example.invalid']
    if remote:
        argv = integration.remote_argv('lab-host', argv)
    with pytest.raises(PermissionError, match='auto_scan_approved'):
        integration.execute_command(loop, tmp_path / 'ledger', 'h', 'a', argv, tmp_path / 'out')
    assert not any(e['type'] == 'action_started' for e in loop.events)
    assert not (tmp_path / 'out').exists()


def test_registered_egress_gate_cannot_be_skipped_by_direct_python_call(tmp_path, monkeypatch):
    monkeypatch.setattr(program_rules_gate, 'load_programs', lambda root: [program()])
    with pytest.raises(PermissionError, match='program rules gate'):
        integration.execute_command(ready(), tmp_path / 'ledger', 'h', 'a',
            ['curl', 'https://lab.example.invalid'], tmp_path / 'out')


def test_literal_hash_in_argument_does_not_hide_target_from_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(program_rules_gate, 'load_programs', lambda root: [program()])
    with pytest.raises(PermissionError, match='program rules gate'):
        integration.execute_command(ready(), tmp_path / 'ledger', 'h', 'a',
            ['curl', '-H', 'X-Note: #literal', 'https://lab.example.invalid'], tmp_path / 'out')


def test_ssh_client_stop_never_claims_remote_acknowledgement(tmp_path, monkeypatch):
    real_popen = subprocess.Popen

    def fake_ssh(argv, **kwargs):
        return real_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)

    monkeypatch.setattr(integration.subprocess, 'Popen', fake_ssh)
    loop = ready()
    assert not integration.remote_execute_command(loop, tmp_path / 'ledger', 'h', 'a',
        'fixture-host', ['sleep', '30'], tmp_path / 'out', timeout=.1)
    assert terminal(loop)['status'] == 'timed_out'
    assert terminal(loop)['execution_stop_confirmed'] is False
    assert terminal(loop)['remote_stop_requires_reconciliation'] is True
