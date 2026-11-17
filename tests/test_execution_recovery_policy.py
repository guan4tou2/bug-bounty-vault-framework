"""Changing an action ID cannot bypass an unknown prior execution or side effect."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_integration import acknowledge_action, execute_command, handoff
from hunt_loop import HuntLoop
from hunt_session import inflight_actions


def test_program_gate_reads_public_workspace_scope(tmp_path):
    import program_rules_gate as gate
    scope = tmp_path / 'workspace/workshop/example/SCOPE.md'
    scope.parent.mkdir(parents=True)
    scope.write_text('## In-Scope\n- app.example.invalid\n\n## Program Rules (machine-readable)\n'
                     '```yaml\nauto_scan_approved: false\n```\n')
    programs = gate.load_programs(tmp_path)
    assert programs and gate.judge('nmap app.example.invalid', programs)


@pytest.mark.parametrize("finished", [False, True])
def test_unconfirmed_execution_blocks_new_id_until_pinned_acknowledgement(tmp_path, finished):
    ledger = tmp_path / "ledger"
    loop = HuntLoop()
    loop.add_hypothesis("h")
    loop.append("action_started", action_id="possibly-wrote", hyp_id="h")
    if finished:
        loop.append("action_finished", action_id="possibly-wrote", hyp_id="h", status="interrupted",
                    exit_ok=False, execution_stop_confirmed=False)
    loop.save(ledger)
    out = tmp_path / "retry"
    with pytest.raises(ValueError, match="side effects"):
        execute_command(loop, ledger, "h", "new-id", [sys.executable, "-c", "print('unexpected')"], out)
    assert not out.exists()
    receipt = tmp_path / "executor-confirmation"
    receipt.write_text("Controlled executor checked stop and the affected resource; no writes persisted.")
    acknowledge_action(loop, ledger, "possibly-wrote", receipt, "effects-checked")
    restored = HuntLoop.load(ledger)
    assert inflight_actions(restored) == []
    assert handoff(restored)["priority"]["execution_stop_requires_reconciliation"] == []
    assert execute_command(restored, ledger, "h", "retry", [sys.executable, "-c", "print('safe retry')"], out)
    assert out.read_text().strip() == "safe retry"
    receipt.write_text("changed acknowledgement")
    with pytest.raises(ValueError, match="side effects"):
        execute_command(restored, ledger, "h", "another-id", [sys.executable, "-c", "print('unsafe')"], tmp_path / "no")


def test_acknowledgement_requires_explicit_effect_inspection_and_nonempty_evidence(tmp_path):
    loop = HuntLoop()
    loop.append("action_started", action_id="a", hyp_id="h")
    receipt = tmp_path / "receipt"
    receipt.write_text("")
    with pytest.raises(ValueError, match="side effects"):
        acknowledge_action(loop, tmp_path / "ledger", "a", receipt, "probably-done")
    with pytest.raises(ValueError, match="nonempty"):
        acknowledge_action(loop, tmp_path / "ledger", "a", receipt, "effects-checked")


def test_running_tool_persists_heartbeats_before_terminal_result(tmp_path):
    from asg_command_runs import action_runs
    loop = HuntLoop()
    loop.add_hypothesis('h')
    ledger = tmp_path / 'ledger'
    assert execute_command(loop, ledger, 'h', 'a',
                           [sys.executable, '-c', 'import time; time.sleep(.25); print("observed")'],
                           tmp_path / 'output', heartbeat_interval=.02)
    restored = HuntLoop.load(ledger)
    beats = [e for e in restored.events if e['type'] == 'action_heartbeat']
    assert beats and beats[0]['action_id'] == 'a'
    assert action_runs(restored.events)[0]['last_heartbeat'] == beats[-1]['at']
