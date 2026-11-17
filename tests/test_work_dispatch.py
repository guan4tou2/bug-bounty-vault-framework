"""Production entry + real controlled fixture processes, without targets or model calls."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import blocked_research as br
import work_cards as wc
import work_dispatch as wd
from hunt_loop import HuntLoop
from tests import test_blocked_research as fixture


def setup(tmp_path, verify='protected'):
    loop, proof = fixture.setup(tmp_path)
    loop.append('genesis', profile='source-audit')
    loop.add_hypothesis('verification-comparison')
    fixture.proposal(loop, proof)
    script = 'import json,sys; print(json.dumps({"access":sys.argv[1],"impact":sys.argv[1]=="protected"}))'
    def binding(hyp, test):
        return {'hypothesis': hyp, 'scope_ref': 'owned:synthetic-fixture', 'risk': 'reads_only',
                'test_argv': [sys.executable, '-c', script, test],
                'control_argv': [sys.executable, '-c', script, 'owner'],
                'checks': {'normal': {'field': 'access', 'equals': 'owner'},
                           'behavior': {'field': 'access', 'equals': 'protected'},
                           'impact': {'field': 'impact', 'equals': True},
                           'rejection': {'field': 'access', 'equals': 'denied'}}}
    config = {'workers': {'controlled-comparison': {'adapter': 'argv-comparison', 'actor': 'researcher'},
                          'independent-verification': {'adapter': 'argv-verification', 'actor': 'separate-verifier'}},
              'bindings': {'b/a': binding('h', 'protected'), 'b': binding('verification-comparison', verify)},
              'output_dir': str(tmp_path / 'private-artifacts')}
    return loop, config


@pytest.mark.parametrize('observation,conclusion,state', [
    ('protected', 'supported', 'completed'), ('denied', 'not_supported', 'completed'),
    ('empty', 'needs_evidence', 'blocked')])
def test_real_cli_dispatch_to_execution_to_independent_result(tmp_path, observation, conclusion, state):
    loop, config = setup(tmp_path, observation)
    vault = tmp_path / 'private-vault'
    ledger = vault / '01 - Targets/example/.state/asg-events.jsonl'
    loop.save(ledger)
    file = tmp_path / 'routing.json'
    file.write_text(json.dumps(config))
    script = Path(__file__).resolve().parents[1] / 'automation/work_dispatch.py'
    for _ in range(3):
        completed = subprocess.run([sys.executable, str(script), 'example', '--config', str(file)],
                                   capture_output=True, text=True, env={**os.environ, 'VAULT_ROOT': str(vault)}, timeout=30)
        assert completed.returncode == 0, completed.stderr
        result = json.loads(completed.stdout)
        assert result['state'] == 'completed', result
    restored = HuntLoop.load(ledger)
    row = br.project(restored.events, restored.base_path)[0]
    assert row['state'] == state and row['conclusion'] == conclusion and row['finding_verified'] is False
    assert restored.capsule()['confirmed'] == {}
    assert [j['state'] for j in wd.jobs(restored.events)] == ['completed'] * 3
    assert len([e for e in restored.events if e['type'] == 'action_finished']) == 4
    for job in wd.jobs(restored.events):
        assert job['result_artifact']['sha256']


def test_normal_live_harness_consumes_same_dispatcher(tmp_path):
    from hunt_run import run_hunt
    from hunt_autodrive import Budget
    from logic_vuln_loop import Env
    loop, config = setup(tmp_path)
    ledger = tmp_path / 'ledger'
    loop.save(ledger)
    report, restored = run_hunt(ledger, owner='owned-fixture', current_env=Env('fixture-v1', 'member', 'fixture'),
        spawn=lambda *_: pytest.fail('typed work should not use legacy worker'),
        propose=lambda *_: pytest.fail('typed work should not replan the whole task'),
        ready_hyp=lambda *_: None, budget=Budget(3, 1), max_rounds=3, work_config=config)
    assert report.rounds == 3
    assert br.project(restored.events, restored.base_path)[0]['state'] == 'completed'


def test_model_result_cannot_impersonate_verifier_or_execute_commands(tmp_path):
    loop, proof = fixture.setup(tmp_path, cause='unknown', normal='unknown')
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    config = {'workers': {'obstruction-analysis': {'adapter': 'analysis', 'actor': 'analyst', 'model': 'fixture',
               'processing_location': 'fixture', 'allowed_locations': ['fixture']}}, 'output_dir': str(tmp_path / 'results')}
    def model(prompt):
        assert str(tmp_path) not in prompt
        return {'operation': 'validate', 'payload': {'outcome': 'supported'}}
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'), spawn=model)
    assert result['state'] == 'failed'
    assert wd.jobs(loop.events)[0]['result_artifact']['sha256']
    assert wc.partition(wc.frontier(loop))['human']
    assert not any(e['type'] in {'action_started', 'verdict'} for e in loop.events)
    with pytest.raises(ValueError, match='gated execution'):
        wd.run_ready(loop, tmp_path / 'ledger', {'workers': {'controlled-comparison':
                     {'adapter': 'analysis', 'actor': 'pretend-executor'}}}, persist=lambda _: None)


def test_analysis_can_return_checked_diagnosis_then_duplicate_is_not_redispatched(tmp_path):
    loop, proof = fixture.setup(tmp_path, cause='unknown', normal='unknown')
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    config = {'workers': {'obstruction-analysis': {'adapter': 'analysis', 'actor': 'analyst', 'model': 'fixture',
               'processing_location': 'fixture', 'allowed_locations': ['fixture']}}}
    calls = []
    def model(prompt):
        calls.append(prompt)
        return {'operation': 'diagnose', 'payload': {'cause': 'unknown', 'layer': 'undetermined',
                'normal': 'succeeds', 'explanation': 'normal operation succeeds but cause still unknown',
                'recovery': 'new discriminator', 'evidence': 'evidence:0'}}
    save = lambda lp: lp.save(tmp_path / 'ledger')
    assert wd.run_ready(loop, tmp_path / 'ledger', config, persist=save, spawn=model)['state'] == 'completed'
    assert br.project(loop.events, tmp_path)[0]['next'] == 'discriminate_obstruction'
    # Same diagnosis is rejected on a fresh card, retained as a failed receipt, and not automatically retried.
    assert wd.run_ready(loop, tmp_path / 'ledger', config, persist=save, spawn=model)['state'] == 'failed'
    assert not wd.run_ready(loop, tmp_path / 'ledger', config, persist=save, spawn=model)['handled']
    assert len(calls) == 2


def test_missing_authorization_never_launches_configured_target_commands(tmp_path):
    loop, config = setup(tmp_path)
    config['bindings']['b/a']['risk'] = 'writes_data'
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert not result['handled'] and result['unavailable'][0]['reason'] == 'original authorization required'
    assert not any(e['type'] == 'action_started' for e in loop.events)
    loop.append('human_go', hyp_id='h', decision='decline')
    loop.append('human_go', hyp_id='verification-comparison', decision='go')
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert result['unavailable'][0]['reason'] == 'original authorization declined'


def test_unresolved_shared_resource_blocks_takeover_even_after_config_change(tmp_path):
    loop, config = setup(tmp_path)
    card = wc.frontier(loop)[0]['work_card']
    task = wd.contract(loop, card, config['workers']['controlled-comparison'], wd.digest(config))
    loop.append('work_dispatched', **task)
    config['workers']['controlled-comparison']['actor'] = 'replacement'
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert result['unsafe'] and not result['handled']
    assert not any(e['type'] == 'action_started' for e in loop.events)


def test_fresh_external_input_reactivates_waiting_without_resetting_budget(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    fixture.proposal(loop, proof)
    test = tmp_path / 'blocked-result'
    test.write_text('fixture denied alternate entry')
    br.attempt(loop, 'b', 'a', result='blocked', observation='denial', excluded='entry alone insufficient',
               recovery='fresh premise', test_evidence=fixture.artifact(test), control_evidence=proof,
               normal_succeeds=True)
    br.close(loop, 'b', reason='missing_data', recovery='fresh premise', untested_reason='external condition missing')
    Path(proof['path']).write_text('old evidence changed')
    fresh = tmp_path / 'new-conditions'
    fresh.write_text('new owned fixture prerequisite established')
    config = {'workers': {'evidence-revalidation': {'adapter': 'artifact-refresh', 'actor': 'evidence-ingress'}},
              'bindings': {'b': {'evidence': fixture.artifact(fresh), 'changed_condition': 'prerequisite repaired',
                                  'recovery': 'establish normal baseline'}}}
    wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    row = br.project(loop.events, tmp_path)[0]
    assert row['state'] == 'blocked' and not row['stale']
    assert wc.obstruction_card(row)['budget_remaining'] == 1
    assert row['history_alternatives'] and not any(e['type'] == 'action_started' for e in loop.events)
