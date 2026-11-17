"""Behavior across dependency changes, actionable gaps and actual dispatch."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import evidence_gaps as gaps
import research_dependencies as dependencies
import work_cards as wc
import work_dispatch as wd
from asg_research import append_to_loop
from hunt_loop import HuntLoop
from research_progress import metrics
from tests import test_blocked_research as fixture
from tests import test_work_dispatch as dispatch_fixture


def gap_setup(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    append_to_loop(loop, 'research_node', node_kind='goal', id='g', text='distinguish server access',
                   criteria=[{'id': 'c', 'text': 'fresh server response after revocation'}])
    gaps.declare(loop, gap_id='cache', goal='goal:g', criterion='c', established='document still visible',
                 question='Does a new server request return protected content?',
                 alternatives=['browser cache', 'new server access'], control='owner normal request',
                 observe='fresh request and returned protected marker', support_limit='this role, object and version only',
                 evidence=proof)
    return loop, proof


def test_dependency_change_follows_transitive_cycle_without_global_invalidation(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    for hid in ('downstream', 'unrelated'):
        loop.add_hypothesis(hid)
    dependencies.link(loop, 'hypothesis:h', 'hypothesis:downstream', reason='uses earlier role-dependent result')
    dependencies.link(loop, 'hypothesis:downstream', 'hypothesis:h', reason='recorded mutual dependency')
    assert not dependencies.project(loop)['affected']
    loop.append('evidence_context', context={'version': 'fixture-v1', 'role': 'admin', 'settings': {}, 'environment': 'fixture'})
    affected = {r['ref'] for r in dependencies.project(loop)['affected']}
    assert {'hypothesis:h', 'hypothesis:downstream'} <= affected
    assert 'hypothesis:unrelated' not in affected
    assert loop.capsule()['confirmed'] == {}


def test_declared_revision_changes_are_scoped_and_relink_requires_explicit_action(tmp_path):
    loop = HuntLoop(base_path=tmp_path)
    loop.add_hypothesis('source'); loop.add_hypothesis('consumer'); loop.add_hypothesis('unrelated')
    dependencies.link(loop, 'hypothesis:source', 'hypothesis:consumer', reason='consumes this specific test')
    loop.append('logic_hypothesis', hyp_id='source', applies_env={'role': 'new-role'})
    assert {r['ref'] for r in dependencies.project(loop)['affected']} == {'hypothesis:consumer'}
    dependencies.link(loop, 'hypothesis:source', 'hypothesis:consumer', reason='reviewed new role dependency')
    assert dependencies.project(loop)['affected'] == []


def test_gap_routes_design_to_proposal_without_claiming_acceptance(tmp_path):
    loop, proof = gap_setup(tmp_path)
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    config = {'workers': {'evidence-gap-analysis': {'adapter': 'analysis', 'actor': 'designer', 'model': 'fixture',
              'processing_location': 'fixture', 'allowed_locations': ['fixture']}}, 'output_dir': str(tmp_path / 'receipts')}
    def analyze(prompt):
        assert 'browser cache' in prompt and 'support_limit' in prompt
        return {'operation': 'propose', 'payload': {'question': 'Compare fresh noncached server response after revocation',
                'reason': 'separates cached display from server disclosure', 'evidence': 'evidence:0', 'requires': []}}
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'), spawn=analyze)
    assert result['state'] == 'completed'
    row = gaps.project(loop)[0]
    assert row['state'] == 'researching' and not row['finding_verified']
    assert any(i['kind'] == 'exploration-review' for i in wc.frontier(loop))
    assert metrics(loop)['model_calls'] == 1 and metrics(loop)['input_tokens'] is None
    assert loop.capsule()['confirmed'] == {}


def test_gap_resolves_only_through_existing_goal_evidence_and_reopens_when_changed(tmp_path):
    loop, proof = gap_setup(tmp_path)
    append_to_loop(loop, 'research_node', node_kind='fact', id='f', text='fresh server response captured',
                   basis='observed', evidence=proof)
    append_to_loop(loop, 'goal_proof', goal='goal:g', criterion='c', source='fact:f', reason='fresh response original')
    assert gaps.project(loop)[0]['state'] == 'resolved'
    Path(proof['path']).write_text('changed artifact')
    assert gaps.project(loop)[0]['state'] == 'waiting'


def test_gap_cannot_drop_prerequisites_or_accept_an_unsupported_result(tmp_path):
    loop, proof = gap_setup(tmp_path)
    card = gaps.card(gaps.project(loop)[0]); original = copy.deepcopy(loop.events)
    with pytest.raises(ValueError):
        wc.apply(loop, card, 'resolve', {'evidence': proof})
    assert loop.events == original
    Path(proof['path']).write_text('new evidence')
    with pytest.raises(ValueError, match='current ready'):
        wc.apply(loop, card, 'propose', {'question': 'fresh test', 'reason': 'different discriminator', 'evidence': proof, 'requires': []})


def test_preview_is_read_only_and_matches_actual_dispatched_work(tmp_path):
    loop, config = dispatch_fixture.setup(tmp_path)
    events = copy.deepcopy(loop.events)
    before = set(tmp_path.rglob('*'))
    plan = wd.preview(loop, config)
    assert loop.events == events and set(tmp_path.rglob('*')) == before
    chosen = next(c for c in plan['choices'] if c['ready'])
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert result['work_id'] == chosen['work_id'] and result['state'] == 'completed'
    assert metrics(loop)['tool_calls'] == 2


def test_preview_and_dispatch_agree_on_authorization_and_dependency_blocks(tmp_path):
    loop, config = dispatch_fixture.setup(tmp_path)
    config['bindings']['b/a']['risk'] = 'writes_data'
    choice = wd.preview(loop, config)['choices'][0]
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda _: None)
    assert choice['reason'] == result['unavailable'][0]['reason'] == 'original authorization required'
    assert not any(e['type'] == 'action_started' for e in loop.events)


def test_cli_preview_does_not_create_lock_receipts_or_change_ledger(tmp_path):
    loop, config = dispatch_fixture.setup(tmp_path)
    root = tmp_path / 'vault'
    ledger = root / '01 - Targets/example/.state/asg-events.jsonl'; loop.save(ledger)
    config_file = tmp_path / 'routing.json'; config_file.write_text(json.dumps(config))
    before = ledger.read_bytes(); files = set(root.rglob('*'))
    result = subprocess.run([sys.executable, str(Path(wd.__file__)), 'example', '--config', str(config_file), '--preview'],
                            env={**os.environ, 'VAULT_ROOT': str(root)}, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['choices'][0]['ready']
    assert ledger.read_bytes() == before and files == set(root.rglob('*'))


def test_same_declared_comparison_is_suppressed_across_ids_but_role_change_is_not(tmp_path):
    loop, config = dispatch_fixture.setup(tmp_path)
    proof = fixture.artifact(tmp_path / 'normal.txt')
    for hid in ('h', 'renamed'):
        loop.add_hypothesis(hid)
        loop.append('logic_hypothesis', hyp_id=hid, invariant='private object stays private', dimension='roles',
                    applies_env={'version': 'fixture-v1', 'role': 'member', 'host': 'fixture'})
    import blocked_research as br
    br.record(loop, 'b2', 'renamed', cause='waf', layer='fixture gateway', explanation='same controlled denial',
              normal='succeeds', evidence=proof, recovery='new discriminator')
    br.propose(loop, 'b2', 'other-id', condition='entry', before='ui', after='a', rationale='equivalent entry',
               comparison='same role and object', information_value=4, impact='low', evidence=proof)
    config['bindings']['b2/other-id'] = copy.deepcopy(config['bindings']['b/a'])
    config['bindings']['b2/other-id']['hypothesis'] = 'renamed'
    wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    plan = wd.preview(loop, config)
    duplicate = next(c for c in plan['choices'] if c['ref'] == 'b2')
    assert not duplicate['ready'] and 'same comparison' in duplicate['reason']
    card = next(i['work_card'] for i in wc.frontier(loop) if i['ref'] == 'b2')
    old_key = wd.comparison_key(loop, card, config['bindings']['b2/other-id'])
    loop.append('evidence_context', context={'version': 'fixture-v1', 'role': 'admin', 'settings': {}, 'environment': 'fixture'})
    assert wd.comparison_key(loop, card, config['bindings']['b2/other-id']) != old_key


def test_dependency_change_marks_only_dependent_delivery_stale(tmp_path):
    from research_delivery import project as delivery
    loop, proof = fixture.setup(tmp_path)
    loop.append('delivery_record', record_kind='flow', revision='fixture-revision', data={'id': 'report-input'})
    loop.append('delivery_record', record_kind='flow', revision='other-revision', data={'id': 'unrelated'})
    dependencies.link(loop, 'hypothesis:h', 'delivery:flow:report-input', reason='uses member role observation')
    Path(proof['path']).write_text('changed observation')
    rows = {r['id']: r for r in delivery(loop.events)['flow']}
    assert rows['report-input']['stale'] and not rows['unrelated']['stale']
