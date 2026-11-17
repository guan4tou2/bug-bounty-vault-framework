"""Event-driven reassessment stays scoped, bounded and separate from verdicts."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import reassessment as ra
import work_cards as wc
import work_dispatch as wd
from tests import test_blocked_research as fixture


def decision(action='retain', subject='inventory', **details):
    return dict(action=action, subject=subject, reason='Review changed fixture evidence',
                uncertainty='No independent impact validation', evidence_refs=['inventory'], details=details)


def pending(loop, reason='queue_exhausted'):
    rid = ra.request(loop, reason)
    return ra.card(next(r for r in ra.view(loop) if r['reassessment_id'] == rid))


def test_same_trigger_and_evidence_version_only_once(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    card = pending(loop)
    for _ in range(3):
        assert pending(loop) == card
        ra.collect(loop)
    assert len([e for e in loop.events if e['type'] == 'reassessment_requested' and e['reason'] == 'queue_exhausted']) == 1
    wc.apply(loop, card, 'decide', {'decisions': [decision()]})
    assert loop.capsule()['confirmed'] == {}
    assert not [i for i in wc.frontier(loop) if i['ref'] == card['ref']]
    pending(loop)
    assert len([e for e in loop.events if e['type'] == 'reassessment_requested' and e['reason'] == 'queue_exhausted']) == 1


def test_changed_evidence_supersedes_pending_snapshot(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    old = pending(loop)
    Path(proof['path']).write_text('new fixture conditions')
    with pytest.raises(ValueError, match='snapshot'):
        wc.apply(loop, old, 'decide', {'decisions': [decision()]})
    ra.collect(loop)
    rows = ra.view(loop)
    assert next(r for r in rows if r['reassessment_id'] == old['ref'])['state'] == 'superseded'
    ready = [r for r in rows if r['reason'] == 'queue_exhausted' and r['state'] == 'proposed']
    assert len(ready) == 1 and not ready[0]['stale']


def test_decisions_are_atomic_and_cannot_verify_or_authorize(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    card = pending(loop)
    before = len(loop.events)
    with pytest.raises(ValueError):
        wc.apply(loop, card, 'decide', {'decisions': [decision('prioritize', 'hypothesis:h', priority=2), decision('verify')]})
    assert len(loop.events) == before
    wc.apply(loop, card, 'decide', {'decisions': [decision('prioritize', 'hypothesis:h', priority=2)]})
    assert loop.events[-2]['type'] == 'research_priority'
    assert loop.capsule()['confirmed'] == {}


def test_deterministic_trigger_does_not_require_model(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    ra.collect(loop)
    row = next(r for r in ra.view(loop) if r['reason'] == 'obstruction')
    assert row['state'] == 'completed' and row['result']['mode'] == 'deterministic'
    with pytest.raises(ValueError, match='existing hypothesis'):
        ra.request(loop, 'queue_exhausted', 'hypothesis:missing')


def test_reassessment_runs_through_production_dispatch_contract(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    loop.save(tmp_path / 'ledger')
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    pending(loop)
    config = {'workers': {'reassessment-analysis': {'adapter': 'analysis', 'actor': 'analyst', 'model': 'configured',
                'processing_location': 'fixture', 'allowed_locations': ['fixture']}}, 'bindings': {},
              'output_dir': str(tmp_path / 'output')}
    calls = []
    def spawn(prompt):
        calls.append(prompt)
        return json.dumps({'operation': 'decide', 'payload': {'decisions': [decision()]}})
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'), spawn=spawn)
    assert result['state'] == 'completed', result
    assert len(calls) == 1
    assert wd.jobs(loop.events)[0]['result_artifact']['sha256']
    wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'), spawn=spawn)
    assert len(calls) == 1 and loop.capsule()['confirmed'] == {}


def test_invalid_multi_decision_is_atomic_and_priority_expires(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    card = pending(loop)
    before = list(loop.events)
    with pytest.raises(ValueError, match='unsupported'):
        wc.apply(loop, card, 'decide', {'decisions': [decision('prioritize', 'hypothesis:h', priority=2),
                                                    decision('verify', 'hypothesis:h')]})
    assert loop.events == before
    wc.apply(loop, card, 'decide', {'decisions': [decision('prioritize', 'hypothesis:h', priority=2)]})
    assert ra.priorities(loop) == {'hypothesis:h': 2}
    Path(proof['path']).write_text('changed conditions')
    assert ra.priorities(loop) == {}


def test_meaningful_event_cooldown_and_deterministic_trigger(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    card = pending(loop, 'no_information_gain')
    wc.apply(loop, card, 'decide', {'decisions': [decision()]})
    loop.add_hypothesis('new-1')
    new = pending(loop, 'no_information_gain')
    assert next(r for r in ra.view(loop) if r['reassessment_id'] == new['ref'])['state'] == 'cooldown'
    for number in (2, 3):
        loop.add_hypothesis('new-' + str(number))
    ra.collect(loop)
    rows = [r for r in ra.view(loop) if r['reason'] == 'no_information_gain']
    assert sum(r['state'] == 'proposed' and not r['stale'] for r in rows) == 1
    rid = ra.request(loop, 'capability_changed')
    assert next(r for r in ra.view(loop) if r['reassessment_id'] == rid)['result']['mode'] == 'deterministic'
    with pytest.raises(ValueError, match='scope'):
        ra.request(loop, 'queue_exhausted', 'unknown')


def test_normal_autodrive_consumes_current_reassessment_order():
    from hunt_autodrive import autodrive, Budget
    from tests.test_hunt_autodrive import _build, ENV
    loop, registry = _build()
    card = pending(loop)
    wc.apply(loop, card, 'decide', {'decisions': [decision('prioritize', 'hypothesis:b-public', priority=2)]})
    seen = []
    def execute(task):
        from logic_vuln_loop import Observation
        seen.append(task.hyp.hyp_id)
        return Observation('test', ok=False, error='fixture unavailable'), Observation('control', ok=False, error='fixture unavailable')
    autodrive(loop, current_env=ENV, dispatch=execute, propose=lambda *_: None,
              ready_hyp=registry.get, budget=Budget(max_actions=1, max_replans=0), max_rounds=1)
    assert seen == ['b-public']
    assert not loop.capsule()['confirmed']


def test_scoped_intent_decisions_cannot_touch_other_or_running_work(tmp_path):
    from asg_research import append_to_loop, project
    loop, _ = fixture.setup(tmp_path)
    loop.add_hypothesis('other')
    append_to_loop(loop, 'research_node', node_kind='goal', id='g', text='owned fixture goal',
                   criteria=[{'id': 'c', 'text': 'bounded evidence'}])
    for hid in ('h', 'other'):
        append_to_loop(loop, 'research_node', node_kind='intent', id=hid, text='bounded fixture test',
                       goals=['goal:g'], hypothesis='hypothesis:' + hid)
    rid = ra.request(loop, 'no_information_gain', 'hypothesis:h')
    card = ra.card(next(r for r in ra.view(loop) if r['reassessment_id'] == rid))
    with pytest.raises(ValueError, match='unsupported'):
        wc.apply(loop, card, 'decide', {'decisions': [decision('pause', 'intent:other')]})
    wc.apply(loop, card, 'decide', {'decisions': [decision('pause', 'intent:h'),
                                                decision('prioritize', 'hypothesis:h', priority=1)]})
    assert ra.priorities(loop) == {'hypothesis:h': 1}
    nodes = {n['ref']: n for n in project(loop.events, loop.base_path)['nodes']}
    assert nodes['intent:h']['state'] == 'paused' and nodes['intent:other']['state'] == 'open'
    append_to_loop(loop, 'research_state', ref='intent:h', state='open', reason='fixture restored')
    append_to_loop(loop, 'research_state', ref='intent:h', state='running', reason='fixture claimed')
    rid = ra.request(loop, 'pre_delivery', 'hypothesis:h')
    card = ra.card(next(r for r in ra.view(loop) if r['reassessment_id'] == rid))
    with pytest.raises(ValueError, match='stop/effects'):
        wc.apply(loop, card, 'decide', {'decisions': [decision('cancel', 'intent:h')]})
