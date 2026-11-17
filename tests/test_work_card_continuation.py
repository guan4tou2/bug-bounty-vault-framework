"""End-to-end continuation across obstruction, verification, waiting and exploration."""
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import blocked_research as br
import work_cards as wc
from hunt_loop import HuntLoop
from logic_vuln_loop import Env, LogicHypothesis
from tests import test_blocked_research as fixture


def supported(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    fixture.proposal(loop, proof)
    raw = tmp_path / 'source-test'
    raw.write_text('owned fixture protected behavior and impact')
    br.attempt(loop, 'b', 'a', result='behavior_observed', observation='fixture impact', excluded='not public',
               recovery='independent comparison', test_evidence=fixture.artifact(raw), control_evidence=proof,
               normal_succeeds=True, behavior_observed=True, impact_observed=True, producer_id='researcher')
    return loop, proof


def card(loop):
    return wc.obstruction_card(br.project(loop.events, loop.base_path)[0])


@pytest.mark.parametrize('outcome,next_action', [('supported', 'research_comparison_completed'),
                                               ('not_supported', 'research_comparison_completed'),
                                               ('needs_evidence', 'validation_needs_evidence')])
def test_success_reaches_independent_result_and_has_a_next_transition(tmp_path, outcome, next_action):
    loop, _ = supported(tmp_path)
    requested = wc.apply(loop, card(loop), 'request_validation', {'reason': 'different context replay'})
    assert requested['next_action'] == 'perform_independent_validation'
    paths = [tmp_path / 'independent-test', tmp_path / 'independent-control']
    for index, path in enumerate(paths):
        path.write_text(f'independent fixture observation {index}')
    payload = dict(request_id=requested['validation_request']['request_id'], outcome=outcome, verifier_id='verifier',
                   reason='fresh TEST/CONTROL comparison', recovery='acquire missing discriminator',
                   test_evidence=fixture.artifact(paths[0]), control_evidence=fixture.artifact(paths[1]))
    with pytest.raises(ValueError, match='producer cannot'):
        wc.apply(loop, requested, 'validate', {**payload, 'verifier_id': 'researcher'})
    completed = wc.apply(loop, requested, 'validate', payload)
    assert completed['next_action'] == next_action
    assert br.project(loop.events, tmp_path)[0]['finding_verified'] is False
    assert loop.capsule()['confirmed'] == {} and loop.capsule()['refuted'] == []
    if outcome == 'needs_evidence':
        assert wc.apply(loop, completed, 'close', {'reason': 'missing_data', 'recovery': 'fresh evidence',
                                                  'untested_reason': 'no discriminator'})['research_state'] == 'waiting'


def test_success_can_be_parked_before_verification_without_a_dead_end(tmp_path):
    loop, _ = supported(tmp_path)
    parked = wc.apply(loop, card(loop), 'close', {'reason': 'missing_data', 'recovery': 'independent account',
                                                'untested_reason': 'verifier unavailable'})
    assert parked['next_action'] == 'wait_for_recovery'


def test_expired_waiting_evidence_can_resume_with_fresh_proof_and_keeps_budget(tmp_path, monkeypatch):
    loop, proof = fixture.setup(tmp_path)
    fixture.proposal(loop, proof)
    result = tmp_path / 'attempt'
    result.write_text('controlled denial')
    br.attempt(loop, 'b', 'a', result='blocked', observation='denied', excluded='entry not sufficient',
               recovery='new premise', test_evidence=fixture.artifact(result), control_evidence=proof,
               normal_succeeds=True)
    br.close(loop, 'b', reason='missing_data', recovery='new input', untested_reason='need prerequisite')
    source = next(e for e in loop.events if e['type'] == 'research_obstruction')
    instant = datetime.now(UTC)
    source['evidence']['applicability']['expires_at'] = (instant + timedelta(seconds=5)).isoformat()
    assess = br.assess_artifact
    monkeypatch.setattr(br, 'assess_artifact', lambda artifact, events: assess(artifact, events,
                                                                            now=instant + timedelta(seconds=10)))
    stale = card(loop)
    assert stale['next_action'] == 'recover_waiting_evidence'
    fresh = tmp_path / 'new-conditions'
    fresh.write_text('owned fixture prerequisite acquired; previous effects checked')
    resumed = wc.apply(loop, stale, 'resume', {'changed_condition': 'new prerequisite',
                       'evidence': fixture.artifact(fresh), 'recovery': 'normal control'})
    assert resumed['next_action'] == 'establish_normal_control' and resumed['budget_remaining'] == 1
    assert len(br.project(loop.events, tmp_path)[0]['history_alternatives']) == 1


def test_waiting_and_human_records_do_not_use_ready_slots(tmp_path):
    loop, proof = fixture.setup(tmp_path)
    br.close(loop, 'b', reason='missing_data', recovery='external input', untested_reason='missing data')
    items = wc.frontier(loop) + [{'kind': 'hypothesis', 'ref': 'other', 'action': 'bounded comparison', 'priority': 2},
                                {'kind': 'human-go', 'action': 'original authorization'}]
    queues = wc.partition(items)
    assert [i['ref'] for i in queues['ready']] == ['other']
    assert queues['waiting'][0]['ref'] == 'b' and queues['human'][0]['kind'] == 'human-go'


def test_actual_scheduler_does_not_resurface_waiting_parent_hypotheses(tmp_path, monkeypatch):
    import asg
    import next_work
    root = tmp_path / 'vault'
    target = root / '01 - Targets/example'
    target.mkdir(parents=True)
    monkeypatch.setattr(asg, 'vault_root', lambda: root)
    monkeypatch.setattr(next_work, 'TARGETS', target.parent)
    loop, proof = fixture.setup(tmp_path)
    loop.append('genesis', profile='source-audit')
    br.close(loop, 'b', reason='missing_data', recovery='external prerequisite', untested_reason='not ready')
    for number in range(3):
        hid = f'waiting-{number}'
        loop.add_hypothesis(hid)
        br.record(loop, f'obstruction-{number}', hid, cause='waf', layer='fixture', explanation='fixture denial',
                  normal='succeeds', evidence=proof, recovery='external prerequisite')
        br.close(loop, f'obstruction-{number}', reason='missing_data', recovery='external prerequisite',
                 untested_reason='not ready')
    loop.add_hypothesis('actually-actionable')
    loop.save(target / '.state/asg-events.jsonl')
    queue = next_work.compute('example')
    assert len(queue['waiting']) == 4
    assert any('actually-actionable' in str(item) for item in queue['next_work'])
    assert not any('waiting-' in str(item) for item in queue['next_work'])


@pytest.mark.parametrize('decision', ['adopt', 'reject'])
def test_exploration_is_reviewed_then_consumed_as_an_existing_hypothesis(tmp_path, decision):
    loop, proof = fixture.setup(tmp_path)
    pid = wc.propose_exploration(loop, question='Is the alternate state discriminating?', reason='current routes insufficient',
                                evidence=proof, requires=['missing-capability'])
    proposed = next(i['work_card'] for i in wc.frontier(loop) if i['kind'] == 'exploration-review')
    hyp = LogicHypothesis('new', 'state', 'fixture rule', Env('fixture-v1', 'member', 'fixture'),
                          'known object', 'owner succeeds', 'read alternate', 'read owner', 'protected',
                          requires=['missing-capability'])
    reviewed = wc.apply(loop, proposed, 'review', {'decision': decision, 'reason': 'evidence-based assessment',
                       'evidence': proof, 'hypothesis': asdict(hyp) if decision == 'adopt' else None})
    assert reviewed['next_action'] == 'exploration_' + ('adopted' if decision == 'adopt' else 'rejected')
    assert not any(i['kind'] == 'exploration-review' for i in wc.frontier(loop))
    if decision == 'adopt':
        assert wc.adopted_hypothesis(loop, 'new').requires == ['missing-capability']
        assert 'new' in loop.capsule()['blocked_hypotheses']
    assert wc.exploration_view(loop)[0]['proposal_id'] == pid
    assert not any(e['type'] == 'action_started' for e in loop.events)
