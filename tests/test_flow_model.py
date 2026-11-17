"""Sharing/revocation MBT pilot against a disposable in-memory implementation."""
import json
import os
import subprocess
import sys
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import flow_model as fm
import research_delivery
from hunt_loop import HuntLoop, Verdict
from logic_vuln_loop import Env, Invariant, LogicHypothesis, Observation, record_invariant

ENV = Env(version='controlled-v1', role='multi-actor', host='in-memory')


@pytest.fixture
def setup(tmp_path):
    loop = HuntLoop(base_path=tmp_path)
    loop.append('evidence_context', context_id='target', context={
        'version': ENV.version, 'role': ENV.role, 'settings': {}, 'environment': {'host': ENV.host}})
    rule = tmp_path / 'policy.txt'
    rule.write_text('After owner revocation neither the former recipient nor a stranger '
                    'may read using that share link.')
    record_invariant(loop, Invariant('revocation', rule.read_text(), source='code',
                                    confidence='stated', evidence_refs=[str(rule)]))
    actors = {name: {'account_ref': 'account:' + name, 'role': name}
              for name in ('stranger', 'owner', 'recipient')}
    definition = {
        'flow_id': 'sharing', 'title': 'Owner creates, shares, reads and revokes a document',
        'environment': asdict(ENV), 'actors': actors,
        'objects': {'doc': {'owner': 'owner', 'relationships': {'recipient': 'grant-recipient', 'stranger': 'no-grant'},
                           'identifiers': {
                               'creation-response': {'source': 'normal owner create response',
                                   'available_to': ['owner'], 'attacker_availability': 'unavailable'},
                               'share-response': {'source': 'normal owner share response and recipient UI',
                                   'available_to': ['owner', 'recipient'], 'attacker_availability': 'harness_only'}}}},
        'states': ['absent', 'private', 'shared', 'revoked'],
        'entries': {'ui': {'interface': 'normal UI'}, 'api': {'interface': 'direct API'}},
        'transitions': [], 'normal_path': ['create', 'share', 'read', 'revoke', 'read-after-revoke']}
    for tid, before, after, actor, action in [
            ('create', 'absent', 'private', 'owner', 'create'),
            ('share', 'private', 'shared', 'owner', 'share'),
            ('read', 'shared', 'shared', 'recipient', 'read'),
            ('revoke', 'shared', 'revoked', 'owner', 'revoke'),
            ('read-after-revoke', 'revoked', 'revoked', 'recipient', 'read')]:
        definition['transitions'].append({
            'id': tid, 'from': before, 'to': after, 'actor': actor, 'object': 'doc', 'entry': 'ui',
            'action': action, 'preconditions': ['actor relationship must authorize this operation'],
            'invariant_refs': ['revocation'],
            'identifier_ref': 'creation-response' if actor == 'owner' else 'share-response'})
    fm.define_flow(loop, definition)
    cases = fm.generate_cases(loop, 'sharing', focus_transition='read-after-revoke')
    return loop, definition, cases


class ShareService:
    """Real stateful fixture; stale-link bug affects only a stranger after revocation."""
    def __init__(self, stale_link_bug=True):
        self.state = 'absent'
        self.document_id = None
        self.link = None
        self.stale_link_bug = stale_link_bug

    def perform(self, action, actor, entry):
        if action == 'create' and self.state == 'absent' and actor == 'owner':
            self.document_id = uuid.uuid4().hex
            self.state = 'private'
            return {'outcome': 'created', 'identifier': self.document_id, 'source': 'create-response'}
        if action == 'share' and actor == 'owner' and self.state in {'private', 'shared'}:
            self.link = uuid.uuid4().hex
            self.state = 'shared'
            return {'outcome': 'shared', 'identifier': self.link, 'source': 'share-response'}
        if action == 'revoke' and actor == 'owner' and self.state in {'shared', 'revoked'}:
            self.state = 'revoked'
            return {'outcome': 'revoked'}
        allowed = action == 'read' and (
            actor == 'owner' or (actor == 'recipient' and self.state == 'shared') or
            (actor == 'stranger' and self.state == 'revoked' and self.stale_link_bug))
        return {'outcome': 'read_allowed' if allowed else 'blocked', 'entry': entry}


def case(loop, kind):
    return next(e for e in loop.events if e['type'] == 'flow_case' and e['case_kind'] == kind)


def execute(loop, tmp_path, selected, trace_id, branch, runner='producer', service=None, stop=None):
    service = service or ShareService()
    fm.start_trace(loop, trace_id, selected['case_id'], branch, runner, ENV)
    view = next(t for t in fm.project(loop.events, tmp_path)['traces'] if t['trace_id'] == trace_id)
    for index, step in enumerate(selected[branch]):
        if index < view['next_step']:
            continue
        if stop is not None and index >= stop:
            return service
        before = service.state
        result = service.perform(step['action'], step['actor'], step['entry'])
        after = service.state
        phases = []
        for phase, outcome in [('pre', before), ('action', result['outcome']), ('post', result['outcome'])]:
            artifact = tmp_path / f'{trace_id}-{index}-{phase}.json'
            artifact.write_text(json.dumps({'runner': runner, 'trace': trace_id, 'index': index,
                'actual': step, 'before': before, 'after': after, 'phase': phase,
                'outcome': outcome, 'result': result}))
            phases.append(Observation(step['action'] if phase == 'action' else phase,
                                      True, outcome, str(artifact)))
        fm.record_step(loop, trace_id, step, before, after, *phases, observed_at=datetime.now(UTC).isoformat())
    fm.finish_trace(loop, trace_id, 'completed')
    return service


def hypothesis():
    return LogicHypothesis('revoked-link-read', 'state', 'revoked grant must block share-link reads',
        ENV, 'revoked', 'normal former-recipient denial', 'read', 'read', 'read_allowed',
        expected_normal_outcome='blocked', invariant_ref='revocation')


def test_plans_preserve_negative_guard_attempts_and_identifier_limits(setup):
    loop, _, ids = setup
    assert len(ids) == 5
    assert fm.generate_cases(loop, 'sharing', focus_transition='read-after-revoke') == ids
    assert len([e for e in loop.events if e['type'] == 'flow_case']) == 5
    boundary = case(loop, 'actor-boundary')
    assert boundary['test'][-1]['actor'] == 'stranger'
    assert boundary['control'][-1]['actor'] == 'recipient'
    assert boundary['authorization'] == 'not-granted-by-plan'
    context = fm.worker_context(loop.events, boundary['case_id'])
    identifier = context['definition']['objects']['doc']['identifiers']['share-response']
    assert identifier['attacker_availability'] == 'harness_only'
    assert 'stranger' not in identifier['available_to']
    assert not fm.project(loop.events)['traces']
    assert fm.project(loop.events)['safety_coverage'] == 'not-established-by-traversal'


@pytest.mark.parametrize('kind', ['normal', 'skip', 'repeat', 'actor-boundary', 'entry-boundary'])
def test_isolated_sut_plans_become_evidenced_actual_comparisons(setup, tmp_path, kind):
    loop, _, _ = setup
    selected = case(loop, kind)
    execute(loop, tmp_path, selected, 'test', 'test')
    execute(loop, tmp_path, selected, 'control', 'control')
    verdict, _ = fm.assess_pair(loop, selected['case_id'], 'test', 'control', hypothesis(),
                                expected_pre_state='revoked')
    assert verdict == (Verdict.CONFIRMED if kind == 'actor-boundary' else
                       Verdict.INCONCLUSIVE if kind == 'skip' else Verdict.REFUTED)
    assert loop.capsule()['confirmed'] == {}
    assert not any(e['type'] in {'verdict', 'finding', 'finding_state'} for e in loop.events)
    assert all(not t['stale'] for t in fm.project(loop.events, tmp_path)['traces'])


def test_resume_uses_next_step_without_repeating_executed_actions(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'normal')
    service = execute(loop, tmp_path, selected, 'partial', 'test', stop=2)
    original_id = service.document_id
    ledger = tmp_path / 'ledger.jsonl'
    loop.save(ledger)
    restored = HuntLoop.load(ledger)
    trace = fm.project(restored.events, tmp_path)['traces'][0]
    assert trace['status'] == 'incomplete' and trace['next_step'] == 2
    with pytest.raises(ValueError, match='every step'):
        fm.finish_trace(restored, 'partial', 'completed')
    execute(restored, tmp_path, selected, 'partial', 'test', service=service)
    assert service.document_id == original_id
    assert len(fm.project(restored.events, tmp_path)['traces'][0]['steps']) == 5


def test_missing_evidence_and_misdeclared_prestate_do_not_record_actual_step(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'normal')
    fm.start_trace(loop, 't', selected['case_id'], 'test', 'producer', ENV)
    step = selected['test'][0]
    obs = Observation('create', True, 'absent', str(tmp_path / 'missing.json'))
    with pytest.raises(ValueError, match='pinned artifact'):
        fm.record_step(loop, 't', step, 'absent', 'private', obs, obs, obs)
    obs.outcome = 'shared'
    with pytest.raises(ValueError, match='pre-read'):
        fm.record_step(loop, 't', step, 'absent', 'private', obs, obs, obs)
    assert fm.project(loop.events)['traces'][0]['next_step'] == 0


def test_reproduction_requires_new_runner_new_evidence_and_stales_on_change(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'actor-boundary')
    for prefix, runner in [('source', 'producer'), ('replay', 'independent-verifier')]:
        for branch in ('test', 'control'):
            execute(loop, tmp_path, selected, prefix + '-' + branch, branch, runner)
    report = tmp_path / 'verifier-result.json'
    report.write_text('Independently replayed this constrained fixture; attacker identifier acquisition is unproven.')
    with pytest.raises(ValueError, match='different verifier'):
        fm.record_reproduction(loop, 'source-test', 'source-control', 'replay-test', 'replay-control',
                               'producer', str(report), hypothesis(), expected_pre_state='revoked')
    fm.record_reproduction(loop, 'source-test', 'source-control', 'replay-test', 'replay-control',
                           'independent-verifier', str(report), hypothesis(), expected_pre_state='revoked')
    view = fm.project(loop.events, tmp_path)
    assert view['reproductions'][0]['stage'] == 'reproduced'
    assert view['reproductions'][0]['finding_verified'] is False
    assert not view['reproductions'][0]['stale']
    assert loop.capsule()['confirmed'] == {}
    (tmp_path / 'replay-test-4-post.json').write_text('changed')
    assert fm.project(loop.events, tmp_path)['reproductions'][0]['stale']
    assert fm.assess_pair(loop, selected['case_id'], 'replay-test', 'replay-control', hypothesis(),
                          expected_pre_state='revoked')[0] == Verdict.INCONCLUSIVE


def test_new_model_revision_preserves_history_and_invalidates_old_actuals(setup, tmp_path):
    loop, definition, _ = setup
    selected = case(loop, 'normal')
    execute(loop, tmp_path, selected, 'normal', 'test')
    definition['title'] += ' revised'
    fm.define_flow(loop, definition)
    view = fm.project(loop.events, tmp_path)
    assert len(view['definitions']) == 1
    assert len([e for e in loop.events if e['type'] == 'delivery_record' and e['record_kind'] == 'flow']) == 2
    assert view['traces'][0]['stale']


def test_changed_invariant_reopens_old_trace_even_without_new_model_definition(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'normal')
    execute(loop, tmp_path, selected, 'test', 'test')
    record_invariant(loop, Invariant('revocation', 'Policy changed; previous comparison no longer suffices.',
                                    source='inferred'))
    assert fm.project(loop.events, tmp_path)['traces'][0]['stale']


def test_existing_delivery_flow_is_the_only_model_authority_and_trace_adapter_needs_finding(setup, tmp_path):
    loop, definition, _ = setup
    revision = fm.define_flow(loop, definition)
    assert revision == research_delivery.records(loop.events)['flow']['sharing']['revision']
    assert not any(e['type'] == 'flow_definition' for e in loop.events)
    selected = case(loop, 'actor-boundary')
    execute(loop, tmp_path, selected, 'test', 'test')
    execute(loop, tmp_path, selected, 'control', 'control')
    options = {'trace_id': 'delivery-trace', 'finding_id': 'LAB-001',
               'phases': ['setup', 'setup', 'control', 'trigger', 'observe'], 'mode': 'api',
               'expected': 'Revoked share link denies both actors.',
               'actual': 'Fixture stranger reads after revocation while normal former recipient is blocked.',
               'impact': 'Controlled fixture only.', 'limitations': 'Attacker identifier was harness-provided.'}
    with pytest.raises(ValueError, match='Finding must'):
        fm.publish_delivery_trace(loop, 'test', 'control', **options)
    assert not research_delivery.records(loop.events)['trace']
    # Represents a separate existing canonical Finding; the flow module creates none.
    loop.append('finding', finding_id='LAB-001', status='tested')
    fm.publish_delivery_trace(loop, 'test', 'control', **options)
    published = research_delivery.project(loop.events)['trace'][0]
    assert published['flow_id'] == 'sharing'
    assert published['flow_id_revision'] == revision
    assert published['research_binding']['trace_ids'] == ['test', 'control']
    assert 'harness_only' in published['data_origin']
    assert not published['stale']
    loop.append('evidence_context', context_id='target', context={
        'version': 'changed-runtime', 'role': ENV.role, 'settings': {}, 'environment': {'host': ENV.host}})
    assert research_delivery.project(loop.events)['trace'][0]['stale']
    loop.append('evidence_context', context_id='target', context={
        'version': ENV.version, 'role': ENV.role, 'settings': {}, 'environment': {'host': ENV.host}})
    assert not research_delivery.project(loop.events)['trace'][0]['stale']
    (tmp_path / 'control-4-post.json').write_text('changed control evidence')
    assert research_delivery.project(loop.events)['trace'][0]['stale']


def test_graphwalker_export_is_bounded_topology_without_executable_guards(setup):
    _, definition, _ = setup
    model = fm.graphwalker_topology(definition)['models'][0]
    assert model['generator'] == 'random(length(20))'
    assert len(model['edges']) == 5
    assert all('guard' not in edge and 'actions' not in edge for edge in model['edges'])
    assert all(edge['properties']['expected_preconditions'] for edge in model['edges'])


def test_bound_case_reaches_existing_worker_and_stale_model_blocks_prompt(setup):
    from hunt_autodrive import WorkerTask
    from hunt_worker import make_dispatch, render_worker_prompt
    loop, definition, _ = setup
    selected = case(loop, 'actor-boundary')
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    assert fm.bind_case(loop, selected['case_id'], hyp.hyp_id, 'revocation')
    context = fm.context_for_hypothesis(loop.events, hyp.hyp_id)
    prompt = render_worker_prompt(WorkerTask(hyp, hyp.invariant, flow_context=context))
    assert 'Bound user-flow comparison' in prompt
    assert selected['case_id'] in prompt and 'harness_only' in prompt
    assert 'stranger' in prompt and 'recipient' in prompt
    definition['title'] = 'Changed normal flow requires a new comparison'
    fm.define_flow(loop, definition)
    context = fm.context_for_hypothesis(loop.events, hyp.hyp_id)
    with pytest.raises(ValueError, match='flow model'):
        render_worker_prompt(WorkerTask(hyp, hyp.invariant, flow_context=context))
    calls = []
    test, control = make_dispatch(lambda *_: calls.append('must-not-run'))(
        WorkerTask(hyp, hyp.invariant, flow_context=context))
    assert calls == [] and not test.ok and not control.ok
    assert 'worker brief' in test.error


def test_changed_runtime_conditions_invalidate_actual_trace_and_worker_context(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'actor-boundary')
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    fm.bind_case(loop, selected['case_id'], hyp.hyp_id, 'revocation')
    execute(loop, tmp_path, selected, 'test', 'test')
    assert not fm.project(loop.events, tmp_path)['traces'][0]['stale']
    loop.append('evidence_context', context_id='target', context={
        'version': 'new-runtime', 'role': ENV.role, 'settings': {}, 'environment': {'host': ENV.host}})
    assert fm.project(loop.events, tmp_path)['traces'][0]['stale']
    assert fm.context_for_hypothesis(loop.events, hyp.hyp_id, tmp_path)['stale']


def test_recording_old_bytes_does_not_invent_a_new_observation_time(setup, tmp_path):
    loop, _, _ = setup
    selected = case(loop, 'normal')
    fm.start_trace(loop, 'unknown-time', selected['case_id'], 'test', 'fixture', ENV)
    step = selected['test'][0]
    service = ShareService()
    result = service.perform(step['action'], step['actor'], step['entry'])
    artifact = tmp_path / 'capture.json'
    artifact.write_text(json.dumps({'before': 'absent', 'after': service.state, 'result': result}))
    fm.record_step(loop, 'unknown-time', step, 'absent', service.state,
                   Observation('pre', True, 'absent', str(artifact)),
                   Observation(step['action'], True, result['outcome'], str(artifact)),
                   Observation('post', True, result['outcome'], str(artifact)))
    trace = fm.project(loop.events, tmp_path)['traces'][0]
    assert trace['stale'] and trace['steps'][0]['recorded_at']
    assert trace['steps'][0]['post']['evidence_ref']['applicability']['observed_at'] is None


def test_flow_cli_uses_canonical_ledger_and_persists_case_binding(setup, tmp_path):
    loop, definition, _ = setup
    loop.append('genesis', profile='source-audit')
    loop.add_hypothesis(hypothesis().hyp_id)
    td = tmp_path / '01 - Targets' / 'fixture'
    ledger = td / '.state/asg-events.jsonl'
    loop.save(ledger)
    model_file = tmp_path / 'flow.json'
    model_file.write_text(json.dumps(definition))
    command = [sys.executable, str(Path(fm.__file__)), td.name]
    process_env = {**os.environ, 'VAULT_ROOT': str(tmp_path)}
    for args in (['define', '--input', str(model_file)], ['plan', '--flow-id', 'sharing']):
        result = subprocess.run([*command, *args], env=process_env, text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
    selected = case(loop, 'actor-boundary')
    result = subprocess.run([*command, 'bind', '--case-id', selected['case_id'],
                             '--hyp-id', hypothesis().hyp_id, '--invariant-ref', 'revocation'],
                            env=process_env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    restored = HuntLoop.load(ledger)
    assert len([e for e in restored.events if e['type'] == 'flow_case']) == 5
    assert fm.context_for_hypothesis(restored.events, hypothesis().hyp_id)['case']['case_id'] == selected['case_id']


def test_generated_views_distinguish_plans_actual_paths_and_replays(setup, tmp_path, monkeypatch):
    import asg
    import next_work
    from hunt_integration import handoff

    loop, _, _ = setup
    loop.append('genesis', profile='source-audit')
    selected = case(loop, 'actor-boundary')
    execute(loop, tmp_path, selected, 'partial', 'test', stop=2)
    td = tmp_path / '01 - Targets' / 'fixture'
    monkeypatch.setattr(asg, 'vault_root', lambda: tmp_path)
    monkeypatch.setattr(next_work, 'TARGETS', td.parent)
    ledger = td / '.state/asg-events.jsonl'
    loop.save(ledger)
    md = asg.project_markdown(td).read_text()
    assert '```mermaid' in md and 'actor-boundary' in md
    assert 'Actual and replayed paths' in md and 'actual/incomplete' in md
    snapshot = json.loads(asg.write_snapshot(td).read_text())
    assert snapshot['flow_model']['flow_ids'] == ['sharing']
    assert snapshot['flow_model']['traces'][0]['next_step'] == 2
    assert not snapshot['flow_model']['reproductions']
    assert handoff(HuntLoop.load(ledger))['priority']['flow_model']['traces'][0]['status'] == 'incomplete'
    # Absolute target paths use the canonical resolver; no real target is read.
    queue = next_work.compute(td.name)['next_work']
    assert any(item['kind'] == 'flow-resume' and item['ref'] == 'partial' for item in queue)
