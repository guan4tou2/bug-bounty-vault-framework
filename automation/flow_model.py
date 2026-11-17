"""Evidence-backed flow plans and actual traces over the existing ASG ledger.

Append/project functions plus a bounded offline path planner: no target executor,
evaluator expressions, target traffic, Finding promotion or authorization inference.
The caller owns the existing ledger lock and guarded_save transaction.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime

import research_delivery
from evidence_applicability import assess_evidence, latest_context
from evidence_refs import artifact_hash, artifact_path, evidence_resolves, normalize_evidence
from hunt_loop import HuntLoop, Verdict
from logic_vuln_loop import (
    Env,
    LogicHypothesis,
    Observation,
    guard_invariant_provenance,
    judge_state_transition,
    resolve_invariant,
)

STEP_KEYS = {'transition_id', 'actor', 'object', 'entry', 'action', 'identifier_ref'}
TERMINAL = {'completed', 'failed', 'cancelled', 'interrupted'}
MODEL_KEYS = ('title', 'environment', 'actors', 'objects', 'states', 'entries', 'transitions', 'normal_path')


def _flow_events(events):
    """Adapter over the existing delivery flow authority; no parallel flow store."""
    result = []
    for event in events:
        if event.get('type') != 'delivery_record' or event.get('record_kind') != 'flow':
            continue
        d = event['data']
        if d.get('efsm_schema') != 1:
            continue
        definition = {'flow_id': d['id'], **{k: d[k] for k in MODEL_KEYS}}
        definition['transitions'] = [{k: v for k, v in t.items() if k not in {'guard', 'expected'}}
                                     for t in d['transitions']]
        result.append({'flow_id': d['id'], 'version': event['revision'], 'definition': definition,
                       'evidence_current': research_delivery.files_current(d['evidence']),
                       'invariant_versions': d.get('invariant_versions', {})})
    return result


def _copy(value):
    return json.loads(json.dumps(value, allow_nan=False))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _event(loop, kind, key, value):
    rows = _flow_events(loop.events) if kind == 'flow_definition' else (
        e for e in loop.events if e['type'] == kind)
    found = [e for e in rows if e.get(key) == value]
    if not found:
        raise ValueError(f'unknown {kind}')
    return found[-1]


def _unique(loop, kind, key, payload):
    prior = [e for e in loop.events if e['type'] == kind and e.get(key) == payload[key]]
    if prior:
        if any(prior[-1].get(k) != v for k, v in payload.items()):
            raise ValueError('identity already has different content')
        return False
    loop.append(kind, **_copy(payload))
    return True


def _definition(loop, version):
    return _event(loop, 'flow_definition', 'version', version)['definition']


def define_flow(loop, definition):
    """Record a declared model. Model guards are expectations, never authorization.

    Identifiers describe the normal user's source and separately the researcher's
    knowledge of attacker availability. A harness-provided ID is not obtainable proof.
    """
    d = _copy(definition)
    for key in ('flow_id', 'title'):
        if not _text(d.get(key)):
            raise ValueError(f'definition requires {key}')
    for key in ('actors', 'objects', 'entries'):
        if not isinstance(d.get(key), dict) or not d[key]:
            raise ValueError(f'definition requires {key} mapping')
    Env(**d['environment'])
    if not isinstance(d.get('states'), list) or not d['states'] or any(not _text(s) for s in d['states']):
        raise ValueError('states must be nonempty names')
    for actor in d['actors'].values():
        if not all(_text(actor.get(k)) for k in ('account_ref', 'role')):
            raise ValueError('actors require account references and roles')
    for obj in d['objects'].values():
        if obj.get('owner') not in d['actors'] or not isinstance(obj.get('relationships'), dict):
            raise ValueError('object requires owner and explicit relationships')
        if not isinstance(obj.get('identifiers'), dict) or not obj['identifiers']:
            raise ValueError('object requires identifier source lineage')
        for identifier in obj['identifiers'].values():
            if not _text(identifier.get('source')) or identifier.get('attacker_availability') not in {
                    'observed', 'inferred', 'unknown', 'harness_only', 'unavailable'}:
                raise ValueError('identifier source and attacker availability must be explicit')
            if not isinstance(identifier.get('available_to'), list) or any(
                    actor not in d['actors'] for actor in identifier['available_to']):
                raise ValueError('identifier availability must reference model actors')
    transitions = d.get('transitions')
    if not isinstance(transitions, list) or not transitions:
        raise ValueError('flow requires transitions')
    ids = set()
    for transition in transitions:
        if 'predicate' in transition:
            from efsm_conditions import validate
            validate(transition['predicate'])
        tid = transition.get('id')
        if not _text(tid) or tid in ids:
            raise ValueError('transition IDs must be unique')
        ids.add(tid)
        for key, table in (('actor', 'actors'), ('object', 'objects'), ('entry', 'entries')):
            if transition.get(key) not in d[table]:
                raise ValueError(f'transition references unknown {key}')
        if any(transition.get(k) not in d['states'] for k in ('from', 'to')):
            raise ValueError('transition states must exist')
        if not _text(transition.get('action')) or not isinstance(transition.get('preconditions'), list):
            raise ValueError('transition needs an action and declarative preconditions')
        if transition.get('identifier_ref') not in d['objects'][transition['object']]['identifiers']:
            raise ValueError('transition identifier source is unknown')
        if not transition.get('invariant_refs') or any(
                resolve_invariant(loop, ref) is None for ref in transition['invariant_refs']):
            raise ValueError('transition requires existing invariant references')
    path = d.get('normal_path')
    if not isinstance(path, list) or not path or any(tid not in ids for tid in path):
        raise ValueError('normal user path must name existing transitions')
    by_id = {t['id']: t for t in transitions}
    if any(by_id[a]['to'] != by_id[b]['from'] for a, b in zip(path, path[1:], strict=False)):
        raise ValueError('normal user path is discontinuous')
    invariant_ids = sorted({ref for t in transitions for ref in t['invariant_refs']})
    invariant_versions = {ref: _digest(asdict(resolve_invariant(loop, ref))) for ref in invariant_ids}
    prior = research_delivery.records(loop.events)['flow'].get(d['flow_id'])
    if prior and prior['data'].get('efsm_schema') == 1:
        current = _event(loop, 'flow_definition', 'flow_id', d['flow_id'])
        if current['definition'] == d and prior['data'].get('invariant_versions') == invariant_versions:
            return prior['revision']
    evidence = []
    for ref in invariant_ids:
        invariant = resolve_invariant(loop, ref)
        for original in invariant.evidence_refs:
            proof = normalize_evidence(original, loop.base_path)
            if isinstance(proof, dict) and proof.get('kind') == 'artifact':
                evidence.append({'path': proof['path'], 'sha256': proof.get('sha256'), 'locator': 'whole-file'})
    data = {**(prior['data'] if prior else {}), **{k: d[k] for k in MODEL_KEYS},
            'id': d['flow_id'], 'efsm_schema': 1, 'entry': by_id[path[0]]['entry'],
            'initial_state': by_id[path[0]]['from'], 'invariant': ', '.join(invariant_ids),
            'rule_source': 'Existing ASG invariant references: ' + ', '.join(invariant_ids),
            'evidence': evidence, 'invariant_versions': invariant_versions,
            'transitions': [{**t, 'guard': '; '.join(t['preconditions']) or 'No declared preconditions',
                             'expected': t['to']} for t in transitions]}
    payload = {'record_kind': 'flow', 'data': data}
    if prior:
        payload['previous_revision'] = prior['revision']
    normalized = research_delivery.normalize(payload, loop)
    loop.append('delivery_record', **normalized)
    return normalized['revision']


def generate_cases(loop, flow_id, *, focus_transition=None):
    """Bounded normal/skip/repeat/actor/entry plans, without filtering failed guards.

    They are proposed cases only. Authorization, identifier availability and guard
    failures stay visible for the existing executor/planner to assess.
    """
    event = _event(loop, 'flow_definition', 'flow_id', flow_id)
    d, version = event['definition'], event['version']
    by_id = {t['id']: t for t in d['transitions']}
    focus = focus_transition or d['normal_path'][-1]
    if focus not in d['normal_path']:
        raise ValueError('focus must be in the normal path')
    normal = [{k: t['id'] if k == 'transition_id' else t[k] for k in STEP_KEYS}
              for tid in d['normal_path'] for t in [by_id[tid]]]
    index = d['normal_path'].index(focus)
    variants = [('normal', normal), ('skip', normal[:index] + normal[index + 1:]),
                ('repeat', normal[:index + 1] + [normal[index]] + normal[index + 1:])]
    actor = next((a for a in d['actors'] if a != normal[index]['actor']), None)
    if actor:
        changed = _copy(normal)
        changed[index]['actor'] = actor
        variants.append(('actor-boundary', changed))
    entry = next((e for e in d['entries'] if e != normal[index]['entry']), None)
    if entry:
        changed = _copy(normal)
        changed[index]['entry'] = entry
        variants.append(('entry-boundary', changed))
    result = []
    for kind, test in variants:
        if not test:
            continue
        data = {'flow_id': flow_id, 'definition_version': version, 'case_kind': kind,
                'test': test, 'control': normal, 'focus_transition': focus,
                'guard_expectations': by_id[focus]['preconditions'],
                'authorization': 'not-granted-by-plan', 'stage': 'planned'}
        cid = flow_id + ':' + kind + ':' + _digest(data)[:16]
        _unique(loop, 'flow_case', 'case_id', {'case_id': cid, **data})
        result.append(cid)
    return result


def start_trace(loop, trace_id, case_id, branch, runner_id, environment):
    case = _event(loop, 'flow_case', 'case_id', case_id)
    if branch not in {'test', 'control'} or not _text(runner_id) or not _text(trace_id):
        raise ValueError('trace needs TEST/CONTROL branch and runner identity')
    if not isinstance(environment, Env):
        raise ValueError('environment must be Env')
    d = _definition(loop, case['definition_version'])
    if not Env(**d['environment']).matches(environment):
        raise ValueError('trace environment does not match model')
    return _unique(loop, 'flow_trace_started', 'trace_id', {
        'trace_id': trace_id, 'case_id': case_id, 'branch': branch,
        'runner_id': runner_id, 'environment': asdict(environment), 'stage': 'actual'})


def _trace(loop, trace_id):
    start = _event(loop, 'flow_trace_started', 'trace_id', trace_id)
    case = _event(loop, 'flow_case', 'case_id', start['case_id'])
    steps = [e for e in loop.events if e['type'] == 'flow_trace_step' and e['trace_id'] == trace_id]
    finished = [e for e in loop.events if e['type'] == 'flow_trace_finished' and e['trace_id'] == trace_id]
    return start, case, steps, finished


def _proof(loop, observation, environment, observed_at=None):
    if not isinstance(observation, Observation) or type(observation.ok) is not bool:
        raise ValueError('actual observations must use Observation and boolean ok')
    proof = normalize_evidence(observation.evidence_ref, loop.base_path, environment, events=loop.events)
    if isinstance(proof, dict) and proof.get('kind') == 'artifact' and 'applicability' not in proof:
        current = latest_context(loop.events) or {}
        proof['applicability'] = {**current, 'version': environment['version'], 'role': environment['role'],
                                  'context_id': 'target', 'observed_at': observed_at}
    path = artifact_path(proof.get('path'), loop.base_path) if isinstance(proof, dict) else None
    if (not isinstance(proof, dict) or proof.get('kind') != 'artifact'
            or path is None or artifact_hash(path) != proof.get('sha256')):
        raise ValueError('each actual observation needs existing pinned artifact evidence')
    if observation.ok and not _text(observation.outcome):
        raise ValueError('successful observation requires actual outcome')
    return {**asdict(observation), 'evidence_ref': proof}


def record_step(loop, trace_id, actual, before_state, after_state, pre, action, post, *, observed_at=None):
    """Append exactly one observed step, after execution; never execute its plan.

    Pre/action/post each pin evidence. Planned guards are not used to discard an
    unauthorized attempt. Unexpected state changes and action deviations are retained.
    """
    start, case, steps, finished = _trace(loop, trace_id)
    if finished or len(steps) >= len(case[start['branch']]):
        raise ValueError('trace is terminal or has no remaining planned step')
    actual = _copy(actual)
    if set(actual) != STEP_KEYS or any(not _text(v) for v in actual.values()):
        raise ValueError('actual action must explicitly identify actor/object/entry/action/identifier')
    d = _definition(loop, case['definition_version'])
    if not _text(before_state) or not _text(after_state):
        raise ValueError('actual states must be explicit observations')
    for key, table in (('actor', 'actors'), ('object', 'objects'), ('entry', 'entries')):
        if actual[key] not in d[table]:
            raise ValueError('actual references an unknown model entity')
    if actual['transition_id'] not in {t['id'] for t in d['transitions']} or actual['identifier_ref'] not in (
            d['objects'][actual['object']]['identifiers']):
        raise ValueError('actual transition/identifier reference is unknown')
    if pre.ok and pre.outcome != before_state:
        raise ValueError('pre-read observation must establish the declared actual state')
    # A product state and a response token are different dimensions (for example,
    # state="revoked" with observed response="content"). Do not equate them.
    if action.action_id != actual['action']:
        raise ValueError('action observation must bind the actual action')
    observed = {name: _proof(loop, obs, start['environment'], observed_at)
                for name, obs in [('pre', pre), ('action', action), ('post', post)]}
    from efsm_conditions import predict
    transition = next(t for t in d['transitions'] if t['id'] == actual['transition_id'])
    variables = {'actor': actual['actor'], 'role': d['actors'][actual['actor']]['role'],
                 'owner': d['objects'][actual['object']]['owner'], 'state': before_state,
                 'entry': actual['entry'],
                 'relationship': d['objects'][actual['object']]['relationships'].get(actual['actor'])}
    loop.append('flow_trace_step', trace_id=trace_id, index=len(steps), actual=actual,
                before_state=before_state, after_state=after_state,
                product_expectation=predict(transition, variables, observed_state=before_state),
                recorded_at=datetime.now(UTC).isoformat(), **observed)


def finish_trace(loop, trace_id, status, *, error=None):
    start, case, steps, finished = _trace(loop, trace_id)
    if status not in TERMINAL or finished:
        raise ValueError('invalid status or already terminal trace')
    if status == 'completed' and (len(steps) != len(case[start['branch']]) or any(
            not e[phase]['ok'] for e in steps for phase in ('pre', 'action', 'post'))):
        raise ValueError('completed trace requires every step and successful observations')
    loop.append('flow_trace_finished', trace_id=trace_id, status=status, error=error)


def _trace_current(loop, trace_id):
    start, case, steps, finished = _trace(loop, trace_id)
    latest = _event(loop, 'flow_definition', 'flow_id', case['flow_id'])
    pinned_model = _event(loop, 'flow_definition', 'version', case['definition_version'])
    rules_changed = any(resolve_invariant(loop, ref) is None or _digest(asdict(resolve_invariant(loop, ref))) != version
                        for ref, version in pinned_model['invariant_versions'].items())
    stale = (case['definition_version'] != latest['version'] or not pinned_model['evidence_current']
             or rules_changed or any(not evidence_resolves(step[phase]['evidence_ref'], loop.base_path, loop.events)
                                     for step in steps for phase in ('pre', 'action', 'post')))
    deviations = [step['index'] for step in steps if step['actual'] != case[start['branch']][step['index']]]
    discontinuities = [b['index'] for a, b in zip(steps, steps[1:], strict=False)
                       if a['after_state'] != b['before_state']]
    return {'trace_id': trace_id, 'case_id': case['case_id'], 'branch': start['branch'],
            'runner_id': start['runner_id'], 'environment': start['environment'],
            'stage': 'actual', 'status': finished[-1]['status'] if finished else 'incomplete',
            'stale': stale, 'deviations': deviations, 'discontinuities': discontinuities, 'steps': steps,
            'next_step': None if finished else len(steps),
            'observed_transition_ids': sorted({s['actual']['transition_id'] for s in steps}),
            'unmodelled_states': sorted({s[key] for s in steps for key in ('before_state', 'after_state')
                                        if s[key] not in pinned_model['definition']['states']}),
            'safety_coverage': 'not-established-by-traversal'}


def assess_pair(loop, case_id, test_id, control_id, hypothesis, *, expected_pre_state,
                test_index=-1, control_index=-1):
    """Advisory differential only; writes no verdict, capability or Finding state."""
    if not isinstance(hypothesis, LogicHypothesis):
        raise ValueError('hypothesis must use the existing LogicHypothesis contract')
    test, control = (_trace_current(loop, tid) for tid in (test_id, control_id))
    if any(t['case_id'] != case_id or t['status'] != 'completed' or t['stale']
           or t['deviations'] or t['discontinuities']
           for t in (test, control)) or test['branch'] != 'test' or control['branch'] != 'control':
        return Verdict.INCONCLUSIVE, 'requires current, complete, explicitly matched TEST/CONTROL traces'
    if test['environment'] != control['environment'] or not hypothesis.applies_env.matches(Env(**test['environment'])):
        return Verdict.INCONCLUSIVE, 'TEST/CONTROL environment mismatch'
    try:
        ts, cs = test['steps'][test_index], control['steps'][control_index]
    except IndexError:
        return Verdict.INCONCLUSIVE, 'requested comparison step is absent'
    inv = resolve_invariant(loop, hypothesis.invariant_ref)
    case = _event(loop, 'flow_case', 'case_id', case_id)
    definition = _definition(loop, case['definition_version'])
    transition = next(t for t in definition['transitions'] if t['id'] == ts['actual']['transition_id'])
    baseline = next(t for t in definition['transitions'] if t['id'] == cs['actual']['transition_id'])
    if inv is None or inv.inv_id not in transition['invariant_refs'] or not inv.evidence_refs or any(
            not evidence_resolves(normalize_evidence(ref, loop.base_path, events=loop.events),
                                  loop.base_path, loop.events)
            for ref in inv.evidence_refs):
        return Verdict.INCONCLUSIVE, 'invariant provenance is unresolved or not bound to this transition'
    if ts['before_state'] != expected_pre_state or expected_pre_state != transition['from'] or (
            cs['before_state'] != baseline['from']) or not (
            hypothesis.expected_normal_outcome and ts['actual']['action'] == hypothesis.test_action
            and cs['actual']['action'] == hypothesis.control_action):
        return Verdict.INCONCLUSIVE, 'expected pre-state and normative CONTROL must be established'
    verdict, reason = judge_state_transition(hypothesis, Observation(**ts['pre']),
                                             Observation(**ts['post']), Observation(**cs['post']))
    return guard_invariant_provenance(inv, verdict, reason)


def record_reproduction(loop, source_test, source_control, replay_test, replay_control,
                        verifier_id, evidence_ref, hypothesis, *, expected_pre_state):
    """Bind a separate runner's replay to exact source/replay trace fingerprints.

    Runner identities must be assigned by the host. A recorded replay is never a
    Finding verification; this pure module cannot authenticate an external runner.
    """
    traces = [_trace_current(loop, tid) for tid in (source_test, source_control, replay_test, replay_control)]
    if traces[2]['runner_id'] != verifier_id or traces[3]['runner_id'] != verifier_id or any(
            t['runner_id'] == verifier_id for t in traces[:2]):
        raise ValueError('replay requires a different verifier runner identity')
    if len({t['trace_id'] for t in traces}) != 4 or len({t['case_id'] for t in traces}) != 1:
        raise ValueError('replay must bind four distinct traces of the same case')
    def outcomes_of(trace):
        return [{k: step[k] for k in ('actual', 'before_state', 'after_state')} | {
            phase: {k: step[phase][k] for k in ('ok', 'outcome', 'error')}
            for phase in ('pre', 'action', 'post')} for step in trace['steps']]
    if any(outcomes_of(traces[i]) != outcomes_of(traces[i + 2]) for i in (0, 1)):
        raise ValueError('replay actual path and outcomes differ from source trace')
    source_paths = {s[p]['evidence_ref']['path'] for t in traces[:2] for s in t['steps']
                    for p in ('pre', 'action', 'post')}
    if any(s[p]['evidence_ref']['path'] in source_paths for t in traces[2:] for s in t['steps']
           for p in ('pre', 'action', 'post')):
        raise ValueError('replay needs its own evidence, not the original trace artifacts')
    outcomes = [assess_pair(loop, traces[0]['case_id'], a, b, hypothesis,
                           expected_pre_state=expected_pre_state)[0]
                for a, b in ((source_test, source_control), (replay_test, replay_control))]
    if outcomes[0] == Verdict.INCONCLUSIVE or outcomes[0] != outcomes[1]:
        raise ValueError('replay did not independently reproduce the advisory result')
    proof = normalize_evidence(evidence_ref, loop.base_path)
    if (not isinstance(proof, dict) or proof.get('kind') != 'artifact'
            or not evidence_resolves(proof, loop.base_path, loop.events)):
        raise ValueError('verifier result requires pinned artifact evidence')
    fingerprint = _digest([t['steps'] for t in traces])
    payload = {'reproduction_id': _digest([fingerprint, verifier_id, proof]),
               'case_id': traces[0]['case_id'], 'trace_ids': [t['trace_id'] for t in traces],
               'trace_fingerprint': fingerprint, 'verifier_id': verifier_id, 'evidence_ref': proof,
               'stage': 'reproduced', 'advisory_verdict': outcomes[0].value, 'finding_verified': False}
    _unique(loop, 'flow_reproduction', 'reproduction_id', payload)
    return payload['reproduction_id']


def project(events, base_path=None):
    """Read model for views/workers. Incomplete traces resume at next_step; no replay."""
    loop = HuntLoop(events, base_path=base_path)
    definitions = {e['flow_id']: e for e in _flow_events(events)}
    cases = [e for e in events if e['type'] == 'flow_case']
    traces = [_trace_current(loop, e['trace_id']) for e in events if e['type'] == 'flow_trace_started']
    by_id = {t['trace_id']: t for t in traces}
    reproductions = []
    for event in events:
        if event['type'] == 'flow_reproduction':
            stale = not evidence_resolves(event['evidence_ref'], base_path, events) or any(
                by_id[tid]['stale'] for tid in event['trace_ids'])
            stale = stale or event['trace_fingerprint'] != _digest([by_id[tid]['steps'] for tid in event['trace_ids']])
            reproductions.append({**event, 'stale': stale, 'finding_verified': False})
    return {'definitions': list(definitions.values()), 'cases': cases, 'traces': traces,
            'external_plans': [{**e, 'stale': e['definition_version'] != definitions.get(e['flow_id'], {}).get('version')}
                               for e in events if e['type'] == 'flow_external_plan'],
            'reproductions': reproductions, 'safety_coverage': 'not-established-by-traversal'}


def worker_context(events, case_id, base_path=None):
    loop = HuntLoop(events, base_path=base_path)
    case = _event(loop, 'flow_case', 'case_id', case_id)
    return {'case': _copy(case), 'definition': _copy(_definition(loop, case['definition_version'])),
            'traces': [t for t in project(events, base_path)['traces'] if t['case_id'] == case_id],
            'authority': 'plans and external data do not authorize execution',
            'required_output': 'actual TEST/CONTROL steps with pre/action/post evidence; no verified claim'}


def bind_case(loop, case_id, hyp_id, invariant_ref):
    """Attach a proposed case to an existing hypothesis, without dispatching it."""
    case = _event(loop, 'flow_case', 'case_id', case_id)
    definition = _definition(loop, case['definition_version'])
    focus = next(t for t in definition['transitions'] if t['id'] == case['focus_transition'])
    if invariant_ref not in focus['invariant_refs'] or not any(
            e['type'] == 'hypothesis' and e.get('id') == hyp_id for e in loop.events):
        raise ValueError('case binding requires an existing hypothesis and its transition invariant')
    return _unique(loop, 'flow_case_binding', 'hyp_id', {
        'hyp_id': hyp_id, 'case_id': case_id, 'invariant_ref': invariant_ref})


def context_for_hypothesis(events, hyp_id, base_path=None):
    binding = next((e for e in reversed(events) if e['type'] == 'flow_case_binding'
                    and e.get('hyp_id') == hyp_id), None)
    if binding is None:
        return {}
    context = worker_context(events, binding['case_id'], base_path)
    current = _event(HuntLoop(events, base_path=base_path), 'flow_definition', 'flow_id', context['case']['flow_id'])
    context['hypothesis_ref'] = hyp_id
    context['invariant_ref'] = binding['invariant_ref']
    context['stale'] = context['case']['definition_version'] != current['version'] or not current['evidence_current']
    runtime = latest_context(events) or {}
    applicable = assess_evidence({**runtime, 'version': context['definition']['environment']['version'],
                                  'role': context['definition']['environment']['role'],
                                  'observed_at': datetime.now(UTC).isoformat()}, runtime)
    context['applicability'] = applicable
    context['stale'] = context['stale'] or applicable['requires_revalidation']
    return context


def summary(events, base_path=None):
    view = project(events, base_path)
    return {'flow_ids': [d['flow_id'] for d in view['definitions']],
            'cases': len(view['cases']),
            'external_plans': [{k: p[k] for k in ('plan_id', 'flow_id', 'stage', 'stale', 'transition_ids',
                                                  'runtime', 'security_coverage')}
                               for p in view['external_plans']],
            'traces': [{key: t[key] for key in ('trace_id', 'case_id', 'stage', 'status', 'stale', 'next_step',
                                                'unmodelled_states', 'safety_coverage')} for t in view['traces']],
            'reproductions': [{key: r[key] for key in ('reproduction_id', 'case_id', 'stage', 'stale',
                                                       'finding_verified')} for r in view['reproductions']],
            'safety_coverage': view['safety_coverage']}


def markdown(events, base_path=None):
    """Expected user flow, proposed boundary matrix, and actual paths stay distinct."""
    view = project(events, base_path)
    if not view['definitions']:
        return ''

    def cell(value):
        return str(value).replace('|', '&#124;').replace('\n', ' ').replace('`', "'")

    def actions(case, branch):
        return ' → '.join(f"{s['actor']}:{s['action']}@{s['entry']}" for s in case[branch])

    lines = ['### User-flow models and boundary cases',
             '_Expected paths and proposals; traversal does not establish security coverage._']
    for model in view['definitions']:
        d = model['definition']
        lines.extend(['', f"#### {cell(d['flow_id'])} — {cell(d['title'])}", '```mermaid', 'flowchart LR'])
        ids = {state: 's' + _digest([d['flow_id'], state])[:12] for state in d['states']}
        for state, node in ids.items():
            label = state.replace('"', '&quot;').replace('\n', ' ')
            lines.append(f'{node}["{label}"]')
        for transition in d['transitions']:
            label = cell(f"{transition['actor']}: {transition['action']} ({transition['entry']})")
            label = label.replace('"', '&quot;')
            lines.append(f'{ids[transition["from"]]} -->|"{label}"| {ids[transition["to"]]}')
        lines.extend(['```', '', '| Case | Boundary | TEST actions | CONTROL actions |', '|---|---|---|---|'])
        for case in view['cases']:
            if case['flow_id'] == d['flow_id'] and case['definition_version'] == model['version']:
                lines.append(f"| {cell(case['case_id'])} | {cell(case['case_kind'])} | "
                             f"{cell(actions(case, 'test'))} | {cell(actions(case, 'control'))} |")
    lines.extend(['', '#### Actual and replayed paths'])
    for plan in view['external_plans']:
        lines.append(f"- `{cell(plan['plan_id'])}`: GraphWalker planned only; stale={plan['stale']}; "
                     f"generated transitions={cell(plan['transition_ids'])}; security coverage not established")
    for trace in view['traces']:
        lines.append(f"- `{cell(trace['trace_id'])}`: actual/{trace['status']}; stale={trace['stale']}; "
                     f"next step={trace['next_step']}; unmodelled states={cell(trace['unmodelled_states'])}")
    for replay in view['reproductions']:
        lines.append(f"- `{replay['reproduction_id']}`: reproduced; stale={replay['stale']}; Finding verified=False")
    return '\n'.join(lines)


def plan_graphwalker(loop, flow_id, binary, *, length=20, seed=42):
    from graphwalker_adapter import generate
    current = _event(loop, 'flow_definition', 'flow_id', flow_id)
    if not current['evidence_current']:
        raise ValueError('flow evidence requires revalidation')
    plan = generate(current['definition'], binary, length=length, seed=seed)
    payload = {**plan, 'definition_version': current['version']}
    plan_id = _digest(payload)
    _unique(loop, 'flow_external_plan', 'plan_id', {**payload, 'plan_id': plan_id})
    return {**payload, 'plan_id': plan_id}


def main():
    import argparse
    from pathlib import Path

    import asg
    from hunt_lock import acquire, guarded_save, release

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    parser.add_argument('command', choices=['define', 'plan', 'bind', 'view'])
    parser.add_argument('--input', type=Path)
    parser.add_argument('--flow-id')
    parser.add_argument('--focus-transition')
    parser.add_argument('--case-id')
    parser.add_argument('--hyp-id')
    parser.add_argument('--invariant-ref')
    parser.add_argument('--graphwalker-binary', type=Path)
    parser.add_argument('--length', type=int, default=20)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    token = acquire(ledger, 'flow-model') if args.command != 'view' else None
    try:
        loop = HuntLoop.load(ledger)
        if args.command != 'view' and not any(e['type'] == 'genesis' for e in loop.events):
            parser.error('target requires an existing genesis')
        if args.command == 'define':
            if args.input is None:
                parser.error('define requires --input')
            result = {'version': define_flow(loop, json.loads(args.input.read_text()))}
        elif args.command == 'plan':
            result = {'cases': generate_cases(loop, args.flow_id, focus_transition=args.focus_transition)}
            if args.graphwalker_binary:
                result['external_plan'] = plan_graphwalker(loop, args.flow_id, args.graphwalker_binary,
                                                           length=args.length, seed=args.seed)
        elif args.command == 'bind':
            result = {'bound': bind_case(loop, args.case_id, args.hyp_id, args.invariant_ref)}
        else:
            result = project(loop.events, loop.base_path)
        if token is not None:
            guarded_save(loop, ledger, token)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        if token is not None:
            release(ledger, token)
    return 0


def publish_delivery_trace(loop, test_id, control_id, *, trace_id, finding_id, phases,
                           mode, expected, actual, impact, limitations):
    """Explicitly adapt a completed experimental pair to the existing delivery trace.

    The existing authority requires an existing Finding and a continuous canonical
    state path. Unsupported negative/discontinuous paths remain in the research
    journal; do not fabricate a normal path or an empty Finding to publish them.
    """
    test, control = (_trace_current(loop, tid) for tid in (test_id, control_id))
    if test['case_id'] != control['case_id'] or test['branch'] != 'test' or control['branch'] != 'control' or any(
            t['status'] != 'completed' or t['stale'] or t['deviations'] or t['discontinuities']
            for t in (test, control)):
        raise ValueError('delivery requires complete current TEST/CONTROL traces')
    if len(phases) != len(test['steps']):
        raise ValueError('each delivery step requires an explicit reporting phase')
    selected = _event(loop, 'flow_case', 'case_id', test['case_id'])
    definition = _definition(loop, selected['definition_version'])

    def refs(step):
        return [{**{key: value for key, value in step[p]['evidence_ref'].items()
                     if key in {'path', 'sha256', 'applicability'}}, 'locator': 'whole-file'}
                for p in ('pre', 'action', 'post')]

    transitions = {t['id']: t for t in definition['transitions']}
    for step in test['steps']:
        transition = transitions[step['actual']['transition_id']]
        if transition['from'] != step['before_state'] or transition['to'] != step['after_state']:
            raise ValueError('actual state path cannot be represented by the current delivery flow')
    data = {'id': trace_id, 'flow_id': definition['flow_id'], 'finding_id': finding_id,
            'actor': ', '.join(sorted({s['actual']['actor'] for s in test['steps']})),
            'environment': json.dumps(test['environment'], sort_keys=True),
            'preconditions': '; '.join(selected['guard_expectations']),
            'data_origin': '; '.join(f"{key}: {value['source']}; attacker availability: "
                                    f"{value['attacker_availability']}"
                                    for obj in definition['objects'].values()
                                    for key, value in obj['identifiers'].items()),
            'expected': expected, 'actual': actual, 'impact': impact, 'limitations': limitations,
            'producer': test['runner_id'], 'mode': mode,
            'steps': [{'transition_id': step['actual']['transition_id'],
                       'action': step['actual']['action'], 'observed': step['post']['outcome'],
                       'actor_ref': step['actual']['actor'], 'entry_ref': step['actual']['entry'],
                       'phase': phase, 'evidence': refs(step)}
                      for step, phase in zip(test['steps'], phases, strict=True)],
            'evidence': [ref for step in control['steps'] for ref in refs(step)],
            'research_binding': {'case_id': test['case_id'], 'trace_ids': [test_id, control_id],
                                 'trace_fingerprint': _digest([test['steps'], control['steps']])}}
    normalized = research_delivery.normalize({'record_kind': 'trace', 'data': data}, loop)
    loop.append('delivery_record', **normalized)
    return normalized['revision']


def graphwalker_topology(definition):
    """Optional JSON topology export, not a GraphWalker execution/EFSM adapter.

    Declarative guards live in properties, never executable guard/actions: an MBT
    engine must not prune the negative authorization cases this module proposes.
    """
    return {'name': definition['flow_id'], 'models': [{
        'id': definition['flow_id'], 'name': definition['title'],
        'startElementId': definition['normal_path'][0],
        'vertices': [{'id': s, 'name': s} for s in definition['states']],
        'edges': [{'id': t['id'], 'name': t['action'], 'sourceVertexId': t['from'],
                   'targetVertexId': t['to'], 'properties': {'expected_preconditions': t['preconditions']}}
                  for t in definition['transitions']],
        'generator': 'random(length(20))'}]}


if __name__ == '__main__':
    raise SystemExit(main())
