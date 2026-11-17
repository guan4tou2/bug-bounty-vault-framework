"""Event-triggered, scoped research inventory and checked planning decisions."""
from __future__ import annotations

import copy
import hashlib
import json

import blocked_research as blocked
from evidence_applicability import assess_artifact, latest_context
from evidence_refs import artifact_hash, artifact_path, evidence_resolves
from hunt_loop import HuntLoop

REASONS = {'obstruction', 'capability_changed', 'conditions_changed', 'evidence_conflict',
           'evidence_changed', 'batch_completed', 'no_information_gain', 'pre_delivery', 'queue_exhausted'}
SEMANTIC = {'hypothesis', 'logic_verdict', 'verdict', 'evidence_context', 'scan_candidate',
            'scan_observation', 'research_obstruction', 'obstruction_attempt', 'obstruction_validation_result',
            'delivery_record', 'flow_trace_step', 'dead_end', 'reassessment_trigger', 'research_state'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def inventory(loop, scope='target'):
    """Facts and references only; observation counts never become security coverage."""
    cap = loop.capsule()
    subjects = None if scope == 'target' else {scope.removeprefix('hypothesis:')}
    blockers = [r for r in blocked.project(loop.events, loop.base_path)
                if subjects is None or r['hyp_id'] in subjects]
    proofs = {}
    def visit(value):
        if not isinstance(value, dict):
            return
        if value.get('kind') == 'comparison':
            visit(value.get('test')); visit(value.get('control'))
        elif value.get('kind') in {None, 'artifact'} and value.get('path'):
            path = artifact_path(value['path'], loop.base_path)
            ref = 'evidence:' + digest([value.get('path'), value.get('sha256')])[:20]
            proofs[ref] = {'ref': ref, 'proof': value, 'available': bool(path),
                           'current_sha256': artifact_hash(path) if path else None,
                           'integrity': evidence_resolves(value, loop.base_path, loop.events),
                           'applicability': assess_artifact(value, loop.events)['status']}
    hypotheses = {}
    for e in loop.events:
        owner = e.get('hyp_id') or e.get('hypothesis') or (e.get('id') if e['type'] == 'hypothesis' else None)
        if subjects is not None and owner not in subjects:
            continue
        if e['type'] == 'hypothesis':
            hypotheses[e['id']] = {'id': e['id'], 'requires': e.get('requires', [])}
        visit(e.get('evidence'))
        for p in e.get('artifacts', []):
            visit(p)
    for row in blockers:
        visit(row['evidence'])
        for a in row['alternatives']:
            visit(a['evidence'])
            if a.get('attempt'):
                visit(a['attempt']['test_evidence']); visit(a['attempt']['control_evidence'])
    from flow_model import project as flows
    flow = flows(loop.events, loop.base_path) if subjects is None else {'definitions': [], 'traces': []}
    case_flow = {e['case_id']: e['flow_id'] for e in loop.events if e['type'] == 'flow_case'}
    traversed = {(case_flow.get(t['case_id']), s['actual']['transition_id'])
                 for t in flow['traces'] if not t['stale'] for s in t['steps']}
    untraversed = [{'flow_id': d['flow_id'], 'transition_id': t['id']} for d in flow['definitions']
                   for t in d['definition']['transitions'] if (d['flow_id'], t['id']) not in traversed]
    def select(values):
        return sorted(v for v in values if subjects is None or v in subjects)
    from asg_research import project as research_project
    research = research_project(loop.events, loop.base_path, cap=cap)
    intents = [{k: n.get(k) for k in ('ref', 'state', 'effective_state', 'hypothesis', 'requires')}
               for n in research['nodes'] if n['kind'] == 'intent'
               and (subjects is None or n.get('hypothesis', '').removeprefix('hypothesis:') in subjects)]
    value = {'scope': scope, 'context': latest_context(loop.events),
             'hypotheses': list(hypotheses.values()), 'capabilities': cap['capabilities'], 'intents': intents,
             'ready': select(cap['ready_hypotheses']), 'blocked': select(cap['blocked_hypotheses']),
             'confirmed': select(cap['confirmed']), 'refuted': select(cap['refuted']),
             'disputed': select(cap['disputed']),
             'obstructions': [{k: r[k] for k in ('obstruction_id', 'hyp_id', 'state', 'next', 'limit')}
                              for r in blockers],
             'remaining_comparisons': {r['obstruction_id']: r['limit'] - r.get('spent_attempts', 0)
                 - sum(bool(a.get('attempt')) for a in r['alternatives']) for r in blockers},
             'evidence': sorted(proofs.values(), key=lambda r: r['ref']),
             'untraversed_transitions': untraversed,
             'dead_paths': [{k: e.get(k) for k in ('hyp_id', 'cause', 'scope', 'reopen_when')}
                            for e in loop.events if e['type'] == 'dead_end'
                            and (subjects is None or e['hyp_id'] in subjects)],
             'limits': 'Traversal is not security coverage; summaries do not replace original artifacts.'}
    return value


def request(loop, reason, scope='target', *, cooldown=3):
    if reason not in REASONS or not isinstance(scope, str) or not scope:
        raise ValueError('known reassessment trigger and explicit scope required')
    if scope != 'target' and (not scope.startswith('hypothesis:') or
            not any(e['type'] == 'hypothesis' and e['id'] == scope[11:] for e in loop.events)):
        raise ValueError('scope must reference an existing hypothesis or target')
    if type(cooldown) is not int or not 0 <= cooldown <= 32:
        raise ValueError('bounded semantic-event cooldown required')
    data = inventory(loop, scope)
    version = digest(data)
    rid = digest([reason, scope, version])
    if any(e['type'] == 'reassessment_requested' and e['reassessment_id'] == rid for e in loop.events):
        return rid
    judgment = reason in {'queue_exhausted', 'no_information_gain', 'evidence_conflict', 'pre_delivery'}
    if reason == 'obstruction':
        judgment = any(r['next'] == 'discriminate_obstruction' for r in data['obstructions'])
    count = sum(e['type'] in SEMANTIC for e in loop.events)
    recent = next((e for e in reversed(loop.events) if e['type'] == 'reassessment_result'
                   and e['scope'] == scope and e['reason'] == reason), None)
    ready_at = max(count, (recent['semantic_count'] + cooldown) if recent and
                   reason in {'queue_exhausted', 'no_information_gain', 'batch_completed'} else count)
    loop.append('reassessment_requested', reassessment_id=rid, reason=reason, scope=scope,
                source_version=version, inventory=data, judgment_needed=judgment,
                ready_at=ready_at, semantic_count=count, budget={'model_calls': 1, 'automatic_retries': 0})
    if not judgment:
        loop.append('reassessment_result', reassessment_id=rid, reason=reason, scope=scope,
                    source_version=version, semantic_count=count, decisions=[], mode='deterministic',
                    conclusion='Existing prerequisite/evidence/obstruction gates handle this inventory', finding_verified=False)
    return rid


def collect(loop, *, batch_size=4):
    """Merge triggers; metadata and model replies are never new trigger facts."""
    if type(batch_size) is not int or not 1 <= batch_size <= 32:
        raise ValueError('batch size must be bounded to 1..32 completed comparisons')
    cursor = next((e['cursor'] for e in reversed(loop.events) if e['type'] == 'reassessment_scan'), 0)
    end = len(loop.events)
    triggers = set()
    obstructions = {e['obstruction_id']: e['hyp_id'] for e in loop.events if e['type'] == 'research_obstruction'}
    for e in tuple(loop.events[cursor:end]):
        kind = e['type']
        if kind == 'research_obstruction':
            triggers.add(('obstruction', 'hypothesis:' + e['hyp_id']))
        elif kind == 'obstruction_attempt' and not e['normal_succeeds']:
            triggers.add(('obstruction', 'hypothesis:' + obstructions[e['obstruction_id']]))
        elif kind == 'verdict' and e.get('status') == 'confirmed' and e.get('provides'):
            triggers.add(('capability_changed', 'target'))
        elif kind == 'evidence_context' and sum(x['type'] == kind for x in loop.events[:end]) > 1:
            triggers.add(('conditions_changed', 'target'))
        elif kind == 'research_progress' and e.get('unchanged_rounds', 0) >= 3:
            triggers.add(('no_information_gain', 'hypothesis:' + e['hyp_id']))
        elif kind == 'reassessment_trigger':
            triggers.add((e['reason'], e.get('scope', 'target')))
        elif kind == 'delivery_record' and e.get('record_kind') in {'report', 'trace'}:
            triggers.add(('pre_delivery', 'target'))
    cap = loop.capsule()
    for hid in cap['disputed']:
        triggers.add(('evidence_conflict', 'hypothesis:' + hid))
    if any(not p['integrity'] or p['applicability'] != 'applicable'
           for p in inventory(loop)['evidence'] if p['proof'].get('applicability')):
        triggers.add(('evidence_changed', 'target'))
    complete = sum(e['type'] in {'logic_verdict', 'obstruction_validation_result'} for e in loop.events)
    previous = next((e.get('completed_batches', 0) for e in reversed(loop.events) if e['type'] == 'reassessment_scan'), 0)
    if complete // batch_size > previous:
        triggers.add(('batch_completed', 'target'))
    for reason, scope in sorted(triggers):
        request(loop, reason, scope)
    for row in view(loop):
        if row['state'] in {'proposed', 'cooldown'} and row['stale']:
            request(loop, row['reason'], row['scope'])
    if end != cursor or triggers:
        loop.append('reassessment_scan', cursor=len(loop.events) + 1, completed_batches=complete // batch_size)
    return view(loop)


def view(loop):
    rows = {}
    latest = {}
    for e in loop.events:
        if e['type'] == 'reassessment_requested':
            rows[e['reassessment_id']] = {**e, 'state': 'proposed'}
            latest[(e['reason'], e['scope'])] = e['reassessment_id']
        elif e['type'] == 'reassessment_result' and e['reassessment_id'] in rows:
            rows[e['reassessment_id']].update(state='completed', result=e)
    semantic_count = sum(e['type'] in SEMANTIC for e in loop.events)
    versions = {}
    for row in rows.values():
        if row['state'] != 'completed' and latest[(row['reason'], row['scope'])] != row['reassessment_id']:
            row['state'] = 'superseded'
        if row['scope'] not in versions:
            versions[row['scope']] = digest(inventory(loop, row['scope']))
        row['stale'] = row.get('result', {}).get('result_version', row['source_version']) != versions[row['scope']]
        if row['state'] != 'completed' and semantic_count < row['ready_at']:
            row['state'] = 'cooldown'
    return list(rows.values())


def card(row):
    return {'schema': 1, 'kind': 'reassessment', 'ref': row['reassessment_id'], 'question': row['reason'],
            'goal': 'Review only changed, scoped research facts and produce evidence-linked decisions',
            'next_action': 'reassess', 'inventory': row['inventory'], 'facts': [],
            'success': 'Checked retain/prioritize/propose or intent lifecycle recommendations',
            'allowed_operations': ['decide'],
            'output_requirements': {'decisions': {'action': ['retain', 'prioritize', 'propose', 'pause', 'resume', 'cancel'],
                'subject': 'existing hypothesis/intent ref, or inventory for retain/propose',
                'reason': 'nonempty bounded text', 'uncertainty': 'explicit limitation',
                'evidence_refs': 'inventory or supplied evidence reference IDs',
                'details': 'priority -2..2 or exploration question/requires; never commands'}},
            'stop': ['one analysis per trigger/evidence version', 'source changes require fresh inventory',
                     'no authorization, Finding verification or unsafe cancellation'],
            'state_version': digest([row['reassessment_id'], row['source_version']])}


def priorities(loop):
    """Advisory ordering expires with the inventory that supported the decision."""
    valid = {r['reassessment_id'] for r in view(loop) if r['state'] == 'completed' and not r['stale']}
    return {e['subject']: e['priority'] for e in loop.events
            if e['type'] == 'research_priority' and e['reassessment_id'] in valid}


def apply(loop, work_card, *, decisions):
    row = next((r for r in view(loop) if r['reassessment_id'] == work_card.get('ref')), None)
    if not row or row['state'] != 'proposed' or row['stale'] or work_card != card(row):
        raise ValueError('current ready reassessment snapshot required')
    if not isinstance(decisions, list) or not 1 <= len(decisions) <= 12:
        raise ValueError('bounded decision list required')
    proofs = {p['ref']: p['proof'] for p in row['inventory']['evidence']}
    known = {'hypothesis:' + h['id'] for h in row['inventory']['hypotheses']}
    stage = HuntLoop(copy.deepcopy(loop.events), base_path=loop.base_path)
    from asg_research import project, append_to_loop
    research = project(stage.events, stage.base_path)
    allowed_intents = {n['ref'] for n in row['inventory']['intents']}
    intents = {n['ref']: n for n in research['nodes'] if n['kind'] == 'intent' and n['ref'] in allowed_intents}
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) - {'action', 'subject', 'reason', 'uncertainty', 'evidence_refs', 'details'}:
            raise ValueError('only structured decisions, evidence and uncertainty are accepted')
        blocked._required(decision.get('reason'), decision.get('uncertainty'))
        refs = decision.get('evidence_refs')
        if not isinstance(refs, list) or not refs or any(ref not in {*proofs, 'inventory'} for ref in refs):
            raise ValueError('decision must cite supplied inventory/evidence references')
        action, subject = decision.get('action'), decision.get('subject')
        details = decision.get('details', {})
        if action == 'retain':
            if subject not in known | {'inventory'} | set(intents):
                raise ValueError('unknown reassessment subject')
        elif action == 'prioritize':
            if subject not in known or type(details.get('priority')) is not int or not -2 <= details['priority'] <= 2:
                raise ValueError('bounded priority for an existing hypothesis required')
            stage.append('research_priority', subject=subject, priority=details['priority'],
                         reason=decision['reason'], reassessment_id=row['reassessment_id'])
        elif action == 'propose':
            from work_cards import propose_exploration
            proof = next((proofs[r] for r in refs if r in proofs), None)
            if proof is None:
                raise ValueError('exploration requires a current original evidence artifact')
            propose_exploration(stage, question=details['question'], reason=decision['reason'],
                                evidence=proof, requires=details.get('requires', []))
        elif action in {'pause', 'resume', 'cancel'} and subject in intents:
            from command_lifecycle import unresolved_actions
            from work_dispatch import jobs
            bound = intents[subject].get('hypothesis', '').removeprefix('hypothesis:')
            dispatched = any(j['state'] in {'running', 'awaiting_validation'}
                             and bound and j.get('binding_hypothesis') == bound for j in jobs(stage.events))
            if intents[subject]['effective_state'] == 'running' or dispatched or (bound and unresolved_actions(stage.events, bound)):
                raise ValueError('running execution requires its original stop/effects acknowledgement')
            append_to_loop(stage, 'research_state', ref=subject,
                           state={'pause': 'paused', 'resume': 'open', 'cancel': 'stopped'}[action], reason=decision['reason'])
        else:
            raise ValueError('unsupported plan transition; execution and authorization remain with their original gates')
    stage.append('reassessment_result', reassessment_id=row['reassessment_id'], reason=row['reason'], scope=row['scope'],
                 source_version=row['source_version'], semantic_count=sum(e['type'] in SEMANTIC for e in loop.events),
                 decisions=decisions, result_version=digest(inventory(stage, row['scope'])), mode='analysis', finding_verified=False)
    loop.events = stage.events
    return {'next_action': 'reassessment_completed', 'decisions': len(decisions), 'finding_verified': False}


def main():
    import argparse
    import asg
    from hunt_lock import acquire, guarded_save, release
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    parser.add_argument('--reason', choices=sorted(REASONS))
    parser.add_argument('--scope', default='target')
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    token = acquire(ledger, 'reassessment')
    try:
        loop = HuntLoop.load(ledger)
        if args.reason:
            request(loop, args.reason, args.scope)
        collect(loop)
        guarded_save(loop, ledger, token)
        print(json.dumps(view(loop), ensure_ascii=False, indent=2))
    finally:
        release(ledger, token)


if __name__ == '__main__':
    main()
