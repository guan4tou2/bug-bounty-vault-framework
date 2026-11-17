"""Executable evidence questions tied to existing ASG goal criteria.

Design work becomes an exploration proposal, then an ordinary gated hypothesis.
Only the original goal's evidence/acceptance contract can resolve the gap.
"""
from __future__ import annotations

import hashlib
import json

import blocked_research as blocked
from asg_research import fingerprint, project as research_project
from evidence_refs import evidence_resolves


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def declare(loop, *, gap_id, goal, criterion, established, question, alternatives, control,
            observe, support_limit, evidence, requires=None):
    blocked._required(gap_id, goal, criterion, established, question, control, observe, support_limit)
    goals = {n['ref']: n for n in research_project(loop.events, loop.base_path)['nodes'] if n['kind'] == 'goal'}
    if goal not in goals or criterion not in {c['id'] for c in goals[goal]['criteria']}:
        raise ValueError('gap must reference an existing goal criterion')
    if not isinstance(alternatives, list) or not 2 <= len(alternatives) <= 8 or any(
            not isinstance(a, str) or not a.strip() for a in alternatives) or len(set(alternatives)) != len(alternatives):
        raise ValueError('two to eight distinct competing explanations required')
    requires = [] if requires is None else requires
    if not isinstance(requires, list) or any(not isinstance(r, str) or not r.strip() for r in requires):
        raise ValueError('explicit capability references required')
    proof = blocked._proof(loop, evidence)
    if any(e['type'] == 'claim_gap_declared' and e['gap_id'] == gap_id for e in loop.events):
        raise ValueError('gap identity is immutable; create a revised gap without rewriting history')
    loop.append('claim_gap_declared', gap_id=gap_id, goal=goal, criterion=criterion,
                goal_revision=fingerprint({k: goals[goal].get(k) for k in ('ref', 'text', 'criteria', 'purpose', 'revision', 'state')}),
                established=established, question=question, alternatives=alternatives, control=control,
                observe=observe, support_limit=support_limit, evidence=proof, requires=sorted(set(requires)))
    return gap_id


def project(loop):
    graph = research_project(loop.events, loop.base_path, cap=loop.capsule())
    goals = {n['ref']: n for n in graph['nodes'] if n['kind'] == 'goal'}
    from work_cards import exploration_view
    proposals = {p['proposal_id']: p for p in exploration_view(loop)}
    linked = {e['gap_id']: e['proposal_id'] for e in loop.events if e['type'] == 'claim_gap_proposed'}
    rows = []
    for event in loop.events:
        if event['type'] != 'claim_gap_declared':
            continue
        goal = goals.get(event['goal'])
        current_goal = fingerprint({k: goal.get(k) for k in ('ref', 'text', 'criteria', 'purpose', 'revision', 'state')}) if goal else None
        stale = current_goal != event['goal_revision'] or not evidence_resolves(event['evidence'], loop.base_path, loop.events)
        missing = sorted(set(event['requires']) - set(loop.capsule()['capabilities']))
        proposal = proposals.get(linked.get(event['gap_id']))
        resolved = bool(goal and not stale and event['criterion'] in goal['satisfied_criteria'])
        state = ('resolved' if resolved else 'waiting' if stale or missing or not goal or goal['state'] == 'abandoned'
                 else 'rejected' if proposal and proposal.get('state') == 'rejected'
                 else 'researching' if proposal else 'ready')
        row = {**event, 'state': state, 'stale': stale, 'missing': missing, 'proposal_id': linked.get(event['gap_id']),
               'hypothesis': (proposal or {}).get('hypothesis'), 'finding_verified': False}
        row['state_version'] = digest([event, state, stale, missing, linked.get(event['gap_id'])])
        rows.append(row)
    return rows


def card(row):
    return {'schema': 1, 'kind': 'evidence-gap', 'ref': row['gap_id'], 'question': row['question'],
            'goal': row['goal'], 'requires': row['requires'], 'next_action': 'design_gap_test',
            'facts': [{'claim': row['established'], 'evidence': row['evidence']}],
            'evidence_gap': {k: row[k] for k in ('criterion', 'alternatives', 'control', 'observe', 'support_limit')},
            'allowed_operations': ['propose'],
            'output_requirements': {'question': 'one discriminating test question', 'reason': 'why it separates explanations',
                                    'evidence': 'supplied reference', 'requires': 'preserve all original prerequisites'},
            'success': 'Create a reviewable exploration proposal; criterion acceptance remains separate',
            'stop': ['stale input', 'missing prerequisites', 'original authorization and effect gates'],
            'state_version': row['state_version']}


def apply(loop, work_card, operation, payload):
    row = next((r for r in project(loop) if r['gap_id'] == work_card.get('ref')), None)
    if not row or row['state'] != 'ready' or work_card != card(row) or operation != 'propose':
        raise ValueError('current ready gap card and a proposal required')
    if set(payload) != {'question', 'reason', 'evidence', 'requires'} or not set(row['requires']) <= set(payload['requires']):
        raise ValueError('complete evidence-linked proposal preserving prerequisites required')
    proof = blocked._proof(loop, payload['evidence'])
    if proof != row['evidence']:
        raise ValueError('proposal must cite the supplied gap evidence')
    from work_cards import propose_exploration
    proposal_id = propose_exploration(loop, **payload)
    loop.append('claim_gap_proposed', gap_id=row['gap_id'], proposal_id=proposal_id)
    return {'next_action': 'review_exploration', 'proposal_id': proposal_id, 'finding_verified': False}
