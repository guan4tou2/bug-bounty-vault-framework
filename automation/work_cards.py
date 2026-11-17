"""Derived work cards, controlled comparisons and checked result transitions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import blocked_research as blocked


TRANSITIONS = {
    "wait_for_recovery": {"resume"},
    'recover_waiting_evidence': {'resume'},
    'validate_original_claim': {'request_validation', 'close'},
    'perform_independent_validation': {'validate', 'close'},
    'validation_needs_evidence': {'request_validation', 'close'},
    "reconcile_execution": {"close"},
    "establish_normal_control": {"diagnose", "close"},
    "discriminate_obstruction": {"diagnose", "close"},
    "stop_budget_exhausted": {"close"},
    "assess_alternatives_or_stop": {"propose", "close"},
    "review_alternative_under_existing_gate": {"attempt", "close"},
    "original_authorization_path": {"close"},
    "revalidate_evidence": {"revalidate", "close"},
}


def execute_alternative(
    loop, ledger, card, *, comparison_hyp_id, test_argv, control_argv, output_dir, scope_ref, interpret, timeout=30,
    producer_id='unattributed-worker',
    on_result=None,
    credentials=None,
):
    """Controlled executor seam. Caller holds the canonical writer lock/authorization.

    interpret consumes saved artifacts, returning observation/excluded/recovery,
    normal_succeeds, behavior_observed and impact_observed. It never sets a verdict.
    Existing program gate, process budgets and restart reconciliation remain active.
    """
    from evidence_applicability import latest_context
    from hunt_integration import execute_command

    rows = {r["obstruction_id"]: r for r in blocked.project(loop.events, loop.base_path)}
    row = rows.get(card.get("ref"))
    if not row or card != obstruction_card(row) or row["next"] != "review_alternative_under_existing_gate":
        raise ValueError("current executable alternative work card required")
    if not scope_ref or comparison_hyp_id not in loop.capsule()["ready_hypotheses"]:
        raise ValueError("explicit scope reference and a ready comparison hypothesis required")
    if (
        not isinstance(test_argv, list)
        or not isinstance(control_argv, list)
        or len(test_argv) != len(control_argv)
        or not test_argv
        or sum(a != b for a, b in zip(test_argv, control_argv, strict=True)) != 1
    ):
        raise ValueError("bounded argv adapter requires exactly one changed argument")
    if not callable(interpret):
        raise ValueError("explicit artifact outcome interpreter required")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 120:
        raise ValueError("work-card operation timeout must be bounded to 120 seconds")
    configuration = hashlib.sha256(
        json.dumps([comparison_hyp_id, test_argv, control_argv, scope_ref], sort_keys=True).encode()
    ).hexdigest()
    prior = next(
        (
            e
            for e in loop.events
            if e["type"] == "work_card_execution_bound" and e["state_version"] == card["state_version"]
        ),
        None,
    )
    if prior and prior["configuration"] != configuration:
        raise ValueError("execution binding changed; preserve previous effects and artifacts")
    if not prior:
        loop.append(
            "work_card_execution_bound",
            obstruction_id=row["obstruction_id"],
            state_version=card["state_version"],
            configuration=configuration,
        )
        loop.save(ledger)
    output_dir = Path(output_dir)
    aid = "work-card:" + card["state_version"]
    paths = {branch: output_dir / (card["state_version"] + "-" + branch + ".txt") for branch in ("control", "test")}
    outcomes = {}
    for branch, argv in [("control", control_argv), ("test", test_argv)]:
        previous = next(
            (
                e
                for e in reversed(loop.events)
                if e["type"] == "action_finished" and e["action_id"] == aid + ":" + branch
            ),
            None,
        )
        if previous:
            path = paths[branch]
            if (
                previous.get("status") != "completed"
                or not previous.get("execution_stop_confirmed")
                or previous.get("output_ref") != str(path.resolve())
                or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != previous.get("sha256")
            ):
                raise ValueError("previous execution or evidence requires reconciliation; no blind retry")
            outcomes[branch] = True
            continue
        try:
            outcomes[branch] = execute_command(
                loop,
                ledger,
                comparison_hyp_id,
                aid + ":" + branch,
                argv,
                paths[branch],
                timeout=timeout,
                scope_ref=scope_ref,
                credential=(credentials or {}).get(branch),
            )
        except PermissionError:
            loop.append(
                "obstruction_execution_denied",
                obstruction_id=row["obstruction_id"],
                state_version=card["state_version"],
                source="existing-program-rules-gate",
            )
            loop.save(ledger)
            raise
        if not outcomes[branch]:
            # Preserve the failure without launching more work after a broken baseline.
            loop.append(
                "work_card_execution_blocked",
                obstruction_id=row["obstruction_id"],
                state_version=card["state_version"],
                branch=branch,
                recovery="reconcile or repair execution",
            )
            loop.save(ledger)
            return {"state": "execution_blocked", "branch": branch, "verdict": "not-established"}
    interpreted = interpret(paths["test"], paths["control"])
    binding = {**(latest_context(loop.events) or {}), "observed_at": datetime.now(UTC).isoformat()}

    def proof(branch):
        return {"kind": "artifact", "path": str(paths[branch]), "applicability": binding}

    result = (
        "behavior_observed"
        if (
            interpreted.get("normal_succeeds") is True
            and interpreted.get("behavior_observed") is True
            and interpreted.get("impact_observed") is True
        )
        else "inconclusive"
    )
    if on_result:
        on_result({'interpretation': interpreted, 'test_artifact': str(paths['test']),
                   'control_artifact': str(paths['control'])})
    refreshed = apply(
        loop,
        card,
        "attempt",
        {
            **interpreted,
            "alternative_id": row["next_alternative"],
            "result": result,
            "test_evidence": proof("test"),
            "control_evidence": proof("control"),
            'producer_id': producer_id,
        },
    )
    loop.save(ledger)
    return refreshed


def obstruction_card(row):
    alternative = next((a for a in row["alternatives"] if a["alternative_id"] == row["next_alternative"]), None)
    card = {
        "schema": 1,
        "kind": "blocked-research",
        'research_state': row['state'],
        'queue': obstruction_queue(row),
        "ref": row["obstruction_id"],
        "question": row["hyp_id"],
        "goal": "Resolve the obstruction without inferring a negative vulnerability result",
        "facts": [
            {
                "claim": row["explanation"],
                "classification": row["cause"],
                "normal_operation": row["normal"],
                "evidence": row["evidence"],
                "stale": row["stale"],
            }
        ],
        "missing": row["next"],
        "next_action": row["next"],
        "reason": "Current evidence, normal baseline, authorization boundary and remaining comparison budget",
        "alternative": {
            k: alternative[k]
            for k in ("alternative_id", "condition", "before", "after", "rationale", "comparison", "evidence")
        }
        if alternative
        else None,
        'comparison_evidence': [{key: a['attempt'][key] for key in
                                 ('test_evidence', 'control_evidence', 'producer_id') if key in a['attempt']}
                                for a in row['alternatives'] if a.get('attempt', {}).get('result') == 'behavior_observed'],
        'validation_request': row.get('validation_request'),
        "budget_remaining": row["limit"]
        - row.get("spent_attempts", 0)
        - sum(bool(a.get("attempt")) for a in row["alternatives"]),
        "success": (
            "Observe original intended behavior and impact with a working normal CONTROL; then independently validate"
        ),
        "failure": "blocked or inconclusive; retain raw TEST/CONTROL and excluded explanations",
        "stop": [
            "scope/platform/approval/safety boundary",
            "budget exhausted",
            "unknown effects",
            "normal CONTROL unavailable",
        ],
        "recovery": row["recovery"],
        "references": ["docs/blocked-research.md"],
        "authority": "Existing executor gates still apply; this card grants no authorization",
        "proposal_escape": "propose a new exploration hypothesis with evidence; no automatic execution",
    }
    import inspect
    card['allowed_operations'] = sorted(TRANSITIONS.get(row['next'], set()))
    card['output_requirements'] = {operation: {
        name: 'required' if parameter.default is inspect.Parameter.empty else 'optional'
        for name, parameter in inspect.signature(getattr(blocked, operation)).parameters.items()
        if name not in {'loop', 'obstruction_id'}} for operation in card['allowed_operations']}
    card["state_version"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    return card


def obstruction_queue(row):
    if row['cause'] in blocked.HARD or row['next'] == 'reconcile_execution':
        return 'human'
    if row['state'] == 'waiting':
        return 'waiting'
    if row['state'] == 'completed' and not row['stale']:
        return 'completed'
    return 'ready'


def attach(items, events, base_path=None):
    rows = {r["obstruction_id"]: r for r in blocked.project(events, base_path)}
    for item in items:
        if 'work_card' in item:
            continue
        if item["kind"] == "blocked-research" and item["ref"] in rows:
            item["work_card"] = obstruction_card(rows[item["ref"]])
        else:
            item["work_card"] = {
                "schema": 1,
                "kind": item["kind"],
                'dispatchable': False,
                'result_contract': 'existing native adapter required; no generic self-completion',
                'state_version': hashlib.sha256(json.dumps([len(events), item], sort_keys=True).encode()).hexdigest(),
                "ref": item.get("ref"),
                "question": item["action"],
                "goal": item["action"],
                "facts": [],
                "missing": item.get("detail", "Consult canonical evidence before execution"),
                "next_action": item["action"],
                "reason": "Existing scheduler priority and prerequisites",
                "success": "Return pinned raw observations for the existing result validator",
                "failure": "Preserve uncertainty; never convert blocked into refuted",
                "stop": ["existing scope, effect, budget and execution gates"],
                "references": [item["skill"]] if item.get("skill") else [],
                "authority": "Proposal only; references are not automatically loaded",
            }
    return items


def apply(loop, card, operation, payload):
    """Caller owns canonical lock/save; result never bypasses a tool gate or sets a verdict."""
    if card.get('kind') == 'research-source':
        from research_sources import apply as source_review
        return source_review(loop, card, operation, payload)
    if card.get('kind') == 'evidence-gap':
        from evidence_gaps import apply as apply_gap
        return apply_gap(loop, card, operation, payload)
    if card.get('kind') == 'reassessment':
        if operation != 'decide':
            raise ValueError('reassessment requires checked decisions')
        from reassessment import apply as apply_reassessment
        return apply_reassessment(loop, card, **payload)
    if card.get('kind') == 'exploration-review':
        if operation != 'review':
            raise ValueError('exploration work requires a review result')
        return exploration_card(review_exploration(loop, card, **payload))
    rows = {r["obstruction_id"]: r for r in blocked.project(loop.events, loop.base_path)}
    row = rows.get(card.get("ref"))
    if not row or card != obstruction_card(row):
        raise ValueError("stale or altered work card; refresh canonical state")
    if operation not in TRANSITIONS.get(row["next"], set()) or "obstruction_id" in payload:
        raise ValueError("result is not a valid next transition")
    if operation == "attempt" and payload.get("alternative_id") != row["next_alternative"]:
        raise ValueError("result must match the selected single alternative")
    getattr(blocked, operation)(loop, row["obstruction_id"], **payload)
    loop.append(
        "work_card_result",
        obstruction_id=row["obstruction_id"],
        operation=operation,
        state_version=card["state_version"],
    )
    return obstruction_card(
        next(r for r in blocked.project(loop.events, loop.base_path) if r["obstruction_id"] == row["obstruction_id"])
    )


def propose_exploration(loop, *, question, reason, evidence, requires):
    if (not isinstance(question, str) or not question.strip() or not isinstance(reason, str) or not reason.strip()
            or not isinstance(requires, list) or any(not isinstance(r, str) or not r.strip() for r in requires)):
        raise ValueError("explicit exploration question, reason and prerequisites required")
    proof = blocked._proof(loop, evidence)
    proposal = dict(question=question, reason=reason, evidence=proof, requires=sorted(set(requires)))
    pid = proposal_id(proposal)
    if not any(p['proposal_id'] == pid for p in exploration_view(loop)):
        loop.append('exploration_proposal', proposal_id=pid, **proposal)
    return pid


def proposal_id(proposal):
    return hashlib.sha256(json.dumps([proposal['question'], proposal['evidence'].get('sha256'),
                                    sorted(proposal['requires'])], sort_keys=True).encode()).hexdigest()


def exploration_view(loop):
    rows = {}
    for e in loop.events:
        if e['type'] == 'exploration_proposal':
            pid = e.get('proposal_id') or proposal_id(e)
            rows[pid] = {**e, 'proposal_id': pid, 'state': 'proposed'}
        elif e['type'] == 'exploration_decision' and e['proposal_id'] in rows:
            rows[e['proposal_id']].update(e)
    from evidence_refs import evidence_resolves
    from evidence_applicability import assess_artifact
    for row in rows.values():
        proofs = [row['evidence']]
        if row.get('review_evidence'):
            proofs.append(row['review_evidence'])
        row['stale'] = any(not evidence_resolves(p, loop.base_path, loop.events)
                           or assess_artifact(p, loop.events)['requires_revalidation'] for p in proofs)
    return list(rows.values())


def exploration_card(row):
    return {'schema': 1, 'kind': 'exploration-review', 'ref': row['proposal_id'],
            'question': row['question'], 'goal': 'Assess a new exploration direction against current facts',
            'facts': [{'evidence': row['evidence'], 'reason': row['reason']}], 'requires': row['requires'],
            'next_action': 'review_exploration' if row['state'] == 'proposed' else 'exploration_' + row['state'],
            'allowed_operations': ['review'],
            'output_requirements': {'decision': 'adopt or reject', 'reason': 'evidence-based reason',
                'evidence': 'supplied evidence reference', 'hypothesis': 'complete LogicHypothesis for adopt'},
            'success': 'Adopt an explicit hypothesis or reject with evidence',
            'stop': ['scope and operation gates remain unchanged', 'stale source evidence'],
            'state_version': hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()}


def review_exploration(loop, card, *, decision, reason, evidence, hypothesis=None):
    from logic_vuln_loop import Env, LogicHypothesis
    row = next((p for p in exploration_view(loop) if p['proposal_id'] == card.get('ref')), None)
    if not row or row['state'] != 'proposed' or row['stale'] or card != exploration_card(row):
        raise ValueError('current unreviewed exploration work card required')
    blocked._required(reason)
    if decision not in {'adopt', 'reject'}:
        raise ValueError('explicit adopt/reject decision required')
    proof = blocked._proof(loop, evidence)
    data = None
    if decision == 'adopt':
        data = dict(hypothesis or {})
        data['applies_env'] = Env(**data.get('applies_env', {}))
        hyp = LogicHypothesis(**data)
        if not set(row['requires']).issubset(hyp.requires):
            raise ValueError('adoption cannot drop proposal prerequisites')
        if any(e['type'] == 'hypothesis' and e['id'] == hyp.hyp_id for e in loop.events):
            raise ValueError('adoption requires a fresh comparison identity')
        for key in ('hyp_id', 'invariant', 'test_action', 'control_action', 'violation_outcome', 'expected_normal'):
            blocked._required(getattr(hyp, key))
        # No dispatch here. Canonical capability and operation gates still apply.
        data = asdict(hyp)
        loop.add_hypothesis(hyp.hyp_id, requires=hyp.requires)
    loop.append('exploration_decision', proposal_id=row['proposal_id'], state='adopted' if data else 'rejected',
                reason=reason, review_evidence=proof, hypothesis=data)
    return next(p for p in exploration_view(loop) if p['proposal_id'] == row['proposal_id'])


def adopted_hypothesis(loop, hyp_id):
    from logic_vuln_loop import Env, LogicHypothesis
    for row in exploration_view(loop):
        data = row.get('hypothesis')
        if row['state'] == 'adopted' and data and data['hyp_id'] == hyp_id:
            if row['stale']:
                raise ValueError('adopted exploration source requires revalidation')
            data = {**data, 'applies_env': Env(**data['applies_env'])}
            return LogicHypothesis(**data)
    return None


def frontier(loop):
    items = []
    from research_sources import project as research_sources, card as source_card
    for row in research_sources(loop):
        if row['superseded']:
            continue
        if row['state'] in {'retrieve', 'review', 'insufficient'} or row['stale'] or row['expired']:
            items.append({'kind': 'research-source', 'ref': row['request_id'], 'priority': 1,
                          'action': source_card(row)['next_action'], 'work_card': source_card(row),
                          'queue': 'waiting' if row['stale'] or row['expired'] or row['state'] == 'insufficient' else 'ready'})
    from credentials import project as credentials, card as credential_card
    for row in credentials(loop.events, loop.base_path):
        if row['state'] != 'valid':
            queue = ('waiting' if credential_card(row)['missing_context'] else 'human' if row['kind'] == 'password' else 'ready'
                     if row['state'] == 'unvalidated' and row['attempts'] < row['validation_limit'] else 'waiting')
            items.append({'kind': 'credential-validation', 'ref': row['credential_ref'], 'queue': queue,
                          'priority': 1, 'action': 'validate_credential', 'work_card': credential_card(row)})
    from evidence_gaps import project as gaps, card as gap_card
    for gap in gaps(loop):
        if gap['state'] != 'resolved':
            items.append({'kind': 'evidence-gap', 'ref': gap['gap_id'], 'action': 'design_gap_test',
                          'queue': 'ready' if gap['state'] == 'ready' else 'human' if gap['state'] == 'rejected' else 'waiting',
                          'priority': 1, 'work_card': gap_card(gap)})
    for row in blocked.project(loop.events, loop.base_path):
        if obstruction_queue(row) != 'completed':
            items.append({'kind': 'blocked-research', 'ref': row['obstruction_id'], 'action': row['next'],
                          'detail': row['recovery'], 'queue': obstruction_queue(row), 'priority': 0,
                          'work_card': obstruction_card(row)})
    for proposal in exploration_view(loop):
        if proposal['state'] == 'proposed':
            items.append({'kind': 'exploration-review', 'ref': proposal['proposal_id'],
                          'action': 'review_exploration', 'queue': 'waiting' if proposal['stale'] else 'ready',
                          'priority': 1, 'work_card': exploration_card(proposal)})
    from reassessment import view as reassessments, card as reassessment_card
    for row in reassessments(loop):
        if row['state'] in {'proposed', 'cooldown'}:
            items.append({'kind': 'reassessment', 'ref': row['reassessment_id'],
                          'action': 'reassess', 'queue': 'waiting' if row['stale'] or row['state'] == 'cooldown' else 'ready',
                          'priority': 1, 'work_card': reassessment_card(row)})
    from work_dispatch import jobs, admission_version
    routing = next((e for e in reversed(loop.events) if e['type'] == 'work_routing_config'), None)
    for item in items:
        unavailable = next((e for e in reversed(loop.events) if e['type'] == 'work_adapter_unavailable'
                            and e['state_version'] == item['work_card']['state_version']
                            and routing and e['config_version'] == routing['config_version']
                            and e.get('admission_version') == admission_version(loop)), None)
        if unavailable:
            item.update(queue=unavailable.get('queue', 'human'), dispatch_state='capability-unavailable',
                        detail=unavailable['reason'])
        prior = next((j for j in reversed(jobs(loop.events))
                      if j['card']['state_version'] == item['work_card']['state_version']
                      and (not routing or j['config_version'] == routing['config_version'])), None)
        if prior and prior['state'] in {'running', 'awaiting_validation'}:
            item.update(queue='human' if prior.get('reconciliation_required') else 'waiting',
                        dispatch_state=prior['state'])
        elif prior and prior['state'] in {'failed', 'cancelled'}:
            item.update(queue='human', dispatch_state=prior['state'])
    return items


def partition(items):
    queues = {'ready': [], 'waiting': [], 'human': []}
    for item in items:
        queue = item.get('queue')
        if queue is None:
            queue = ('human' if item['kind'] == 'human-go' else
                     'waiting' if item.get('state') in {'waiting', 'blocked', 'paused'} else 'ready')
        if queue in queues:
            queues[queue].append(item)
    return queues


def main():
    import argparse
    from pathlib import Path

    import asg
    from hunt_lock import acquire, guarded_save, release
    from hunt_loop import HuntLoop

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument(
        "--input", type=Path, required=True, help="JSON with card, operation and payload; or exploration payload"
    )
    parser.add_argument("--explore", action="store_true")
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    token = acquire(ledger, "work-card-result")
    try:
        loop = HuntLoop.load(ledger)
        data = json.loads(args.input.read_text())
        result = propose_exploration(loop, **data) if args.explore else apply(loop, **data)
        guarded_save(loop, ledger, token)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        release(ledger, token)


if __name__ == "__main__":
    main()
