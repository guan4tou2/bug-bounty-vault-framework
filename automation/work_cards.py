"""Derived work cards, controlled comparisons and checked result transitions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import blocked_research as blocked


def execute_alternative(
    loop, ledger, card, *, comparison_hyp_id, test_argv, control_argv, output_dir, scope_ref, interpret, timeout=30
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
        },
    )
    loop.save(ledger)
    return refreshed


def obstruction_card(row):
    alternative = next((a for a in row["alternatives"] if a["alternative_id"] == row["next_alternative"]), None)
    card = {
        "schema": 1,
        "kind": "blocked-research",
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
    card["state_version"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    return card


def attach(items, events, base_path=None):
    rows = {r["obstruction_id"]: r for r in blocked.project(events, base_path)}
    for item in items:
        if item["kind"] == "blocked-research" and item["ref"] in rows:
            item["work_card"] = obstruction_card(rows[item["ref"]])
        else:
            item["work_card"] = {
                "schema": 1,
                "kind": item["kind"],
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
    rows = {r["obstruction_id"]: r for r in blocked.project(loop.events, loop.base_path)}
    row = rows.get(card.get("ref"))
    if not row or card != obstruction_card(row):
        raise ValueError("stale or altered work card; refresh canonical state")
    allowed = {
        "wait_for_recovery": {"resume"},
        "reconcile_execution": {"close"},
        "establish_normal_control": {"diagnose", "close"},
        "discriminate_obstruction": {"diagnose", "close"},
        "stop_budget_exhausted": {"close"},
        "assess_alternatives_or_stop": {"propose", "close"},
        "review_alternative_under_existing_gate": {"attempt", "close"},
        "original_authorization_path": {"close"},
        "revalidate_evidence": {"diagnose", "close"},
    }
    if operation not in allowed.get(row["next"], set()) or "obstruction_id" in payload:
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
    if not question.strip() or not reason.strip() or not isinstance(requires, list):
        raise ValueError("explicit exploration question, reason and prerequisites required")
    proof = blocked._proof(loop, evidence)
    # Remains a proposal for normal planning/authorization, not a ready hypothesis.
    loop.append("exploration_proposal", question=question, reason=reason, evidence=proof, requires=requires)


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
