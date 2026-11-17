"""Shared, bounded obstruction research journal. Never grants execution authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from command_lifecycle import unresolved_actions
from evidence_applicability import assess_artifact, latest_context
from evidence_refs import evidence_resolves, normalize_evidence

CAUSES = {
    "unknown",
    "waf",
    "permission",
    "rate_limit",
    "session",
    "prerequisite",
    "tool",
    "scope",
    "platform_prohibition",
    "human_approval",
    "safety_gate",
}
HARD = {"scope", "platform_prohibition", "human_approval", "safety_gate"}
WAIT = {"missing_data", "missing_authorization", "cost", "stop_condition", "exhausted"}
PROMPT = """Return blocked actions as ok=false with raw evidence and uncertainty, never 'not vulnerable'.
Do only this card's assigned comparison; return alternative hypotheses to the Harness.
Scope, platform prohibitions, approval and safety gates are not bypass targets.
Changed responses alone establish neither intended behavior nor impact; you do not set a verdict."""


def _proof(loop, value):
    proof = normalize_evidence(value, loop.base_path, events=loop.events)
    if (
        not isinstance(proof, dict)
        or proof.get("kind") != "artifact"
        or not proof.get("sha256")
        or not evidence_resolves(proof, loop.base_path, loop.events)
        or assess_artifact(proof, loop.events)["requires_revalidation"]
    ):
        raise ValueError("current pinned raw artifact evidence required")
    return proof


def _required(*values):
    if any(not isinstance(v, str) or not v.strip() or len(v) > 2048 for v in values):
        raise ValueError("nonempty bounded explanation and recovery fields required (2048 characters)")


def capture_worker_block(loop, hyp_id, test=None, control=None):
    """Automatic result ingress: evidence of reported failure, never target protection attribution."""
    if any(r["hyp_id"] == hyp_id for r in project(loop.events, loop.base_path)):
        return
    context = latest_context(loop.events)
    if loop.base_path is None or not context:
        if not any(e["type"] == "obstruction_evidence_gap" and e["hyp_id"] == hyp_id for e in loop.events):
            loop.append(
                "obstruction_evidence_gap",
                hyp_id=hyp_id,
                reason="Capture raw result and explicit environment before diagnosing obstruction",
            )
        return
    payload = {
        "hyp_id": hyp_id,
        "test": asdict(test) if test else None,
        "control": asdict(control) if control else None,
        "meaning": "Worker-reported failure only; cause and product behavior unconfirmed",
    }
    raw = json.dumps(payload, sort_keys=True).encode()
    identity = hashlib.sha256(raw).hexdigest()
    directory = Path(loop.base_path) / ".state/obstructions"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (identity + ".json")
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    proof = {
        "kind": "artifact",
        "path": str(path),
        "sha256": identity,
        "applicability": {**context, "observed_at": datetime.now(UTC).isoformat()},
    }
    try:
        record(
            loop,
            "worker:" + identity,
            hyp_id,
            cause="unknown",
            layer="worker result",
            explanation="Worker reported an incomplete comparison; diagnose before attributing a protection",
            normal="unknown",
            evidence=proof,
            recovery="successful same-role normal baseline and diagnosed layer",
        )
    except ValueError:
        if not any(e["type"] == "obstruction_evidence_gap" and e["hyp_id"] == hyp_id for e in loop.events):
            loop.append(
                "obstruction_evidence_gap",
                hyp_id=hyp_id,
                evidence=proof,
                reason="Explicit evidence applicability needs repair before obstruction diagnosis",
            )


def record(loop, obstruction_id, hyp_id, *, cause, layer, explanation, normal, evidence, recovery, limit=3):
    _required(obstruction_id, hyp_id, layer, explanation, recovery)
    if cause not in CAUSES or normal not in {"succeeds", "fails", "unknown"}:
        raise ValueError("explicit obstruction classification and normal baseline required")
    if type(limit) is not int or not 1 <= limit <= 3:
        raise ValueError("alternative budget must be 1..3")
    if not any(e["type"] == "hypothesis" and e["id"] == hyp_id for e in loop.events):
        raise ValueError("existing hypothesis required")
    if any(e["type"] == "research_obstruction" and e["obstruction_id"] == obstruction_id for e in loop.events):
        raise ValueError("obstruction identity already exists; preserve history")
    if any(e["type"] == "research_obstruction" and e["hyp_id"] == hyp_id for e in loop.events):
        raise ValueError("hypothesis already has obstruction history; resume it without resetting budget")
    loop.append(
        "research_obstruction",
        obstruction_id=obstruction_id,
        hyp_id=hyp_id,
        cause=cause,
        layer=layer,
        explanation=explanation,
        normal=normal,
        evidence=_proof(loop, evidence),
        recovery=recovery,
        limit=limit,
    )


def _row(loop, obstruction_id):
    return next((row for row in project(loop.events, loop.base_path) if row["obstruction_id"] == obstruction_id), None)


def diagnose(loop, obstruction_id, *, cause, layer, explanation, normal, evidence, recovery):
    row = _row(loop, obstruction_id)
    _required(layer, explanation, recovery)
    if not row or row["cause"] in HARD or row["state"] != "blocked":
        raise ValueError("original authorization path required for protected boundaries")
    if cause not in CAUSES or normal not in {"succeeds", "fails", "unknown"}:
        raise ValueError("explicit classification and normal baseline required")
    proof = _proof(loop, evidence)
    repeated = any(
        e["type"] in {"research_obstruction", "obstruction_diagnosed"}
        and e.get("obstruction_id") == obstruction_id
        and (e["cause"], e["normal"], e["evidence"]["sha256"]) == (cause, normal, proof["sha256"])
        for e in loop.events
    )
    if repeated or (cause, normal, proof["sha256"]) == (row["cause"], row["normal"], row["evidence"]["sha256"]):
        raise ValueError("no new diagnostic evidence or classification; do not repeat identical premises")
    loop.append(
        "obstruction_diagnosed",
        obstruction_id=obstruction_id,
        cause=cause,
        layer=layer,
        explanation=explanation,
        normal=normal,
        evidence=proof,
        recovery=recovery,
    )


def propose(
    loop,
    obstruction_id,
    alternative_id,
    *,
    condition,
    before,
    after,
    rationale,
    comparison,
    information_value,
    impact,
    evidence,
):
    row = _row(loop, obstruction_id)
    _required(alternative_id, condition, before, after, rationale, comparison)
    if not row or row["state"] != "blocked" or row["cause"] in HARD:
        raise ValueError("authorization boundaries and closed obstructions cannot be bypassed")
    if row["cause"] == "unknown" or row["normal"] != "succeeds" or row["stale"]:
        raise ValueError("diagnose obstruction and obtain a current successful normal baseline first")
    if unresolved_actions(loop.events, row["hyp_id"]):
        raise ValueError("reconcile execution and effects first")
    if before == after or type(information_value) is not int or not 1 <= information_value <= 5:
        raise ValueError("one changed condition and information value 1..5 required")
    if impact not in {"low", "medium"}:
        raise ValueError("bounded low/medium impact only; higher impact needs a separate plan")
    if len(row["alternatives"]) + row.get("spent_attempts", 0) >= row["limit"] or any(
        a["alternative_id"] == alternative_id or (a["condition"], a["before"], a["after"]) == (condition, before, after)
        for a in row["alternatives"]
    ):
        raise ValueError("duplicate alternative or exhausted alternative budget")
    loop.append(
        "obstruction_alternative",
        obstruction_id=obstruction_id,
        alternative_id=alternative_id,
        condition=condition,
        before=before,
        after=after,
        rationale=rationale,
        comparison=comparison,
        information_value=information_value,
        impact=impact,
        evidence=_proof(loop, evidence),
    )


def attempt(
    loop,
    obstruction_id,
    alternative_id,
    *,
    result,
    observation,
    excluded,
    recovery,
    test_evidence,
    control_evidence,
    normal_succeeds,
    behavior_observed=False,
    impact_observed=False,
    producer_id='unattributed-worker',
):
    row = _row(loop, obstruction_id)
    _required(observation, excluded, recovery)
    _required(producer_id)
    if not row or row["cause"] in HARD or row["state"] != "blocked" or row["stale"]:
        raise ValueError("obstruction is unavailable for alternative research")
    selected = next((a for a in row["alternatives"] if a["alternative_id"] == alternative_id), None)
    if not selected or selected.get("attempt"):
        raise ValueError("unknown or already attempted alternative")
    if result not in {"blocked", "inconclusive", "behavior_observed"} or any(
        type(value) is not bool for value in (normal_succeeds, behavior_observed, impact_observed)
    ):
        raise ValueError("explicit comparison result required")
    if result == "behavior_observed" and not (
        normal_succeeds and behavior_observed is True and impact_observed is True
    ):
        raise ValueError("response changes alone do not establish intended behavior or impact")
    if unresolved_actions(loop.events, row["hyp_id"]):
        raise ValueError("reconcile execution and effects first")
    test, control = _proof(loop, test_evidence), _proof(loop, control_evidence)
    if test == control:
        raise ValueError("distinct TEST and normal CONTROL artifacts required")
    loop.append(
        "obstruction_attempt",
        obstruction_id=obstruction_id,
        alternative_id=alternative_id,
        result=result,
        observation=observation,
        excluded=excluded,
        recovery=recovery,
        test_evidence=test,
        control_evidence=control,
        normal_succeeds=normal_succeeds,
        behavior_observed=behavior_observed,
        impact_observed=impact_observed,
        producer_id=producer_id,
    )
    used = row.get("spent_attempts", 0) + sum(bool(a.get("attempt")) for a in row["alternatives"]) + 1
    if result != "behavior_observed" and used >= row["limit"]:
        loop.append(
            "obstruction_stopped",
            obstruction_id=obstruction_id,
            reason="exhausted",
            recovery=recovery,
            untested_reason="Program-enforced alternative comparison budget exhausted",
        )


def close(loop, obstruction_id, *, reason, recovery, untested_reason):
    row = _row(loop, obstruction_id)
    _required(recovery, untested_reason)
    if not row or row["state"] not in {'blocked', 'awaiting_validation'} or reason not in WAIT:
        raise ValueError("open obstruction and explicit stopping reason required")
    used = row.get("spent_attempts", 0) + sum(bool(a.get("attempt")) for a in row["alternatives"])
    if (
        reason == "exhausted"
        and used < row["limit"]
        and (not row["alternatives"] or any(not a.get("attempt") for a in row["alternatives"]))
    ):
        raise ValueError("exhausted requires actual alternative comparisons")
    loop.append(
        "obstruction_stopped",
        obstruction_id=obstruction_id,
        reason=reason,
        recovery=recovery,
        untested_reason=untested_reason,
    )


def resume(loop, obstruction_id, *, changed_condition, evidence, recovery):
    row = _row(loop, obstruction_id)
    _required(changed_condition, recovery)
    if not row or row["state"] != "waiting" or row["cause"] in HARD:
        raise ValueError("waiting research and original authorization boundaries must be respected")
    if unresolved_actions(loop.events, row["hyp_id"]):
        raise ValueError("reconcile previous effects first")
    proof = _proof(loop, evidence)
    if (proof["sha256"], proof['path']) == (row["evidence"]["sha256"], row['evidence']['path']):
        raise ValueError("new evidence of changed premises required")
    loop.append(
        "obstruction_resumed",
        obstruction_id=obstruction_id,
        changed_condition=changed_condition,
        evidence=proof,
        recovery=recovery,
    )


def revalidate(loop, obstruction_id, *, changed_condition, evidence, recovery):
    row = _row(loop, obstruction_id)
    if not row or row['state'] == 'waiting' or not row['stale'] or row['cause'] in HARD:
        raise ValueError('stale active research requires revalidation; waiting research uses resume')
    _required(changed_condition, recovery)
    if unresolved_actions(loop.events, row['hyp_id']):
        raise ValueError('reconcile previous effects first')
    proof = _proof(loop, evidence)
    if (proof['path'], proof['sha256']) == (row['evidence']['path'], row['evidence']['sha256']):
        raise ValueError('fresh evidence artifact required, not relabelled source evidence')
    loop.append('obstruction_resumed', obstruction_id=obstruction_id, changed_condition=changed_condition,
                evidence=proof, recovery=recovery)


def _source_version(row):
    return hashlib.sha256(json.dumps(row['alternatives'], sort_keys=True).encode()).hexdigest()


def request_validation(loop, obstruction_id, *, reason):
    row = _row(loop, obstruction_id)
    _required(reason)
    if not row or row['stale'] or row['state'] not in {'blocked', 'completed'} or not any(
            a.get('attempt', {}).get('result') == 'behavior_observed' for a in row['alternatives']):
        raise ValueError('current observed behavior and impact required before independent validation')
    if unresolved_actions(loop.events, row['hyp_id']):
        raise ValueError('reconcile previous execution first')
    version = _source_version(row)
    prior = [v for v in row['validations'] if v['source_version'] == version]
    if len(prior) >= 2:
        close(loop, obstruction_id, reason='stop_condition', recovery='fresh discriminating evidence for verification',
              untested_reason='Independent comparison budget exhausted; conclusion remains unverified')
        return None
    request_id = hashlib.sha256(json.dumps([obstruction_id, version, len(row.get('validations', []))]).encode()).hexdigest()
    loop.append('obstruction_validation_requested', obstruction_id=obstruction_id,
                request_id=request_id, source_version=version, reason=reason)
    return request_id


def validate(loop, obstruction_id, *, request_id, outcome, verifier_id, reason, recovery,
             test_evidence, control_evidence):
    row = _row(loop, obstruction_id)
    _required(request_id, verifier_id, reason, recovery)
    if (not row or row['state'] != 'awaiting_validation' or row['stale']
            or row['validation_request']['request_id'] != request_id
            or row['validation_request']['source_version'] != _source_version(row)):
        raise ValueError('current matching independent validation request required')
    if outcome not in {'supported', 'not_supported', 'needs_evidence'}:
        raise ValueError('explicit independent comparison outcome required')
    producers = {a['attempt'].get('producer_id', 'unattributed-worker') for a in row['alternatives'] if a.get('attempt')}
    if verifier_id in producers:
        raise ValueError('source producer cannot perform independent validation')
    test, control = _proof(loop, test_evidence), _proof(loop, control_evidence)
    source_paths = {p['path'] for a in row['alternatives'] if a.get('attempt')
                    for p in (a['attempt']['test_evidence'], a['attempt']['control_evidence'])}
    if test['path'] == control['path'] or {test['path'], control['path']} & source_paths:
        raise ValueError('independent TEST/CONTROL artifacts must be distinct from the source')
    loop.append('obstruction_validation_result', obstruction_id=obstruction_id, request_id=request_id,
                source_version=_source_version(row), outcome=outcome, verifier_id=verifier_id,
                reason=reason, recovery=recovery, test_evidence=test, control_evidence=control,
                finding_verified=False, independence='runner-reported-separate-context')


def project(events, base_path=None):
    rows = {}
    for event in events:
        kind, oid = event["type"], event.get("obstruction_id")
        if kind == "research_obstruction":
            rows[oid] = {**event, "state": "blocked", "alternatives": [], "conclusion": "inconclusive",
                         'validations': [], 'finding_verified': False}
        elif oid in rows:
            if kind == "obstruction_resumed":
                rows[oid].pop("execution_problem", None)
                rows[oid]["history_alternatives"] = (
                    rows[oid].get("history_alternatives", []) + rows[oid]["alternatives"]
                )
                rows[oid]["spent_attempts"] = rows[oid].get("spent_attempts", 0) + sum(
                    bool(a.get("attempt")) for a in rows[oid]["alternatives"]
                )
                rows[oid]["alternatives"] = []
                rows[oid].pop('validation_request', None)
                rows[oid].pop('validation_outcome', None)
                rows[oid].update(
                    state="blocked",
                    conclusion='inconclusive',
                    normal="unknown",
                    evidence=event["evidence"],
                    recovery=event["recovery"],
                    changed_condition=event["changed_condition"],
                )
            elif kind == "obstruction_execution_denied":
                rows[oid].update(cause="safety_gate", execution_problem="program gate rejected execution")
            elif kind == "work_card_execution_blocked":
                rows[oid]["execution_problem"] = "reconcile or repair prior execution"
                rows[oid]["spent_attempts"] = rows[oid].get("spent_attempts", 0) + 1
            elif kind == "obstruction_diagnosed":
                rows[oid].update(
                    {key: event[key] for key in ("cause", "layer", "explanation", "normal", "evidence", "recovery")}
                )
            elif kind == "obstruction_alternative":
                rows[oid]["alternatives"].append(dict(event))
            elif kind == "obstruction_attempt":
                for a in rows[oid]["alternatives"]:
                    if a["alternative_id"] == event["alternative_id"]:
                        a["attempt"] = event
                if event["normal_succeeds"] is not True:
                    rows[oid]["normal"] = "fails"
            elif kind == "obstruction_stopped":
                rows[oid].update(
                    state="waiting",
                    stop_reason=event["reason"],
                    recovery=event["recovery"],
                    untested_reason=event["untested_reason"],
                )
            elif kind == 'obstruction_validation_requested':
                rows[oid].update(state='awaiting_validation', validation_request=event)
            elif kind == 'obstruction_validation_result':
                rows[oid]['validations'].append(event)
                rows[oid].update(state='completed' if event['outcome'] != 'needs_evidence' else 'blocked',
                                 validation_outcome=event['outcome'], recovery=event['recovery'],
                                 conclusion=event['outcome'])
    for row in rows.values():
        proofs = [row["evidence"]]
        for a in row["alternatives"]:
            proofs.append(a["evidence"])
            if a.get("attempt"):
                proofs += [a["attempt"]["test_evidence"], a["attempt"]["control_evidence"]]
        if row.get('validation_outcome') and row['validations']:
            latest = row['validations'][-1]
            proofs += [latest['test_evidence'], latest['control_evidence']]
        row["stale"] = any(
            not evidence_resolves(p, base_path, events) or assess_artifact(p, events)["requires_revalidation"]
            for p in proofs
        )
        candidates = sorted(
            (a for a in row["alternatives"] if not a.get("attempt")),
            key=lambda a: (a["impact"] != "low", -a["information_value"], a["alternative_id"]),
        )
        if row["cause"] in HARD:
            row["next"] = "original_authorization_path"
        elif row["stale"]:
            row["next"] = "recover_waiting_evidence" if row['state'] == 'waiting' else 'revalidate_evidence'
        elif row["state"] == "waiting":
            row["next"] = "wait_for_recovery"
        elif row['state'] == 'completed':
            row['next'] = 'research_comparison_completed'
        elif row['state'] == 'awaiting_validation':
            row['next'] = 'perform_independent_validation'
        elif row.get('validation_outcome') == 'needs_evidence':
            row['next'] = 'validation_needs_evidence'
        elif row.get("execution_problem"):
            row["next"] = "reconcile_execution"
        elif any(a.get("attempt", {}).get("result") == "behavior_observed" for a in row["alternatives"]):
            row["next"] = "validate_original_claim"
        elif row.get("spent_attempts", 0) + sum(bool(a.get("attempt")) for a in row["alternatives"]) >= row["limit"]:
            row["next"] = "stop_budget_exhausted"
        elif row["normal"] != "succeeds":
            row["next"] = "establish_normal_control"
        elif row["cause"] == "unknown":
            row["next"] = "discriminate_obstruction"
        else:
            row["next"] = "review_alternative_under_existing_gate" if candidates else "assess_alternatives_or_stop"
        row["next_alternative"] = (
            candidates[0]["alternative_id"] if candidates and row["next"].startswith("review_") else None
        )
    return list(rows.values())


def markdown(events, base_path=None):
    rows = project(events, base_path)
    if not rows:
        return ""

    def cell(value):
        return str(value).replace("|", "&#124;").replace("\n", " ").replace("`", "'")

    lines = [
        "### Blocked research and bounded alternatives",
        "_Blocked remains inconclusive; an alternative observation is not a Finding verification._",
        "| Hypothesis | Cause | Next | Attempts / limit | Recovery |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        used = row.get("spent_attempts", 0) + sum(bool(a.get("attempt")) for a in row["alternatives"])
        lines.append(
            "| "
            + " | ".join(
                cell(v) for v in (row["hyp_id"], row["cause"], row["next"], f"{used}/{row['limit']}", row["recovery"])
            )
            + " |"
        )
    return "\n".join(lines)


def main():
    import asg
    from hunt_lock import acquire, guarded_save, release
    from hunt_loop import HuntLoop

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("operation", choices=["record", "diagnose", "propose", "attempt", "close", "resume", "view"])
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    token = acquire(ledger, "blocked-research") if args.operation != "view" else None
    try:
        loop = HuntLoop.load(ledger)
        if args.operation != "view":
            if args.input is None:
                parser.error("mutation requires --input JSON")
            globals()[args.operation](loop, **json.loads(args.input.read_text()))
            guarded_save(loop, ledger, token)
        print(json.dumps(project(loop.events, loop.base_path), ensure_ascii=False, indent=2))
    finally:
        if token is not None:
            release(ledger, token)


if __name__ == "__main__":
    main()
