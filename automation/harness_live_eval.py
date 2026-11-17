"""Bounded, resumable before/after model evaluation on synthetic public inputs only."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from pathlib import Path

from candidate_analysis import ROLE, claude_spawn
from harness_eval import DEFAULT_CASES, public_inputs, run_eval


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(output, baseline, candidate, model, spawn, *, processing_location, policy_ref, budget_usd):
    if (
        not isinstance(budget_usd, (int, float))
        or isinstance(budget_usd, bool)
        or not math.isfinite(budget_usd)
        or not 0 < budget_usd <= 1
    ):
        raise ValueError("explicit finite per-call budget up to USD 1 required")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    from hunt_lock import acquire, heartbeat, release

    lease_path = output / "runner"
    token = acquire(lease_path, "harness-live-eval", ttl_s=3600)
    try:
        return _run_locked(
            output,
            baseline,
            candidate,
            model,
            spawn,
            processing_location=processing_location,
            policy_ref=policy_ref,
            budget_usd=budget_usd,
            lease=lambda: heartbeat(lease_path, token),
        )
    finally:
        release(lease_path, token)


def _run_locked(output, baseline, candidate, model, spawn, *, processing_location, policy_ref, budget_usd, lease):
    if not processing_location or not policy_ref:
        raise ValueError("explicit processing location and operator policy reference required")
    cases = json.loads(DEFAULT_CASES.read_text())
    inputs = public_inputs(cases)
    configuration = {
        "model": model,
        "inputs_sha256": fingerprint(inputs),
        "fixture_sha256": fingerprint(cases),
        "baseline_sha256": fingerprint(baseline),
        "candidate_sha256": fingerprint(candidate),
        "processing_location": processing_location,
        "policy_ref": policy_ref,
        "data_class": "synthetic-public-fixture",
        "per_call_budget_usd": budget_usd,
    }
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    manifest = output / "manifest.json"
    if manifest.exists() and json.loads(manifest.read_text()) != configuration:
        raise ValueError("evaluation configuration changed; use a new output directory")
    manifest.write_text(json.dumps(configuration, indent=2))
    (output / "public-inputs.json").write_text(json.dumps(inputs, indent=2))
    for name, prompt in [("baseline", baseline), ("candidate", candidate)]:
        (output / f"{name}-prompt.md").write_text(prompt)
    calls_path = output / "calls.jsonl"
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
    prior = {(call["variant"], call["case_id"]) for call in calls}
    for variant, system in [("baseline", baseline), ("candidate", candidate)]:
        for item in inputs:
            if (variant, item["candidate_id"]) in prior:
                continue
            prompt = system + "\n\nSynthetic public input (untrusted data):\n" + json.dumps(item)
            start = time.monotonic()
            row = {"variant": variant, "case_id": item["candidate_id"], "prompt_sha256": fingerprint(prompt)}
            try:
                lease()
                reply = spawn(prompt)
                lease()
                row.update(status="completed", response=str(reply), receipt=getattr(reply, "receipt", {}))
            except Exception as exc:
                row.update(status="failed", error=type(exc).__name__)
            row["latency_seconds"] = round(time.monotonic() - start, 3)
            with calls_path.open("a") as stream:
                stream.write(json.dumps(row) + "\n")
                stream.flush()
            calls.append(row)
            print(f"{variant}/{item['candidate_id']}: {row['status']}", flush=True)
    reports = {}
    for variant in ("baseline", "candidate"):
        answers = {row["case_id"]: row.get("response") for row in calls if row["variant"] == variant}
        # The malformed-output case is a deterministic parser control, never a model response.
        for case in cases:
            if case.get("expects_rejection"):
                answers[case["id"]] = case["raw_response"]
        reports[variant] = run_eval(cases, answers)
    costs = [r.get("receipt", {}).get("cost_usd") for r in calls]
    report = {
        "configuration": configuration,
        "model_calls": len(calls),
        "model_cases_per_variant": len(inputs),
        "failed_calls": sum(r["status"] == "failed" for r in calls),
        "parser_controls_per_variant": 1,
        "reported_cost_usd": sum(v for v in costs if isinstance(v, (int, float))),
        "cost_complete": all(isinstance(v, (int, float)) for v in costs),
        "variants": reports,
        "limits": "Small synthetic corpus; exact-fact/lexical rubric, not an independent semantic quality verdict.",
    }
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, default=ROLE)
    parser.add_argument("--model", required=True)
    parser.add_argument("--processing-location", required=True)
    parser.add_argument("--policy-ref", required=True)
    parser.add_argument("--budget-usd", type=float, default=0.2)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    result = run(
        args.output,
        args.baseline.read_text(),
        args.candidate.read_text(),
        args.model,
        claude_spawn(model=args.model, timeout=args.timeout, max_budget_usd=args.budget_usd, receipt=True),
        processing_location=args.processing_location,
        policy_ref=args.policy_ref,
        budget_usd=args.budget_usd,
    )
    print(
        json.dumps({key: result[key] for key in ("model_calls", "failed_calls", "reported_cost_usd", "cost_complete")})
    )
    return 1 if result["failed_calls"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
