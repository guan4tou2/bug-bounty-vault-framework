"""Small deterministic Harness rubric; no model is invoked by this evaluator.

Default mode checks handcrafted reference fixtures, not model quality. External
responses can be scored with --responses, but semantic correctness still needs
independent review: exact declared facts and explicit rubric terms are checked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from candidate_analysis import parse_analysis_result

DEFAULT_CASES = Path(__file__).resolve().parents[1] / "tests/fixtures/harness_eval/cases.json"


def public_inputs(cases):
    """Export only synthetic observations; keep the reference oracle out of model input."""
    return [{"candidate_id": case["id"], "evidence_version": "fixture-v1",
             "observations": case["observations"], "evidence_refs": ["evidence:0"],
             "task": ("Analyze this saved candidate; separate observation/inference, missing proof "
                      "and a discriminating next step.")}
            for case in cases if not case.get("expects_rejection")]


def reference_response(case):
    if case.get("expects_rejection"):
        return case["raw_response"]
    return {"candidate_id": case["id"], "evidence_version": "fixture-v1",
            "assessment": case["assessment"], "support": case["support"], "against": case["against"],
            "missing_evidence": case["missing_evidence"], "suggested_validation": [case["next_step"]],
            "evidence_refs": ["evidence:0"]}


def evaluate_response(case, response):
    job = {"candidate_id": case["id"], "evidence_version": "fixture-v1",
           "snapshot": {"artifacts": [{"path": "fixture://" + case["id"]}]}}
    try:
        result = parse_analysis_result(response, job)
    except (ValueError, TypeError, KeyError):
        return {"case": case["id"], "schema_accepted": False,
                "passed": bool(case.get("expects_rejection")), "checks": {"invalid_output_rejected": True}}
    declared = {"observation: " + fact for fact in case["observations"]}
    support = result["support"]
    next_step = " ".join(result["suggested_validation"]).lower()
    checks = {
        "citation": result["evidence_refs"] == ["fixture://" + case["id"]],
        "grounded_observation": (any(line in declared for line in support)
                                 and all(line in declared or line.startswith("inference: ") for line in support)),
        "discriminating_next_step": all(term in next_step for term in case.get("next_step_terms", [])),
        "uncertainty": bool(result["missing_evidence"]) and result["assessment"] == case.get("assessment"),
    }
    return {"case": case["id"], "schema_accepted": True,
            "passed": not case.get("expects_rejection", False) and all(checks.values()), "checks": checks}


def run_eval(cases=None, responses=None):
    cases = json.loads(DEFAULT_CASES.read_text()) if cases is None else cases
    results = []
    for case in cases:
        if responses is not None and case["id"] not in responses:
            results.append({"case": case["id"], "schema_accepted": False, "passed": False,
                            "checks": {"response_present": False}})
        else:
            results.append(evaluate_response(case, responses[case["id"]] if responses is not None
                                             else reference_response(case)))
    names = {name for result in results for name in result["checks"]}
    return {"mode": "supplied-response-rubric" if responses is not None else "reference-fixture-self-check",
            "eval_version": "harness-rubric/v1",
            "fixture_sha256": hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest(),
            "model_calls": 0, "model_quality_measured": False,
            "cases": len(results), "passed": sum(result["passed"] for result in results),
            "checks": {name: {"passed": sum(result["checks"].get(name) is True for result in results),
                              "evaluated": sum(name in result["checks"] for result in results)}
                       for name in sorted(names)},
            "results": results,
            "limits": "Exact declared facts and lexical next-step terms only; not semantic or live-model validation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--responses", type=Path)
    parser.add_argument("--export-inputs", action="store_true",
                        help="print synthetic model inputs without reference answers")
    args = parser.parse_args()
    if args.export_inputs:
        print(json.dumps(public_inputs(json.loads(args.fixtures.read_text())), ensure_ascii=False, indent=2))
        return 0
    report = run_eval(json.loads(args.fixtures.read_text()),
                      json.loads(args.responses.read_text()) if args.responses else None)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] == report["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
