"""Resume does not spend twice or send the expected answer to a model."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import harness_live_eval as live


def test_resume_and_manifest_pinning(tmp_path):
    calls = []

    def spawn(prompt):
        calls.append(prompt)
        assert "reference_response" not in prompt and "oracle_terms" not in prompt
        return "{}"

    args = (tmp_path, "baseline", "candidate", "fixture", spawn)
    options = {"processing_location": "fixture", "policy_ref": "operator:fixture", "budget_usd": 0.1}
    report = live.run(*args, **options)
    assert report["model_calls"] == len(calls) == 12
    live.run(*args, **options)
    assert len(calls) == 12
    with pytest.raises(ValueError, match="configuration changed"):
        live.run(tmp_path, "changed", "candidate", "fixture", spawn, **options)


def test_failed_call_is_retained_without_automatic_retry(tmp_path):
    def spawn(_):
        raise TimeoutError("fixture")

    report = live.run(
        tmp_path,
        "a",
        "b",
        "fixture",
        spawn,
        processing_location="fixture",
        policy_ref="operator:fixture",
        budget_usd=0.1,
    )
    assert report["failed_calls"] == 12
    assert report["reported_cost_usd"] == 0 and not report["cost_complete"]
