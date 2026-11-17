"""Product conditions remain distinct from research state and authorization."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from efsm_conditions import evaluate, predict, validate


def test_three_valued_typed_conditions():
    predicate = {
        "all": [
            {"field": "role", "op": "eq", "value": "owner"},
            {"field": "state", "op": "in", "value": ["private", "shared"]},
        ]
    }
    assert evaluate(predicate, {"role": "owner", "state": "shared"}) == "true"
    assert evaluate(predicate, {"role": "owner"}) == "unknown"
    assert evaluate(predicate, {"role": "recipient"}) == "false"
    assert evaluate({"field": "n", "op": "eq", "value": True}, {"n": 1}) == "false"


def test_false_guard_keeps_negative_security_test_possible():
    result = predict(
        {"from": "shared", "to": "revoked", "predicate": {"field": "role", "op": "eq", "value": "owner"}},
        {"role": "recipient"},
        observed_state="shared",
    )
    assert result["negative_test_candidate"] and not result["execution_authorized"]
    assert result["expected_product_state"] is None
    assert result["research_conclusion"] == "not-established"


def test_no_expressions_or_silent_unknown_operators():
    with pytest.raises(ValueError):
        validate({"eval": '__import__("os")'})
    with pytest.raises(ValueError):
        evaluate({"field": "role", "op": "regex", "value": ".*"}, {})
    assert evaluate(None, {}) == "unknown"
