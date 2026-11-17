"""Small declarative product guards, three-valued results; no code evaluation."""

from __future__ import annotations


def validate(predicate, depth=0):
    if not isinstance(predicate, dict) or depth > 8:
        raise ValueError("bounded declarative condition required")
    if set(predicate) in ({"all"}, {"any"}):
        values = next(iter(predicate.values()))
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError("bounded nonempty condition list required")
        for value in values:
            validate(value, depth + 1)
    elif set(predicate) == {"field", "op", "value"}:
        if (
            not isinstance(predicate["field"], str)
            or not predicate["field"]
            or predicate["op"] not in {"eq", "ne", "in"}
        ):
            raise ValueError("unsupported predicate")
        value = predicate["value"]
        if predicate["op"] == "in":
            if not isinstance(value, list) or not 1 <= len(value) <= 32:
                raise ValueError("bounded membership values required")
            values = value
        else:
            values = [value]
        if any(type(v) not in {str, int, bool, type(None)} for v in values):
            raise ValueError("scalar predicate values required")
    else:
        raise ValueError("unsupported predicate shape")


def evaluate(predicate, variables):
    if predicate is None:
        return "unknown"
    validate(predicate)
    if "all" in predicate or "any" in predicate:
        operator = "all" if "all" in predicate else "any"
        results = [evaluate(p, variables) for p in predicate[operator]]
        decisive, default = ("false", "true") if operator == "all" else ("true", "false")
        return decisive if decisive in results else "unknown" if "unknown" in results else default
    field, operation, expected = predicate["field"], predicate["op"], predicate["value"]
    if field not in variables:
        return "unknown"
    actual = variables[field]

    def equal(value):
        return type(actual) is type(value) and actual == value

    result = (
        any(equal(v) for v in expected)
        if operation == "in"
        else equal(expected)
        if operation == "eq"
        else not equal(expected)
    )
    return "true" if result else "false"


def predict(transition, variables, *, observed_state):
    """Expectation only. A false product guard does not forbid an authorized negative test."""
    guard = evaluate(transition.get("predicate"), variables)
    return {
        "guard": guard,
        "from_matches": observed_state == transition["from"],
        "expected_product_state": transition["to"] if guard == "true" else None,
        "negative_test_candidate": guard == "false",
        "execution_authorized": False,
        "research_conclusion": "not-established",
    }
