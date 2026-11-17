"""Read-only evidence applicability, separate from artifact integrity and verdicts.

Old data remains readable. Missing target conditions are unknown, never wildcard
matches. Only explicitly supplied expiry times expire evidence; no global TTL.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path

REQUIRED = ("version", "role", "settings", "environment")
OPTIONAL_CONDITIONS = ("account_ref", "conditions", "revision")
UNKNOWN = {"", "*", "unknown", "unspecified", "n/a"}


def _known(value):
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in UNKNOWN
    if isinstance(value, dict):
        return all(_known(item) for item in value.values())
    if isinstance(value, list):
        return all(_known(item) for item in value)
    return math.isfinite(value) if isinstance(value, float) else isinstance(value, (bool, int))


def _condition_known(key, value):
    if key in ("version", "role", "account_ref"):
        return isinstance(value, str) and _known(value)
    if key in ("settings", "conditions"):
        return isinstance(value, dict) and _known(value)
    if key == "environment":
        return isinstance(value, (str, dict)) and bool(value) and _known(value)
    return _known(value)


def _time(value):
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        if value.endswith("-00:00"):
            raise ValueError("unknown local offset")
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("timestamp must include a timezone")
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(UTC)


def latest_context(events, context_id="target"):
    """Read the latest explicit current-condition declaration from the same ledger.

    Imports are historical observations, not current-context declarations. Never
    infer today's version/settings from the newest scanner artifact.
    """
    for event in reversed(events):
        if event.get("type") == "evidence_context" and event.get("context_id", "target") == context_id:
            context = event.get("context")
            return json.loads(json.dumps(context)) if isinstance(context, dict) else None
    return None


def binding_from_scan(manifest, context):
    """Capture explicit target conditions; scanner version is not target version."""
    binding = {key: context[key] for key in (*REQUIRED, *OPTIONAL_CONDITIONS) if key in context}
    binding["observed_at"] = manifest.get("observed_at", manifest.get("started_at"))
    binding["context_id"] = context.get("context_id", "target")
    if "expires_at" in manifest:
        binding["expires_at"] = manifest["expires_at"]
    return binding


def assess_evidence(bindings, current_context=None, now=None):
    """Return {status, reasons, requires_revalidation}; never grants verification.

    Precedence: explicit expiry, known changed conditions, unknown information,
    then applicable. Empty settings dictionaries are an explicit declaration of
    no relevant settings, while omitted settings are unknown.
    """
    unknown, changed = [], []
    if not isinstance(bindings, dict):
        bindings = {}
    if not isinstance(current_context, dict):
        current_context = {}
    try:
        instant = _time(now) if now is not None else datetime.now(UTC)
    except (ValueError, TypeError, OverflowError):
        return {"status": "unknown", "reasons": ["invalid current time"], "requires_revalidation": True}
    observed = None
    try:
        observed = _time(bindings.get("observed_at"))
        if observed > instant:
            unknown.append("observed_at is in the future")
    except (ValueError, TypeError, OverflowError):
        unknown.append("missing or invalid observed_at")
    if "expires_at" in bindings:
        try:
            expiry = _time(bindings["expires_at"])
            if observed is not None and expiry <= observed:
                unknown.append("expires_at does not follow observed_at")
            elif instant >= expiry:
                return {"status": "expired", "reasons": ["explicit expires_at reached"],
                        "requires_revalidation": True}
        except (ValueError, TypeError, OverflowError):
            unknown.append("invalid expires_at")
    for key in (*REQUIRED, *(key for key in OPTIONAL_CONDITIONS if key in bindings)):
        old, current = bindings.get(key), current_context.get(key)
        if not _condition_known(key, old):
            unknown.append("missing or unknown evidence " + key)
        elif not _condition_known(key, current):
            unknown.append("missing or unknown current " + key)
        elif old != current:
            changed.append(key + " changed")
    # Explicit effective_at means conditions changed at that instant, even if
    # values later reverted. Routine context reads should not set effective_at.
    if "effective_at" in current_context:
        try:
            effective = _time(current_context["effective_at"])
            if effective > instant:
                unknown.append("current effective_at is in the future")
            elif observed is not None and effective > observed:
                changed.append("current conditions became effective after evidence")
        except (ValueError, TypeError, OverflowError):
            unknown.append("invalid current effective_at")
    status = "conditions_changed" if changed else "unknown" if unknown else "applicable"
    return {"status": status, "reasons": changed + unknown, "requires_revalidation": status != "applicable"}


def assess_artifact(artifact, events, now=None):
    """Convenience adapter for imports and generic typed artifact evidence."""
    bindings = artifact.get("applicability") if isinstance(artifact, dict) else None
    context_id = bindings.get("context_id", "target") if isinstance(bindings, dict) else "target"
    return assess_evidence(bindings, latest_context(events, context_id), now)


def record_context(target, context, context_id="target"):
    """Record an explicit current-condition declaration, never infer from scans."""
    import asg
    if not isinstance(context, dict) or not isinstance(context_id, str) or not context_id.strip():
        raise ValueError("context must be a mapping with a named context_id")
    allowed = {*REQUIRED, *OPTIONAL_CONDITIONS, "effective_at"}
    if set(context) - allowed:
        raise ValueError("unsupported context fields; use controlled condition references")
    text = json.dumps(context, allow_nan=False)
    if re.search(r'"(?:password|passwd|secret|token|cookie|authorization|credential)"\s*:', text, re.I):
        raise ValueError("context must use controlled references, not credentials")
    if "effective_at" in context:
        _time(context["effective_at"])
    asg.append_event(target, "evidence_context", context_id=context_id, context=json.loads(text))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--context-id", default="target")
    args = parser.parse_args()
    record_context(args.target, json.loads(args.context.read_text()), args.context_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
