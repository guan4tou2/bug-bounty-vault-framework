"""Conservative, bounded input selection before advisory model processing.

Raw HTTP messages and extracted values never cross this boundary. Original bytes,
paths and precise locators stay in the ledger; models receive opaque references.
This is minimization, not a claim that a regex can detect every possible secret.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

SENSITIVE_KEY = re.compile(r"auth|cookie|token|secret|password|passwd|api.?key|credential|private.?key", re.I)
BEARER = re.compile(r"\b(?:Bearer|Basic)\s+\S+", re.I)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
ASSIGNMENT = re.compile(r"\b(?:token|secret|password|api[_-]?key|authorization)\s*[:=]\s*\S+", re.I)
PATH = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s/\\]+[/\\])+[^\s]*")
OPAQUE_VALUE = re.compile(r"\b[A-Za-z0-9_+/=-]{32,}\b")


class ProcessingPolicyBlockedError(ValueError):
    """No model call is authorized by the recorded processing policy."""


def check_processing_policy(job, processing_location, authorization=None):
    policy = job["snapshot"].get("source", {}).get("model_processing_policy")
    allowed = policy.get("allowed_locations") if isinstance(policy, dict) else None
    authorized = authorization.get('allowed_locations') if isinstance(authorization, dict) else None
    if (not isinstance(processing_location, str) or not processing_location
            or not isinstance(allowed, list) or not allowed
            or any(not isinstance(value, str) or not value for value in allowed)
            or processing_location not in allowed
            or not isinstance(authorized, list) or processing_location not in authorized
            or any(not isinstance(value, str) or not value.strip() for value in authorized)
            or not isinstance(authorization.get('policy_ref'), str) or not authorization['policy_ref'].strip()):
        raise ProcessingPolicyBlockedError("unsupported model processing policy")
    return {"processing_location": processing_location, "selection_version": "analysis-input/v1",
            "policy_ref": authorization.get('policy_ref')}


def safe_text(value):
    if not isinstance(value, (str, int, float, bool)):
        return "[omitted]"
    text = str(value)
    text = BEARER.sub("[credential omitted]", text)
    text = JWT.sub("[credential omitted]", text)
    text = ASSIGNMENT.sub("[credential omitted]", text)
    text = PATH.sub("[path omitted]", text)
    text = OPAQUE_VALUE.sub("[opaque value omitted]", text)
    return text[:256]


def safe_context(value, *, depth=0):
    if depth > 3:
        return "[omitted]"
    if isinstance(value, dict):
        return {safe_text(key): "[credential omitted]" if SENSITIVE_KEY.search(str(key))
                else safe_context(item, depth=depth + 1) for key, item in list(value.items())[:20]}
    if isinstance(value, list):
        return [safe_context(item, depth=depth + 1) for item in value[:10]]
    return safe_text(value)


def asset_reference(value):
    """Retain endpoint identity without transmitting URL path/query/userinfo."""
    value = str(value)
    reference = hashlib.sha256(value.encode()).hexdigest()[:20]
    try:
        parts = urlsplit(value)
        if parts.scheme in {"http", "https"} and parts.hostname:
            return {"scheme": parts.scheme, "endpoint_ref": reference}
    except ValueError:
        pass
    return {"endpoint_ref": reference}


def selected_candidate(candidate):
    # Do not recursively copy arbitrary scan metadata, URLs, bodies or extracted
    # matches. These are pointers/labels, never observations of runtime impact.
    selected = {key: safe_text(candidate[key]) for key in (
        "candidate_id", "candidate_type", "template_id", "matcher_name", "status",
        "observation_type", "protocol", "port", "service", "matched",
    ) if key in candidate}
    selected["asset"] = asset_reference(candidate.get("asset", ""))
    context = candidate.get("context", {})
    selected["context"] = {key: safe_context(context[key]) for key in ("role", "conditions")
                           if key in context}
    if "account_ref" in context:
        selected["context"]["account_ref"] = 'actor:' + hashlib.sha256(
            str(context['account_ref']).encode()).hexdigest()[:20]
    return selected


def selected_record(raw):
    """Only parser identity/matcher facts; HTTP bodies and credentials are omitted."""
    selected = {key: safe_text(raw[key]) for key in ("template-id", "matcher-name", "type", "matcher-status")
                if key in raw}
    info = raw.get("info", {})
    if isinstance(info, dict) and info.get("severity") in {"info", "low", "medium", "high", "critical", "unknown"}:
        selected["scanner_severity"] = info["severity"]
    request = raw.get("request")
    if isinstance(request, str):
        method = request.split(" ", 1)[0]
        if method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            selected["request_method"] = method
    response = raw.get("response")
    if isinstance(response, str):
        status = re.match(r"HTTP/[0-9.]+ ([0-9]{3})\b", response)
        if status:
            selected["response_status"] = int(status.group(1))
    selected["omissions"] = ["raw HTTP messages", "headers/cookies", "URL path/query/userinfo",
                             "extracted values", "local file paths", "unselected metadata"]
    return selected
