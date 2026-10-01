#!/usr/bin/env python3
"""curl_gate.py — PreToolUse gate for outbound curl/wget/http requests.

Classifies each request by its side-effect semantics (risk_tier.py, the single
classifier) and defers the real judgement to the driving model — no model call on the
hot path. HTTP method is one signal, not the whole rule:
  reads_only / state_query  → allow silently
  writes_data               → WARN (exit 0): make sure impact is known + authorized
  service_impact            → BLOCK (exit 2): destructive / service-impacting

Scope: only engages on an actual request tool (curl/wget/http); arbitrary Bash is never
classified, so destructive-keyword regex can never block an unrelated command. Localhost /
.test / .localhost are exempt (own-app testing). Phase ordering stays in phase_gate.sh.

This is a deterministic floor, valuable precisely when a weaker model is driving: it keeps
read-before-write discipline without needing the model to remember it. Override: declare
the tier inline with BB_RISK=<tier> (e.g. a POST that is really a search → state_query);
full skip BB_SKIP_RISK_GATE=1. Exit 0 = allow, Exit 2 = block.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import risk_tier  # noqa: E402

_LOCALHOST = re.compile(r"(localhost|127\.0\.0\.1|\[::1\]|\.localhost|\.test)")
_REQUEST = re.compile(r"(?:^|[\s;&|(){}`])(?:curl|wget|http)(?:\s|$)")


def main() -> int:
    try:
        obj = json.loads(sys.stdin.read())
    except Exception:
        return 0
    if (obj or {}).get("tool_name") != "Bash":
        return 0
    cmd = ((obj.get("tool_input") or {}).get("command") or "")
    if not cmd.strip() or not _REQUEST.search(cmd) or _LOCALHOST.search(cmd):
        return 0
    if os.environ.get("BB_SKIP_RISK_GATE") == "1" or "BB_SKIP_RISK_GATE=1" in cmd:
        return 0

    em = re.search(r"BB_RISK=(reads_only|state_query|writes_data|service_impact)", cmd)
    tier = risk_tier.classify_command(cmd, explicit=(em.group(1) if em else None))

    if tier == "service_impact":
        sys.stderr.write(
            "curl-gate/risk: service_impact — a possibly destructive / service-impacting "
            "request (fuzz/flood/reboot/wipe/drop/...-all) was blocked.\n"
            "Semantic judgement (not a method guess): it blocks 'dangerous', not 'non-GET'.\n"
            "Confirm authorization + a rollback plan; when safe, override once with "
            "BB_SKIP_RISK_GATE=1, or if misclassified declare the tier: BB_RISK=writes_data.\n"
        )
        return 2
    if tier == "writes_data":
        sys.stderr.write(
            "curl-gate/risk: writes_data — a write action (not a blind method guess). "
            "Make sure the impact is known and within authorization before sending.\n"
            "If it is really a query (e.g. a POST search): prefix BB_RISK=state_query.\n"
        )
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
