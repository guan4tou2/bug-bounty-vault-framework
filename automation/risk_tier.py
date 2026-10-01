#!/usr/bin/env python3
"""risk_tier.py — the single risk classifier for the workspace.

Both the autonomous loop (hunt_autodrive.action_risk) and the interactive path (a
PreToolUse Bash gate, curl_gate.sh) classify an action into one of four tiers by its
ACTUAL side-effect semantics — HTTP method is ONE signal, not the whole rule:

  reads_only     — no side effect (default; comparison probes, GETs, reads)
  state_query    — reads a lot / enumerates, but creates or modifies nothing
  writes_data    — creates / modifies / deletes / sends
  service_impact — may degrade or destroy the service (fuzz/flood/dos/reboot/wipe/drop)

The classifier is pure regex plus an explicit declared field — NO model call. That is
deliberate: it is cheap, deterministic, and auditable, it runs on every gated action, and
it gives a reliable floor even when a weaker model is driving the harness. The real
judgement is deferred to the driving model (the gate surfaces the tier and the model
decides / can declare `BB_RISK`); a model is NOT called on the hot path. An independent
model may re-judge OFFLINE to improve the regex (see risk_tier_calibrate.py).

This is a floor, not a replacement for judgement: a weaker model benefits from keeping it
strict (read-before-write discipline), a stronger model can lean on the declared tier.
"""
from __future__ import annotations

import re

RISK_TIERS = ("reads_only", "state_query", "writes_data", "service_impact")

# service-impacting / destructive semantics (checked first — strongest).
# "...-all" mass operations (flush-all / purge-all / revoke-all) are destructive, not a
# single write — surfaced by risk_tier_calibrate against an independent model.
_IMPACT_RE = re.compile(
    r"\b(fuzz|flood|brute[-\s]?force|spray|mass|bulk|dos|ddos|reboot|restart|shutdown|"
    r"wipe|drop\s+table|rm\s+-rf|truncate|overload|"
    r"(flush|purge|revoke|delete|clear|reset)[-_\s]?all)\b", re.I)
# write / mutate / send semantics. The state-changing verbs on the second row were blind
# spots surfaced by the offline calibration (risk_tier_calibrate.py).
_WRITE_RE = re.compile(
    r"\b(post|put|patch|delete|upload|write|create|insert|update|modify|remove|send|"
    r"submit|register|invite|transfer|purchase|checkout|mutation|set\b|add\b|"
    r"purge|flush|reset|revoke|disable|enable|suspend|grant|approve|reject|cancel|"
    r"deactivate|activate|publish|unpublish|deploy|rollback)\b", re.I)
# heavy-read / enumeration (reads a lot but changes nothing)
_STATE_RE = re.compile(r"\b(enumerate|list\s+all|bulk\s+query|count\s+all)\b", re.I)
# curl/wget write-method or body flags → writes_data signal on a raw command line
_CURL_WRITE_RE = re.compile(
    r"-X\s*(POST|PUT|PATCH|DELETE)\b|--data(-raw|-binary|-urlencode)?\b|"
    r"(^|\s)-d\s|--form\b|(^|\s)-F\s|--upload-file\b|-T\s", re.I)


def classify_text(text: str, explicit: str | None = None) -> str:
    """Risk tier of a free-text action description. An explicit declared tier wins."""
    if explicit in RISK_TIERS:
        return explicit
    t = text or ""
    if _IMPACT_RE.search(t):
        return "service_impact"
    if _WRITE_RE.search(t):
        return "writes_data"
    if _STATE_RE.search(t):
        return "state_query"
    return "reads_only"


def classify_command(cmd: str, explicit: str | None = None) -> str:
    """Risk tier of a raw shell command (the interactive-path analogue). HTTP method /
    body flags are ONE signal, combined with destructive-keyword semantics — so a
    `curl ... reboot` GET is service_impact and a benign read stays reads_only."""
    if explicit in RISK_TIERS:
        return explicit
    c = cmd or ""
    if _IMPACT_RE.search(c):
        return "service_impact"
    if _CURL_WRITE_RE.search(c) or _WRITE_RE.search(c):
        return "writes_data"
    if _STATE_RE.search(c):
        return "state_query"
    return "reads_only"


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Classify an action/command into a risk tier.")
    ap.add_argument("text", nargs="+", help="action description or raw command")
    ap.add_argument("--command", action="store_true", help="treat input as a raw shell command")
    ap.add_argument("--explicit", default=None, help="a declared tier to honour")
    a = ap.parse_args()
    joined = " ".join(a.text)
    tier = (classify_command if a.command else classify_text)(joined, explicit=a.explicit)
    print(tier)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
