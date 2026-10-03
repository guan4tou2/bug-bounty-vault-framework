#!/usr/bin/env python3
"""check_asg_note_contradictions.py — flag ASG notes that claim a READ but hit a WRITE.

Why
---
An ASG surface note can read like:

    "POST /api/x/contract/{id} (IDOR oracle, leaks order IDs)"

That labels a WRITE endpoint (POST that creates a record) as an "IDOR oracle / leaks" —
a READ conclusion. Acting on that label and enumerating it means repeatedly calling a
write endpoint against records that are not yours, which the ROE forbids. Only an actual
single probe reveals the write semantics.

The ASG is not lying — it faithfully stores whatever someone wrote, and what they wrote
was an un-verified interpretation. This gate makes one dangerous shape visible: the verb
is a WRITE but the conclusion is a READ. A read conclusion tempts "just sample it a few
more times", and each call to a write endpoint can mutate someone else's data.

Read/write classification reuses risk_tier.classify_text (one semantic classifier, not a
second copy).

Usage: python3 automation/check_asg_note_contradictions.py <target>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

VAULT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(VAULT / "automation"))

try:
    from risk_tier import classify_text
except Exception as e:  # pragma: no cover
    print(f"⚠️  cannot import risk_tier: {e}", file=sys.stderr)
    sys.exit(2)

# READ-conclusion words: a note containing these claims it can read/enumerate some data.
# If the same note's endpoint is write-semantic, that is a contradiction — enumerating it
# means repeatedly calling a write endpoint.
READ_CLAIM_RE = re.compile(
    r"\b(idor\s*oracle|oracle|leaks?\b|leak(?:ed|ing)?\b|enumerat|disclos|"
    r"read(?:s|able)?\b|exfiltrat)",
    re.I)


def events(target: str) -> list[dict]:
    f = VAULT / "01 - Targets" / target / ".state" / "asg-events.jsonl"
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def check(target: str) -> list[str]:
    bad: list[str] = []
    surfaces: dict[str, str] = {}   # surface name -> name + note text
    handled: set[str] = set()       # surfaces already tested / dead-ended — danger is past
    for e in events(target):
        t = e.get("type")
        if t == "surface":
            name = e.get("name") or ""
            note = e.get("note") or ""
            surfaces[name] = (name + "  " + note).strip()
            if e.get("untested") is False:
                handled.add(name)
        # A surface counts as handled if a dead_end points at it, or any event's
        # resolves hits it. Substring match both ways — surface names often carry
        # commas/parens while --resolves splits on commas, so exact match misses.
        refs = []
        if t == "dead_end":
            refs.append(e.get("surface") or e.get("name") or "")
        refs.extend(e.get("resolves") or [])
        for ref in refs:
            ref = (ref or "").strip()
            if not ref:
                continue
            for n in surfaces:
                if n and (ref in n or n in ref):
                    handled.add(n)

    for name, text in surfaces.items():
        if name in handled:
            continue
        if not READ_CLAIM_RE.search(text):
            continue
        tier = classify_text(text)
        if tier in ("writes_data", "service_impact"):
            verb = _why_write(text)
            bad.append(f"{name[:70]}\n       -> note claims a read, but endpoint is {tier} "
                       f"({verb}). Enumerating it hits a write endpoint — probe once first.")
    return bad


def _why_write(text: str) -> str:
    from risk_tier import _WRITE_RE
    m = _WRITE_RE.search(text)
    return f"matched write verb `{m.group(0)}`" if m else "write semantics"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 automation/check_asg_note_contradictions.py <target>",
              file=sys.stderr)
        return 2
    target = sys.argv[1]
    bad = check(target)
    print(f"-- ASG note verb contradictions: {target} --")
    if not bad:
        print("OK: no note labelled a read that is actually a write")
        return 0
    for b in bad:
        print(f"FAIL {b}")
    print("\n   Such a note tempts enumeration of a write endpoint (ROE forbids writing")
    print("   to others' data). Probe once to confirm semantics, then fix the note wording.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
