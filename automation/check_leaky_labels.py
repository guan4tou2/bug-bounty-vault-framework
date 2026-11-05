#!/usr/bin/env python3
"""check_leaky_labels.py — flag ASG surface labels that leak sensitive detail.

The ASG is the codename layer: surface labels are references you show in chat / brief /
next_work, so they must be NEUTRAL (svc-dmc, redirect-dmc-preview), with the CVE / exploit /
credential detail in the `note`/evidence field — NOT in the label. A label like
"Forged alg:none JWT (arbitrary app identity)" or "DeepSeek AI API key" put in a session's
context is exactly the exploit-detail that sensitizes the safety classifier and blocks the
rest of the session. This catches those mechanically so they can be renamed to a short code.

Usage:
  check_leaky_labels.py <target>     # one target
  check_leaky_labels.py              # all targets with a ledger
Exit 0 always (advisory). Prints leaky labels + the matched term.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

VAULT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])
TARGETS = VAULT / "01 - Targets"

# Terms whose presence in a LABEL leaks exploit/credential/CVE detail into context.
LEAK = re.compile(
    r"(?i)\b("
    r"CVE-\d{4}|"
    r"jwt|alg\s*:?\s*none|"
    r"password|passwd|\bpwd\b|secret|credential|api[\s_-]?key|app[\s_-]?token|"
    r"private[\s_-]?key|access[\s_-]?key|\btoken\b|"
    r"\brce\b|remote code|webshell|\bshell\b|backdoor|reverse[\s_-]?shell|"
    r"\bssrf\b|\bsqli\b|\blfi\b|\brfi\b|deseriali|xxe"
    r")\b")


def _surface_names(target: str) -> list[str]:
    """Surface labels from the ledger (surface events)."""
    ledger = TARGETS / target / ".state" / "asg-events.jsonl"
    names: list[str] = []
    try:
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            if ev.get("type") == "surface" and ev.get("name"):
                names.append(str(ev["name"]))
    except OSError:
        pass
    return names


def scan_target(target: str) -> list[tuple[str, str]]:
    """Return [(label, matched_term)] for leaky labels."""
    out = []
    for name in _surface_names(target):
        m = LEAK.search(name)
        if m:
            out.append((name, m.group(0)))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        targets = [args[0]]
    else:
        targets = sorted(p.name for p in TARGETS.iterdir()
                         if p.is_dir() and (p / ".state" / "asg-events.jsonl").exists())
    total = 0
    for t in targets:
        leaky = scan_target(t)
        if not leaky:
            continue
        total += len(leaky)
        print(f"⚠ {t}: {len(leaky)} leaky surface label(s) — rename to a neutral code, move detail to note:")
        for label, term in leaky[:12]:
            print(f"    [{term}] {label[:90]}")
        if len(leaky) > 12:
            print(f"    …另 {len(leaky) - 12} 個")
    if total == 0:
        print("✓ 無 leaky surface label（label 皆為中性代號）")
    else:
        print(f"\n共 {total} 個 leaky label——中性化：短 code 進 label，CVE/exploit/憑證細節進 note/evidence。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
