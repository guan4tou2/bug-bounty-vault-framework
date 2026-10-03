#!/usr/bin/env python3
"""check_submission_layout.py — enforce the Submissions/ folder conventions as a gate.

Why
---
When finalizing a submission package, "which file do I actually send?" is surprisingly
easy to get wrong. Recurring mistakes, none of them "wrong content" — all "thing in the
wrong place", and the cost is the next person (or the next session) sending the wrong file:

  · the archive sits several directories away from the package it archives
  · a pre-merge batch folder duplicates a merged one, so every finding has two docx and
    nothing says which is the one to send
  · a docx is older than its source md and still holds deleted text
  · an orphan evidence file lives under Forms/Evidence/ while the real Evidence/ lacks it
  · a draft superseded by the cover letter still has status: ready

Conventions (enforced here)
---------------------------
    Submissions/
      Forms/
        FORM - <ID> - <title>.md   one per finding, the source of truth
        <batch>-docx/              docx to send, one folder per batch
        <batch>-submitted/         renamed after sending; gate stops checking it
        <batch>.7z                 archive sits NEXT TO the folder it archives, not inside
        email-<batch>.md           the cover letter for that batch
        _withheld/                 docx decided not to send
    Evidence/                      all evidence files, this one place only

Checks
------
  1. no second Evidence dir under Submissions/
  2. a finding ID must not appear in two pending batch folders
  3. a docx in a pending folder must not be older than its source md
  4. a FORM with status submitted must not still have its docx in a pending folder
  5. an archive must not sit inside the folder it archives
  6. a cover letter with status ready must have a matching pending folder

Usage: python3 automation/check_submission_layout.py <target>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

VAULT = Path(__file__).resolve().parent.parent
PENDING = re.compile(r"docx$")          # pending batch: ends in -docx
SENT = re.compile(r"submitted|_withheld")


def form_status(p: Path) -> str:
    head = p.read_text(encoding="utf-8", errors="replace")[:600]
    m = re.search(r'^status:\s*"?([a-z_-]+)"?', head, re.M)
    return m.group(1) if m else ""


def fid(name: str) -> str:
    m = re.search(r"[A-Z]{2,6}-\d{3,4}", name)
    return m.group(0) if m else ""


def check(target: str) -> list[str]:
    bad: list[str] = []
    sub = VAULT / "01 - Targets" / target / "Submissions"
    forms = sub / "Forms"
    if not forms.is_dir():
        return [f"not found: {forms}"]

    # 1) duplicate Evidence dir
    for d in sub.rglob("Evidence"):
        if d.is_dir():
            n = len(list(d.iterdir()))
            bad.append(f"second Evidence/ under Submissions ({d.relative_to(sub)}, {n} items)"
                       " — evidence lives only in <target>/Evidence/")

    pend = [d for d in forms.iterdir()
            if d.is_dir() and PENDING.search(d.name) and not SENT.search(d.name)]

    # 2) same id in two pending batches
    seen: dict[str, str] = {}
    for d in pend:
        for f in d.glob("*.docx"):
            i = fid(f.name)
            if not i:
                continue
            if i in seen and seen[i] != d.name:
                bad.append(f"{i} is in both {seen[i]}/ and {d.name}/ — "
                           f"old batch not cleaned up, you'll send the wrong one")
            seen[i] = d.name

    # 3) docx older than source md; 4) sent FORM still in a pending folder
    for d in pend:
        for f in d.glob("*.docx"):
            i = fid(f.name)
            md = next(iter(forms.glob(f"FORM - {i}*.md")), None) if i else None
            if md is None:
                bad.append(f"{d.name}/{f.name[:40]}… no matching FORM markdown")
                continue
            if md.stat().st_mtime > f.stat().st_mtime:
                bad.append(f"{i}: docx older than source md — regenerate it")
            if form_status(md) == "submitted":
                bad.append(f"{i}: FORM is submitted but its docx is still in pending "
                           f"{d.name}/ — rename the folder to -submitted")

    # 5) archive inside the folder it archives
    for d in forms.iterdir():
        if d.is_dir():
            for z in list(d.glob("*.7z")) + list(d.glob("*.zip")):
                bad.append(f"archive inside the folder it archives ({d.name}/{z.name}) — "
                           f"move it up one level, or a re-pack bundles the old archive too")

    # 6) ready cover letter with no matching pending folder
    for mail in forms.glob("email-*.md"):
        if form_status(mail) != "ready":
            continue
        tag = mail.stem.replace("email-", "")
        if not any(tag in d.name for d in pend):
            bad.append(f"{mail.name} is ready but there is no matching {tag}-docx/ pending folder")

    return bad


def main() -> int:
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        # target-scoped; nothing to do without a target (e.g. run_checks with no target)
        print("no target given, skipping")
        return 0
    bad = check(sys.argv[1])
    print(f"-- submission layout: {sys.argv[1]} --")
    if not bad:
        print("OK: layout conforms")
        return 0
    for b in bad:
        print(f"FAIL {b}")
    print("\n   Conventions: see the header of this file.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
