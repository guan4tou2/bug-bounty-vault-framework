#!/usr/bin/env python3
"""sync_pattern_index — auto-sync Pattern Index count + detect missing/orphan rows.

What it does (race-free):
- Counts `Pattern - *.md` files in `09 - Knowledge Base/` (canonical source).
- Reads `Pattern Index.md`; rewrites the `> NN 個 Pattern ...` header line to match.
- Lists every `[[Pattern - X]]` wikilink in the index body.
- Reports:
    * patterns on disk but NOT indexed (missing rows)
    * indexed but NOT on disk (orphan rows / typos)

Modes:
  --check           : exit 1 if count drifts OR missing/orphan rows exist. No file writes.
  --fix             : auto-fix the count line; missing/orphan rows still reported (manual).
  --staged          : like --check but only if Pattern Index.md or Pattern - *.md is staged.

Run from anywhere; resolves vault root from script path.

Purpose: eliminate the parallel-session race where two writers both bump the count.
The number is derived from disk, so concurrent edits in different scopes
(_kb/Pattern - X by session A, _kb/Pattern - Y by session B) merge cleanly via
hook-recomputed count instead of fighting over the header line.
"""
from __future__ import annotations

import re
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "09 - Knowledge Base"
INDEX = KB / "Pattern Index.md"
COUNT_RE = re.compile(r"^(>\s*)(\d+)( 個 Pattern)", re.MULTILINE)
WIKILINK_RE = re.compile(r"\[\[(Pattern - [^\]|#]+?)(?:[#|][^\]]*)?\]\]")


def disk_patterns() -> set[str]:
    """Set of pattern basenames (without .md) actually on disk."""
    return {p.stem for p in KB.glob("Pattern - *.md")}


def indexed_patterns(text: str) -> set[str]:
    """Pattern names referenced by [[wikilink]] in the index."""
    return {m.group(1).strip() for m in WIKILINK_RE.finditer(text)}


def staged_paths() -> list[Path]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only"], cwd=ROOT, text=True
        )
        return [ROOT / p for p in out.splitlines() if p]
    except subprocess.CalledProcessError:
        return []


def should_run_staged() -> bool:
    paths = staged_paths()
    if not paths:
        return False
    for p in paths:
        name = p.name
        if name == "Pattern Index.md":
            return True
        if name.startswith("Pattern - ") and name.endswith(".md"):
            return True
    return False


def main(argv: list[str]) -> int:
    mode_check = "--check" in argv
    mode_fix = "--fix" in argv
    mode_staged = "--staged" in argv
    if not (mode_check or mode_fix or mode_staged):
        print("usage: sync_pattern_index.py [--check | --fix | --staged]", file=sys.stderr)
        return 2

    if mode_staged and not should_run_staged():
        return 0  # no relevant files staged; pass silently
    # In --staged mode: auto-fix is implicit (count is derivable, no race-loss risk);
    # missing/orphan rows are warned but not blocked (CWE/sev/case is human work).
    if mode_staged:
        mode_fix = True

    if not INDEX.is_file():
        print(f"error: {INDEX} not found", file=sys.stderr)
        return 2

    text = INDEX.read_text(encoding="utf-8")
    disk = disk_patterns()
    indexed = indexed_patterns(text)
    on_disk_count = len(disk)

    # Find current count line — capture only the number group for surgical replace
    m = COUNT_RE.search(text)
    cur_count = int(m.group(2)) if m else None

    issues = []
    fixed_lines = []

    if cur_count != on_disk_count:
        if mode_fix:
            new_text = COUNT_RE.sub(
                lambda mo: f"{mo.group(1)}{on_disk_count}{mo.group(3)}",
                text,
                count=1,
            )
            INDEX.write_text(new_text, encoding="utf-8")
            fixed_lines.append(f"[fixed] count {cur_count} → {on_disk_count}")
        else:
            issues.append(f"count drift: header says {cur_count}, disk has {on_disk_count} patterns")

    missing = disk - indexed
    orphan = indexed - disk

    if missing:
        issues.append(f"{len(missing)} pattern(s) on disk but NOT in index:")
        for p in sorted(missing):
            issues.append(f"  • [[{p}]]")

    if orphan:
        issues.append(f"{len(orphan)} pattern(s) in index but NOT on disk (typo / deleted?):")
        for p in sorted(orphan):
            issues.append(f"  • [[{p}]]")

    if fixed_lines:
        # If the script auto-fixed the index during a pre-commit run, restage so
        # the fix lands in this commit instead of dirtying the tree afterwards.
        if mode_staged:
            try:
                subprocess.run(["git", "add", str(INDEX)], cwd=ROOT, check=False)
            except Exception:
                pass
        print("\n".join(fixed_lines))

    if issues:
        # --check: block (CI / manual gate). --staged: warn, don't block. --fix: report.
        stream = sys.stderr if mode_check else sys.stdout
        print("\n".join(issues), file=stream)
        return 1 if mode_check else 0

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
