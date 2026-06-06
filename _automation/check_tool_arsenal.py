#!/usr/bin/env python3
"""check_tool_arsenal.py — drift report for Tool - Arsenal Index.

Unlike Pattern Index (where the count line is auto-derivable), Tool Arsenal
mismatches are semantically meaningful and need a human decision:

  • on disk but NOT in index → either add to index OR mark as legacy/internal
  • in index but NOT on disk → either create the note OR clean up the dangling link

Modes:
  --report     : print drift to stdout. exit 0 always (informational).
  --check      : same, but exit 1 if drift exists (use in CI / pre-commit).
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "09 - Knowledge Base"
TOOLS_DIR = ROOT / "05 - Tools"
INDEX = KB / "Tool - Arsenal Index.md"
WIKILINK_RE = re.compile(r"\[\[(Tool - [^\]|#]+?)(?:[#|][^\]]*)?\]\]")


def disk_tools() -> set[str]:
    """Scan both `09 - Knowledge Base/` and `05 - Tools/` for Tool - *.md
    files. Obsidian wikilinks resolve by basename across folders, so the
    Tool Arsenal Index can reference tools that live in either canonical
    location."""
    found = set()
    for d in (KB, TOOLS_DIR):
        if d.is_dir():
            for p in d.glob("Tool - *.md"):
                if p.stem != "Tool - Arsenal Index":
                    found.add(p.stem)
    return found


def indexed_tools(text: str) -> set[str]:
    return {m.group(1).strip() for m in WIKILINK_RE.finditer(text)}


def main(argv):
    mode_check = "--check" in argv
    if not INDEX.is_file():
        print(f"error: {INDEX} not found", file=sys.stderr)
        return 2
    text = INDEX.read_text(encoding="utf-8")
    disk = disk_tools()
    indexed = indexed_tools(text)
    missing = sorted(disk - indexed)
    orphan = sorted(indexed - disk)

    if not missing and not orphan:
        print(f"✓ Tool Arsenal Index in sync — {len(disk)} tools indexed.")
        return 0

    print(f"Tool Arsenal drift report:")
    print(f"  on disk : {len(disk)}")
    print(f"  indexed : {len(indexed)}")
    print()
    if missing:
        print(f"⚠ {len(missing)} tool note(s) on disk but NOT in index:")
        for t in missing:
            print(f"   • [[{t}]]")
        print()
    if orphan:
        print(f"⚠ {len(orphan)} reference(s) in index but NO note on disk:")
        for t in orphan:
            print(f"   • [[{t}]] → create note OR remove link")
        print()
    return 1 if mode_check else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
