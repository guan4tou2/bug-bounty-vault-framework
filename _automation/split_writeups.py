#!/usr/bin/env python3
"""split_writeups.py — split External Writeups - 2026 Collection.md into per-writeup files.

Race-elimination rationale: this monolith is 1424 lines and growing — every
Batch 2/3/N harvest appends to the bottom. Splitting eliminates the write
hotspot the same way split_lessons.py did for Lessons Learned.

Heuristic boundaries:
  Writeup heading = `## <ID>. <title>` where ID is `1-9..NN` or `B1-B11`.
  Non-writeup `##` sections (e.g. `## Cross-writeup observations`, `## Batch 2 ...`) are
  kept in the MOC head as "between-writeup commentary" if they appear among
  writeups, and as MOC content if before/after the writeup block.

Output:
  09 - Knowledge Base/Writeups/WU-NNN-<slug>.md   (numeric IDs zero-padded)
  09 - Knowledge Base/Writeups/WU-BNNN-<slug>.md  (B-prefixed deep reads)

The original Collection.md becomes a MOC: head (TOC + intro) + Dataview
listing + literal directory.

Modes: --dry-run / --apply.
"""
from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "09 - Knowledge Base"
SRC = KB / "External Writeups - 2026 Collection.md"
OUT_DIR = KB / "Writeups"

# Match writeup heading: ## 1. Title  or  ## B3. Title
WRITEUP_HEAD = re.compile(r"^##\s+([A-Z]?\d+)\.\s+(.+?)\s*$", re.MULTILINE)


def slugify(text: str, max_len: int = 50) -> str:
    text = unicodedata.normalize("NFKC", text)
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif 0x4e00 <= ord(ch) <= 0x9fff:
            out.append(ch)
        elif ch in " -_/:":
            out.append("-")
    slug = "".join(out)
    slug = re.sub(r"-+", "-", slug).strip("-")
    if len(slug) > max_len:
        slug = slug[:max_len].rstrip("-")
    return slug or "untitled"


def split(text: str):
    """Return (head, [(id, title, body), ...]).

    Note: between-writeup ## section headers (e.g. `## Cross-writeup observations`) without
    a numeric ID get absorbed into the PRECEDING writeup's body — that's how
    they sit semantically in the source.
    """
    matches = list(WRITEUP_HEAD.finditer(text))
    if not matches:
        return text, []
    head = text[: matches[0].start()]
    writeups = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        wid = m.group(1)
        title = m.group(2).strip()
        body = text[m.end() : end].strip()
        writeups.append((wid, title, body))
    return head, writeups


def writeup_filename(wid: str, title: str) -> str:
    if wid.isdigit():
        nn = f"{int(wid):03d}"
        prefix = "WU"
    else:
        m = re.match(r"^([A-Z]+)(\d+)$", wid)
        if m:
            nn = f"{m.group(1)}{int(m.group(2)):03d}"
            prefix = "WU"
        else:
            nn = wid
            prefix = "WU"
    return f"{prefix}-{nn}-{slugify(title)}.md"


def write_writeup(wid: str, title: str, body: str, apply: bool):
    fn = writeup_filename(wid, title)
    path = OUT_DIR / fn
    fm = (
        "---\n"
        "type: writeup\n"
        f"id: \"{wid}\"\n"
        f"title: \"{title}\"\n"
        "tags:\n  - bb-writeup\n  - external\n"
        "---\n\n"
    )
    content = fm + f"# {wid}. {title}\n\n{body}\n"
    if apply:
        OUT_DIR.mkdir(exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return path


def write_moc(head: str, writeups, apply: bool):
    moc_tail = (
        "\n\n---\n\n"
        "## Individual Writeup Files\n\n"
        "> Since 2026-06-04, each writeup is split into `Writeups/WU-NNN-<slug>.md` (eliminating the monolith write hotspot).\n"
        "> This file becomes a MOC + index; add new writeups under `Writeups/`, do not append to this file anymore.\n\n"
        "```dataview\n"
        "TABLE WITHOUT ID\n"
        "  link(file.link, file.name) AS \"File\",\n"
        "  title AS \"Title\",\n"
        "  file.cday AS \"Created\"\n"
        "FROM \"09 - Knowledge Base/Writeups\"\n"
        "WHERE type = \"writeup\"\n"
        "SORT id ASC\n"
        "```\n\n"
        "## Full Index (literal list)\n\n"
    )
    rows = []
    for wid, title, _ in writeups:
        fn = writeup_filename(wid, title)
        basename = Path(fn).stem
        rows.append(f"- {wid}. [[{basename}|{title}]]")
    content = head.rstrip() + moc_tail + "\n".join(rows) + "\n"
    if apply:
        SRC.write_text(content, encoding="utf-8")
    return content


def main(argv):
    apply = "--apply" in argv
    if not SRC.is_file():
        print(f"error: {SRC} not found", file=sys.stderr)
        return 2
    text = SRC.read_text(encoding="utf-8")
    head, writeups = split(text)
    print(f"head: {len(head)} chars; writeups: {len(writeups)}")
    if not writeups:
        print("nothing to split (file already MOC?)")
        return 0
    print(f"first: {writeups[0][0]}. {writeups[0][1]}")
    print(f"last:  {writeups[-1][0]}. {writeups[-1][1]}")
    names = {}
    for wid, title, _ in writeups:
        fn = writeup_filename(wid, title)
        if fn in names:
            print(f"COLLISION: {fn} for {wid} and {names[fn]}", file=sys.stderr)
        names[fn] = wid
    if not apply:
        print(f"\nDRY RUN — pass --apply to write. Would create {len(writeups)} files.")
        return 0
    for wid, title, body in writeups:
        write_writeup(wid, title, body, apply=True)
    write_moc(head, writeups, apply=True)
    print(f"\nAPPLIED — {len(writeups)} writeups → {OUT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
