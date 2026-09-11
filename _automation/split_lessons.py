#!/usr/bin/env python3
"""split_lessons.py — split Lessons Learned.md into per-lesson files.

Race-elimination rationale: Lessons Learned.md is 3188 lines / 141 entries
— a hot file that every parallel writer touches. Splitting → each lesson
becomes its own file `Lessons/LL-NNN-<slug>.md`; parallel writers no longer
collide. The top-level `Lessons Learned.md` is rewritten as a MOC that:
- preserves the manually-curated class-based index tables (head section)
- adds a Dataview query rendering all individual lessons sorted by id desc

Run modes:
  --dry-run   : print what would be written, no changes.
  --apply     : do the split; original Lessons Learned.md becomes the MOC.

The script is idempotent on re-runs: it parses lessons from whichever source
file has them (the monolith on first run, the MOC sees nothing on subsequent).
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "09 - Knowledge Base"
SRC = KB / "Lessons Learned.md"
OUT_DIR = KB / "Lessons"

# Match lesson header: `### Lesson #NN. <title>` (NN may be 1-3 digits, optionally W prefix)
LESSON_HEAD = re.compile(r"^###\s+Lesson\s+#([A-Z]?\d+)\.\s*(.+?)\s*$", re.MULTILINE)


def slugify(text: str, max_len: int = 50) -> str:
    """Make a filesystem-friendly slug from Chinese/English mixed title."""
    # Normalize, drop control chars
    text = unicodedata.normalize("NFKC", text)
    # Replace anything that's not [a-z0-9-] or CJK with dash
    out = []
    for ch in text.lower():
        if ch.isalnum():
            out.append(ch)
        elif 0x4e00 <= ord(ch) <= 0x9fff:  # CJK unified ideograph
            out.append(ch)
        elif ch in " -_/:":
            out.append("-")
        # drop others
    slug = "".join(out)
    # collapse multiple dashes
    slug = re.sub(r"-+", "-", slug).strip("-")
    if len(slug) > max_len:
        # truncate at boundary
        slug = slug[:max_len].rstrip("-")
    return slug or "untitled"


def split(text: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (head_text_before_first_lesson, [(id, title, body), ...])."""
    matches = list(LESSON_HEAD.finditer(text))
    if not matches:
        return text, []
    head = text[: matches[0].start()]
    lessons = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        lid = m.group(1)
        title = m.group(2).strip()
        body = text[m.end() : end].strip()
        lessons.append((lid, title, body))
    return head, lessons


def lesson_filename(lid: str, title: str) -> str:
    """LL-NNN-<slug>.md (NNN zero-padded if numeric, else preserve prefix)."""
    if lid.isdigit():
        nn = f"{int(lid):03d}"
    else:
        # 'W13' → keep as is, but pad number portion
        m = re.match(r"^([A-Z]+)(\d+)$", lid)
        if m:
            nn = f"{m.group(1)}{int(m.group(2)):03d}"
        else:
            nn = lid
    return f"LL-{nn}-{slugify(title)}.md"


def write_lesson(lid: str, title: str, body: str, apply: bool) -> Path:
    fn = lesson_filename(lid, title)
    path = OUT_DIR / fn
    # Build frontmatter
    fm = (
        "---\n"
        "type: lesson\n"
        f"id: \"{lid}\"\n"
        f"title: \"{title}\"\n"
        "tags:\n  - bb-lesson\n"
        "---\n\n"
    )
    content = fm + f"# Lesson #{lid}. {title}\n\n{body}\n"
    if apply:
        OUT_DIR.mkdir(exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return path


def write_moc(head: str, lessons: list[tuple[str, str, str]], apply: bool) -> str:
    """Rewrite Lessons Learned.md as a MOC with the head index + dataview."""
    # The head section already contains the frontmatter + class-based index.
    # Append a directory + dataview query.
    moc_tail = (
        "\n\n---\n\n"
        "## Individual Lesson Files\n\n"
        "> Since 2026-06-04, each lesson is split into `Lessons/LL-NNN-<slug>.md` (eliminating the parallel-session write hotspot).\n"
        "> This file becomes a MOC + index; add new lessons under `Lessons/`, do not append to this file anymore.\n\n"
        "```dataview\n"
        "TABLE WITHOUT ID\n"
        "  link(file.link, replace(file.name, \"LL-\", \"#\")) AS \"Lesson\",\n"
        "  title AS \"Title\",\n"
        "  file.cday AS \"Created\"\n"
        "FROM \"09 - Knowledge Base/Lessons\"\n"
        "WHERE type = \"lesson\"\n"
        "SORT id DESC\n"
        "```\n\n"
        "## Full Index (literal list)\n\n"
    )
    rows = []
    for lid, title, _ in lessons:
        fn = lesson_filename(lid, title)
        basename = Path(fn).stem
        rows.append(f"- #{lid} [[{basename}|{title}]]")
    content = head.rstrip() + moc_tail + "\n".join(rows) + "\n"
    if apply:
        SRC.write_text(content, encoding="utf-8")
    return content


def main(argv: list[str]) -> int:
    apply = "--apply" in argv
    dry = "--dry-run" in argv or not apply
    if not SRC.is_file():
        print(f"error: {SRC} not found", file=sys.stderr)
        return 2
    text = SRC.read_text(encoding="utf-8")
    head, lessons = split(text)
    print(f"head: {len(head)} chars; lessons: {len(lessons)}")
    if not lessons:
        print("nothing to split (file already MOC?)")
        return 0
    # Sanity: show first/last
    print(f"first: #{lessons[0][0]} {lessons[0][1]}")
    print(f"last:  #{lessons[-1][0]} {lessons[-1][1]}")
    # Detect filename collisions
    names: dict[str, str] = {}
    for lid, title, _ in lessons:
        fn = lesson_filename(lid, title)
        if fn in names:
            print(f"COLLISION: {fn} for #{lid} and #{names[fn]}", file=sys.stderr)
        names[fn] = lid
    if dry and not apply:
        print(f"\nDRY RUN — pass --apply to write. Would create {len(lessons)} files.")
        return 0
    # Write all lesson files
    for lid, title, body in lessons:
        write_lesson(lid, title, body, apply=True)
    # Rewrite MOC
    write_moc(head, lessons, apply=True)
    print(f"\nAPPLIED — {len(lessons)} lessons → {OUT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
