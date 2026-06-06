#!/usr/bin/env python3
"""staging_status.py — render a TRIAGE STATUS for _staging/session-learning/.

Categories:
  ✅ verified  : status: verified — ready to promote into KB / canonical.
  🟡 proposed  : status: proposed — needs human review.
  ⚠️ no_status : frontmatter missing status: line — author should add.

Writes _staging/session-learning/STATUS.md (machine-rendered, overwrite each run).
Run from anywhere; resolves vault root from script location.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGING = ROOT / "_staging" / "session-learning"
PROPOSED = STAGING / "proposed"
OUT = STAGING / "STATUS.md"

STATUS_RE = re.compile(r"^status:\s*(\S+)", re.MULTILINE)
TITLE_RE = re.compile(r"^title:\s*\"?([^\"\n]+)\"?", re.MULTILINE)


def scan(dirs):
    rows = []
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.md")):
            text = p.read_text(encoding="utf-8", errors="replace")
            m_status = STATUS_RE.search(text)
            m_title = TITLE_RE.search(text)
            status = m_status.group(1).strip() if m_status else None
            title = m_title.group(1).strip() if m_title else p.stem
            rows.append((p, status, title))
    return rows


def render(rows):
    by_cat = {"verified": [], "proposed": [], "no_status": []}
    for p, status, title in rows:
        cat = status if status in ("verified", "proposed") else "no_status"
        by_cat[cat].append((p, title))

    lines = [
        "---",
        "type: reference",
        "category: staging-triage",
        "tags: [staging, triage, machine-generated]",
        "---",
        "",
        "# Staging — Session-Learning Triage Status",
        "",
        "> 自動產生。重跑 `python3 _automation/staging_status.py` 更新。",
        "> 三類:`verified` 可促進 KB、`proposed` 待 review、`no_status` 缺欄位。",
        "",
        f"**Totals**: verified={len(by_cat['verified'])}  proposed={len(by_cat['proposed'])}  no_status={len(by_cat['no_status'])}",
        "",
    ]
    for cat, emoji, blurb in [
        ("verified", "✅", "Ready to promote into KB (move out of staging)."),
        ("proposed", "🟡", "Pending human triage — read, decide promote/drop/edit."),
        ("no_status", "⚠️", "Missing `status:` field — author should set proposed/verified."),
    ]:
        lines.append(f"## {emoji} {cat} ({len(by_cat[cat])})")
        lines.append("")
        lines.append(f"> {blurb}")
        lines.append("")
        for p, title in by_cat[cat]:
            rel = p.relative_to(ROOT)
            lines.append(f"- `{rel}` — {title}")
        lines.append("")
    return "\n".join(lines)


def main(argv):
    rows = scan([PROPOSED])
    out = render(rows)
    if "--print" in argv:
        print(out)
        return 0
    OUT.write_text(out, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(rows)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
