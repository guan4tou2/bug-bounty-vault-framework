#!/usr/bin/env python3
"""check_docx_package.py — check the file you SHIP, not its source.

Why
---
Report-quality gates typically read the FORM markdown. But the vendor receives a .docx
generated from it, and the markdown->docx step is unwatched. Two defects that pass the
markdown gates but ship in the docx:

  1. STALE: the docx was generated before a later markdown edit, so deleted text is still
     inside the Word file. The markdown is clean; the docx is not. (mtime catches it.)
  2. FILENAME LEAK: a field references an embedded screenshot's filename. The image is
     embedded, so that file is NOT attached — the reader hunts for an attachment that
     does not exist. python-docx also writes the filename into the image object name
     (<pic:cNvPr name=…>), invisible in the body but visible in Word's alt-text pane and
     in PDF accessibility metadata.

Common shape: a control exists, but not on the path the work actually takes. The checks
below read the deliverable itself.

Language-specific phrase lists (explanatory padding, unattached-file promises) default to
English and can be overridden with env vars for a non-English vendor form:
  BB_DOCX_PADDING="in other words|simply put|..."    (pipe-separated)
  BB_DOCX_PROMISES="see attachment|enclosed herewith|..."
  BB_DOCX_SCREENSHOT_KW="screenshot|screen capture|poc image"

Usage:
    python3 automation/check_docx_package.py <docx dir> [--forms <FORM md dir>]
    python3 automation/check_docx_package.py --target <target>
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import zipfile
from pathlib import Path

VAULT = Path(__file__).resolve().parent.parent

# Filenames that should not appear in the body. If an image is embedded, that file is not
# attached, so naming it points at an attachment that does not exist.
#
# Must not be preceded by `/` or `.` — otherwise it matches the vendor's own URL paths
# inside reproduce steps (e.g. https://host/assets/api.json), which are evidence to copy
# verbatim, not an attachment reference.
FILENAME_RE = re.compile(
    r"(?<![/.\w])([A-Za-z0-9][A-Za-z0-9._-]*\.(?:png|jpe?g|gif|txt|har|pdf))", re.I)

# Finding-ID shape, e.g. ABC-123 / DEF-0421. Used to map a docx to its source FORM md
# regardless of filename prefix (vendor forms prefix the docx name in their own language).
ID_RE = re.compile(r"[A-Z]{2,6}-\d{3,4}")


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    v = os.environ.get(name)
    return tuple(s for s in v.split("|") if s) if v else default


# Explanatory padding — a report states the finding, it does not lecture around it.
EXPLAINY = _env_list("BB_DOCX_PADDING", (
    "in other words", "simply put", "it should be noted", "it is worth mentioning",
    "for the avoidance of doubt", "to clarify", "needless to say"))

# Promising something that is not actually attached.
PROMISE = _env_list("BB_DOCX_PROMISES", (
    "see attachment", "see attached", "attached separately", "provided separately",
    "enclosed herewith", "as attached"))

SCREENSHOT_KW = _env_list("BB_DOCX_SCREENSHOT_KW", (
    "screenshot", "screen capture", "poc image"))


def docx_text(p: Path) -> str:
    """Visible text of document.xml: strip tags, newline between paragraphs."""
    with zipfile.ZipFile(p) as z:
        xml = z.read("word/document.xml").decode("utf-8", "replace")
    xml = re.sub(r"</w:p>", "\n", xml)
    return re.sub(r"<[^>]+>", "", xml)


def docx_raw(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        return z.read("word/document.xml").decode("utf-8", "replace")


def image_count(p: Path) -> int:
    with zipfile.ZipFile(p) as z:
        return sum(1 for n in z.namelist() if n.startswith("word/media/"))


def source_md(docx: Path, forms_dir: Path) -> Path | None:
    """Map a docx to its source FORM markdown by the finding ID both share.

    Prefix-agnostic: a vendor form prefixes the docx name in its own language, so match on
    the ID (ABC-123) rather than the full stem.
    """
    m = ID_RE.search(docx.stem)
    if not m:
        return None
    fid = m.group(0)
    for cand in forms_dir.glob("FORM - *.md"):
        if fid in cand.stem:
            return cand
    return None


SENT = ("submitted", "withdrawn", "triaged", "resolved", "duplicate", "na")


def already_sent(md: Path | None) -> bool:
    """A sent batch can't be changed; re-checking it only makes the gate permanently red
    (then the whole gate gets ignored). Judge by FORM status, not folder name."""
    if md is None or not md.is_file():
        return False
    head = md.read_text(encoding="utf-8", errors="replace")[:600]
    m = re.search(r'^status:\s*"?([a-z_-]+)"?', head, re.M)
    return bool(m and m.group(1) in SENT)


def check(docx: Path, forms_dir: Path | None) -> list[str]:
    bad: list[str] = []
    text = docx_text(docx)
    raw = docx_raw(docx)
    low = text.lower()

    # 1) Older than its source — markdown edited, docx not regenerated
    if forms_dir:
        md = source_md(docx, forms_dir)
        if md is None:
            bad.append("no matching FORM markdown found — cannot tell if stale")
        elif md.stat().st_mtime > docx.stat().st_mtime:
            bad.append("older than its source md — regenerate it")

    # 2) Filename in body or in image metadata
    for m in dict.fromkeys(FILENAME_RE.findall(text)):
        bad.append(f"filename `{m}` in body — the image is embedded, that file is not attached")
    body_names = set(FILENAME_RE.findall(text))
    for m in dict.fromkeys(FILENAME_RE.findall(raw)):
        if m not in body_names:
            bad.append(f"filename `{m}` left in image metadata "
                       "(<pic:cNvPr name=…>, visible in Word's alt-text pane)")

    # 3) Unattached-file promise
    for kw in PROMISE:
        if kw in low:
            bad.append(f"promises something not attached: {kw!r}")

    # 4) Explanatory padding
    for kw in EXPLAINY:
        if kw in low:
            bad.append(f"explanatory padding: {kw!r}")

    # 5) Screenshot field declared but no image embedded
    if any(kw in low for kw in SCREENSHOT_KW) and image_count(docx) == 0:
        bad.append("a screenshot field is present but word/media/ is empty — no image embedded")

    return bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("docx_dir", type=Path, nargs="?")
    ap.add_argument("--target", help="scan all *-docx batch dirs under this target")
    ap.add_argument("--forms", type=Path,
                    help="dir holding the FORM markdown (default: docx dir's parent)")
    a = ap.parse_args()

    # A positional arg that is not an existing dir is treated as a target name, so this
    # works both standalone and when run_checks passes $TARGET positionally.
    target = a.target
    if a.docx_dir and not a.docx_dir.is_dir():
        target = target or str(a.docx_dir)
        a.docx_dir = None
    if not target and not a.docx_dir:
        print("no target/docx dir given, skipping")
        return 0

    dirs: list[Path] = []
    if target:
        base = VAULT / "01 - Targets" / target / "Submissions" / "Forms"
        if not base.is_dir():
            print(f"no Submissions/Forms for target {target}, skipping")
            return 0
        # Sent batches are not re-checked — unchangeable, would make the gate permanently red.
        dirs = [d for d in sorted(base.glob("*docx*"))
                if d.is_dir() and "submitted" not in d.name]
    elif a.docx_dir:
        dirs = [a.docx_dir]

    files, total, sent = 0, 0, 0
    for d in dirs:
        forms_dir = a.forms or d.parent
        forms_dir = forms_dir if forms_dir.is_dir() else None
        for f in sorted(d.glob("*.docx")):
            if already_sent(source_md(f, forms_dir) if forms_dir else None):
                sent += 1
                continue
            files += 1
            bad = check(f, forms_dir)
            if bad:
                total += 1
                print(f"FAIL {f.name}")
                for b in bad:
                    print(f"     {b}")
    tail = f" ({sent} already sent, not re-checked)" if sent else ""
    if not files:
        print(f"no docx to check{tail}")
        return 0
    print(f"-- {files} checked, {total} with issues{tail} --")
    if total:
        print("   You ship the docx, not the md. A green md does not mean this is sendable.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
