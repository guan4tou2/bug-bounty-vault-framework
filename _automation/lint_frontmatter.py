#!/usr/bin/env python3
"""Vault frontmatter lint — fileClass + mandatory fields per template schema.

Used as pre-commit hook (see _automation/install_hook.sh) to reject commits
that introduce Findings / Attempts / Submissions / Recon notes missing required
frontmatter. Templates live in 07 - Templates/.

Usage:
  python3 lint_frontmatter.py [<file> ...]      # lint specific files
  python3 lint_frontmatter.py --staged          # lint all staged .md (pre-commit mode)
  python3 lint_frontmatter.py --all             # full scan of 01 - Targets/

Exit 0 = clean, exit 1 = violations found (printed to stderr).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

VAULT_ROOT = Path(__file__).resolve().parent.parent  # repo root = vault root

# Schemas: { dir_pattern: (kind_label, required_fields, enums) }
# enums maps field → list of allowed values (membership check); enums[field] == None means non-empty only
ENUM_SEVERITY = ["P1", "P2", "P3", "P4", "P5"]
ENUM_VERIFICATION_LEVEL = ["A", "B", "C", "D"]
ENUM_GRADE = ["A", "B", "C", "D"]
ENUM_VERIFIED_EVIDENCE = ["live", "source_code", "static", "theoretical"]
# Source of truth: 10 - Meta/fileClasses/Finding.md (metadata-menu dropdown values).
ENUM_FINDING_STATUS = ["discovered", "verified", "ready", "submitted", "duplicate", "na", "accepted", "fixed", "on_hold", "killed", "withdrawn"]
ENUM_RISK = ["critical", "high", "medium", "low", "info"]
ENUM_ATTEMPT_RESULT = ["exploitable", "not_exploitable", "inconclusive", "blocked", "parked"]
ENUM_ATTEMPT_REASON = ["prerequisite_unmet", "waf_blocked", "no_session", "not_in_scope", "duplicate_likely", "other"]
# Source of truth: 10 - Meta/fileClasses/Submission.md
ENUM_SUBMISSION_STATUS = ["ready", "submitted", "triaged", "duplicate", "na", "accepted", "fixed", "withdrawn", "needs_revalidation", "superseded"]
# Source of truth: 10 - Meta/fileClasses/Form.md
ENUM_FORM_STATUS = ["ready", "submitted", "withdrawn", "duplicate", "na", "needs_revalidation", "superseded"]
ENUM_RECON_STATUS = ["wip", "complete", "interrupted"]
TIME_RE = re.compile(r"^\d{2}:\d{2}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

SCHEMAS = {
    "Findings": {
        "kind": "Finding",
        "fileclass_field": ("fileClass", "Finding"),
        "required": ["target", "finding_id", "severity", "verification_level", "verified_evidence", "status", "discovered_date", "discovered_time"],
        "enums": {
            "severity": ENUM_SEVERITY,
            "verification_level": ENUM_VERIFICATION_LEVEL,
            "verified_evidence": ENUM_VERIFIED_EVIDENCE,
            "status": ENUM_FINDING_STATUS,
            "risk": ENUM_RISK,
            "grade": ENUM_GRADE,
        },
        "regex": {"discovered_time": TIME_RE, "discovered_date": DATE_RE, "last_verified": DATE_RE},
        "wikilink_fields": ["target", "pattern", "related_pattern"],
    },
    "Attempts": {
        "kind": "Attempt",
        "fileclass_field": ("fileClass", "Attempt"),
        "required": ["target", "attempt_date", "attempt_time", "result", "result_reason"],
        "enums": {
            "result": ENUM_ATTEMPT_RESULT,
            "result_reason": ENUM_ATTEMPT_REASON,
        },
        "regex": {"attempt_time": TIME_RE, "attempt_date": DATE_RE},
        "wikilink_fields": ["target"],
    },
    "Submissions": {
        "kind": "Submission",
        "fileclass_field": ("type", "submission"),
        "required": ["fileClass", "target", "platform", "severity", "status"],
        "enums": {
            "fileClass": ["Submission", "Form"],
            "severity": ENUM_SEVERITY,
            "status": ENUM_SUBMISSION_STATUS,
        },
        "regex": {},
        "wikilink_fields": ["target"],
    },
    "Recon": {
        "kind": "Recon",
        "fileclass_field": ("fileClass", "Recon"),
        "required": ["target", "session_date", "session_time_start", "status"],
        "enums": {"status": ENUM_RECON_STATUS},
        "regex": {"session_date": DATE_RE, "session_time_start": TIME_RE},
        "wikilink_fields": ["target"],
    },
}

# Matches [[Note Name]] or [[Note Name|alias]] or [[Note Name#heading]].
WIKILINK_RE = re.compile(r"\[\[([^\]|#]+?)(?:[#|][^\]]*)?\]\]")

# Cached set of known note stems (lazy-init on first wikilink check).
_known_notes: set[str] | None = None


def known_notes() -> set[str]:
    global _known_notes
    if _known_notes is None:
        skip = {"_automation", "kb-index-out", ".obsidian", ".trash"}
        _known_notes = {
            p.stem
            for p in VAULT_ROOT.rglob("*.md")
            if not any(s in p.parts for s in skip)
        }
    return _known_notes

# Files exempt from lint (templates, indices, etc.)
EXEMPT_NAMES = {"_index.md", "_MOC.md", "_INDEX.md"}
EXEMPT_PREFIXES = ("Template -",)


def parse_frontmatter(text: str) -> dict | None:
    """Minimal YAML frontmatter parser — returns None if no frontmatter."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end < 0:
        return None
    body = text[4:end]
    fm: dict[str, str] = {}
    for line in body.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("  ", "\t", "-")):
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        if val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        fm[key] = val
    return fm


def detect_kind(rel_path: Path) -> str | None:
    """Infer schema kind from path. Returns dir name in SCHEMAS or None."""
    parts = rel_path.parts
    # Path under 01 - Targets/<target>/{Findings,Attempts,Submissions,Recon}/...
    if "01 - Targets" in parts or "Targets" in parts:
        for i, p in enumerate(parts):
            if p in SCHEMAS:
                return p
    return None


def is_exempt(rel_path: Path) -> bool:
    name = rel_path.name
    if name in EXEMPT_NAMES:
        return True
    return any(name.startswith(p) for p in EXEMPT_PREFIXES)


def lint_file(path: Path) -> list[str]:
    """Return list of error strings; empty list = clean."""
    rel = path.relative_to(VAULT_ROOT) if path.is_absolute() else path
    if is_exempt(rel):
        return []
    kind = detect_kind(rel)
    if kind is None:
        return []  # not under a schema-controlled directory
    schema = SCHEMAS[kind]
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [f"{rel}: file not found"]
    fm = parse_frontmatter(text)
    if fm is None:
        return [f"{rel}: missing YAML frontmatter (--- ... ---)"]

    errors: list[str] = []
    # fileClass / type check
    fc_field, fc_value = schema["fileclass_field"]
    if fm.get(fc_field, "") != fc_value:
        errors.append(f"{rel}: {fc_field} must be '{fc_value}', got '{fm.get(fc_field, '<missing>')}'")
    # required fields non-empty
    for field in schema["required"]:
        v = fm.get(field, "").strip()
        if not v or v in ("[[]]", '""', "''", "[]"):
            errors.append(f"{rel}: required field '{field}' is empty")
    # Build per-file enum map — Submissions schema dispatches status enum by
    # the file's `fileClass:` (Submission vs Form have different value sets).
    file_enums = dict(schema["enums"])
    if kind == "Submissions" and fm.get("fileClass", "") == "Form":
        file_enums["status"] = ENUM_FORM_STATUS
    # enums
    for field, allowed in file_enums.items():
        v = fm.get(field, "").strip()
        if v and v not in allowed:
            # tolerate template placeholder format like "P1 | P2 | P3"
            if "|" in v:
                errors.append(f"{rel}: '{field}' still has template placeholder '{v}' — pick one of {allowed}")
            else:
                errors.append(f"{rel}: '{field}' must be one of {allowed}, got '{v}'")
    # regex
    for field, rx in schema["regex"].items():
        v = fm.get(field, "").strip()
        if v and not rx.match(v):
            errors.append(f"{rel}: '{field}' format invalid (got '{v}')")
    # wikilink resolution — flags dead [[Note]] links in target / pattern fields
    for field in schema.get("wikilink_fields", []):
        v = fm.get(field, "").strip()
        if not v or v in ("null", "~"):
            continue
        links = WIKILINK_RE.findall(v)
        if not links:
            # Field has a value but no [[wikilink]] — flag only if value looks like
            # it should be a link (i.e. contains a hyphen-prefixed type marker).
            if v.startswith(("Target -", "Pattern -")):
                errors.append(f"{rel}: '{field}' value '{v}' should be a [[wikilink]]")
            continue
        notes = known_notes()
        for link in links:
            name = link.strip()
            if name not in notes:
                errors.append(f"{rel}: '{field}' wikilink [[{name}]] does not resolve to any note")
    return errors


def staged_md_files() -> list[Path]:
    """Return staged .md files (Added or Modified) under 01 - Targets/."""
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=AM"],
            cwd=VAULT_ROOT,
            text=True,
        )
    except subprocess.CalledProcessError:
        return []
    return [VAULT_ROOT / line for line in out.splitlines() if line.endswith(".md") and ("01 - Targets" in line or "Targets/" in line)]


def all_target_md_files() -> list[Path]:
    targets_dir = VAULT_ROOT / "01 - Targets"
    if not targets_dir.exists():
        return []
    return list(targets_dir.rglob("*.md"))


def check_duplicate_finding_ids(files: list[Path]) -> list[str]:
    """Cross-file rule: finding_id must be unique across the vault.

    Returns error strings (one per offending ID). Empty list when clean.
    Only enforced on a full scan (--all or --staged with all Findings); when
    linting a single file we don't have enough context to detect duplicates.
    """
    # Only look at Findings under 01 - Targets/<t>/Findings/
    finding_files = [
        f for f in files
        if f.is_file() and "Findings" in f.parts and f.name.startswith("Finding -")
    ]
    if len(finding_files) < 2:
        return []
    id_to_paths: dict[str, list[Path]] = {}
    for f in finding_files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        fm = parse_frontmatter(text)
        if not fm:
            continue
        fid = fm.get("finding_id", "").strip()
        if not fid or "|" in fid:  # skip empty or template placeholder
            continue
        id_to_paths.setdefault(fid, []).append(f)
    errors: list[str] = []
    for fid, paths in sorted(id_to_paths.items()):
        if len(paths) > 1:
            rel_paths = [str(p.relative_to(VAULT_ROOT) if p.is_absolute() else p) for p in paths]
            errors.append(
                f"DUPLICATE finding_id '{fid}' used by {len(paths)} files:\n  - "
                + "\n  - ".join(rel_paths)
            )
    return errors


USAGE = """usage: lint_frontmatter.py [--staged | --all | <file.md> ...]

  --staged   lint all staged .md files (pre-commit mode)
  --all      lint every target .md file in the vault
  <file.md>  lint the given .md files
  -h, --help show this help
"""


def main(argv: list[str]) -> int:
    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return 0

    known_flags = {"--staged", "--all"}
    unknown = [a for a in argv if a.startswith("-") and a not in known_flags]
    if unknown:
        print(f"error: unknown argument(s): {' '.join(unknown)}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    if "--staged" in argv:
        files = staged_md_files()
    elif "--all" in argv:
        files = all_target_md_files()
    else:
        files = [Path(a) for a in argv if a.endswith(".md")]
        positional = [a for a in argv if not a.startswith("-")]
        if positional and not files:
            print(f"error: positional args must be .md files: {' '.join(positional)}\n", file=sys.stderr)
            print(USAGE, file=sys.stderr)
            return 2

    if not files:
        return 0

    all_errors: list[str] = []
    for f in files:
        all_errors.extend(lint_file(f))

    # Cross-file rule: duplicate finding_id detection.
    # Always run on --all; on --staged only if multiple Findings are staged.
    if "--all" in argv or "--staged" in argv:
        # For --staged, expand to full Finding set so we catch dup against unchanged
        # files in the vault. For --all the files list already includes everything.
        scan_set = files if "--all" in argv else all_target_md_files()
        all_errors.extend(check_duplicate_finding_ids(scan_set))

    if all_errors:
        print("\n".join(all_errors), file=sys.stderr)
        print(f"\n{len(all_errors)} frontmatter violation(s). Fix before commit, or amend with `git commit --no-verify` (not recommended).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
