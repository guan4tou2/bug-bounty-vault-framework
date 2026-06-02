#!/usr/bin/env python3
"""Minimal vault health check.

Public-safe equivalent of audit_workspace.sh (vault subset).
Checks structural integrity without requiring the full automation suite.

Usage:
    python3 automation/check_vault.py
    python3 automation/check_vault.py --target gitlab
    python3 automation/check_vault.py --fix     # auto-fix what's possible

See docs/session-lifecycle.md for context.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT / "01 - Targets"
KB_DIR = ROOT / "09 - Knowledge Base"

# ANSI colors
G = "\033[0;32m"
R = "\033[0;31m"
Y = "\033[0;33m"
B = "\033[0;34m"
N = "\033[0m"

# Required subdirectories per target
REQUIRED_SUBDIRS = [
    "Findings", "Submissions", "Submissions/Forms",
    "Attempts", "Recon", "Services", "Credentials",
    "Notes", "Attack Chains", "Screenshots",
]

# Valid KB name prefixes (extend as your vault evolves)
KB_PREFIXES = [
    "Pattern -", "Pattern Index", "Playbook -", "Tool -",
    "Resource -", "Skill -", "Reference Card -", "Checklist -",
    "Lesson -", "Lessons Learned", "Lint Checklist",
    "Knowledge Base Index", "Wiki Schema",
    "Dataview -", "External Writeups",
    "AGENTS", "CLAUDE", "CODEX", "GEMINI",
    "index", "log", "kb-index-out",
]


def check_target(target_dir: Path, fix: bool = False) -> tuple[int, int]:
    """Check a single target directory. Returns (failures, warnings)."""
    failures = 0
    warnings = 0
    name = target_dir.name

    # Target page must exist
    target_page = target_dir / f"Target - {name}.md"
    if not target_page.exists():
        print(f"  {R}[FAIL]{N} {name}: missing Target - {name}.md")
        failures += 1
    else:
        # Check frontmatter has required fields
        text = target_page.read_text()
        if "---" not in text:
            print(f"  {Y}[WARN]{N} {name}: Target page has no frontmatter")
            warnings += 1

    # Required subdirectories
    for subdir in REQUIRED_SUBDIRS:
        d = target_dir / subdir
        if not d.exists():
            if fix:
                d.mkdir(parents=True, exist_ok=True)
                (d / ".gitkeep").touch()
                print(f"  {G}[FIX]{N}  {name}: created {subdir}/")
            else:
                print(f"  {Y}[WARN]{N} {name}: missing {subdir}/")
                warnings += 1

    # Findings should have consistent naming
    findings_dir = target_dir / "Findings"
    if findings_dir.exists():
        for f in findings_dir.glob("*.md"):
            if f.name == ".gitkeep":
                continue
            if not f.name.startswith("Finding -"):
                print(f"  {Y}[WARN]{N} {name}: non-standard Finding name: {f.name}")
                warnings += 1

    # Submissions should have consistent naming
    submissions_dir = target_dir / "Submissions"
    if submissions_dir.exists():
        for f in submissions_dir.glob("*.md"):
            if f.name == ".gitkeep":
                continue
            if not f.name.startswith("Submission -"):
                print(f"  {Y}[WARN]{N} {name}: non-standard Submission name: {f.name}")
                warnings += 1

    return failures, warnings


def check_kb() -> tuple[int, int]:
    """Check Knowledge Base naming conventions."""
    failures = 0
    warnings = 0

    if not KB_DIR.exists():
        print(f"  {Y}[WARN]{N} 09 - Knowledge Base/ not found")
        return 0, 1

    for f in KB_DIR.glob("*.md"):
        name = f.name
        if not any(name.startswith(prefix) for prefix in KB_PREFIXES):
            # Allow files that don't match if they're clearly structural
            if name in ("README.md", "_INDEX.md"):
                continue
            print(f"  {Y}[WARN]{N} KB naming: {name} doesn't match known prefix")
            warnings += 1

    # No Target pages should live in KB
    for f in KB_DIR.glob("Target -*.md"):
        print(f"  {R}[FAIL]{N} Target page in KB (should be in 01 - Targets/): {f.name}")
        failures += 1

    return failures, warnings


def check_active_sessions() -> None:
    """Report active session locks."""
    active_dir = ROOT / "automation" / "active_sessions"
    if not active_dir.exists():
        return

    locks = list(active_dir.glob("*.lock"))
    if locks:
        print(f"\n{B}Active sessions:{N}")
        for lock_file in locks:
            try:
                import json
                data = json.loads(lock_file.read_text())
                scope = data.get("scope", "?")
                owner = data.get("owner", "?")
                claimed = data.get("claimed_at", "?")[:16]
                print(f"  {scope} (owner={owner}, claimed={claimed})")
            except Exception:
                print(f"  {lock_file.name} (unreadable)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check vault structural health")
    parser.add_argument("--target", help="Check a specific target only")
    parser.add_argument("--fix", action="store_true", help="Auto-fix missing directories")
    args = parser.parse_args()

    total_failures = 0
    total_warnings = 0
    target_count = 0

    print(f"\n{'='*50}")
    print(f"  Vault Health Check")
    print(f"{'='*50}\n")

    # Target checks
    if args.target:
        target_dir = TARGETS_DIR / args.target
        if not target_dir.is_dir():
            print(f"{R}[FAIL]{N} Target directory not found: {args.target}")
            return 1
        f, w = check_target(target_dir, fix=args.fix)
        total_failures += f
        total_warnings += w
        target_count = 1
    else:
        if TARGETS_DIR.exists():
            for target_dir in sorted(TARGETS_DIR.iterdir()):
                if not target_dir.is_dir() or target_dir.name.startswith(("_", ".")):
                    continue
                f, w = check_target(target_dir, fix=args.fix)
                total_failures += f
                total_warnings += w
                target_count += 1

    # KB checks
    print(f"\n{B}Knowledge Base:{N}")
    f, w = check_kb()
    total_failures += f
    total_warnings += w

    # Active sessions
    check_active_sessions()

    # Summary
    print(f"\n{'='*50}")
    print(f"  Targets checked: {target_count}")
    if total_failures:
        print(f"  {R}{total_failures} failure(s), {total_warnings} warning(s){N}")
    elif total_warnings:
        print(f"  {G}0 failures{N}, {Y}{total_warnings} warning(s){N}")
    else:
        print(f"  {G}All checks passed{N}")
    print(f"{'='*50}\n")

    return 1 if total_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
