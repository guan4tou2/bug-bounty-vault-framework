#!/usr/bin/env python3
"""Check an adopted private vault scaffold without rejecting runtime workspace files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REQUIRED_FILES = [
    "AGENTS.md",
    "AGENTS_QUICK.md",
    "README.md",
    "docs/architecture.md",
    "docs/workflow.md",
    "docs/session-lifecycle.md",
    "docs/preflight-checks.md",
    "docs/evidence-model.md",
    "templates/target.md",
    "templates/recon-note.md",
    "templates/finding.md",
    "templates/review-note.md",
    "templates/handoff.md",
    "templates/operation-log.md",
    "bbflow/scope.example.yaml",
    "scripts/start_session.py",
    "scripts/end_session.py",
    "scripts/new_note.py",
]

REQUIRED_DIRS = [
    ".obsidian",
    "agents",
    "bbflow",
    "docs",
    "hooks",
    "prompts",
    "scripts",
    "skills",
    "templates",
    "workspace",
    "workspace/workshop",
    "workspace/tools",
    "workspace/reports",
    "workspace/logs",
    "targets",
    "wiki",
    "dashboard",
]


def check_path(root: Path) -> list[str]:
    errors: list[str] = []

    for rel in REQUIRED_FILES:
        if not (root / rel).is_file():
            errors.append(f"missing required file: {rel}")

    for rel in REQUIRED_DIRS:
        if not (root / rel).is_dir():
            errors.append(f"missing required directory: {rel}")

    workspace_ignore = root / "workspace" / ".gitignore"
    if not workspace_ignore.is_file():
        errors.append("missing workspace/.gitignore")
    elif "*" not in workspace_ignore.read_text(encoding="utf-8", errors="ignore"):
        errors.append("workspace/.gitignore should ignore runtime contents")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=".", help="Path to the adopted private vault root")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"[fail] path does not exist: {root}", file=sys.stderr)
        return 2

    errors = check_path(root)
    if errors:
        for error in errors:
            print(f"[fail] {error}", file=sys.stderr)
        return 1

    print(f"[ok] private vault check passed: {root}")
    print("[ok] runtime files under workspace/ are allowed in this private check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

