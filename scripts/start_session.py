#!/usr/bin/env python3
"""Start a public-safe framework session in the ignored workspace scaffold."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from validate_scope_file import validate_scope


ROOT = Path(__file__).resolve().parents[1]


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return cleaned or "untitled"


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def render_template(path: Path, replacements: dict[str, str]) -> str:
    text = path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        text = text.replace(f"<{key}>", value)
    return text


def validate_scope_if_provided(scope_file: str | None) -> int:
    if not scope_file:
        return 0

    path = ROOT / scope_file
    if not path.exists():
        print(f"[fail] scope file not found: {scope_file}", file=sys.stderr)
        return 2

    errors = validate_scope(path)
    if errors:
        for error in errors:
            print(f"[fail] {error}", file=sys.stderr)
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--summary", default="new framework session")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    scope_status = validate_scope_if_provided(args.scope_file)
    if scope_status != 0:
        return scope_status

    safe_target = slug(args.target)
    session_id = f"{safe_target}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    now = timestamp()
    target_dir = ROOT / "workspace" / "workshop" / safe_target
    target_dir.mkdir(parents=True, exist_ok=True)

    state_path = target_dir / "SESSION_STATE.json"
    if state_path.exists() and not args.force:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("status") == "active":
            print(f"[fail] active session already exists for {safe_target}; pass --force to replace", file=sys.stderr)
            return 1

    replacements = {
        "target": args.target,
        "program": args.program,
        "scope_file": args.scope_file or "not provided",
        "session_id": session_id,
        "status": "active",
        "timestamp": now,
        "summary": args.summary,
        "knowledge_capture": "pending",
    }

    handoff = render_template(ROOT / "templates" / "handoff.md", replacements)
    operation_log = render_template(ROOT / "templates" / "operation-log.md", replacements)

    (target_dir / "HANDOFF.md").write_text(handoff, encoding="utf-8")
    (target_dir / "OPERATION_LOG.md").write_text(operation_log, encoding="utf-8")
    state_path.write_text(
        json.dumps(
            {
                "target": args.target,
                "program": args.program,
                "scope_file": args.scope_file,
                "session_id": session_id,
                "status": "active",
                "started_at": now,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"[ok] session started: {safe_target}")
    print(f"[ok] workspace: {target_dir.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

