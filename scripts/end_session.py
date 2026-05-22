#!/usr/bin/env python3
"""Close a public-safe framework session in the ignored workspace scaffold."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-")
    return cleaned or "untitled"


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def append_closeout(operation_log: Path, ended_at: str, summary: str, knowledge_capture: str) -> None:
    with operation_log.open("a", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write("## Closeout\n\n")
        fh.write(f"- Time: {ended_at}\n")
        fh.write(f"- Summary: {summary}\n")
        fh.write(f"- Knowledge Capture: {knowledge_capture}\n")


def close_handoff(handoff_path: Path, ended_at: str, summary: str, knowledge_capture: str) -> None:
    text = handoff_path.read_text(encoding="utf-8")
    text = text.replace("Status: active", "Status: closed")
    text += "\n"
    text += "## Final Closeout\n\n"
    text += "- Status: closed\n"
    text += f"- Ended: {ended_at}\n"
    text += f"- Summary: {summary}\n"
    text += f"- Knowledge Capture: {knowledge_capture}\n"
    handoff_path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--knowledge-capture", default="none")
    args = parser.parse_args(argv)

    safe_target = slug(args.target)
    target_dir = ROOT / "workspace" / "workshop" / safe_target
    state_path = target_dir / "SESSION_STATE.json"
    handoff_path = target_dir / "HANDOFF.md"
    operation_log_path = target_dir / "OPERATION_LOG.md"

    missing = [path for path in (state_path, handoff_path, operation_log_path) if not path.exists()]
    if missing:
        names = ", ".join(path.name for path in missing)
        print(f"[fail] session files missing for {safe_target}: {names}", file=sys.stderr)
        return 1

    state = json.loads(state_path.read_text(encoding="utf-8"))
    ended_at = timestamp()
    state["status"] = "closed"
    state["ended_at"] = ended_at
    state["summary"] = args.summary
    state["knowledge_capture"] = args.knowledge_capture

    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    append_closeout(operation_log_path, ended_at, args.summary, args.knowledge_capture)
    close_handoff(handoff_path, ended_at, args.summary, args.knowledge_capture)

    print(f"[ok] session ended: {safe_target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

