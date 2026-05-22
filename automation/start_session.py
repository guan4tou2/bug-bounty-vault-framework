#!/usr/bin/env python3
"""Minimal session start: claim scope + print handoff brief.

Public-safe equivalent of claim.sh + session_start_brief.sh.
Works standalone without the full automation suite.

Usage:
    python3 automation/start_session.py <scope> [--owner NAME] [--eta-minutes N]
    python3 automation/start_session.py gitlab/oauth --eta-minutes=60

See docs/session-lifecycle.md for the full protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_DIR = ROOT / "automation" / "active_sessions"
EXPIRED_DIR = ACTIVE_DIR / "_expired"


def safe_scope(scope: str) -> str:
    return scope.replace("/", "--")


def lock_path(scope: str) -> Path:
    return ACTIVE_DIR / f"{safe_scope(scope)}.lock"


def load_lock(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def conflicts_with(scope: str) -> list[str]:
    """Return list of active scopes that conflict with the requested scope."""
    conflicts = []
    for lock_file in ACTIVE_DIR.glob("*.lock"):
        data = load_lock(lock_file)
        if not data:
            continue
        existing = data["scope"]
        # Exact match, prefix of existing, or existing is prefix of new
        if (existing == scope
                or scope.startswith(existing + "/")
                or existing.startswith(scope + "/")):
            owner = data.get("owner", "?")
            claimed = data.get("claimed_at", "?")
            conflicts.append(f"  {existing} (owner={owner}, claimed={claimed})")
    return conflicts


def claim(scope: str, owner: str, eta_minutes: int) -> bool:
    """Attempt to claim a scope lock. Returns True on success."""
    ACTIVE_DIR.mkdir(parents=True, exist_ok=True)
    EXPIRED_DIR.mkdir(parents=True, exist_ok=True)

    conflicts = conflicts_with(scope)
    if conflicts:
        print(f"BLOCKED: scope '{scope}' conflicts with active locks:")
        for c in conflicts:
            print(c)
        print("\nUse --force to override (not implemented in minimal version).")
        return False

    lp = lock_path(scope)
    if lp.exists():
        print(f"BLOCKED: lock already exists: {lp.name}")
        return False

    now = datetime.now(timezone.utc)
    lock_data = {
        "session_id": uuid.uuid4().hex[:16],
        "owner": owner,
        "scope": scope,
        "target": scope.split("/")[0],
        "claimed_at": now.isoformat(),
        "last_heartbeat": now.isoformat(),
        "expected_release": (now + timedelta(minutes=eta_minutes)).isoformat(),
        "host": os.uname().nodename,
    }
    lp.write_text(json.dumps(lock_data, indent=2) + "\n")
    print(f"CLAIMED: {scope} (owner={owner}, eta={eta_minutes}m)")
    print(f"  Lock: {lp}")
    print(f"  Session ID: {lock_data['session_id']}")
    return True


def print_brief(target: str) -> None:
    """Print a minimal handoff brief from workspace files."""
    # Try to find workspace root
    workspace_root = None
    for candidate in [
        ROOT / "workspace" / "workshop" / target,
        ROOT.parent / ".vault-workspace" / "workshop" / target,
    ]:
        if candidate.is_dir():
            workspace_root = candidate
            break

    if not workspace_root:
        print(f"\n  No workspace found for '{target}'. Run init_target.sh first.")
        return

    print(f"\n--- Handoff Brief: {target} ---")

    # HANDOFF.md
    handoff = workspace_root / "HANDOFF.md"
    if handoff.exists():
        lines = handoff.read_text().splitlines()
        # Extract "What I Was Doing" and "Immediate Next Step" sections
        in_section = False
        section_name = ""
        for line in lines:
            if line.startswith("## ") and any(k in line for k in ["在做什麼", "Was Doing", "下一步", "Next Step", "阻塞", "Block"]):
                in_section = True
                section_name = line
                print(f"\n{line}")
                continue
            if in_section and line.startswith("## "):
                in_section = False
                continue
            if in_section and line.strip():
                print(f"  {line.strip()}")
    else:
        print("  HANDOFF.md: missing")

    # FINDINGS_QUICK_REF.md
    qref = workspace_root / "FINDINGS_QUICK_REF.md"
    if qref.exists():
        lines = [l for l in qref.read_text().splitlines() if l.strip() and not l.startswith("#") and not l.startswith(">")]
        count = len([l for l in lines if l.startswith("|") and "---" not in l]) - 1  # minus header
        print(f"\n  Existing findings: {max(0, count)}")
    else:
        print("  FINDINGS_QUICK_REF.md: missing")

    # RECON_DB.md status
    recon = workspace_root / "RECON_DB.md"
    if recon.exists():
        import time
        mtime = recon.stat().st_mtime
        age_hours = int((time.time() - mtime) / 3600)
        print(f"  RECON_DB.md last modified: {age_hours}h ago")
    else:
        print("  RECON_DB.md: missing")


def main() -> int:
    parser = argparse.ArgumentParser(description="Start a bug bounty session: claim scope + print brief")
    parser.add_argument("scope", help="Scope to claim (e.g., 'gitlab', 'gitlab/oauth', '_meta')")
    parser.add_argument("--owner", default=os.environ.get("CLAUDE_MODEL", "claude"), help="Session owner name")
    parser.add_argument("--eta-minutes", type=int, default=120, help="Expected session duration in minutes")
    args = parser.parse_args()

    if not claim(args.scope, args.owner, args.eta_minutes):
        return 1

    target = args.scope.split("/")[0]
    if target != "_meta":
        print_brief(target)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
