#!/usr/bin/env python3
"""round_logger.py — structured JSONL operational round log.

Separates OPERATIONAL records (what the session did, what tools ran, what the
operator decided) from the ASG EVENT LOG (hunt_loop.py, which tracks hypotheses /
verdicts / capabilities — the domain model).

Why separate:
  - ASG events are the truth for capsule projection; round ops are the truth for
    "what did session X actually do and why". Mixing them bloats capsule replay.
  - Round ops are the PRIMARY token-saving lever: a JSONL line is 3-5x smaller
    than the prose paragraph it replaces in RECON_DB Round Log.
  - After auto-compression, `context_brief()` reloads the capsule + last N ops
    to restore 95% of the model's situational awareness — prose cannot do this.

Format: one JSON object per line, always carrying `sid` (session ID) and `ts`.
Fields beyond that are action-specific. The file is append-only; cross-session
queries use `jq 'select(.sid=="abc123")'`.

    from round_logger import RoundLogger
    rl = RoundLogger(target="acme", session_id=loop.session_id)
    rl.log("scan", tool="feroxbuster", target="https://acme.com", result="found=12")
    rl.log("test", endpoint="/api/users", method="GET", status=403, verdict="blocked")
    rl.log("decision", choice="skip_idor", reason="no second account available")

    # after auto-compression, reload context:
    from round_logger import context_brief
    brief = context_brief("acme", session_id=loop.session_id)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import asg
    def _target_dir(target: str) -> Path:
        return asg.target_dir(target)
    def _default_round_log(target: str) -> Path:
        # co-located with the ASG ledger in .state/ — MUST match where hunt_run.py
        # writes it (asg.ledger_path(target).parent / "round_log.jsonl"), else
        # context_brief reads a different file than the run wrote.
        return asg.ledger_path(target).parent / "round_log.jsonl"
    def _default_ledger(target: str) -> Path:
        return asg.ledger_path(target)
except ImportError:
    def _target_dir(target: str) -> Path:
        return Path(target)
    def _default_round_log(target: str) -> Path:
        return Path(target) / "round_log.jsonl"
    def _default_ledger(target: str) -> Path:
        return Path(target) / "asg-events.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RoundLogger:
    """Append-only JSONL operational log, one file per target."""

    def __init__(self, target: str, session_id: str,
                 path: Optional[Path] = None):
        self.session_id = session_id
        self.target = target
        if path is not None:
            self.path = Path(path)
        else:
            self.path = _default_round_log(target)

    def log(self, action: str, **data) -> dict:
        entry = {"sid": self.session_id, "ts": _now(), "action": action}
        entry.update(data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def scan(self, tool: str, target_url: str, found: int = 0,
             **extra) -> dict:
        return self.log("scan", tool=tool, target_url=target_url,
                        found=found, **extra)

    def test(self, endpoint: str, method: str = "GET",
             status: Optional[int] = None, verdict: str = "",
             **extra) -> dict:
        return self.log("test", endpoint=endpoint, method=method,
                        status=status, verdict=verdict, **extra)

    def decision(self, choice: str, reason: str = "", **extra) -> dict:
        return self.log("decision", choice=choice, reason=reason, **extra)

    def set_mode(self, mode: str, reason: str = "") -> dict:
        """Record the current interaction mode (ALIGNMENT / EXECUTION).

        ALIGNMENT = user has a specific mental model still being pinned down;
        confirm structure before acting. EXECUTION = goal is clear, act then
        report. Recording it lets context_brief() restore the MODE (not just the
        facts) after auto-compression — the compaction summary + "resume directly"
        prompt otherwise silently flips a stopped session back into EXECUTION.
        """
        return self.log("mode", mode=mode, reason=reason)

    def current_mode(self, sid: Optional[str] = None) -> Optional[dict]:
        """The last recorded interaction mode for this session, or None."""
        entries = self.read_session(sid) if (sid or self.session_id) else self.read_all()
        for e in reversed(entries):
            if e.get("action") == "mode":
                return {"mode": e.get("mode"), "reason": e.get("reason", ""),
                        "ts": e.get("ts")}
        return None

    def error(self, tool: str, message: str, **extra) -> dict:
        return self.log("error", tool=tool, message=message[:500], **extra)

    def handoff(self, reason: str, capsule: Optional[dict] = None,
                **extra) -> dict:
        return self.log("handoff", reason=reason, capsule=capsule, **extra)

    # ── read ops ───────────────────────────────────────────────────────────
    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def read_session(self, sid: Optional[str] = None) -> list[dict]:
        sid = sid or self.session_id
        return [e for e in self.read_all() if e.get("sid") == sid]

    def recent(self, n: int = 10) -> list[dict]:
        all_entries = self.read_all()
        return all_entries[-n:]

    def session_recent(self, n: int = 10,
                       sid: Optional[str] = None) -> list[dict]:
        entries = self.read_session(sid)
        return entries[-n:]

    def summary(self) -> dict:
        entries = self.read_all()
        sids = set(e.get("sid", "") for e in entries)
        actions = {}
        for e in entries:
            a = e.get("action", "unknown")
            actions[a] = actions.get(a, 0) + 1
        verdicts = {}
        for e in entries:
            v = e.get("verdict")
            if v:
                verdicts[v] = verdicts.get(v, 0) + 1
        return {
            "total_entries": len(entries),
            "sessions": len(sids),
            "actions": actions,
            "verdicts": verdicts,
        }


def context_brief(target: str, session_id: Optional[str] = None,
                  n_recent: int = 5,
                  ledger_path: Optional[Path] = None,
                  round_log_path: Optional[Path] = None) -> dict:
    """Post-compression context reload: capsule + last N round ops.

    Returns a dict suitable for injecting into the conversation after
    auto-compression wipes hunting state. Gives the model:
      - Current ASG capsule (what's confirmed/ready/blocked/disputed)
      - Last N operational actions (what was just tried)
      - Session stats (how many actions, how many confirmed)

    Usage after compression:
        brief = context_brief("acme", session_id="abc123")
        # inject brief into the prompt / handoff doc
    """
    from hunt_loop import HuntLoop

    lp = ledger_path
    if lp is None:
        lp = _default_ledger(target)
    capsule = {}
    if lp.exists():
        loop = HuntLoop.load(lp)
        capsule = loop.capsule()

    rl = RoundLogger(target, session_id=session_id or "",
                     path=round_log_path)
    if session_id:
        recent = rl.session_recent(n_recent, session_id)
    else:
        recent = rl.recent(n_recent)

    stats = rl.summary()
    mode = rl.current_mode(session_id)

    return {
        "target": target,
        "session_id": session_id,
        "interaction_mode": mode,   # None until a mode is recorded; restores the
        #                             MODE after compaction, not just the facts.
        "capsule": capsule,
        "recent_ops": recent,
        "stats": stats,
    }
