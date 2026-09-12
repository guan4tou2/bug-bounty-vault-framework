#!/usr/bin/env python3
"""hunt_session.py — the entry a Claude session actually calls to RESUME a hunt
and pick the next step. Shares the existing ledger (automation/hunt_loop.py) — it
does NOT create another state store, capsule format, or ledger.

Why this exists: the loop/integration modules are libraries. Without an entry a
session invokes, "resume after compaction / interrupt and continue correctly" is
never exercised. This is that entry.

Usage:
  python3 automation/hunt_session.py resume <ledger.jsonl>   # recovery brief
  python3 automation/hunt_session.py status <ledger.jsonl>   # one-line run_state

`resume` prints the Current-State Capsule a session reads after a compaction or a
takeover: run_state, confirmed capabilities, open/blocked/disputed hypotheses,
untested surface, INFLIGHT (interrupted) actions that must be reconciled before any
re-run, and a single deterministic next_action. It is a projection of the ledger,
not a new source of truth.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hunt_loop import HuntLoop, RunState  # noqa: E402


def inflight_actions(loop: HuntLoop) -> list[str]:
    """Actions started but never finished — an interrupt/compaction landed between
    `action_started` and `action_finished`. These must be reconciled (verify
    whether they actually ran) BEFORE any re-run, so evidence is not lost and an
    unverified action is not blindly repeated."""
    started, finished = {}, set()
    for e in loop.events:
        if e.get("kind") == "action_started":
            started[e["action_id"]] = e
        elif e.get("kind") == "action_finished":
            finished.add(e["action_id"])
    return sorted(a for a in started if a not in finished)


def _objective(loop: HuntLoop) -> str | None:
    for e in loop.events:
        if e.get("kind") == "objective":
            return e.get("text")
    return None


def dead_paths(loop: HuntLoop) -> list[dict]:
    """The scoped dead-end graveyard for the handoff view. autodrive records
    `dead_end` events (record_dead_end) and reads them back INSIDE the loop to
    avoid re-proposing — but a human takeover / a compaction that rebuilds from
    this brief never saw them. Surfacing them here is what stops a takeover from
    re-treading a path already refuted/blocked, while `reopen_when` + `scope`
    keep "dead for role=anon" from being read as "dead for every role"."""
    latest: dict[str, dict] = {}
    for e in loop.events:
        if e.get("kind") == "dead_end":
            latest[e["hyp_id"]] = {
                "hyp_id": e["hyp_id"], "cause": e.get("cause"),
                "scope": e.get("scope"), "reopen_when": e.get("reopen_when"),
            }
    return [latest[k] for k in sorted(latest)]


def next_action(cap: dict, inflight: list[str], run_state: RunState) -> str:
    """One deterministic next step, so a resumed session continues rather than
    re-deciding from scratch. Priority: reconcile interrupts first."""
    if inflight:
        return (f"RECONCILE interrupted action '{inflight[0]}' (check its evidence/output to decide "
                f"if it completed) before running anything else")
    if cap["disputed"]:
        return f"RESOLVE dispute on '{cap['disputed'][0]}' with a discriminating control experiment"
    if cap["ready_hypotheses"]:
        return f"RUN hypothesis '{cap['ready_hypotheses'][0]}' (test action vs control)"
    if cap["untested_surface"]:
        return f"MAP/HYPOTHESISE on untested surface '{cap['untested_surface'][0]}' (replanning; not done)"
    if cap["blocked_hypotheses"]:
        return f"UNBLOCK '{cap['blocked_hypotheses'][0]}' (acquire the missing capability/env)"
    return "COMPLETED — no ready work, no untested surface, nothing disputed/blocked"


def resume_brief(loop: HuntLoop) -> dict:
    cap = loop.capsule()
    inflight = inflight_actions(loop)
    # run_state: a genuine interrupt keeps us in RUNNING-with-work, but the brief
    # surfaces the interrupt explicitly via inflight + next_action.
    run_state = loop.run_state()
    lessons = sorted({e["lesson_id"] for e in loop.events if e.get("kind") == "lesson"})
    # surfaces positively swept clean (probed, uniformly gated, no anomaly). Without
    # this, resume can't tell "checked and clean" from "never checked" — live wms-r1
    # friction #1. These are already excluded from untested_surface.
    swept = sorted({s for e in loop.events if e.get("kind") == "surface_swept"
                    for s in e.get("surfaces", [])})
    return {
        "objective": _objective(loop),
        "run_state": run_state.value,
        "event_cursor": cap["event_cursor"],
        "capabilities": cap["capabilities"],
        "ready_hypotheses": cap["ready_hypotheses"],
        "blocked_hypotheses": cap["blocked_hypotheses"],
        "disputed": cap["disputed"],
        "invalidated_hypotheses": cap.get("invalidated_hypotheses", []),
        "untested_surface": cap["untested_surface"],
        "swept_clean": swept,                  # probed + gated, no anomaly (positive evidence)
        "dead_paths": dead_paths(loop),        # tried + dead (scoped) + when to reopen — don't re-tread
        "inflight_actions": inflight,          # interrupted — reconcile before re-run
        "lessons_available": lessons,
        "next_action": next_action(cap, inflight, run_state),
    }


def _render(brief: dict) -> str:
    dead_labels = [f"{d['hyp_id']}({d['cause']})" for d in brief["dead_paths"]]
    lines = ["── hunt resume brief ──"]
    if brief["objective"]:
        lines.append(f"objective : {brief['objective']}")
    lines += [
        f"run_state : {brief['run_state']}   (events: {brief['event_cursor']})",
        f"caps      : {brief['capabilities'] or '—'}",
        f"ready     : {brief['ready_hypotheses'] or '—'}",
        f"blocked   : {brief['blocked_hypotheses'] or '—'}",
        f"disputed  : {brief['disputed'] or '—'}",
        f"untested  : {brief['untested_surface'] or '—'}",
        f"dead-path : {dead_labels or '—'}  (don't re-tread; see reopen_when)",
        f"INFLIGHT  : {brief['inflight_actions'] or '—'}  (reconcile before re-run)",
        f"lessons   : {brief['lessons_available'] or '—'}",
        "",
        f"NEXT → {brief['next_action']}",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Resume/continue a hunt over the shared ledger")
    p.add_argument("command", choices=["resume", "status"])
    p.add_argument("ledger")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    ledger_exists = Path(args.ledger).exists()
    loop = HuntLoop.load(args.ledger)
    if args.command == "status":
        print(loop.run_state().value)
        return 0
    brief = resume_brief(loop)
    brief["ledger_exists"] = ledger_exists          # distinguish new hunt from a typo'd path
    if args.json:
        print(json.dumps(brief, ensure_ascii=False, indent=2))
    else:
        if not ledger_exists:
            print(f"⚠ ledger not found: {args.ledger} — treating as a NEW empty hunt.")
            print("  If you expected existing state, check the path (typo?).\n")
        print(_render(brief))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
