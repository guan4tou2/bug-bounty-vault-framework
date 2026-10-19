#!/usr/bin/env python3
"""Read-only next-action projection over the ASG ledger.

Usage: python3 automation/next_work.py <target> [--limit 3]
Research tasks stay in the existing ledger; this view is never a second backlog.
"""
from __future__ import annotations

import argparse
import json

from hunt_loop import HuntLoop
from hunt_session import inflight_actions


def compute(target, *, limit=3):
    import asg
    from asg_research import project

    loop = HuntLoop.load(asg.ledger_path(target))
    cap = loop.capsule()
    graph = project(loop.events, loop.base_path, cap=cap)
    summary = graph["summary"]
    nodes = {node["ref"]: node for node in graph["nodes"]}
    items = []

    def add(kind, ref, action):
        items.append({"kind": kind, "ref": ref, "action": action})

    for ref in inflight_actions(loop):
        add("reconcile", ref, "Inspect the interrupted action's evidence before any rerun")
    for ref in cap["disputed"]:
        add("dispute", ref, "Resolve the conflicting verdicts with a discriminating control")
    for ref in summary["running_intents"]:
        add("research-resume", ref, "Resume recorded work and inspect existing outputs: " + nodes[ref]["text"])
    for ref in sorted(summary["ready_intents"], key=lambda r: (-nodes[r].get("priority", 5), r)):
        add("research-intent", ref, nodes[ref]["text"])
    bound = {nodes[ref].get("hypothesis", "").removeprefix("hypothesis:")
             for ref in summary["ready_intents"]}
    dead = {event["hyp_id"] for event in loop.events if event.get("type") == "dead_end"}
    for ref in cap["ready_hypotheses"]:
        if ref not in bound and ref not in dead:
            add("hypothesis", ref, "Run the bounded test/control comparison")
    for ref in cap["untested_surface"]:
        add("surface", ref, "Map the surface and register its testable hypotheses")
    for ref in cap["blocked_hypotheses"]:
        add("unblock", ref, "Acquire the missing capability or environment")
    if not summary["running_intents"] and not summary["ready_intents"]:
        for ref in summary["open_goals"]:
            add("goal-review", ref, "Review missing acceptance evidence: " + nodes[ref]["text"])
        for ref in summary["unsettled_intents"]:
            add("research-unblock", ref, "Resolve paused work or missing prerequisites: " + nodes[ref]["text"])
    return {"target": asg.target_dir(target).name, "event_cursor": cap["event_cursor"],
            "items": items[:max(0, limit)]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args(argv)
    print(json.dumps(compute(args.target, limit=args.limit), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
