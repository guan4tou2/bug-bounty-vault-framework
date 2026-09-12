#!/usr/bin/env python3
"""asg.py — the single authority for a target's Attack Surface Graph.

Converges the two things that both called themselves "ASG":
  1. the hand-maintained Markdown YAML-schema file (read by surface_graph_lib), and
  2. the hunt event ledger (hunt_loop).
into ONE machine state (the event ledger) plus read-only projections.

Three responsibilities, one place:
  * RESOLVER — the canonical, single source of every per-target ASG path. Fixes the
    filename-contract split (`Attack Surface Graph.md` vs the contract
    `Attack Surface Graph - <target>.md`): all code addresses the ASG through here.
  * append_event() — the SOLE write interface. Resolves the ledger, takes the
    single-writer lock (hunt_lock), appends one event, guard-saves, releases. Nothing
    else should write the ledger directly.
  * project_markdown() / write_snapshot() — one-way projections FROM the ledger: a
    generated block inside the Markdown ASG (preserving the operator's own content)
    and a JSON snapshot for the Obsidian/Dataview dashboard.

Non-goal here: force-migrating existing YAML-schema instances or rewiring every
caller — those ride on this seam next. Existing Markdown stays readable; new machine
state flows through append_event.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

sys_path_hint = Path(__file__).resolve().parent
import sys
if str(sys_path_hint) not in sys.path:
    sys.path.insert(0, str(sys_path_hint))

from hunt_loop import HuntLoop
from hunt_lock import acquire, release, guarded_save

TARGETS_DIRNAME = "01 - Targets"
GEN_START = "<!-- ASG:GENERATED:START -->"
GEN_END = "<!-- ASG:GENERATED:END -->"


# ── RESOLVER (the single source of ASG paths) ───────────────────────────────
def vault_root() -> Path:
    return Path(__file__).resolve().parents[1]


def target_dir(target: str | Path) -> Path:
    """Accept a target NAME or any path under it and return the canonical target
    directory (the immediate child of `01 - Targets/`), validated (no traversal)."""
    root = (vault_root() / TARGETS_DIRNAME).resolve()
    p = Path(target)
    if not (p.is_absolute() or TARGETS_DIRNAME in p.parts):
        return (root / p.name).resolve()          # bare target name
    cand = p.resolve()
    if root not in cand.parents:
        raise ValueError(f"target {target!r} does not resolve under {TARGETS_DIRNAME}/")
    while cand.parent != root:                     # climb to the target dir
        cand = cand.parent
    return cand


def _basename(target: str | Path) -> str:
    return target_dir(target).name


def state_dir(target: str | Path) -> Path:
    return target_dir(target) / ".state"


def ledger_path(target: str | Path) -> Path:
    """The AUTHORITY: the append-only event ledger for this target."""
    return state_dir(target) / "asg-events.jsonl"


def snapshot_path(target: str | Path) -> Path:
    return state_dir(target) / "asg-snapshot.json"


def markdown_path(target: str | Path) -> Path:
    """The human-readable PROJECTION. Canonical name = the contract name
    (`Attack Surface Graph - <target>.md`), never `Attack Surface Graph.md`."""
    return target_dir(target) / f"Attack Surface Graph - {_basename(target)}.md"


# ── SOLE WRITER ─────────────────────────────────────────────────────────────
def append_events(target: str | Path, events: list[tuple[str, dict]], *,
                  owner: Optional[str] = None) -> None:
    """Append a batch of events under ONE lock acquisition (atomic save). The
    single write path for the ledger — one-off writers use append_event()."""
    led = ledger_path(target)
    led.parent.mkdir(parents=True, exist_ok=True)
    owner = owner or os.environ.get("CLAUDE_MODEL", "asg")
    token = acquire(led, owner)
    try:
        loop = HuntLoop.load(led)
        for kind, data in events:
            loop.append(kind, **data)
        guarded_save(loop, led, token)
    finally:
        release(led, token)


def append_event(target: str | Path, kind: str, *, owner: Optional[str] = None,
                 **data) -> None:
    """The ONLY way to write a single ASG state event. Resolves the ledger, takes
    the single-writer lock, appends, guard-saves, releases. Raises
    hunt_lock.ConcurrentWriter if another live writer holds the ledger."""
    append_events(target, [(kind, data)], owner=owner)


# ── MIGRATION: existing YAML-schema Markdown ASG -> ledger events ────────────
def migrate_yaml_to_ledger(target: str | Path) -> dict:
    """Best-effort, IDEMPOTENT import of a hand-maintained YAML-schema ASG onto the
    ledger, so the ledger becomes the authority while the Markdown stays readable.

    Faithful mapping (not lossless): capability_state(confirmed) -> a confirmed
    verdict carrying evidence `migrated:<source>` (the old model's confirmed = 已成功
    利用, so it keeps the evidence invariant, transparently labelled); nodes ->
    surfaces; findings(validated) -> confirmed hypotheses; dead edges -> dead_ends.
    Re-running with unchanged Markdown is a no-op (content digest guard)."""
    import hashlib
    from surface_graph_lib import load_graph, _real_nodes, node_identifier

    md = markdown_path(target)
    if not md.exists():
        return {"migrated": 0, "reason": "no Markdown ASG to migrate"}
    graph = load_graph(str(md))
    if not graph:
        return {"migrated": 0, "reason": "no YAML block in Markdown ASG"}
    # digest the PARSED YAML source, not the whole file — so projecting a generated
    # block into the Markdown later does not change it and break idempotency.
    digest = hashlib.sha256(json.dumps(graph, sort_keys=True, default=str).encode()).hexdigest()
    led = ledger_path(target)
    prior = HuntLoop.load(led) if led.exists() else HuntLoop([])
    if any(e.get("kind") == "migration" and e.get("digest") == digest for e in prior.events):
        return {"migrated": 0, "reason": "already migrated (same content)"}

    events: list[tuple[str, dict]] = [("migration", {"source": "yaml", "digest": digest})]
    for n in _real_nodes(graph):
        events.append(("surface", {"node_id": str(node_identifier(n)), "untested": True}))
    for cap in graph.get("capability_state", []) or []:
        if isinstance(cap, dict) and cap.get("state") == "confirmed" and cap.get("cap"):
            c = str(cap["cap"]); hid = f"migrated:{c}"
            events.append(("hypothesis", {"hyp_id": hid, "requires": []}))
            events.append(("verdict", {"hyp_id": hid, "verdict": "confirmed",
                                        "evidence_ref": f"migrated:{cap.get('source', 'yaml')}",
                                        "provides": [c]}))
    for f in graph.get("findings", []) or []:
        fid = isinstance(f, dict) and f.get("id")
        if not fid:
            continue
        hid = f"finding:{fid}"
        events.append(("hypothesis", {"hyp_id": hid, "requires": list(f.get("requires", []) or [])}))
        if f.get("status") == "validated":
            events.append(("verdict", {"hyp_id": hid, "verdict": "confirmed",
                                        "evidence_ref": str(fid),
                                        "provides": list(f.get("provides", []) or [])}))
    for e in graph.get("edges", []) or []:
        if isinstance(e, dict) and e.get("status") == "dead":
            hid = f"edge:{e.get('src')}->{e.get('dst')}"
            events.append(("dead_end", {"hyp_id": hid, "cause": "refuted",
                                        "reason": e.get("reason", ""),
                                        "reopen_when": "a new capability / variant"}))
    append_events(target, events)
    return {"migrated": len(events) - 1, "digest": digest}


# ── PROJECTIONS (one-way, from the ledger) ──────────────────────────────────
def _summary(target: str | Path) -> dict:
    """Materialize the capsule + resume view once, for both projections."""
    from hunt_session import resume_brief, dead_paths
    loop = HuntLoop.load(ledger_path(target))
    cap = loop.capsule()
    brief = resume_brief(loop)
    return {"loop": loop, "cap": cap, "brief": brief, "dead_paths": dead_paths(loop)}


def write_snapshot(target: str | Path) -> Path:
    """Frontmatter/Dataview-friendly JSON snapshot of current state."""
    s = _summary(target); cap = s["cap"]; brief = s["brief"]
    snap = {
        "target": _basename(target),
        "run_state": brief["run_state"],
        "event_cursor": cap["event_cursor"],
        "capabilities": cap["capabilities"],
        "hypotheses_ready": len(cap["ready_hypotheses"]),
        "hypotheses_blocked": len(cap["blocked_hypotheses"]),
        "disputed": len(cap["disputed"]),
        "dead_paths": len(s["dead_paths"]),
        "untested_surface": len(cap["untested_surface"]),
        "next_action": brief["next_action"],
    }
    p = snapshot_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def _render_generated(target: str | Path) -> str:
    s = _summary(target); cap = s["cap"]; brief = s["brief"]
    def block(title, items):
        body = "\n".join(f"- {i}" for i in items) if items else "- —"
        return f"### {title}\n{body}"
    dead = [f"{d['hyp_id']} ({d.get('cause', '?')}) — reopen: {d.get('reopen_when', '?')}"
            for d in s["dead_paths"]]
    return "\n\n".join([
        "_generated from `.state/asg-events.jsonl` — do not edit inside this block; "
        "write below in Operator Notes_",
        f"### Current Frontier\n- run_state: **{brief['run_state']}**  (events: {cap['event_cursor']})\n"
        f"- next: {brief['next_action']}",
        block("Capabilities (CG)", cap["capabilities"]),
        block("Work Queue (DAG) — ready", cap["ready_hypotheses"]),
        block("Blocked", cap["blocked_hypotheses"]),
        block("Disputed", cap["disputed"]),
        block("Dead Paths (don't re-tread; see reopen)", dead),
    ])


def project_markdown(target: str | Path) -> Path:
    """Render the generated block into the Markdown ASG, preserving everything
    outside the ASG:GENERATED markers (the operator's own content). Creates the
    file with an Operator Notes section if absent."""
    generated = f"{GEN_START}\n{_render_generated(target)}\n{GEN_END}"
    md = markdown_path(target)
    if md.exists():
        txt = md.read_text(encoding="utf-8")
        if GEN_START in txt and GEN_END in txt:
            txt = re.sub(re.escape(GEN_START) + r".*?" + re.escape(GEN_END),
                         lambda _m: generated, txt, count=1, flags=re.DOTALL)
        else:
            # operator file with no generated block yet: append, never overwrite
            txt = txt.rstrip() + "\n\n" + generated + "\n"
        md.write_text(txt, encoding="utf-8")
    else:
        fm = (f"---\nfileClass: AttackSurfaceGraph\ntarget: {_basename(target)}\n"
              f"generated_from: .state/asg-events.jsonl\n---\n\n")
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(f"{fm}# Attack Surface Graph - {_basename(target)}\n\n"
                      f"{generated}\n\n## Operator Notes\n\n", encoding="utf-8")
    return md


def project_all(target: str | Path) -> dict:
    """Refresh every projection from the ledger."""
    return {"markdown": str(project_markdown(target)), "snapshot": str(write_snapshot(target))}


def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="ASG single-authority resolver + projections.")
    ap.add_argument("action", choices=["paths", "project", "snapshot", "migrate"])
    ap.add_argument("target")
    a = ap.parse_args(argv)
    if a.action == "paths":
        print(json.dumps({"target_dir": str(target_dir(a.target)),
                          "ledger": str(ledger_path(a.target)),
                          "markdown": str(markdown_path(a.target)),
                          "snapshot": str(snapshot_path(a.target))}, ensure_ascii=False, indent=2))
    elif a.action == "project":
        print(json.dumps(project_all(a.target), ensure_ascii=False, indent=2))
    elif a.action == "snapshot":
        print(str(write_snapshot(a.target)))
    elif a.action == "migrate":
        print(json.dumps(migrate_yaml_to_ledger(a.target), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
