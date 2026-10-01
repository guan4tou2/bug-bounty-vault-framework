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


def _read_events(ledger: Path) -> list[dict]:
    """Read all events from a JSONL ledger file."""
    if not ledger.exists():
        return []
    events: list[dict] = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events

TARGETS_DIRNAME = "01 - Targets"
GEN_START = "<!-- ASG:GENERATED:START -->"
GEN_END = "<!-- ASG:GENERATED:END -->"

# ── PHASE LOCKING ──────────────────────────────────────────────────────────────
PHASES = ("engage", "osint", "recon", "map", "exploit", "foothold", "report")

PROFILE_CHAINS: dict[str, tuple[str, ...]] = {
    "web":          ("engage", "osint", "recon", "map", "exploit", "foothold", "report"),
    "firmware":     ("engage", "recon", "map", "exploit", "report"),
    "source-audit": ("engage", "recon", "map", "exploit", "report"),
    "engagement":   ("engage", "osint", "recon", "map", "exploit", "foothold", "report"),
}

# ── FINDING STATE MACHINE ──────────────────────────────────────────────────────
FINDING_STATES = ("hypothesis", "tested", "adversary-verified", "confirmed")
FINDING_TRANSITIONS: dict[str, list[str]] = {
    "hypothesis":          ["tested"],
    "tested":              ["adversary-verified", "hypothesis"],
    "adversary-verified":  ["confirmed", "tested"],
    "confirmed":           [],
}

# Mandatory workers that fire when a finding reaches "confirmed".
# Order matters: `verb-matrix` is a PREREQUISITE for chain/expand (see
# complete_worker). It forces the read+write verb matrix (GET + PUT/PATCH/DELETE,
# cross-tenant) to be covered — or explicitly waived with a reason — BEFORE the
# more engaging chain/expand work can be closed. Root cause it fixes: "stopping at
# GET" was enforced only by the recall-triggered idor-coverage skill; this makes
# node-level write-path coverage an automatic gate (surfaces in check_pending_workers
# → blocks submission). Findings rarely carry vuln_class, so verb-matrix is
# required for EVERY confirmed finding and waived per-finding when it does not apply
# (complete-worker <t> <id> verb-matrix "n/a: <why no object/write path>").
MANDATORY_WORKERS = ("verb-matrix", "chain", "expand")


# ── RESOLVER (the single source of ASG paths) ───────────────────────────────
def vault_root() -> Path:
    return Path(__file__).resolve().parents[1]


def target_dir(target: str | Path) -> Path:
    """Accept a target NAME or any path under it and return the canonical target
    directory (the immediate child of `01 - Targets/`), validated (no traversal)."""
    root = (vault_root() / TARGETS_DIRNAME).resolve()
    p = Path(target)
    if len(p.parts) == 1 and not p.is_absolute() and p.parts[0] not in (".", ".."):
        cand = (root / p.parts[0]).resolve()       # bare target name
    else:
        cand = p.resolve()                          # path form
    if cand == root or root not in cand.parents:
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

def has_genesis(target: str | Path) -> dict | None:
    """Return the genesis event if one exists, else None."""
    led = ledger_path(target)
    if not led.exists():
        return None
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "genesis":
            return ev
    return None


# ── PHASE QUERIES ──────────────────────────────────────────────────────────────

def current_phase(target: str | Path) -> str | None:
    """Derive the current phase from the ledger. None if no genesis."""
    led = ledger_path(target)
    if not led.exists():
        return None
    phase = None
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "genesis":
            phase = "engage"
        elif ev.get("type") == "phase":
            phase = ev.get("to")
    return phase


def phase_chain(target: str | Path) -> tuple[str, ...]:
    """Return the phase chain for this target's profile."""
    genesis = has_genesis(target)
    profile = genesis.get("profile", "web") if genesis else "web"
    return PROFILE_CHAINS.get(profile, PHASES)


def advance_phase(target: str | Path, to: str, *, reason: str = "") -> dict:
    """Advance the target to a new phase. Validates ordering within the
    profile's chain. Returns {ok, from, to} or {ok: False, reason}."""
    genesis = has_genesis(target)
    if not genesis:
        return {"ok": False, "reason": "no genesis"}
    cur = current_phase(target)
    chain = phase_chain(target)
    if to not in chain:
        profile = genesis.get("profile", "web")
        return {"ok": False, "reason": f"phase '{to}' not in chain for profile '{profile}'"}
    cur_idx = chain.index(cur) if cur and cur in chain else -1
    to_idx = chain.index(to)
    if to_idx <= cur_idx:
        return {"ok": False, "reason": f"cannot go backward: {cur} -> {to}"}
    # Coverage-before-report gate: entering the report phase with most of the attack
    # surface still untested is the harvest-bias failure mode (find a lot ≠ covered).
    # The number is objective (status()); require a tested-surface floor before report.
    # Strict by default — being blocked in recon is intended; thorough coverage is the
    # point. Override: BB_SKIP_COVERAGE_GATE=1 ; tune: BB_COVERAGE_FLOOR (0..1).
    if to == "report" and os.environ.get("BB_SKIP_COVERAGE_GATE") != "1":
        st = status(target)
        tot = st.get("surfaces_total", 0) or 0
        unt = st.get("surfaces_untested", 0) or 0
        if tot > 0:
            tested_ratio = (tot - unt) / tot
            try:
                floor = float(os.environ.get("BB_COVERAGE_FLOOR", "0.8"))
            except ValueError:
                floor = 0.8
            if tested_ratio < floor:
                return {"ok": False, "reason":
                        f"coverage {tested_ratio:.0%} < {floor:.0%} 門檻"
                        f"（{tot - unt}/{tot} surface 測過）——surface 大多未測，不進 report。"
                        f" 先把 surface 測完並在 ledger 標記（surface 事件 untested=False），"
                        f"或 BB_SKIP_COVERAGE_GATE=1 放行、BB_COVERAGE_FLOOR=<0..1> 調門檻。"}
    append_event(target, "phase", to=to, **{"from": cur}, reason=reason)
    return {"ok": True, "from": cur, "to": to}


def phase_index(target: str | Path) -> int:
    """Return the numeric index of the current phase in the target's chain.
    -1 if no genesis/phase."""
    cur = current_phase(target)
    if cur is None:
        return -1
    chain = phase_chain(target)
    return chain.index(cur) if cur in chain else -1


def phase_allows(target: str | Path, required_phase: str) -> bool:
    """True if the current phase >= required_phase in the chain."""
    cur = current_phase(target)
    if cur is None:
        return False
    chain = phase_chain(target)
    if cur not in chain or required_phase not in chain:
        return True
    return chain.index(cur) >= chain.index(required_phase)


# ── FINDING STATE QUERIES ──────────────────────────────────────────────────────

def finding_state(target: str | Path, finding_id: str) -> str | None:
    """Derive the current state of a finding from ledger events."""
    led = ledger_path(target)
    if not led.exists():
        return None
    state = None
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "finding" and ev.get("finding_id") == finding_id:
            state = "hypothesis"
        elif ev.get("type") == "finding_state" and ev.get("finding_id") == finding_id:
            state = ev.get("to")
    return state


def advance_finding(target: str | Path, finding_id: str, to: str, *,
                    reason: str = "", **data) -> dict:
    """Advance a finding's state. Validates allowed transitions.
    When transitioning to 'confirmed', auto-emits worker_required events
    for each MANDATORY_WORKERS entry."""
    cur = finding_state(target, finding_id)
    if cur is None:
        return {"ok": False, "reason": f"no finding event for {finding_id}"}
    allowed = FINDING_TRANSITIONS.get(cur, [])
    if to not in allowed:
        return {"ok": False, "reason": f"cannot transition {finding_id}: {cur} -> {to} "
                f"(allowed: {allowed})"}
    events: list[tuple[str, dict]] = [
        ("finding_state", {"finding_id": finding_id, "to": to,
                           "from": cur, "reason": reason, **data})
    ]
    if to == "confirmed":
        for worker in MANDATORY_WORKERS:
            events.append(("worker_required", {
                "finding_id": finding_id, "worker": worker,
            }))
    append_events(target, events)
    result: dict = {"ok": True, "finding_id": finding_id, "from": cur, "to": to}
    if to == "confirmed":
        result["workers_queued"] = list(MANDATORY_WORKERS)
    return result


def pending_workers(target: str | Path, finding_id: str | None = None) -> list[dict]:
    """Return worker_required events that have no matching worker_done.
    If finding_id is None, returns all pending workers across all findings."""
    led = ledger_path(target)
    if not led.exists():
        return []
    required: list[dict] = []
    done: set[tuple[str, str]] = set()
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "worker_required":
            required.append(ev)
        elif ev.get("type") == "worker_done":
            done.add((ev.get("finding_id", ""), ev.get("worker", "")))
    pending = [r for r in required
               if (r.get("finding_id", ""), r.get("worker", "")) not in done]
    if finding_id is not None:
        pending = [r for r in pending if r.get("finding_id") == finding_id]
    return pending


def complete_worker(target: str | Path, finding_id: str, worker: str, *,
                    reason: str = "", **data) -> dict:
    """Mark a mandatory worker as done for a finding."""
    if worker not in MANDATORY_WORKERS:
        return {"ok": False, "reason": f"unknown worker: {worker} (valid: {MANDATORY_WORKERS})"}
    cur = finding_state(target, finding_id)
    if cur != "confirmed":
        return {"ok": False, "reason": f"{finding_id} is not confirmed (state: {cur})"}
    # Prerequisite: node-level verb coverage before chaining/expanding. Only applies
    # when verb-matrix was actually required for this finding (older confirmed findings
    # predate it, so they are unaffected).
    if worker in ("chain", "expand"):
        pend = {r.get("worker") for r in pending_workers(target, finding_id)}
        if "verb-matrix" in pend:
            return {"ok": False, "reason":
                    f"verb-matrix 未完成——先測完讀寫全動詞矩陣（GET + PUT/PATCH/DELETE、"
                    f"物件 ID 變體、跨租戶）再 close '{worker}'（別停在 GET）。"
                    f" 不適用就豁免：python3 automation/asg.py complete-worker "
                    f"{_basename(target)} {finding_id} verb-matrix \"n/a: <為何無 object/write path>\""}
    append_event(target, "worker_done", finding_id=finding_id, worker=worker,
                 reason=reason, **data)
    remaining = pending_workers(target, finding_id)
    return {"ok": True, "finding_id": finding_id, "worker": worker,
            "remaining": [r.get("worker") for r in remaining]}


def record_finding(target: str | Path, finding_id: str, **data) -> dict:
    """Record a new finding in the ledger. Idempotent: refuses if already exists."""
    existing = finding_state(target, finding_id)
    if existing is not None:
        return {"ok": False, "reason": f"{finding_id} already in ledger (state: {existing})"}
    append_event(target, "finding", finding_id=finding_id, **data)
    return {"ok": True, "finding_id": finding_id, "state": "hypothesis"}


# ── SOLE WRITER ─────────────────────────────────────────────────────────────
def append_events(target: str | Path, events: list[tuple[str, dict]], *,
                  owner: Optional[str] = None) -> None:
    """Append a batch of events under ONE lock acquisition (atomic save). The
    single write path for the ledger — one-off writers use append_event()."""
    led = ledger_path(target)
    led.parent.mkdir(parents=True, exist_ok=True)
    owner = owner or os.environ.get("CLAUDE_MODEL", "asg")
    token = acquire(led, owner)
    # Events carried no time of their own, so "this verdict is N days old" could not
    # be computed at all — the session brief was asserting a 14-day staleness rule
    # against a number nothing could produce. Stamp new events so that window can
    # eventually be derived from evidence instead of invented. Existing events stay
    # as they are; anything reading `at` must treat it as optional.
    import datetime as _dt
    now = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        loop = HuntLoop.load(led)
        for kind, data in events:
            data.setdefault("at", now)
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
    verdict carrying evidence `migrated:<source>` (the old model's confirmed =
    so it keeps the evidence invariant, transparently labelled); nodes ->
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
    if any(e.get("type") == "migration" and e.get("digest") == digest for e in prior.events):
        return {"migrated": 0, "reason": "already migrated (same content)"}

    existing_ids: set[str] = set()
    for ev in prior.events:
        for key in ("name", "id"):
            if key in ev:
                existing_ids.add(str(ev[key]))

    events: list[tuple[str, dict]] = [("migration", {"source": "yaml", "digest": digest})]
    for n in _real_nodes(graph):
        nid = str(node_identifier(n))
        if nid not in existing_ids:
            events.append(("surface", {"name": nid, "untested": True}))
    for cap in graph.get("capability_state", []) or []:
        if isinstance(cap, dict) and cap.get("cap") and cap.get("state", "confirmed") == "confirmed":
            c = str(cap["cap"]); hid = f"migrated:{c}"
            if hid not in existing_ids:
                events.append(("hypothesis", {"id": hid, "requires": []}))
                events.append(("verdict", {"hypothesis": hid, "status": "confirmed",
                                            "evidence": f"migrated:{cap.get('source', 'yaml')}",
                                            "provides": [c]}))
    for f in graph.get("findings", []) or []:
        fid = isinstance(f, dict) and f.get("id")
        if not fid:
            continue
        hid = f"finding:{fid}"
        if hid not in existing_ids:
            events.append(("hypothesis", {"id": hid, "requires": list(f.get("requires", []) or [])}))
            if f.get("status") == "validated":
                events.append(("verdict", {"hypothesis": hid, "status": "confirmed",
                                            "evidence": str(fid),
                                            "provides": list(f.get("provides", []) or [])}))
    for e in graph.get("edges", []) or []:
        if isinstance(e, dict) and e.get("status") == "dead":
            hid = f"edge:{e.get('src')}->{e.get('dst')}"
            if hid not in existing_ids:
                events.append(("dead_end", {"hyp_id": hid, "cause": "refuted",
                                            "reason": e.get("reason", ""),
                                            "reopen_when": "a new capability / variant"}))
    new_count = len(events) - 1
    if new_count > 0:
        append_events(target, events)
    return {"migrated": new_count, "digest": digest}


# ── PROJECTIONS (one-way, from the ledger) ──────────────────────────────────
def _summary(target: str | Path) -> dict:
    """Materialize the capsule + resume view once, for both projections."""
    from hunt_session import resume_brief, dead_paths
    loop = HuntLoop.load(ledger_path(target))
    cap = loop.capsule()
    brief = resume_brief(loop)
    return {"loop": loop, "cap": cap, "brief": brief, "dead_paths": dead_paths(loop)}


# ── VERDICT CONFIDENCE + CHAIN PROJECTION ─────────────────────────────────
# Verdict confidence levels: how the verdict was obtained
CONFIDENCE_LEVELS = ("theoretical", "static", "dynamic", "reproduced")


def chain_projection(target: str | Path) -> dict:
    """Compute attack chain graph from meta events + capability edges.
    Returns root-cause groups, chain edges, and a confidence breakdown."""
    led = ledger_path(target)
    if not led.exists():
        return {"chains": [], "root_cause_groups": [], "confidence": {}}

    hypotheses = {}
    verdicts = {}
    meta_edges = []
    cap_requires = {}

    for e in _read_events(led):
        if e["type"] == "hypothesis":
            hid = e.get("id", "")
            hypotheses[hid] = e.get("claim", "")
            reqs = e.get("requires", [])
            if reqs:
                cap_requires[hid] = reqs
        elif e["type"] == "verdict":
            verdicts[e.get("hypothesis", "")] = {
                "status": e.get("status", ""),
                "severity": e.get("severity", ""),
                "confidence": e.get("confidence", "static"),
            }
        elif e["type"] == "meta":
            action = e.get("action", "")
            src = e.get("hypothesis", "")
            if action == "variant_of":
                meta_edges.append(("variant", src, e.get("variant_of", "")))
            elif action == "chain":
                meta_edges.append(("chain", src, e.get("chain", "")))
            elif action == "enrichment_of":
                meta_edges.append(("enrichment", src, e.get("enrichment_of", "")))

    # Connected components for root-cause grouping
    from collections import defaultdict
    adj: dict[str, set] = defaultdict(set)
    for etype, src, dst in meta_edges:
        if etype == "variant":
            adj[src].add(dst)
            adj[dst].add(src)
        elif etype == "enrichment":
            adj[src].add(dst)

    visited: set[str] = set()
    groups = []
    for node in hypotheses:
        if node in visited:
            continue
        group: set[str] = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            group.add(n)
            for neighbor in adj.get(n, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        if len(group) > 1:
            groups.append(sorted(group))

    # Confidence breakdown
    conf_counts: dict[str, int] = defaultdict(int)
    for v in verdicts.values():
        conf_counts[v.get("confidence", "static")] += 1

    return {
        "meta_edges": [{"type": t, "src": s, "dst": d} for t, s, d in meta_edges],
        "root_cause_groups": groups,
        "total_hypotheses": len(hypotheses),
        "unique_root_causes": len(hypotheses) - sum(len(g) - 1 for g in groups),
        "confidence_breakdown": dict(conf_counts),
        "capability_dependencies": cap_requires,
    }


def auto_chain(target: str | Path) -> dict:
    """Auto-compute attack chains from CG requires/provides + meta edges.
    Returns chain graph data + Mermaid flowchart."""
    led = ledger_path(target)
    if not led.exists():
        return {"entry_points": [], "chains": [], "capabilities": [], "mermaid": ""}

    from collections import defaultdict

    hyps: dict[str, dict] = {}
    meta_edges: list[tuple[str, str, str]] = []

    for e in _read_events(led):
        if e["type"] == "hypothesis":
            hid = e.get("id", "")
            prev = hyps.get(hid, {})
            hyps[hid] = {
                "claim": e.get("claim", "") or prev.get("claim", ""),
                "requires": e.get("requires", prev.get("requires", [])),
                "provides": prev.get("provides", []),
                "severity": e.get("severity", "") or prev.get("severity", ""),
                "status": prev.get("status", ""),
            }
        elif e["type"] == "verdict":
            hid = e.get("hypothesis", "")
            if hid in hyps:
                hyps[hid]["status"] = e.get("status", "")
                hyps[hid]["severity"] = e.get("severity", "") or hyps[hid]["severity"]
                hyps[hid]["provides"] = e.get("provides", [])
        elif e["type"] == "meta":
            action = e.get("action", "")
            src = e.get("hypothesis", "")
            if action == "variant_of":
                meta_edges.append(("variant", src, e.get("variant_of", "")))
            elif action == "chain":
                meta_edges.append(("chain", src, e.get("chain", "")))
            elif action == "enrichment_of":
                meta_edges.append(("enrichment", src, e.get("enrichment_of", "")))

    confirmed = {h: d for h, d in hyps.items() if d["status"] == "confirmed"}

    effective = HuntLoop.load(led).capsule()
    invalidated = set(effective['invalidated_hypotheses'])
    live_caps = set(effective['capabilities'])
    confirmed = {h: {**d, 'provides': [c for c in d['provides'] if c in live_caps]}
                 for h, d in confirmed.items() if h not in invalidated}

    cap_providers: dict[str, list[str]] = defaultdict(list)
    cap_consumers: dict[str, list[str]] = defaultdict(list)
    for hid, data in confirmed.items():
        for cap in data["provides"]:
            cap_providers[cap].append(hid)
        for cap in data["requires"]:
            cap_consumers[cap].append(hid)

    entry_points = sorted(h for h, d in confirmed.items() if not d["requires"])

    chain_edges = []
    for cap in cap_providers:
        for provider in cap_providers[cap]:
            for consumer in cap_consumers.get(cap, []):
                chain_edges.append({"from": provider, "capability": cap, "to": consumer})

    all_caps = set()
    for d in confirmed.values():
        all_caps.update(d["provides"])

    # Determine which nodes belong in the graph
    in_graph: set[str] = set()
    for hid, d in confirmed.items():
        if d["provides"] or d["requires"]:
            in_graph.add(hid)
    for _, src, dst in meta_edges:
        if src in confirmed:
            in_graph.add(src)
        if dst in confirmed:
            in_graph.add(dst)
    for e in chain_edges:
        in_graph.add(e["from"])
        in_graph.add(e["to"])

    # Generate Mermaid
    lines = ["graph TD"]
    lines.append("    classDef p1 fill:#dc2626,color:white,stroke:#991b1b")
    lines.append("    classDef p2 fill:#ea580c,color:white,stroke:#c2410c")
    lines.append("    classDef p3 fill:#ca8a04,color:black,stroke:#a16207")
    lines.append("    classDef cap fill:#2563eb,color:white,stroke:#1d4ed8,stroke-dasharray:5")

    # Capability nodes
    for cap in sorted(all_caps):
        cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
        lines.append(f'    {cid}(("{cap}")):::cap')

    # Hypothesis nodes
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        sev = confirmed[hid]["severity"] or "?"
        sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        lines.append(f'    {safe}["{hid} {sev}"]:::{sc}')

    # Provides edges
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        for cap in confirmed[hid]["provides"]:
            cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
            lines.append(f"    {safe} -->|provides| {cid}")

    # Requires edges
    for hid in sorted(in_graph):
        if hid not in confirmed:
            continue
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", hid)
        for cap in confirmed[hid]["requires"]:
            cid = "CAP_" + re.sub(r"[^a-zA-Z0-9]", "_", cap)
            lines.append(f"    {cid} -->|enables| {safe}")

    # Meta edges
    for mtype, src, dst in meta_edges:
        ss = re.sub(r"[^a-zA-Z0-9_-]", "_", src)
        dd = re.sub(r"[^a-zA-Z0-9_-]", "_", dst)
        if src not in in_graph and src in confirmed:
            sev = confirmed[src]["severity"] or "?"
            sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
            lines.append(f'    {ss}["{src} {sev}"]:::{sc}')
            in_graph.add(src)
        if dst not in in_graph and dst in confirmed:
            sev = confirmed[dst]["severity"] or "?"
            sc = "p1" if sev == "P1" else "p2" if sev == "P2" else "p3"
            lines.append(f'    {dd}["{dst} {sev}"]:::{sc}')
            in_graph.add(dst)
        if mtype == "variant":
            lines.append(f"    {ss} -.->|variant-of| {dd}")
        elif mtype == "chain":
            lines.append(f"    {ss} ==>|chain| {dd}")
        elif mtype == "enrichment":
            lines.append(f"    {ss} -.->|enriches| {dd}")

    return {
        "entry_points": entry_points,
        "chain_edges": chain_edges,
        "capabilities": sorted(all_caps),
        "total_confirmed": len(confirmed),
        "nodes_in_graph": len(in_graph),
        "mermaid": "\n".join(lines),
    }


def write_snapshot(target: str | Path) -> Path:
    """Frontmatter/Dataview-friendly JSON snapshot of current state."""
    s = _summary(target); cap = s["cap"]; brief = s["brief"]
    chains = auto_chain(target)
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
        "chain_edges": len(chains["chain_edges"]),
        "chain_entry_points": len(chains["entry_points"]),
        "chain_capabilities": len(chains["capabilities"]),
    }
    p = snapshot_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def _render_generated(target: str | Path) -> str:
    s = _summary(target); cap = s["cap"]; brief = s["brief"]
    chains = auto_chain(target)
    def block(title, items):
        body = "\n".join(f"- {i}" for i in items) if items else "- —"
        return f"### {title}\n{body}"
    dead = [f"{d['hyp_id']} ({d.get('cause', '?')}) — reopen: {d.get('reopen_when', '?')}"
            for d in s["dead_paths"]]
    chain_items: list[str] = []
    if chains["chain_edges"]:
        from collections import Counter
        cap_counts = Counter(e["capability"] for e in chains["chain_edges"])
        chain_items.append(
            f"{len(chains['chain_edges'])} edges, "
            f"{len(chains['entry_points'])} entry points, "
            f"{len(chains['capabilities'])} capabilities"
        )
        for cap_name, cnt in cap_counts.most_common(5):
            chain_items.append(f"  {cap_name}: {cnt}")
    return "\n\n".join([
        "_generated from `.state/asg-events.jsonl` — do not edit inside this block; "
        "write below in Operator Notes_",
        f"### Current Frontier\n- run_state: **{brief['run_state']}**  (events: {cap['event_cursor']})\n"
        f"- next: {brief['next_action']}",
        block("Capabilities (CG)", cap["capabilities"]),
        block("Attack Chains (auto-computed)", chain_items),
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


# ── SURFACE DISPOSITION: derived state, never hand-maintained ───────────────
# Why (2026-09-21, SonicDX): the hand-written YAML carried `disposition: untested`
# on every node, frozen at the day the graph was drawn. Nobody updated it and
# nobody read it, so it was a write-only field that actively lied — surfaces with
# a recorded `confirmed` verdict still advertised themselves as untested, and
# next_action kept pointing at work that was already done. The ledger already
# supports flipping a surface (`surface` event with untested=False,
# hunt_loop.py:151); what was missing was anything that used it. So: verdicts may
# now declare which surfaces they settle, and `disposition` becomes a projection.

def surface_state(target: str | Path) -> dict[str, str]:
    """Derive each surface's current disposition from the ledger alone.

    Precedence: the latest verdict that claims the surface wins; otherwise an
    explicit `untested: False` surface event marks it tested; otherwise untested.
    """
    loop = HuntLoop.load(ledger_path(target))
    # latest verdict per hypothesis — the ledger is append-only, so a hypothesis
    # may carry several historical verdicts and only the last one is current.
    latest: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") == "verdict" and e.get("hypothesis"):
            status = str(e.get("status", "")).strip()
            if status in ("confirmed", "refuted", "inconclusive"):
                latest[str(e["hypothesis"])] = status

    state: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") != "surface" or not e.get("name"):
            continue
        name = str(e["name"])
        if e.get("untested", True):
            state[name] = "untested"
            continue
        # A surface closed out by reference inherits that hypothesis's verdict,
        # so `refuted` reaches the projection instead of a flat `tested`.
        state[name] = latest.get(str(e.get("settled_by", "")), "tested")

    # A verdict may also claim its surfaces directly (record_verdict writes both).
    for e in loop.events:
        if e.get("type") != "verdict":
            continue
        status = str(e.get("status", "")).strip()
        if status not in ("confirmed", "refuted", "inconclusive"):
            continue
        for name in e.get("resolves", []) or []:
            if str(name) in state:
                state[str(name)] = status
    return state


def verdict_volatility(target: str | Path) -> dict:
    """How often a verdict on this target has later been overturned.

    A re-verification that contradicts an earlier verdict is the only direct
    evidence that a target's state moves. SonicDX produced several in one day
    (extdev inconclusive->refuted, the WMS help index 404->200, the ASP.NET version
    leak inconclusive->confirmed), which is precisely why a stale verdict there is
    dangerous. Reporting the measured flip count beats asserting a made-up window.
    """
    loop = HuntLoop.load(ledger_path(target))
    seq: dict[str, list[str]] = {}
    for e in loop.events:
        if e.get("type") == "verdict" and e.get("hypothesis"):
            s = str(e.get("status", "")).strip()
            if s in ("confirmed", "refuted", "inconclusive"):
                seq.setdefault(str(e["hypothesis"]), []).append(s)
    flipped = {h: v for h, v in seq.items() if len(set(v)) > 1}
    return {"hypotheses": len(seq), "flipped": len(flipped),
            "flips": {h: v for h, v in flipped.items()}}


def record_verdict(target: str | Path, hypothesis: str, status: str, *,
                   resolves: "list[str] | tuple[str, ...]" = (), **data) -> None:
    """Append a verdict and, atomically, close out the surfaces it settles.

    Use this instead of a bare append_event("verdict", ...) so a decided surface
    stops being advertised as untested. `resolves` holds surface names exactly as
    the ledger spells them (== the YAML node label); unknown names are recorded on
    the verdict but flip nothing, so a typo degrades to a no-op rather than to
    silent corruption.
    """
    known = surface_state(target)
    events: list[tuple[str, dict]] = [
        ("verdict", {"hypothesis": hypothesis, "status": status,
                     "resolves": [str(r) for r in resolves], **data})
    ]
    if status in ("confirmed", "refuted", "inconclusive"):
        for name in resolves:
            if str(name) in known:
                events.append(("surface", {"name": str(name), "untested": False}))
    append_events(target, events)


_DISPOSITION_RE = re.compile(r"^(?P<indent>\s*)disposition:\s*(?P<val>\S.*?)\s*$")
_NODE_START_RE = re.compile(r"^\s*-\s+id:\s*\S")
_LABEL_RE = re.compile(r"^\s*label:\s*[\"']?(?P<label>.+?)[\"']?\s*$")


# A projection must only ever ADD information. The operator's disposition
# vocabulary is richer than the ledger's: `covered`, `blocked`, `deferred`,
# `[finding]` all say more than a bare `tested`, and far more than `untested`.
# Overwriting them from the ledger would re-open settled work and manufacture
# false "untested" signals — the exact failure this projection exists to end.
# So rank the values and only ever move a node UP the lattice.
_DISPOSITION_RANK = {
    "untested": 0,
    "tested": 1,
    # Everything the operator writes that is not a lifecycle value outranks
    # `tested`; unknown strings fall here too (see _rank).
    "inconclusive": 3,
    "refuted": 4,
    "confirmed": 4,
}
_OPERATOR_RANK = 2  # covered / blocked / deferred / "[finding]" / anything bespoke


def _rank(value: str) -> int:
    return _DISPOSITION_RANK.get(value.strip().strip('"\''), _OPERATOR_RANK)


def project_dispositions(target: str | Path) -> dict:
    """Rewrite `disposition:` in the Markdown YAML block from the ledger, upward only.

    Only that one field is touched: ids, labels, hypotheses and comments are the
    operator's and are preserved byte-for-byte. A node whose label the ledger has
    never seen is left alone rather than guessed at, and a node already carrying a
    richer disposition than the ledger can justify is left alone too.
    """
    md = markdown_path(target)
    if not md.exists():
        return {"updated": 0, "reason": "no Markdown ASG"}
    state = surface_state(target)
    if not state:
        return {"updated": 0, "reason": "ledger has no surfaces"}

    lines = md.read_text(encoding="utf-8").splitlines(keepends=True)
    label: str | None = None
    updated = 0
    changes: list[str] = []
    kept: list[str] = []
    for i, line in enumerate(lines):
        if _NODE_START_RE.match(line):
            label = None
            continue
        m_label = _LABEL_RE.match(line)
        if m_label:
            label = m_label.group("label").strip()
            continue
        m_disp = _DISPOSITION_RE.match(line)
        if not m_disp or label is None:
            continue
        derived = state.get(label)
        current = m_disp.group("val")
        if derived is None or derived == current:
            continue
        if _rank(derived) <= _rank(current):
            # The ledger knows no more than the file already says. Leave it.
            kept.append(f"{label}: kept {current} (ledger only has {derived})")
            continue
        eol = "\n" if line.endswith("\n") else ""
        lines[i] = f"{m_disp.group('indent')}disposition: {derived}{eol}"
        changes.append(f"{label}: {current} -> {derived}")
        updated += 1
    if updated:
        md.write_text("".join(lines), encoding="utf-8")
    return {"updated": updated, "changes": changes, "kept": kept, "markdown": str(md)}


def project_all(target: str | Path) -> dict:
    """Refresh every projection from the ledger."""
    return {"markdown": str(project_markdown(target)),
            "dispositions": project_dispositions(target),
            "snapshot": str(write_snapshot(target))}


def status(target: str | Path) -> dict:
    """The SINGLE SOURCE for target statistics. Never hand-write these numbers."""
    led = ledger_path(target)
    if not led.exists():
        return {"error": f"no ledger for {target}"}
    genesis = has_genesis(target)
    if not genesis:
        return {"error": f"no genesis for {target}"}
    phase = current_phase(target)
    chain = phase_chain(target)
    findings: dict[str, str] = {}
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "finding":
            findings[ev.get("finding_id", "")] = "hypothesis"
        elif ev.get("type") == "finding_state":
            findings[ev.get("finding_id", "")] = ev.get("to", "")
    by_state: dict[str, list[str]] = {}
    for fid, st in findings.items():
        by_state.setdefault(st, []).append(fid)
    pw = pending_workers(target)
    surfaces = surface_state(target)
    untested = sum(1 for s in surfaces.values() if s == "untested")
    chains = auto_chain(target)
    return {
        "target": _basename(target),
        "profile": genesis.get("profile", "web"),
        "phase": phase,
        "phase_chain": list(chain),
        "findings_total": len(findings),
        "findings_by_state": {k: len(v) for k, v in sorted(by_state.items())},
        "pending_workers": len(pw),
        "pending_workers_detail": [
            {"finding_id": w.get("finding_id"), "worker": w.get("worker")}
            for w in pw
        ],
        "surfaces_total": len(surfaces),
        "surfaces_untested": untested,
        "chain_edges": len(chains.get("chain_edges", [])),
        "chain_entry_points": len(chains.get("entry_points", [])),
    }


def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="ASG single-authority resolver + projections.")
    ap.add_argument("action", choices=["paths", "project", "snapshot", "migrate", "chains",
                                       "auto-chain", "surfaces", "phase", "advance-phase",
                                       "finding-state", "record-finding", "advance-finding",
                                       "status", "pending-workers", "complete-worker"])
    ap.add_argument("target")
    ap.add_argument("extra", nargs="*", default=[])
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
    elif a.action == "surfaces":
        st = surface_state(a.target)
        undecided = [n for n, s in st.items() if s == "untested"]
        print(json.dumps({"total": len(st), "untested": len(undecided),
                          "by_state": {s: sorted(n for n, v in st.items() if v == s)
                                       for s in sorted(set(st.values()))}},
                         ensure_ascii=False, indent=2))
    elif a.action == "chains":
        print(json.dumps(chain_projection(a.target), ensure_ascii=False, indent=2))
    elif a.action == "auto-chain":
        result = auto_chain(a.target)
        mermaid = result.pop("mermaid")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print("\n--- Mermaid ---")
        print(mermaid)
    elif a.action == "phase":
        p = current_phase(a.target)
        chain = phase_chain(a.target)
        idx = phase_index(a.target)
        print(json.dumps({"phase": p, "index": idx, "chain": list(chain)},
                         ensure_ascii=False, indent=2))
    elif a.action == "advance-phase":
        if len(a.extra) < 1:
            print("usage: asg.py advance-phase <target> <to-phase> [reason]", file=sys.stderr)
            return 1
        to = a.extra[0]
        reason = " ".join(a.extra[1:])
        print(json.dumps(advance_phase(a.target, to, reason=reason),
                         ensure_ascii=False, indent=2))
    elif a.action == "finding-state":
        if len(a.extra) < 1:
            print("usage: asg.py finding-state <target> <finding-id>", file=sys.stderr)
            return 1
        fid = a.extra[0]
        print(json.dumps({"finding_id": fid, "state": finding_state(a.target, fid)},
                         ensure_ascii=False, indent=2))
    elif a.action == "record-finding":
        if len(a.extra) < 1:
            print("usage: asg.py record-finding <target> <finding-id>", file=sys.stderr)
            return 1
        fid = a.extra[0]
        print(json.dumps(record_finding(a.target, fid), ensure_ascii=False, indent=2))
    elif a.action == "advance-finding":
        if len(a.extra) < 2:
            print("usage: asg.py advance-finding <target> <finding-id> <to-state> [reason]",
                  file=sys.stderr)
            return 1
        fid, to = a.extra[0], a.extra[1]
        reason = " ".join(a.extra[2:])
        print(json.dumps(advance_finding(a.target, fid, to, reason=reason),
                         ensure_ascii=False, indent=2))
    elif a.action == "status":
        print(json.dumps(status(a.target), ensure_ascii=False, indent=2))
    elif a.action == "pending-workers":
        fid = a.extra[0] if a.extra else None
        pw = pending_workers(a.target, fid)
        print(json.dumps([{"finding_id": w.get("finding_id"), "worker": w.get("worker")}
                          for w in pw], ensure_ascii=False, indent=2))
    elif a.action == "complete-worker":
        if len(a.extra) < 2:
            print("usage: asg.py complete-worker <target> <finding-id> <worker> [reason]",
                  file=sys.stderr)
            return 1
        fid, worker = a.extra[0], a.extra[1]
        reason = " ".join(a.extra[2:])
        print(json.dumps(complete_worker(a.target, fid, worker, reason=reason),
                         ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
