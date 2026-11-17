#!/usr/bin/env python3
"""asg_command_runs.py — read-time projection of recon_runs.jsonl → ASG command_runs[].

The ASG schema defines a top-level `command_runs[]` (execution provenance), but nothing
hand-fills it. recon_ingest.sh records every recon tool run into
<target>/.state/recon_runs.jsonl; this renders that evidence as the command_runs[] YAML
projection — DERIVED ON READ, never written back into the ASG markdown (same principle as
capability_view: 同一份事實只存一次，其餘皆投影，否則 drift 是數學保證).

Use it to paste an up-to-date command_runs[] into a report, or to see recon coverage by
dimension. Output is the YAML block plus a per-dimension coverage tally comment.

Usage: asg_command_runs.py <target> [--json]
Exit 0 always (a view); prints a note if there is no recorded recon yet.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recon_dimensions_lib as rdl  # noqa: E402

ROOT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])
TARGETS = ROOT / "01 - Targets"


def load_runs(tdir: Path) -> list[dict]:
    runs = tdir / ".state" / "recon_runs.jsonl"
    out = []
    try:
        for line in runs.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("type") == "command_run":
                ev = dict(ev)
                # Legacy telemetry has no execution identity. Pin it to content,
                # never its position in a mutable file; do not invent a start.
                ev.setdefault("id", "legacy-" + hashlib.sha256(line.encode()).hexdigest()[:24])
                ev.setdefault("status", "succeeded" if ev.get("exit_code") == 0 else
                              "unknown" if ev.get("exit_code") is None else "failed")
                ev.setdefault("command", ev.get("cmd", ""))
                ev.setdefault("finished_at", ev.get("at"))
                out.append(ev)
    except OSError:
        pass
    return list({event["id"]: event for event in out}.values())


def action_runs(events: list[dict]) -> list[dict]:
    """Project persisted execution attempts; telemetry is never execution control."""
    runs = {}
    for event in events:
        kind, rid = event.get("type"), event.get("action_id")
        if not rid or kind not in {"action_started", "action_running", "action_finished", "action_heartbeat"}:
            continue
        run = runs.setdefault(rid, {"id": rid, "type": "command_run", "status": "unknown"})
        if kind == "action_started":
            run.update(status="running", started_at=event.get("started_at", event.get("at")),
                       command=shlex.join(event.get("argv", [])), hyp_id=event.get("hyp_id"),
                       output_ref=event.get("output_ref"), owner_pid=event.get("owner_pid"),
                       owner_host=event.get("owner_host"), heartbeat_interval=event.get("heartbeat_interval"),
                       scope_ref=event.get("scope_ref"), tool_version=event.get("tool_version"))
        elif kind == "action_running":
            run.update(pid=event.get("pid"), last_heartbeat=event.get("at"))
        elif kind == "action_heartbeat":
            run.update(last_heartbeat=event.get("at"))
        else:
            run.update(status=event.get("status") or ("succeeded" if event.get("exit_ok") else "failed"),
                       finished_at=event.get("finished_at", event.get("at")),
                       exit_code=event.get("returncode", event.get("exit_code")), error=event.get("error"),
                       sha256=event.get("sha256"), output_ref=event.get("output_ref"),
                       stop_confirmed=event.get("execution_stop_confirmed"),
                       remote_stop_requires_reconciliation=event.get("remote_stop_requires_reconciliation", False))
    for run in runs.values():
        run["liveness"] = "terminal" if run["status"] != "running" else "unknown"
        if run["status"] == "running":
            from command_lifecycle import owner_gone
            if owner_gone(run):
                run["liveness"] = "controller_lost"
            elif run.get("heartbeat_interval") and run.get("last_heartbeat"):
                try:
                    at = datetime.fromisoformat(run["last_heartbeat"].replace("Z", "+00:00"))
                    age = (datetime.now(UTC) - at).total_seconds()
                    run["liveness"] = "heartbeat_stale" if age > max(30, run["heartbeat_interval"] * 3) else "active"
                except (ValueError, TypeError):
                    pass
        run["evidence_status"] = artifact_status(run.get("output_ref"), run.get("sha256"))
        run["stale"] = run["evidence_status"] in {"missing", "changed"}
    return list(runs.values())


def artifact_status(path, expected):
    """Check execution evidence without changing the recorded execution outcome."""
    if not expected:
        return "unavailable"
    try:
        from evidence_refs import artifact_hash
        return "valid" if artifact_hash(path) == expected else "changed"
    except (OSError, TypeError):
        return "missing"


def project(runs: list[dict]) -> dict:
    """Group runs by dimension for the coverage tally."""
    by_dim: dict[str, dict] = {}
    for r in runs:
        d = r.get("dim") or "?"
        e = by_dim.setdefault(d, {"runs": 0, "tools": set(), "out_lines": 0})
        e["runs"] += 1
        if r.get("tool"):
            e["tools"].add(r["tool"])
        e["out_lines"] += int(r.get("out_lines") or 0)
        statuses = e.setdefault("statuses", {})
        status = r.get("status", "unknown")
        statuses[status] = statuses.get(status, 0) + 1
    return by_dim


def main():
    if len(sys.argv) < 2 or sys.argv[1].startswith("--"):
        print(__doc__)
        return 0
    target = sys.argv[1]
    as_json = "--json" in sys.argv[2:]
    tdir = TARGETS / target
    runs = load_runs(tdir)
    ledger = tdir / ".state" / "asg-events.jsonl"
    if ledger.exists():
        from hunt_loop import HuntLoop
        runs += action_runs(HuntLoop.load(ledger).events)

    if as_json:
        print(json.dumps({"target": target, "command_runs": runs,
                          "coverage": {d: {**v, "tools": sorted(v["tools"])}
                                       for d, v in project(runs).items()}},
                         ensure_ascii=False, indent=2))
        return 0

    if not runs:
        print(f"# {target}: 尚無 recon_runs 紀錄（recon_ingest 尚未錄到任何 catalogued 工具）。")
        return 0

    by_dim = project(runs)
    print(f"# command_runs[] — auto-projected from {target}/.state/recon_runs.jsonl")
    print(f"# recon coverage by dimension ({len(runs)} run(s)):")
    for d in rdl.FLOOR:
        if d in by_dim:
            v = by_dim[d]
            print(f"#   {d}: {v['runs']} run(s) via {', '.join(sorted(v['tools']))}"
                  f" → {v['out_lines']} output lines")
    for d, v in by_dim.items():
        if d not in rdl.FLOOR:
            print(f"#   {d} (non-floor): {v['runs']} run(s) via {', '.join(sorted(v['tools']))}")
    print("command_runs:")
    import yaml
    print(yaml.safe_dump(runs, allow_unicode=True, sort_keys=False).rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
