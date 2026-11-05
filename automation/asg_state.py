"""Materialize one ledger revision for all human/machine views.

The public target resolver lives in asg.read_state(). This module owns the
read-model implementation; generated Markdown is never a ledger input.
"""
from pathlib import Path
from evidence_refs import finding_records
from hunt_loop import HuntLoop
from hunt_session import resume_brief, dead_paths


def read_state(target_dir: Path) -> dict:
    td = Path(target_dir)
    ledger = td / ".state" / "asg-events.jsonl"
    md = td / f"Attack Surface Graph - {td.name}.md"
    if not ledger.exists():
        from surface_graph_lib import load_graph
        graph = load_graph(str(md)) if md.exists() else {}
        loop = HuntLoop(base_path=td)
        from asg_research import project
        return {"source": "legacy" if graph else "empty", "target": td.name,
                "research": project([], td),
                "event_cursor": 0, "loop": loop, "capsule": loop.capsule(),
                "brief": resume_brief(loop), "dead_paths": [], "genesis": {},
                "phase": None, "findings": graph.get("findings") or [],
                "paths": graph.get("paths") or [], "nodes": graph.get("nodes") or [],
                "edges": graph.get("edges") or [],
                "capability_state": graph.get("capability_state") or [],
                "recon_dimensions": graph.get("recon_dimensions") or []}

    loop = HuntLoop.load(ledger)  # one strict read; corrupted state cannot fall back
    cap = loop.capsule()
    from asg_research import project
    research = project(loop.events, td, cap=cap)
    findings, hypotheses, surfaces, dead = finding_records(loop.events), {}, {}, {}
    genesis, phase, context = {}, None, {}
    for event in loop.events:
        kind = event["type"]
        if kind == "genesis":
            genesis = event
            phase = "engage"
        elif kind == "phase":
            phase = event.get("to", phase)
        elif kind == "recon_context":
            context = event.get("data") or {}
        elif kind == "hypothesis":
            hypotheses[str(event["id"])] = dict(event)
        elif kind == "verdict":
            hid = str(event["hypothesis"])
            hypotheses.setdefault(hid, {"id": hid, "requires": []})
        elif kind == "surface":
            name = str(event["name"])
            surfaces[name] = {**surfaces.get(name, {}), **event, "identifier": name}
        elif kind == "dead_end":
            dead[str(event["hyp_id"])] = dict(event)

    # Historical imports registered finding:<id> hypotheses without a finding
    # event. They are ledger members, even when their proof remains unresolved.
    for hid, hypothesis in hypotheses.items():
        if hid.startswith("finding:"):
            fid = hid.removeprefix("finding:")
            findings.setdefault(fid, {"id": fid, "status": "hypothesis", "implicit_finding": True,
                                      "requires": list(hypothesis.get("requires") or []),
                                      "provides": list(hypothesis.get("provides") or [])})

    # The same capsule that drives resume supplies the effective capabilities.
    # Raw finding.provides describes a candidate; it cannot grant current access.
    for fid, finding in findings.items():
        ids = (fid, f"finding:{fid}")
        effective = sorted({c for hid in ids for c in cap["confirmed"].get(hid, [])
                            if c in cap["capabilities"]})
        finding["declared_provides"] = list(finding.get("provides") or [])
        finding["provides"] = [] if finding.get("status") == "withdrawn" else effective

    path_map = {}
    for hid, hypothesis in hypotheses.items():
        fid = hid.removeprefix("finding:")
        if findings.get(fid, {}).get("status") == "withdrawn":
            status = "withdrawn"
        elif hid in cap["disputed"]:
            status = "disputed"
        elif hid in cap["confirmed"]:
            status = "confirmed"
        elif hid in cap["evidence_rejected"]:
            status = "needs_evidence"
        elif hid in cap["refuted"] or hid in dead:
            status = "dead_end"
        elif hid in cap["blocked_hypotheses"] or hid in cap["invalidated_hypotheses"]:
            status = "blocked"
        else:
            status = "hypothesis"
        path_map[hid] = {**hypothesis, "name": hid, "status": status}
        if hid in dead:
            path_map[hid].update({k: dead[hid].get(k) for k in ("cause", "scope", "reopen_when")})
    for hid, event in dead.items():
        path_map.setdefault(hid, {**event, "name": hid, "status": "dead_end"})
    # Finding-only stubs also remain visible when no hypothesis has been declared.
    for fid, finding in findings.items():
        if fid not in path_map and f"finding:{fid}" not in path_map:
            path_map[f"finding:{fid}"] = {"name": f"finding:{fid}", "status": finding["status"]}

    for fid, finding in findings.items():
        path = path_map.get(f"finding:{fid}", path_map.get(fid, {}))
        finding["capability_status"] = path.get("status", "hypothesis")
        finding["declared_requires"] = list(finding.get("requires") or [])
        if "requires" in path:
            finding["requires"] = path["requires"]

    sources = {}
    for hid, caps in cap["confirmed"].items():
        for capability in caps:
            if capability in cap["capabilities"]:
                sources.setdefault(capability, hid)
    return {"source": "ledger", "target": td.name, "research": research,
            "event_cursor": cap["event_cursor"], "loop": loop, "capsule": cap,
            "brief": resume_brief(loop, cap=cap), "dead_paths": dead_paths(loop),
            "genesis": genesis, "phase": phase,
            "findings": [findings[k] for k in sorted(findings)],
            "paths": [path_map[k] for k in sorted(path_map)],
            "nodes": [surfaces[k] for k in sorted(surfaces)], "edges": [],
            "capability_state": [{"cap": c, "source": sources[c], "state": "confirmed"}
                                 for c in cap["capabilities"]],
            "recon_dimensions": context.get("recon_dimensions") or []}
