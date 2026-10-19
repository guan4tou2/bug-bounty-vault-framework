"""Research provenance over the existing ASG ledger; no second state store.

Nodes describe goals, work, observations and hints. Finding identities and actual
capabilities stay in the existing ASG model. A lineage edge is never an access grant.
All live writes are validated by asg.append_events while holding its writer lock.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from evidence_refs import evidence_resolves, finding_records, normalize_evidence


EVENTS = {"research_node", "research_state", "research_link", "goal_proof", "research_digest"}
KINDS = {"goal", "intent", "fact", "hint"}
STATES = {
    "goal": {"open", "abandoned"},
    "intent": {"open", "running", "paused", "done", "blocked", "exhausted", "stopped"},
    "fact": {"active", "withdrawn"}, "hint": {"active", "consumed", "withdrawn"},
}
TRANSITIONS = {
    "open": {"running", "paused", "stopped"},
    "running": {"done", "blocked", "exhausted", "paused", "stopped"},
    "paused": {"open", "stopped"}, "blocked": {"open", "stopped"},
    "exhausted": {"open", "stopped"}, "done": {"open"}, "stopped": {"open"},
}
RELATIONS = {
    "spawns": ({"root", "goal"}, {"goal", "intent"}),
    "derived_from": ({"fact", "finding", "hint"}, {"intent"}),
    "yields": ({"intent"}, {"fact", "finding"}),
    "depends_on": ({"intent"}, {"intent"}),
    "tests": ({"intent"}, {"hypothesis"}),
}
BASES = {"observed", "source-claimed", "inferred", "unknown"}
COMMON_NODE_FIELDS = {"node_kind", "id", "text", "at", "amend"}
NODE_FIELDS = {
    "goal": {"criteria", "purpose", "parent_goal"},
    "intent": {"goals", "parents", "depends_on", "requires", "hypothesis", "priority"},
    "fact": {"intent", "basis", "source", "checked_at", "source_revision", "evidence", "environment"},
    "hint": {"goal", "intent"},
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _ref(kind, identifier):
    if kind not in KINDS | {"digest", "finding", "hypothesis"} or not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError("research identity requires a kind and stable ASCII id")
    return f"{kind}:{identifier}"


def validate_shape(event):
    """Shape validation used on strict ledger reads as well as live writes."""
    kind = event["type"]
    required = {
        "research_node": ("node_kind", "id", "text"), "research_state": ("ref", "state", "reason"),
        "research_link": ("src", "rel", "dst"),
        "goal_proof": ("goal", "criterion", "source", "reason", "source_sha256", "goal_sha256"),
        "research_digest": ("id", "text", "members", "member_hashes"),
    }.get(kind, ())
    for field in required:
        value = event.get(field)
        expected = list if field == "members" else dict if field == "member_hashes" else str
        if not isinstance(value, expected) or not value:
            raise ValueError(f"{kind} requires nonempty {field}")
    if kind == "research_node":
        if "amend" in event and type(event["amend"]) is not bool:
            raise ValueError("research amend requires a boolean")
        if "state" in event:
            raise ValueError("research states require separate transition events")
        _ref(event["node_kind"], event["id"])
        if event["node_kind"] not in KINDS:
            raise ValueError("unsupported research node kind")
        if set(event) - (COMMON_NODE_FIELDS | NODE_FIELDS[event["node_kind"]] | {"type", "ts", "sid"}):
            raise ValueError("research node contains fields unsupported for its kind")
        if not event["text"].strip():
            raise ValueError("research text cannot be blank")
        if event["node_kind"] == "goal" and ("criteria" in event or not event.get("amend")):
            criteria = event.get("criteria")
            if not isinstance(criteria, list) or not criteria or any(
                not isinstance(c, dict) or set(c) != {"id", "text"} or
                not isinstance(c["id"], str) or not _ID.fullmatch(c["id"]) or
                not isinstance(c["text"], str) or not c["text"].strip() for c in criteria):
                raise ValueError("invalid goal criteria")
            if len({c["id"] for c in criteria}) != len(criteria):
                raise ValueError("duplicate criterion id")
        if "purpose" in event and event["purpose"] not in {"research", "validation"}:
            raise ValueError("invalid goal purpose")
        if event["node_kind"] == "intent" and not event.get("amend") and not event.get("goals"):
            raise ValueError("intent requires goals")
        if event["node_kind"] == "fact" and ("basis" in event or not event.get("amend")) and event.get("basis") not in BASES:
            raise ValueError("invalid fact basis")
        if "priority" in event and (type(event["priority"]) is not int or not 0 <= event["priority"] <= 10):
            raise ValueError("invalid intent priority")
    for field in ("goals", "parents", "depends_on", "requires", "members"):
        if field in event and (not isinstance(event[field], list) or
                               any(not isinstance(v, str) or not v for v in event[field])):
            raise ValueError(f"research {field} requires a list of references")
    if kind == "research_node":
        for field in ("parent_goal", "hypothesis", "intent", "goal", "basis", "source", "checked_at", "source_revision"):
            if field in event and (not isinstance(event[field], str) or not event[field].strip()):
                raise ValueError(f"research {field} requires nonempty text")
        if event["node_kind"] == "fact" and event.get("basis") == "source-claimed" and not event.get("amend"):
            source = urlparse(event.get("source", ""))
            if source.scheme not in {"http", "https"} or not source.netloc:
                raise ValueError("source-claimed fact requires an exact source URL")
            try:
                if datetime.fromisoformat(event.get("checked_at", "").replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError()
            except (ValueError, TypeError):
                raise ValueError("source-claimed fact requires checked_at with timezone") from None


def _edges_for(node):
    if not node:
        return []
    ref, kind = node["ref"], node["kind"]
    edges = []
    if kind == "goal":
        edges.append({"src": node.get("parent_goal", "root"), "rel": "spawns", "dst": ref})
    if kind == "intent":
        edges.extend({"src": g, "rel": "spawns", "dst": ref} for g in node.get("goals", []))
        edges.extend({"src": p, "rel": "derived_from", "dst": ref} for p in node.get("parents", []))
        edges.extend({"src": p, "rel": "depends_on", "dst": ref} for p in node.get("depends_on", []))
        if node.get("hypothesis"):
            edges.append({"src": ref, "rel": "tests", "dst": node["hypothesis"]})
    if kind == "fact" and node.get("intent"):
        edges.append({"src": node["intent"], "rel": "yields", "dst": ref})
    return edges


def _goal_material(goal):
    return {k: goal.get(k) for k in ("ref", "text", "criteria", "purpose", "revision", "state")}


def _source_eligible(node, goal):
    if node["kind"] == "finding":
        return node.get("effective_confirmed", False)
    if node["kind"] != "fact" or node["state"] != "active" or not node.get("evidence_valid"):
        return False
    return node.get("basis") == "observed" or (
        goal.get("purpose") == "research" and node.get("basis") == "source-claimed")


def _finding_proof(identifier, record, events, base):
    """The legacy capability contract is broader than goal-proof eligibility.

    Keep its historical semantics, but never accept an unresolvable legacy
    string or an empty Finding as evidence for a research acceptance criterion.
    """
    candidates = [record.get("evidence") or record.get("poc_ref")]
    candidates.extend(e.get("evidence") for e in reversed(events)
                      if e.get("type") == "verdict" and e.get("hypothesis") in {identifier, f"finding:{identifier}"}
                      and e.get("status") == "confirmed")
    for value in candidates:
        proof = normalize_evidence(value, base, events=events)
        if evidence_resolves(proof, base, events):
            return proof
    return None


def project(events, base=None, *, cap=None):
    """Deterministic replay. Digests are removable views, never evidence inputs."""
    empty = {"enabled": False, "nodes": [], "edges": [], "digests": [], "summary": {
        "open_goals": [], "met_goals": [], "abandoned_goals": [], "ready_intents": [], "running_intents": [],
        "blocked_intents": [], "unsettled_intents": [], "active_hints": [], "stale_digests": [],
        "gated_hypotheses": [],
    }}
    if not any(e["type"] in EVENTS for e in events):
        return empty
    cap = cap or {}
    nodes = {"root": {"ref": "root", "kind": "root", "id": "root", "text": "Task", "state": "active"}}
    for fid, rec in finding_records(events).items():
        # Existing identities are referenced, never copied into research_node events.
        ref = f"finding:{fid}"
        proof = _finding_proof(fid, rec, events, base)
        nodes[ref] = {**rec, "ref": ref, "id": fid, "kind": "finding",
                      "text": rec.get("title", fid), "state": rec.get("status", "hypothesis"),
                      "resolved_proof": proof,
                      "effective_confirmed": rec.get("status") in {"adversary-verified", "confirmed"}
                      and any(h in cap.get("confirmed", {}) for h in (fid, ref))
                      and proof is not None}
    links, proofs, digests = [], {}, {}
    for index, event in enumerate(events, 1):
        kind = event["type"]
        if kind == "hypothesis":
            ref = f"hypothesis:{event['id']}"
            nodes[ref] = {"ref": ref, "kind": "hypothesis", "id": event["id"],
                          "text": event.get("claim", event["id"]), "state": "registered"}
        elif kind == "research_node":
            ref = _ref(event["node_kind"], event["id"])
            previous = nodes.get(ref, {})
            node = {**previous, **{k: v for k, v in event.items() if k not in {"type", "amend"}},
                    "ref": ref, "kind": event["node_kind"], "revision": index}
            node.setdefault("state", "open" if node["kind"] in {"goal", "intent"} else "active")
            nodes[ref] = node
        elif kind == "research_state" and event["ref"] in nodes:
            nodes[event["ref"]].update(state=event["state"], state_reason=event["reason"])
        elif kind == "research_link":
            links.append({k: event[k] for k in ("src", "rel", "dst")})
        elif kind == "goal_proof":
            proofs[(event["goal"], event["criterion"])] = event
        elif kind == "research_digest":
            digests[event["id"]] = event

    for node in nodes.values():
        if node["kind"] == "fact":
            node["evidence_valid"] = evidence_resolves(node.get("evidence"), base, events)
        links.extend(_edges_for(node))
    for fid, rec in finding_records(events).items():
        if rec.get("intent_id"):
            links.append({"src": f"intent:{rec['intent_id']}", "rel": "yields", "dst": f"finding:{fid}"})
    edges = {(e["src"], e["rel"], e["dst"]): e for e in links}
    # Explicit link commands have the same operational meaning as node fields.
    for edge in links:
        if edge["src"] not in nodes or edge["dst"] not in nodes:
            continue
        source, destination = nodes[edge["src"]], nodes[edge["dst"]]
        field = {"depends_on": "depends_on", "derived_from": "parents", "spawns": "goals"}.get(edge["rel"])
        if destination["kind"] == "intent" and field:
            destination[field] = sorted(set(destination.get(field, [])) | {source["ref"]})
        if edge["rel"] == "tests" and source["kind"] == "intent":
            source["hypothesis"] = destination["ref"]

    # Pin source AND acceptance definition; changed proof, withdrawn facts or a
    # revoked capability automatically reopen goals rather than preserving a badge.
    for node in nodes.values():
        if node["kind"] != "goal":
            continue
        node["satisfied_criteria"] = []
        for criterion in node["criteria"]:
            proof = proofs.get((node["ref"], criterion["id"]))
            source = nodes.get(proof["source"]) if proof else None
            valid = bool(source and _source_eligible(source, node)
                         and fingerprint(source) == proof["source_sha256"]
                         and fingerprint(_goal_material(node)) == proof["goal_sha256"])
            if proof:
                key = (proof["source"], "proves", node["ref"], criterion["id"])
                edges[key] = {"src": proof["source"], "rel": "proves", "dst": node["ref"],
                              "criterion": criterion["id"], "valid": valid, "reason": proof["reason"]}
            if valid:
                node["satisfied_criteria"].append(criterion["id"])
        node["effective_state"] = "abandoned" if node["state"] == "abandoned" else (
            "met" if len(node["satisfied_criteria"]) == len(node["criteria"]) else "open")

    have = set(cap.get("capabilities", []))
    summary = empty["summary"]
    for node in nodes.values():
        if node["kind"] == "goal":
            summary[{"open": "open_goals", "met": "met_goals", "abandoned": "abandoned_goals"}[
                node["effective_state"]]].append(node["ref"])
        elif node["kind"] == "intent":
            missing = [f"capability:{r}" for r in node.get("requires", []) if r not in have]
            missing += [r for r in node.get("depends_on", []) if nodes.get(r, {}).get("state") != "done"]
            if node.get("goals") and all(nodes[g].get("effective_state") == "abandoned" for g in node["goals"]):
                missing.append("goals:abandoned")
            node["missing"] = missing
            node["effective_state"] = "blocked" if node["state"] == "open" and missing else node["state"]
            if node["effective_state"] == "open":
                summary["ready_intents"].append(node["ref"])
            elif node["effective_state"] == "running":
                summary["running_intents"].append(node["ref"])
            elif node["effective_state"] == "blocked":
                summary["blocked_intents"].append(node["ref"])
            if node["state"] not in {"done", "stopped"}:
                summary["unsettled_intents"].append(node["ref"])
            if node.get("hypothesis") and node["effective_state"] != "open":
                summary["gated_hypotheses"].append(node["hypothesis"].removeprefix("hypothesis:"))
        elif node["kind"] == "hint" and node["state"] == "active":
            summary["active_hints"].append(node["ref"])

    # An active descendant keeps its ancestors hot. Only settled intent/fact
    # members may fold; goals/findings/hints and their original bytes remain visible.
    hot = {n["ref"] for n in nodes.values() if n["kind"] == "intent" and n["state"] not in {"done", "stopped"}}
    hot |= {e["dst"] for e in edges.values() if e["rel"] == "yields" and e["src"] in hot}
    changed = True
    while changed:
        before = len(hot)
        hot |= {e["src"] for e in edges.values() if e["rel"] in RELATIONS and e["dst"] in hot}
        changed = len(hot) != before
    digest_nodes = []
    for identifier, event in sorted(digests.items()):
        members = event["members"]
        valid = all(r in nodes and r not in hot and nodes[r]["kind"] in {"intent", "fact"}
                    and fingerprint(nodes[r]) == event["member_hashes"].get(r) for r in members)
        if not valid:
            summary["stale_digests"].append(f"digest:{identifier}")
        digest = {"ref": f"digest:{identifier}", "kind": "digest", "id": identifier,
                  "text": event["text"], "state": "active" if valid else "stale", "members": members}
        digest_nodes.append(digest)
        for member in members:
            edges[(digest["ref"], "covers", member)] = {"src": digest["ref"], "rel": "covers", "dst": member, "valid": valid}
    for values in summary.values():
        values[:] = sorted(set(values))
    return {"enabled": True, "nodes": [nodes[k] for k in sorted(nodes)],
            "edges": [edges[k] for k in sorted(edges)], "digests": digest_nodes, "summary": summary,
            "hot": sorted(hot)}


def _assert_link(src, rel, dst, nodes, edges):
    if src not in nodes or dst not in nodes or src == dst or rel not in RELATIONS:
        raise ValueError("research link requires existing, distinct endpoints and a supported relation")
    left, right = RELATIONS[rel]
    if nodes[src]["kind"] not in left or nodes[dst]["kind"] not in right:
        raise ValueError("research relation has incompatible endpoint kinds")
    if rel == "tests" and any(e["src"] == src and e["rel"] == rel and e["dst"] != dst for e in edges):
        raise ValueError("one intent tests one bounded hypothesis")
    # proves/covers are views, not causal edges. Causal lineage must stay acyclic.
    todo, seen = [dst], set()
    while todo:
        current = todo.pop()
        if current == src:
            raise ValueError("research lineage cycle")
        if current not in seen:
            seen.add(current)
            todo.extend(e["dst"] for e in edges if e["src"] == current and e["rel"] in RELATIONS)


def normalize_event(kind, data, loop):
    """Validate against this locked ledger revision and pin derived receipts."""
    data = dict(data)
    if kind not in EVENTS:
        if kind == "finding" and "intent_id" in data:
            if not isinstance(data["intent_id"], str) or not data["intent_id"].strip():
                raise ValueError("finding intent_id must be a stable id")
            data["intent_id"] = data["intent_id"].removeprefix("intent:")
            fid = data.get("finding_id")
            if not isinstance(fid, str) or not fid.strip():
                raise ValueError("finding provenance requires its canonical id")
            # Replay the proposed patch so only its former automatic yield is
            # replaced. Explicit historical yields remain in the provisional
            # graph and participate in the same causal-cycle gate.
            graph = project(loop.events + [{"type": kind, **data}], loop.base_path, cap=loop.capsule())
            nodes = {n["ref"]: n for n in graph["nodes"]}
            src, dst = f"intent:{data['intent_id']}", f"finding:{fid}"
            if nodes.get(src, {}).get("kind") != "intent":
                raise ValueError("finding intent_id must reference this target's research intent")
            _assert_link(src, "yields", dst, nodes, graph["edges"])
        return data
    if not loop.events:
        raise ValueError("initialize or explicitly migrate the ASG ledger before research operations")
    graph = project(loop.events, loop.base_path, cap=loop.capsule())
    nodes = {n["ref"]: n for n in graph["nodes"]}
    nodes.setdefault("root", {"ref": "root", "kind": "root"})
    if kind == "research_node":
        node_kind, identifier = data.get("node_kind"), data.get("id")
        ref = _ref(node_kind, identifier)
        if node_kind not in KINDS:
            raise ValueError("unsupported research node kind")
        previous = nodes.get(ref)
        if previous and not data.get("amend", False):
            raise ValueError("research node already exists; use --amend explicitly")
        if not previous and data.get("amend", False):
            raise ValueError("cannot amend a research node that does not exist")
        merged = {**(previous or {}), **data, "kind": node_kind, "ref": ref}
        if previous:
            data.setdefault("text", previous["text"])
        validate_shape({"type": kind, **data})
        allowed = COMMON_NODE_FIELDS | NODE_FIELDS[node_kind]
        if set(data) - allowed or not isinstance(merged.get("text"), str) or not merged["text"].strip():
            raise ValueError("research node requires text and supported fields only")
        if node_kind == "goal":
            merged.setdefault("purpose", "validation")
            if merged["purpose"] not in {"research", "validation"}:
                raise ValueError("goal purpose must be research or validation")
            criteria = merged.get("criteria")
            if not isinstance(criteria, list) or not criteria:
                raise ValueError("goal requires explicit acceptance criteria")
            ids = []
            for criterion in criteria:
                if not isinstance(criterion, dict) or set(criterion) != {"id", "text"}:
                    raise ValueError("criterion requires id and text")
                _ref("goal", criterion["id"])
                if not isinstance(criterion["text"], str) or not criterion["text"].strip():
                    raise ValueError("criterion requires nonempty text")
                ids.append(criterion["id"])
            if len(set(ids)) != len(ids):
                raise ValueError("duplicate criterion id")
            data["purpose"] = merged["purpose"]
        elif node_kind == "intent":
            if not merged.get("goals"):
                raise ValueError("intent must name at least one goal")
            for goal in merged["goals"]:
                if nodes.get(goal, {}).get("kind") != "goal":
                    raise ValueError("intent goal must exist in this target")
            if merged.get("hypothesis") and nodes.get(merged["hypothesis"], {}).get("kind") != "hypothesis":
                raise ValueError("intent hypothesis must already be registered")
            if type(merged.get("priority", 5)) is not int or not 0 <= merged.get("priority", 5) <= 10:
                raise ValueError("intent priority must be 0..10")
        elif node_kind == "fact":
            if merged.get("basis") not in BASES:
                raise ValueError("fact requires an explicit basis")
            if merged["basis"] == "source-claimed":
                url = urlparse(merged.get("source", ""))
                if url.scheme not in {"http", "https"} or not url.netloc:
                    raise ValueError("source-claimed fact requires an exact source URL")
                try:
                    if datetime.fromisoformat(merged.get("checked_at", "").replace("Z", "+00:00")).tzinfo is None:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise ValueError("source-claimed fact requires checked_at with timezone") from None
        elif node_kind == "hint":
            for field, target_kind in (("goal", "goal"), ("intent", "intent")):
                if merged.get(field) and nodes.get(merged[field], {}).get("kind") != target_kind:
                    raise ValueError("hint scope must reference this target's goal or intent")
        provisional = {**nodes, ref: merged}
        for edge in _edges_for(merged):
            _assert_link(edge["src"], edge["rel"], edge["dst"], provisional,
                         [e for e in graph["edges"] if e not in _edges_for(previous or {})])
    elif kind == "research_state":
        node = nodes.get(data.get("ref"), {})
        if node.get("kind") not in STATES or data.get("state") not in STATES[node["kind"]]:
            raise ValueError("invalid research state")
        if not str(data.get("reason", "")).strip():
            raise ValueError("state transition requires a reason")
        if node["kind"] == "intent":
            if data["state"] not in TRANSITIONS.get(node["state"], set()):
                raise ValueError("invalid intent transition; reopen before retrying")
            if data["state"] == "running" and node.get("missing"):
                raise ValueError("intent prerequisites are not satisfied")
            if data["state"] == "done" and not any(e["src"] == node["ref"] and e["rel"] == "yields" for e in graph["edges"]):
                raise ValueError("record intent outputs before marking done")
    elif kind == "research_link":
        _assert_link(data.get("src"), data.get("rel"), data.get("dst"), nodes, graph["edges"])
    elif kind == "goal_proof":
        goal, source = nodes.get(data.get("goal"), {}), nodes.get(data.get("source"), {})
        if goal.get("kind") != "goal" or goal.get("state") != "open":
            raise ValueError("proof requires an open goal")
        if data.get("criterion") not in {c["id"] for c in goal["criteria"]}:
            raise ValueError("proof must identify an existing acceptance criterion")
        if not source or not _source_eligible(source, goal):
            raise ValueError("goal proof requires eligible, resolvable evidence; hints/digests/inferences do not qualify")
        data.update(source_sha256=fingerprint(source), goal_sha256=fingerprint(_goal_material(goal)))
    elif kind == "research_digest":
        _ref("digest", data.get("id"))
        members = data.get("members", [])
        if not isinstance(members, list) or len(set(members)) < 2:
            raise ValueError("digest requires at least two distinct members")
        for ref in members:
            node = nodes.get(ref, {})
            if node.get("kind") not in {"intent", "fact"} or ref in graph.get("hot", []):
                raise ValueError("only cold facts and settled intents can be summarized")
        data["members"] = sorted(set(members))
        data["member_hashes"] = {r: fingerprint(nodes[r]) for r in data["members"]}
        data.setdefault("text", "\n".join(f"{r} [{nodes[r].get('basis', nodes[r]['state'])}]: {nodes[r]['text'][:160]}" for r in data["members"]))
    validate_shape({"type": kind, **data})
    return data


def append_to_loop(loop, kind, **data):
    """For the existing lock-owning hunt runner; persistence remains its callback."""
    if "evidence" in data:
        data["evidence"] = normalize_evidence(data["evidence"], loop.base_path, events=loop.events)
    loop.append(kind, **normalize_event(kind, data, loop))


def brief(graph, *, limit=8):
    """Small read-only handoff, expanding raw details only on request."""
    active = [d for d in graph["digests"] if d["state"] == "active"]
    covered = {r for d in active for r in d["members"]}
    return {"summary": graph["summary"],
            "goals": [{k: n.get(k) for k in ("ref", "text", "criteria", "satisfied_criteria", "effective_state")}
                      for n in graph["nodes"] if n["kind"] == "goal"],
            "hints": [n for n in graph["nodes"] if n["ref"] in graph["summary"]["active_hints"]][:limit],
            "recent_facts": sorted([n for n in graph["nodes"] if n["kind"] == "fact" and n["ref"] not in covered],
                                   key=lambda n: n["revision"], reverse=True)[:limit],
            "digests": active[-limit:]}


def worker_context(graph, intent):
    """Only relevant goal, input and hint summaries cross the worker boundary."""
    refs = set(intent.get("goals", [])) | set(intent.get("parents", []))
    result = []
    for node in graph["nodes"]:
        relevant_hint = node["kind"] == "hint" and node["state"] == "active" and (
            (not node.get("goal") and not node.get("intent")) or
            node.get("goal") in refs or node.get("intent") == intent["ref"])
        if node["ref"] in refs or relevant_hint:
            text = node["text"][:600]
            evidence_status = f", evidence_valid={node['evidence_valid']}" if "evidence_valid" in node else ""
            basis = f", basis={node['basis']}" if node.get("basis") else ""
            result.append(f"{node['ref']} [state={node['state']}{basis}{evidence_status}]: {text}")
            if node.get("source"):
                result.append(f"source={node['source']} checked_at={node.get('checked_at', 'unknown')}")
            if node["kind"] == "goal":
                result.extend(f"acceptance {c['id']}: {c['text'][:300]}" for c in node["criteria"])
    return result


def settle_test_intent(loop, intent, hypothesis, verdict):
    """Record the bounded runner's real outcome; do not invent a Finding or proof."""
    from hunt_loop import Verdict
    observed = next((e for e in reversed(loop.events) if e["type"] == "logic_verdict"
                     and e.get("hyp_id") == hypothesis), {})
    proof = observed.get("evidence") or next((e.get("evidence") for e in reversed(loop.events)
                  if e["type"] == "verdict" and e.get("hypothesis") == hypothesis), None)
    execution = observed.get("execution", "unknown")
    identifier = "run-" + fingerprint([intent["ref"], len(loop.events)])[:20]
    append_to_loop(loop, "research_node", node_kind="fact", id=identifier,
                   text=f"TEST={observed.get('test_outcome')}; CONTROL={observed.get('control_outcome')}; verdict={verdict.value}; execution={execution}",
                   basis="observed" if execution == "ok" else "unknown", evidence=proof, intent=intent["ref"])
    state = "done" if verdict in {Verdict.CONFIRMED, Verdict.REFUTED} else (
        "blocked" if execution != "ok" or verdict == Verdict.BLOCKED else "exhausted")
    append_to_loop(loop, "research_state", ref=intent["ref"], state=state,
                   reason=f"Bounded test returned {verdict.value}; no automatic goal promotion")


def cli(argv):
    import asg
    parser = argparse.ArgumentParser(description="ASG research provenance; same ledger, no live execution")
    parser.add_argument("target")
    sub = parser.add_subparsers(dest="action", required=True)
    for kind in sorted(KINDS):
        p = sub.add_parser(kind)
        p.add_argument("id")
        p.add_argument("--text")
        p.add_argument("--data-file", type=Path)
        p.add_argument("--amend", action="store_true")
        if kind == "goal":
            p.add_argument("--criterion", action="append", default=[], help="id=text; repeatable")
            p.add_argument("--purpose", choices=["research", "validation"])
            p.add_argument("--parent-goal")
        elif kind == "intent":
            p.add_argument("--goal", action="append", default=[])
            p.add_argument("--parent", action="append", default=[])
            p.add_argument("--depends-on", action="append", default=[])
            p.add_argument("--requires", action="append", default=[])
            p.add_argument("--hypothesis")
            p.add_argument("--priority", type=int)
        elif kind == "fact":
            p.add_argument("--basis", choices=sorted(BASES))
            for flag in ("intent", "evidence", "source", "checked-at", "source-revision"):
                p.add_argument("--" + flag)
        else:
            p.add_argument("--goal")
            p.add_argument("--intent")
    p = sub.add_parser("state")
    p.add_argument("ref"); p.add_argument("state"); p.add_argument("--reason", required=True)
    p = sub.add_parser("link")
    p.add_argument("src"); p.add_argument("rel", choices=sorted(RELATIONS)); p.add_argument("dst")
    p = sub.add_parser("prove")
    p.add_argument("goal"); p.add_argument("criterion"); p.add_argument("source"); p.add_argument("--reason", required=True)
    p = sub.add_parser("digest")
    p.add_argument("id"); p.add_argument("--member", action="append", required=True); p.add_argument("--text")
    for action in ("show", "brief", "expand"):
        p = sub.add_parser(action)
        if action == "expand": p.add_argument("ref")
    args = parser.parse_args(argv)
    try:
        if args.action in KINDS:
            data = json.loads(args.data_file.read_text()) if args.data_file else {}
            if not isinstance(data, dict): raise ValueError("data-file must contain a JSON object")
            for field, value in vars(args).items():
                if field not in {"target", "action", "data_file", "criterion", "goal", "parent", "depends_on"} and value is not None and value != [] and not (field == "amend" and value is False):
                    data[field] = value
            data.update(node_kind=args.action, id=args.id)
            if args.action == "goal" and args.criterion:
                data["criteria"] = [{"id": v.split("=", 1)[0], "text": v.split("=", 1)[1]} for v in args.criterion if "=" in v]
                if len(data["criteria"]) != len(args.criterion): raise ValueError("criterion must use id=text")
            if args.action == "intent":
                for field, values, prefix in (("goals", args.goal, "goal"), ("parents", args.parent, None), ("depends_on", args.depends_on, "intent")):
                    if values: data[field] = [v if not prefix or v.startswith(prefix + ":") else _ref(prefix, v) for v in values]
            else:
                if getattr(args, "goal", None):
                    data["goal"] = args.goal if args.goal.startswith("goal:") else _ref("goal", args.goal)
            for field, prefix in (("intent", "intent"), ("hypothesis", "hypothesis"), ("parent_goal", "goal")):
                if data.get(field) and not data[field].startswith(prefix + ":"): data[field] = _ref(prefix, data[field])
            asg.append_event(args.target, "research_node", **data)
        elif args.action == "state":
            asg.append_event(args.target, "research_state", ref=args.ref, state=args.state, reason=args.reason)
        elif args.action == "link":
            asg.append_event(args.target, "research_link", src=args.src, rel=args.rel, dst=args.dst)
        elif args.action == "prove":
            goal = args.goal if args.goal.startswith("goal:") else _ref("goal", args.goal)
            asg.append_event(args.target, "goal_proof", goal=goal, criterion=args.criterion, source=args.source, reason=args.reason)
        elif args.action == "digest":
            data = {"id": args.id, "members": args.member}
            if args.text: data["text"] = args.text
            asg.append_event(args.target, "research_digest", **data)
        graph = asg.read_state(args.target)["research"]
        if args.action == "expand":
            digest = next((d for d in graph["digests"] if d["ref"] == args.ref), None)
            refs = digest["members"] if digest else [args.ref]
            result = {"nodes": [n for n in graph["nodes"] if n["ref"] in refs], "digest": digest}
            if not result["nodes"]: raise ValueError("research reference not found")
        else:
            result = graph if args.action == "show" else brief(graph)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(f"research operation rejected: {exc}", file=__import__("sys").stderr)
        return 2
