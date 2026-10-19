"""One strict JSONL read contract for every ASG projection.

Missing ledgers mean no stored events. Existing unreadable/corrupt ledgers are
unavailable state, never an empty or partially reconstructed work queue.
"""
from pathlib import Path
import json
import re


def _research_history(event, definitions, known_refs, links, finding_links):
    """Check historical structure without rejudging now-stale evidence."""
    from asg_research import (validate_shape, _ref, _edges_for, _assert_link,
                              STATES, TRANSITIONS)
    validate_shape(event)
    kind = event["type"]
    nodes = {r: {"ref": r, "kind": r.partition(":")[0]} for r in known_refs}
    nodes.update({r: {**d, "ref": r, "kind": d["node_kind"]} for r, d in definitions.items()})
    edges = links + list(finding_links.values()) + [edge for n in nodes.values() for edge in _edges_for(n)]
    if kind == "research_node":
        if "state" in event:
            raise ValueError("research states require separate transition events")
        ref = _ref(event["node_kind"], event["id"])
        previous = definitions.get(ref)
        if bool(previous) != bool(event.get("amend")):
            raise ValueError("research amendments require an original node")
        merged = {**(previous or {}), **event, "amend": False}
        validate_shape({k: v for k, v in merged.items() if k != "state"})
        references = [r for field in ("goals", "parents", "depends_on") for r in merged.get(field, [])]
        references += [merged[f] for f in ("parent_goal", "hypothesis", "intent", "goal") if merged.get(f)]
        if any(r not in known_refs for r in references):
            raise ValueError("research reference is unavailable")
        node_kind = event["node_kind"]
        if node_kind == "intent" and any(nodes[g]["kind"] != "goal" for g in merged["goals"]):
            raise ValueError("intent requires goal references")
        if node_kind == "goal":
            criteria = merged["criteria"]
            if (merged.get("purpose", "validation") not in {"research", "validation"}
                    or len({c["id"] for c in criteria}) != len(criteria)):
                raise ValueError("invalid goal definition")
        if node_kind == "intent" and (type(merged.get("priority", 5)) is not int
                                      or not 0 <= merged.get("priority", 5) <= 10):
            raise ValueError("invalid intent priority")
        if node_kind == "hint":
            for field in ("goal", "intent"):
                if merged.get(field) and nodes[merged[field]]["kind"] != field:
                    raise ValueError("invalid hint scope")
        node = {**merged, "ref": ref, "kind": node_kind}
        provisional = {**nodes, ref: node}
        old_edges = _edges_for(nodes.get(ref))
        for edge in _edges_for(node):
            _assert_link(edge["src"], edge["rel"], edge["dst"], provisional,
                         [e for e in edges if e not in old_edges])
        merged.setdefault("state", "open" if node_kind in {"goal", "intent"} else "active")
        definitions[ref] = merged
        known_refs.add(ref)
    elif kind == "research_state":
        ref = event["ref"]
        node_kind = ref.partition(":")[0]
        if ref not in definitions or event["state"] not in STATES.get(node_kind, set()):
            raise ValueError("invalid research state reference")
        if node_kind == "intent" and event["state"] not in TRANSITIONS.get(definitions[ref]["state"], set()):
            raise ValueError("invalid historical intent transition")
        definitions[ref]["state"] = event["state"]
    elif kind == "research_link":
        _assert_link(event["src"], event["rel"], event["dst"], nodes, edges)
        links.append({k: event[k] for k in ("src", "rel", "dst")})
    elif kind == "goal_proof":
        goal = definitions.get(event["goal"], {})
        if (goal.get("node_kind") != "goal" or event["source"] not in known_refs
                or event["source"].partition(":")[0] not in {"fact", "finding"}
                or event["criterion"] not in {c["id"] for c in goal["criteria"]}):
            raise ValueError("invalid proof reference")
        if any(not re.fullmatch(r"[a-f0-9]{64}", event[f]) for f in ("source_sha256", "goal_sha256")):
            raise ValueError("invalid proof fingerprint")
    elif kind == "research_digest":
        _ref("digest", event["id"])
        members = event["members"]
        if (len(members) < 2 or len(set(members)) != len(members)
                or any(r not in definitions or definitions[r]["node_kind"] not in {"fact", "intent"} for r in members)
                or set(event["member_hashes"]) != set(members)
                or any(not isinstance(h, str) or not re.fullmatch(r"[a-f0-9]{64}", h)
                       for h in event["member_hashes"].values())):
            raise ValueError("invalid digest membership")


class LedgerReadError(ValueError):
    def __init__(self, path, line, reason):
        self.path, self.line, self.reason = Path(path), line, reason
        super().__init__(f"ledger unavailable: {self.path}:{line}: {reason}")


def read_ledger_events(path: str | Path) -> list[dict]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        raise LedgerReadError(path, 0, type(exc).__name__) from exc
    events = []
    research_definitions = {}
    known_refs = {"root"}
    research_links = []
    finding_links = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            # Do not include raw event text, which can contain credentials.
            raise LedgerReadError(path, number, "invalid JSON") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str) or not event["type"]:
            raise LedgerReadError(path, number, "event requires a non-empty type")
        required = {
            "surface": ("name",), "hypothesis": ("id",),
            "verdict": ("hypothesis", "status"), "revoke": ("cap",),
            "finding": ("finding_id",), "finding_state": ("finding_id", "to"),
            "dead_end": ("hyp_id",), "evidence": ("id", "evidence"),
        }.get(event["type"], ())
        if any(key not in event for key in required):
            raise LedgerReadError(path, number, f"{event['type']} event missing required field")
        for key in required:
            if key != "evidence" and (not isinstance(event[key], str) or not event[key].strip()):
                raise LedgerReadError(path, number, f"{event['type']} event requires string {key}")
        for key in ("requires", "provides"):
            if key in event and (not isinstance(event[key], list)
                                 or any(not isinstance(item, str) or not item for item in event[key])):
                raise LedgerReadError(path, number, f"event requires a list of strings for {key}")
        from asg_research import EVENTS
        if event["type"] in EVENTS:
            try:
                _research_history(event, research_definitions, known_refs, research_links, finding_links)
            except (ValueError, TypeError, KeyError):
                raise LedgerReadError(path, number, "invalid research event shape") from None
        if event["type"] == "finding":
            fid = event["finding_id"]
            if "intent_id" in event:
                from asg_research import _assert_link, _edges_for
                intent = event["intent_id"]
                if not isinstance(intent, str) or not intent.strip():
                    raise LedgerReadError(path, number, "invalid finding intent reference")
                src, dst = f"intent:{intent}", f"finding:{fid}"
                nodes = {r: {"ref": r, "kind": r.partition(":")[0]} for r in known_refs}
                nodes.update({r: {**d, "ref": r, "kind": d["node_kind"]} for r, d in research_definitions.items()})
                nodes[dst] = {"ref": dst, "kind": "finding"}
                # Replacing this canonical automatic yield must not remove an
                # explicit research_link with the same endpoints.
                edges = research_links + [e for key, e in finding_links.items() if key != fid]
                edges += [e for n in nodes.values() for e in _edges_for(n)]
                try:
                    _assert_link(src, "yields", dst, nodes, edges)
                except (ValueError, TypeError, KeyError):
                    raise LedgerReadError(path, number, "invalid finding intent lineage") from None
                finding_links[fid] = {"src": src, "rel": "yields", "dst": dst}
            known_refs.add(f"finding:{fid}")
        elif event["type"] == "hypothesis":
            known_refs.add(f"hypothesis:{event['id']}")
        events.append(event)
    return events
