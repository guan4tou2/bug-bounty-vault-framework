#!/usr/bin/env python3
"""Read-only JSON Canvas projection of ASG research provenance."""
import hashlib
import json
from pathlib import Path


def build_research_canvas(target: str) -> dict:
    """Research provenance in its own read-only Canvas view of the same ledger."""
    import asg
    graph = asg.read_state(target)["research"]
    kind_cols = {"root": 0, "goal": 1, "hint": 1, "intent": 2,
                 "fact": 3, "finding": 4, "hypothesis": 4, "digest": 5}
    colors = {"goal": "4", "intent": "5", "fact": "2", "finding": "1", "hint": "6", "digest": "3"}
    labels = {relation: relation for relation in ("spawns", "derived_from", "yields", "proves",
              "covers", "depends_on", "tests")}
    rows, nodes = {}, []
    for node in graph["nodes"] + graph["digests"]:
        col = kind_cols[node["kind"]]
        row = rows.get(col, 0)
        rows[col] = row + 1
        state = node.get("effective_state", node.get("state", ""))
        basis = f" / {node['basis']}" if node.get("basis") else ""
        nodes.append({"id": node["ref"], "type": "text", "x": col * 350, "y": row * 170,
                      "width": 320, "height": 145,
                      "text": f"**{node['ref']}** [{state}{basis}]\n{node['text']}",
                      "color": colors.get(node["kind"], "0")})
    ids = {n["id"] for n in nodes}
    edges = []
    for edge in graph["edges"]:
        if edge["src"] not in ids or edge["dst"] not in ids:
            continue
        material = json.dumps(edge, sort_keys=True, ensure_ascii=False)
        identifier = hashlib.sha256(material.encode()).hexdigest()[:20]
        edges.append({"id": identifier, "fromNode": edge["src"], "toNode": edge["dst"],
                      "fromSide": "right", "toSide": "left", "toEnd": "arrow",
                      "label": labels[edge["rel"]] + (" [stale]" if edge.get("valid") is False else ""),
                      "color": "1" if edge.get("valid") is False else "2"})
    return {"nodes": nodes, "edges": edges}


def write_research_canvas(target) -> Path:
    import asg
    output = asg.markdown_path(target).with_suffix("")
    output = output.with_name(output.name + " - research.canvas")
    output.write_text(json.dumps(build_research_canvas(target), ensure_ascii=False,
                                 indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main(argv=None):
    import argparse
    import asg
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research", action="store_true", required=True)
    parser.add_argument("source", help="Target name, target directory or its ASG Markdown")
    args = parser.parse_args(argv)
    target = asg.target_dir(args.source)
    print(write_research_canvas(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
