#!/usr/bin/env python3
"""Query engine for CHAIN_GRAPH.md attack chain graphs.

Parses the markdown node/edge tables and supports path queries, cost-based
ranking, kill chain coverage analysis, and summary statistics.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TextIO

# ── Cost model (Decepticon-inspired) ────────────────────────────────────────

EDGE_BASE_COST: dict[str, float] = {
    "credential-chain": 2.0,
    "access-escalation": 3.0,
    "lateral-movement": 4.0,
    "data-chain": 1.0,
    "config-chain": 2.0,
    "trust-boundary": 5.0,
}
DEFAULT_BASE_COST = 3.0

CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "verified": 1.0,
    "theoretical": 2.0,
    "speculative": 5.0,
}
DEFAULT_CONF_MULT = 3.0

KILL_CHAIN_STAGES = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class Node:
    id: str
    type: str = ""
    component: str = ""
    severity: str = ""
    stage: str = ""
    status: str = ""
    requires: str = ""
    yields: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


@dataclass
class Edge:
    source: str
    target: str
    type: str = ""
    confidence: str = ""
    rationale: str = ""

    @property
    def cost(self) -> float:
        base = EDGE_BASE_COST.get(self.type.lower(), DEFAULT_BASE_COST)
        mult = CONFIDENCE_MULTIPLIER.get(self.confidence.lower(), DEFAULT_CONF_MULT)
        return base * mult

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v}
        d["cost"] = self.cost
        return d


@dataclass
class ChainGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    _adj: dict[str, list[Edge]] = field(default_factory=lambda: defaultdict(list))

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)
        self._adj[edge.source].append(edge)

    def neighbors(self, node_id: str) -> list[Edge]:
        return self._adj.get(node_id, [])

    def entry_nodes(self) -> list[str]:
        targets = {e.target for e in self.edges}
        sources = {e.source for e in self.edges}
        roots = sources - targets
        for nid, n in self.nodes.items():
            if "unauth" in n.requires.lower():
                roots.add(nid)
        return sorted(roots) if roots else sorted(self.nodes.keys())

    def terminal_nodes(self) -> list[str]:
        sources = {e.source for e in self.edges}
        targets = {e.target for e in self.edges}
        return sorted(targets - sources) if (targets - sources) else sorted(self.nodes.keys())


# ── Markdown parser ─────────────────────────────────────────────────────────

_TABLE_ROW = re.compile(r"^\|(.+)\|$")
_SEP_ROW = re.compile(r"^\|[\s:|-]+\|$")


def _parse_table(lines: list[str]) -> list[dict[str, str]]:
    rows: list[list[str]] = []
    headers: list[str] | None = None
    for line in lines:
        line = line.strip()
        m = _TABLE_ROW.match(line)
        if not m:
            if headers is not None:
                break
            continue
        if _SEP_ROW.match(line):
            continue
        cells = [c.strip() for c in m.group(1).split("|")]
        if headers is None:
            headers = [h.lower().replace(" ", "_") for h in cells]
        else:
            rows.append(cells)
    if headers is None:
        return []
    result = []
    for cells in rows:
        padded = cells + [""] * (len(headers) - len(cells))
        result.append(dict(zip(headers, padded[: len(headers)])))
    return result


def parse_chain_graph(fp: TextIO) -> ChainGraph:
    text = fp.read()
    graph = ChainGraph()
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        hdr = re.match(r"^##\s+(\w+)", line)
        if hdr:
            current = hdr.group(1).lower()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    for row in _parse_table(sections.get("nodes", [])):
        graph.add_node(Node(
            id=row.get("id", ""),
            type=row.get("type", ""),
            component=row.get("component", ""),
            severity=row.get("severity", ""),
            stage=row.get("stage", ""),
            status=row.get("status", ""),
            requires=row.get("requires", ""),
            yields=row.get("yields", row.get("yield", "")),
        ))
    for row in _parse_table(sections.get("edges", [])):
        graph.add_edge(Edge(
            source=row.get("source", ""),
            target=row.get("target", ""),
            type=row.get("type", ""),
            confidence=row.get("confidence", ""),
            rationale=row.get("rationale", ""),
        ))
    return graph


# ── Graph queries ───────────────────────────────────────────────────────────

@dataclass
class Path:
    nodes: list[str]
    edges: list[Edge]

    @property
    def cost(self) -> float:
        return sum(e.cost for e in self.edges)

    @property
    def weakest_confidence(self) -> str:
        order = ["verified", "theoretical", "speculative"]
        worst = 0
        for e in self.edges:
            c = e.confidence.lower()
            idx = order.index(c) if c in order else len(order)
            worst = max(worst, idx)
        return order[worst] if worst < len(order) else "unknown"

    def to_dict(self, graph: ChainGraph) -> dict:
        stages = []
        for nid in self.nodes:
            n = graph.nodes.get(nid)
            if n and n.stage:
                for s in n.stage.split(","):
                    s = s.strip()
                    if s and s not in stages:
                        stages.append(s)
        final_node = graph.nodes.get(self.nodes[-1])
        return {
            "nodes": self.nodes,
            "edges": [e.to_dict() for e in self.edges],
            "cost": self.cost,
            "confidence": self.weakest_confidence,
            "kill_chain_progression": stages,
            "final_severity": final_node.severity if final_node else "",
            "length": len(self.edges),
        }


def _find_paths(graph: ChainGraph, start: str, end: str | None,
                max_depth: int = 15) -> list[Path]:
    results: list[Path] = []

    def dfs(current: str, visited: set[str], path_nodes: list[str],
            path_edges: list[Edge]) -> None:
        if len(path_edges) > max_depth:
            return
        if end is not None and current == end:
            results.append(Path(list(path_nodes), list(path_edges)))
            return
        edges = graph.neighbors(current)
        if not edges and end is None and len(path_edges) > 0:
            results.append(Path(list(path_nodes), list(path_edges)))
            return
        for edge in edges:
            if edge.target not in visited:
                visited.add(edge.target)
                path_nodes.append(edge.target)
                path_edges.append(edge)
                dfs(edge.target, visited, path_nodes, path_edges)
                path_edges.pop()
                path_nodes.pop()
                visited.discard(edge.target)

    visited = {start}
    dfs(start, visited, [start], [])
    return results


def _resolve_node_set(graph: ChainGraph, spec: str) -> list[str]:
    if spec in graph.nodes:
        return [spec]
    low = spec.lower()
    if low == "unauthenticated":
        return [nid for nid, n in graph.nodes.items()
                if "unauth" in n.requires.lower()]
    if low in SEVERITY_RANK:
        return [nid for nid, n in graph.nodes.items()
                if n.severity.lower() == low]
    if low in KILL_CHAIN_STAGES:
        return [nid for nid, n in graph.nodes.items()
                if low in n.stage.lower()]
    return graph.entry_nodes() if low == "entry" else []


def query_paths(graph: ChainGraph, from_spec: str | None, to_spec: str | None,
                cheapest: bool = False) -> list[dict]:
    starts = _resolve_node_set(graph, from_spec) if from_spec else graph.entry_nodes()
    ends = _resolve_node_set(graph, to_spec) if to_spec else [None]  # type: ignore[list-item]
    all_paths: list[Path] = []
    for s in starts:
        for e in ends:
            all_paths.extend(_find_paths(graph, s, e))
    seen: set[tuple[str, ...]] = set()
    deduped: list[Path] = []
    for p in all_paths:
        key = tuple(p.nodes)
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    if cheapest:
        deduped.sort(key=lambda p: p.cost)
    return [p.to_dict(graph) for p in deduped]


def query_coverage(graph: ChainGraph) -> dict:
    covered: set[str] = set()
    for n in graph.nodes.values():
        for s in n.stage.lower().split(","):
            s = s.strip()
            if s in KILL_CHAIN_STAGES:
                covered.add(s)
    return {
        "covered": sorted(covered),
        "total_stages": len(KILL_CHAIN_STAGES),
        "covered_count": len(covered),
        "coverage_pct": round(100 * len(covered) / len(KILL_CHAIN_STAGES), 1),
    }


def query_gaps(graph: ChainGraph) -> dict:
    cov = query_coverage(graph)
    covered = set(cov["covered"])
    gaps = [s for s in KILL_CHAIN_STAGES if s not in covered]
    return {"gaps": gaps, "gap_count": len(gaps), **cov}


def query_summary(graph: ChainGraph) -> dict:
    paths = query_paths(graph, None, None, cheapest=True)
    cheapest = paths[0] if paths else None
    highest: dict | None = None
    for p in paths:
        sev = p.get("final_severity", "").lower()
        if highest is None or SEVERITY_RANK.get(sev, -1) > SEVERITY_RANK.get(
                highest.get("final_severity", "").lower(), -1):
            highest = p
    cov = query_coverage(graph)
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "paths": len(paths),
        "cheapest_path": cheapest,
        "highest_impact_path": highest,
        "kill_chain": cov,
    }


# ── Table formatter ─────────────────────────────────────────────────────────

def _fmt_table(paths: list[dict]) -> str:
    if not paths:
        return "(no paths found)"
    lines = ["| # | Path | Cost | Confidence | Stages | Final Severity |",
             "|---|------|------|------------|--------|----------------|"]
    for i, p in enumerate(paths, 1):
        chain = " → ".join(p["nodes"])
        stages = " → ".join(p.get("kill_chain_progression", []))
        lines.append(
            f"| {i} | {chain} | {p['cost']:.1f} | {p['confidence']} "
            f"| {stages} | {p.get('final_severity', '')} |"
        )
    return "\n".join(lines)


def _fmt_coverage(data: dict) -> str:
    lines = [f"Kill chain coverage: {data['covered_count']}/{data['total_stages']}"
             f" ({data['coverage_pct']}%)"]
    for s in KILL_CHAIN_STAGES:
        mark = "✅" if s in data.get("covered", []) else "⬜"
        lines.append(f"  {mark} {s}")
    return "\n".join(lines)


def _fmt_gaps(data: dict) -> str:
    lines = [f"Kill chain gaps: {data['gap_count']}"]
    for g in data.get("gaps", []):
        lines.append(f"  ⬜ {g}")
    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Query engine for CHAIN_GRAPH.md attack chain graphs.")
    ap.add_argument("graph", help="Path to CHAIN_GRAPH.md")
    ap.add_argument("--from", dest="from_spec", help="Start node, stage, severity, or 'unauthenticated'")
    ap.add_argument("--to", dest="to_spec", help="End node, stage, severity, or 'impact'")
    ap.add_argument("--all-paths", action="store_true", help="Enumerate all paths")
    ap.add_argument("--cheapest", action="store_true", help="Sort paths by cost (ascending)")
    ap.add_argument("--coverage", action="store_true", help="Kill chain stage coverage")
    ap.add_argument("--gaps", action="store_true", help="Kill chain stage gaps")
    ap.add_argument("--progression", action="store_true", help="Show kill chain progression per path")
    ap.add_argument("--summary", action="store_true", help="Graph summary statistics")
    ap.add_argument("--table", action="store_true", help="Human-readable table output")
    args = ap.parse_args()

    with open(args.graph, encoding="utf-8") as f:
        graph = parse_chain_graph(f)

    if not graph.nodes:
        print(json.dumps({"error": "no nodes parsed from graph"}), file=sys.stderr)
        sys.exit(1)

    if args.summary:
        result = query_summary(graph)
        print(json.dumps(result, indent=2))
        return

    if args.coverage:
        result = query_coverage(graph)
        if args.table:
            print(_fmt_coverage(result))
        else:
            print(json.dumps(result, indent=2))
        return

    if args.gaps:
        result = query_gaps(graph)
        if args.table:
            print(_fmt_gaps(result))
        else:
            print(json.dumps(result, indent=2))
        return

    from_spec = args.from_spec
    to_spec = args.to_spec
    if args.all_paths:
        from_spec = from_spec or None
        to_spec = to_spec or None

    if not args.all_paths and not from_spec and not to_spec:
        ap.print_help()
        sys.exit(0)

    paths = query_paths(graph, from_spec, to_spec, cheapest=args.cheapest)
    if args.table:
        print(_fmt_table(paths))
    else:
        print(json.dumps(paths, indent=2))


if __name__ == "__main__":
    main()
