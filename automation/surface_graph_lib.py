#!/usr/bin/env python3
"""Parse + query a per-target Attack Surface Graph file.

The graph file is markdown with one fenced ```yaml``` block (the machine
source of truth). This module is the ONE place that parses it; the
surface-map gate, audit, and canvas renderer all call in here.
"""
from __future__ import annotations
from datetime import datetime
import re
import sys

_STRUCTURAL = {"resolves_to", "hosts", "trusts", "related", "connects_to"}
_OFFENSIVE = {"exploits", "pivots_to", "leads_to"}
_PLACEHOLDER = {"", "—", None}
_YAML_BLOCK = re.compile(r"```yaml\s*\n(.*?)\n```", re.DOTALL)


def load_graph(path: str) -> dict:
    """Return the parsed yaml block as a dict ({} if absent). Raises on bad yaml."""
    import yaml  # deferred so a missing dep is a clear ImportError at call time
    text = open(path, encoding="utf-8").read()
    m = _YAML_BLOCK.search(text)
    if not m:
        return {}
    data = yaml.safe_load(m.group(1))
    return data or {}


def _real_nodes(graph: dict) -> list[dict]:
    nodes = graph.get("nodes") or []
    out = []
    for n in nodes:
        if isinstance(n, dict) and node_identifier(n) not in _PLACEHOLDER:
            out.append(n)
    return out


def node_identifier(node: dict) -> object:
    """Return the canonical identifier, accepting legacy graphs that used label."""
    identifier = node.get("identifier")
    return identifier if identifier not in _PLACEHOLDER else node.get("label")


def count_nodes(path: str) -> int:
    return len(_real_nodes(load_graph(path)))


def node_identifiers(path: str) -> list[str]:
    return [str(node_identifier(n)) for n in _real_nodes(load_graph(path))]


def edge_category(rel: str) -> str:
    if rel in _STRUCTURAL:
        return "structural"
    if rel in _OFFENSIVE:
        return "offensive"
    return "unknown"


def discovery_time_coverage(graph: dict) -> tuple[int, int]:
    nodes = _real_nodes(graph)
    return sum(node.get("discovered_at") is not None for node in nodes), len(nodes)


def _timestamp(value: object, label: str, errors: list[str]) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"{label} must be an RFC3339 timestamp with timezone")
            return None
    else:
        errors.append(f"{label} must be an RFC3339 timestamp with timezone")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{label} must be an RFC3339 timestamp with timezone")
        return None
    return parsed


def validate_temporal_provenance(graph: dict) -> list[str]:
    """Validate node discovery times and separately recorded command intervals.

    Missing discovery timestamps are mandatory for schema_version >= 2. Legacy
    graphs remain readable, but any temporal fields they do contain are still
    validated.
    """
    errors: list[str] = []
    try:
        schema_version = int(graph.get("schema_version", 1))
    except (TypeError, ValueError):
        errors.append("schema_version must be an integer")
        schema_version = 1

    nodes = _real_nodes(graph)
    nodes_by_id: dict[str, dict] = {}
    for node in nodes:
        node_id = str(node.get("id", "")).strip()
        if not node_id:
            errors.append("node: id is required")
            continue
        if node_id in nodes_by_id:
            errors.append(f"node {node_id}: duplicate id")
            continue
        nodes_by_id[node_id] = node

    raw_runs = graph.get("command_runs") or []
    if not isinstance(raw_runs, list):
        errors.append("command_runs must be a list")
        raw_runs = []
    runs_by_id: dict[str, dict] = {}
    run_intervals: dict[str, tuple[datetime, datetime]] = {}
    for raw_run in raw_runs:
        if not isinstance(raw_run, dict):
            errors.append("command_run: entry must be a mapping")
            continue
        run_id = str(raw_run.get("id", "")).strip()
        if not run_id:
            errors.append("command_run: id is required")
            continue
        if run_id in runs_by_id:
            errors.append(f"command_run {run_id}: duplicate id")
            continue
        runs_by_id[run_id] = raw_run

        command = raw_run.get("command")
        if not isinstance(command, str) or not command.strip():
            errors.append(f"command_run {run_id}: command is required")
        started = _timestamp(
            raw_run.get("started_at"), f"command_run {run_id}: started_at", errors
        )
        finished = _timestamp(
            raw_run.get("finished_at"), f"command_run {run_id}: finished_at", errors
        )
        if started is not None and finished is not None:
            if finished < started:
                errors.append(f"command_run {run_id}: finished_at precedes started_at")
            else:
                run_intervals[run_id] = (started, finished)

        for field in ("discovered_nodes", "observed_nodes"):
            references = raw_run.get(field) or []
            if not isinstance(references, list):
                errors.append(f"command_run {run_id}: {field} must be a list")
                continue
            for reference in references:
                node_id = str(reference)
                if node_id not in nodes_by_id:
                    errors.append(
                        f"command_run {run_id}: {field} references unknown node {node_id}"
                    )

    for node_id, node in nodes_by_id.items():
        discovered_value = node.get("discovered_at")
        discovered = None
        if discovered_value is None:
            if schema_version >= 2:
                errors.append(
                    f"node {node_id}: discovered_at is required by schema_version {schema_version}"
                )
        else:
            discovered = _timestamp(
                discovered_value, f"node {node_id}: discovered_at", errors
            )

        last_seen = None
        if node.get("last_seen_at") is not None:
            last_seen = _timestamp(
                node.get("last_seen_at"), f"node {node_id}: last_seen_at", errors
            )
        if discovered is not None and last_seen is not None and last_seen < discovered:
            errors.append(f"node {node_id}: last_seen_at precedes discovered_at")

        discovered_by = node.get("discovered_by")
        if discovered_by in (None, "", "manual"):
            continue
        run_id = str(discovered_by)
        run = runs_by_id.get(run_id)
        if run is None:
            errors.append(
                f"node {node_id}: discovered_by references unknown command_run {run_id}"
            )
            continue
        if node_id not in [str(value) for value in (run.get("discovered_nodes") or [])]:
            errors.append(
                f"node {node_id}: command_run {run_id} does not list it in discovered_nodes"
            )
        interval = run_intervals.get(run_id)
        if discovered is not None and interval is not None:
            started, finished = interval
            if discovered < started or discovered > finished:
                errors.append(
                    f"node {node_id}: discovered_at falls outside command_run {run_id} interval"
                )

    for run_id, run in runs_by_id.items():
        for reference in run.get("discovered_nodes") or []:
            node = nodes_by_id.get(str(reference))
            if node is not None and str(node.get("discovered_by", "")) != run_id:
                errors.append(
                    f"command_run {run_id}: node {reference} does not point back via discovered_by"
                )

    return errors


def set_disposition(path: str, node_id: str, disposition: str, note: str | None = None) -> int:
    """Surgically set a node's `disposition` via line edit (preserves comments/formatting).

    Does NOT reserialize the YAML (that would strip the human-maintained `# ===` comments).
    Locates the `- id: <node_id>` block, replaces/inserts its `disposition:` line, then
    re-parses to confirm the write took (returns 6 if the file no longer parses cleanly).
    """
    import re
    import datetime

    allowed = {"untested", "suspected", "validated", "covered", "false_positive", "blocked", "deferred"}
    if disposition not in allowed:
        print(
            f"surface_graph_lib: warning: unusual disposition '{disposition}' (allowed: {sorted(allowed)})",
            file=sys.stderr,
        )
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except Exception as e:
        print(f"surface_graph_lib: cannot read {path}: {e}", file=sys.stderr)
        return 3
    lines = text.split("\n")
    id_re = re.compile(r'^(\s*)-\s+id:\s*["\']?' + re.escape(node_id) + r'["\']?\s*$')
    start = dash_indent = None
    for i, ln in enumerate(lines):
        m = id_re.match(ln)
        if m:
            start, dash_indent = i, len(m.group(1))
            break
    if start is None:
        print(f"surface_graph_lib: node id not found: {node_id}", file=sys.stderr)
        return 5
    end = len(lines)
    field_indent = dash_indent + 2
    got_field_indent = False
    for j in range(start + 1, len(lines)):
        ln = lines[j]
        if ln.strip() == "" or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent <= dash_indent:
            end = j
            break
        if not got_field_indent:
            field_indent, got_field_indent = indent, True
    disp_re = re.compile(r"^\s*disposition:\s*.*$")
    disp_idx = next((j for j in range(start, end) if disp_re.match(lines[j])), None)
    new_line = " " * field_indent + f"disposition: {disposition}"
    if note:
        new_line += f"  # {note} ({datetime.date.today().isoformat()})"
    if disp_idx is not None:
        lines[disp_idx] = new_line
    else:
        lines.insert(start + 1, new_line)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    try:
        g = load_graph(path)
        ok = any(
            str(n.get("id")) == node_id and n.get("disposition") == disposition
            for n in _real_nodes(g)
        )
        if not ok:
            print(
                f"surface_graph_lib: WARNING wrote but re-parse did not confirm disposition for {node_id}",
                file=sys.stderr,
            )
            return 6
    except Exception as e:
        print(f"surface_graph_lib: WARNING file may be malformed after edit: {e}", file=sys.stderr)
        return 6
    print(f"{node_id}: disposition -> {disposition}")
    return 0


def _main(argv: list[str]) -> int:
    if len(argv) >= 5 and argv[1] == "set-disposition":
        return set_disposition(argv[2], argv[3], argv[4], argv[5] if len(argv) > 5 else None)
    if len(argv) == 3 and argv[1] in {
        "count-nodes",
        "discovery-coverage",
        "validate-provenance",
    }:
        try:
            if argv[1] == "count-nodes":
                print(count_nodes(argv[2]))
                return 0
            graph = load_graph(argv[2])
            if argv[1] == "discovery-coverage":
                timed, total = discovery_time_coverage(graph)
                print(f"{timed}/{total}")
                return 0
            errors = validate_temporal_provenance(graph)
            if errors:
                for error in errors:
                    print(f"surface_graph_lib: {error}", file=sys.stderr)
                return 4
            return 0
        except Exception as e:  # parse error / bad yaml → let caller fail-open
            print(f"surface_graph_lib: parse error: {e}", file=sys.stderr)
            return 3
    print(
        "usage: surface_graph_lib.py <count-nodes|discovery-coverage|validate-provenance> <graph-file>\n"
        "       surface_graph_lib.py set-disposition <graph-file> <node-id> <disposition> [note]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
