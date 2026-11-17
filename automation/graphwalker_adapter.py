"""Optional bounded GraphWalker offline planner; generated paths never authorize tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from flow_model import graphwalker_topology


def generate(definition, binary, *, length=20, seed=42, timeout=30):
    if type(length) is not int or not 1 <= length <= 200 or type(seed) is not int or not 1 <= seed < 2**64:
        raise ValueError("bounded path length 1..200 and a nonzero u64 seed required")
    if not 0 < timeout <= 120:
        raise ValueError("bounded runtime required")
    binary = str(Path(binary).resolve(strict=True))
    prefix = []
    if os.uname().sysname == "Darwin":
        prefix = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"]
    version = subprocess.run(
        [*prefix, binary, "--version"], capture_output=True, text=True, timeout=timeout, check=True
    ).stdout.strip()
    if not version.startswith("graphwalker 1.0.4 "):
        raise ValueError("this adapter was verified with GraphWalker 1.0.4; review a new runtime before adoption")
    model = graphwalker_topology(definition)
    model["models"][0]["generator"] = f"random(length({length}))"
    with tempfile.TemporaryDirectory(prefix="vault-graphwalker-") as directory:
        path = Path(directory) / "model.json"
        path.write_text(json.dumps(model))
        checked = subprocess.run(
            [*prefix, binary, "check", "--gw", str(path)], capture_output=True, text=True, timeout=timeout, check=True
        )
        result = subprocess.run(
            [*prefix, binary, "offline", "--gw", str(path), "--seed", str(seed)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    edges = {edge["id"]: edge for edge in model["models"][0]["edges"]}
    vertices = {vertex["id"] for vertex in model["models"][0]["vertices"]}
    if len(rows) > length + 1 or not rows:
        raise ValueError("runtime did not honor the bounded generator")
    path = []
    for row in rows:
        identifier = row.get("currentElementId")
        if row.get("modelId") != definition["flow_id"] or identifier not in edges.keys() | vertices:
            raise ValueError("runtime returned unknown model elements")
        if identifier in edges:
            if path and edges[path[-1]]["targetVertexId"] != edges[identifier]["sourceVertexId"]:
                raise ValueError("generated transitions are discontinuous")
            path.append(identifier)
    return {
        "stage": "planned",
        "flow_id": definition["flow_id"],
        "runtime": version,
        "length_bound": length,
        "seed": seed,
        "network_denied": bool(prefix),
        "model_sha256": hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest(),
        "transition_ids": path,
        "elements": rows,
        "check_receipt": checked.stdout.strip(),
        "generated_transitions": sorted(set(path)),
        "security_coverage": "not-established",
        "authorization": "not-granted-by-generated-path",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("definition", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--length", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(
        json.dumps(
            generate(json.loads(args.definition.read_text()), args.binary, length=args.length, seed=args.seed), indent=2
        )
    )


if __name__ == "__main__":
    main()
