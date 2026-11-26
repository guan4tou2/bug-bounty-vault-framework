#!/usr/bin/env python3
"""api_schema_diff.py — Compare OpenAPI spec vs discovered endpoints.

Finds endpoints present in recon but missing from the spec (shadow/undocumented),
endpoints in the spec but not seen in recon (untested), and parameter mismatches.

Usage:
    python3 -I automation/api_schema_diff.py --spec openapi.json --recon RECON_DB.md [--json] [--table]
    python3 -I automation/api_schema_diff.py --spec openapi.yaml --discovered endpoints.txt [--json]

Input formats:
    --spec: OpenAPI 3.x JSON or YAML file
    --recon: Vault RECON_DB.md (parses endpoint tables)
    --discovered: plain text file, one endpoint per line (METHOD /path)
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def load_spec(path: str) -> dict[str, Any]:
    """Load OpenAPI spec from JSON or YAML."""
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
            return yaml.safe_load(text)
        except ImportError:
            sys.exit("PyYAML required for YAML specs. Install: pip install pyyaml")
    return json.loads(text)


def extract_spec_endpoints(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract endpoints from OpenAPI spec as {METHOD /path: {params, ...}}."""
    endpoints: dict[str, dict[str, Any]] = {}
    base = ""
    if "servers" in spec and spec["servers"]:
        url = spec["servers"][0].get("url", "")
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = parsed.path.rstrip("/")

    paths = spec.get("paths", {})
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        full_path = base + path_template if base else path_template
        path_params = [
            p["name"] for p in path_item.get("parameters", [])
            if isinstance(p, dict) and "name" in p
        ]
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method not in path_item:
                continue
            op = path_item[method]
            if not isinstance(op, dict):
                continue
            params = list(path_params)
            for p in op.get("parameters", []):
                if isinstance(p, dict) and "name" in p and p["name"] not in params:
                    params.append(p["name"])
            body_params: list[str] = []
            rb = op.get("requestBody", {})
            if isinstance(rb, dict):
                content = rb.get("content", {})
                for ct_obj in content.values():
                    if isinstance(ct_obj, dict) and "schema" in ct_obj:
                        schema = ct_obj["schema"]
                        if isinstance(schema, dict):
                            body_params.extend(schema.get("properties", {}).keys())

            key = f"{method.upper()} {full_path}"
            endpoints[key] = {
                "params": sorted(set(params)),
                "body_params": sorted(set(body_params)),
                "summary": op.get("summary", ""),
                "operation_id": op.get("operationId", ""),
                "deprecated": op.get("deprecated", False),
                "security": bool(op.get("security", spec.get("security"))),
            }
    return endpoints


def normalize_path(path: str) -> str:
    """Normalize path for comparison: /users/123/posts → /users/{id}/posts."""
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    path = re.sub(r"/[0-9a-f]{24,}", "/{id}", path)
    return path


def parse_recon_endpoints(path: str) -> dict[str, dict[str, Any]]:
    """Parse endpoints from RECON_DB.md tables."""
    text = Path(path).read_text(encoding="utf-8")
    endpoints: dict[str, dict[str, Any]] = {}
    endpoint_re = re.compile(
        r"\|\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\|\s*([^\|]+)\s*\|",
        re.IGNORECASE,
    )
    url_method_re = re.compile(
        r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S+)", re.IGNORECASE
    )
    for line in text.splitlines():
        m = endpoint_re.search(line)
        if m:
            method = m.group(1).upper()
            path_str = m.group(2).strip()
            key = f"{method} {path_str}"
            endpoints[key] = {"source": "recon_table"}
            continue
        m = url_method_re.search(line)
        if m:
            method = m.group(1).upper()
            path_str = m.group(2).strip()
            key = f"{method} {path_str}"
            endpoints[key] = {"source": "recon_text"}
    return endpoints


def parse_discovered_endpoints(path: str) -> dict[str, dict[str, Any]]:
    """Parse endpoints from plain text file (METHOD /path per line)."""
    endpoints: dict[str, dict[str, Any]] = {}
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            method, path_str = parts[0].upper(), parts[1]
            key = f"{method} {path_str}"
            endpoints[key] = {"source": "discovered"}
        elif len(parts) == 1 and parts[0].startswith("/"):
            key = f"GET {parts[0]}"
            endpoints[key] = {"source": "discovered", "method_inferred": True}
    return endpoints


def match_endpoints(
    spec_eps: dict[str, dict[str, Any]],
    disc_eps: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compare spec vs discovered endpoints."""
    spec_norm: dict[str, str] = {}
    for key in spec_eps:
        parts = key.split(" ", 1)
        norm = f"{parts[0]} {normalize_path(parts[1])}"
        spec_norm[norm] = key

    disc_norm: dict[str, str] = {}
    for key in disc_eps:
        parts = key.split(" ", 1)
        norm = f"{parts[0]} {normalize_path(parts[1])}"
        disc_norm[norm] = key

    spec_norm_keys = set(spec_norm.keys())
    disc_norm_keys = set(disc_norm.keys())

    matched = spec_norm_keys & disc_norm_keys
    shadow = disc_norm_keys - spec_norm_keys
    untested = spec_norm_keys - disc_norm_keys

    results: dict[str, Any] = {
        "matched": [],
        "shadow_endpoints": [],
        "untested_endpoints": [],
        "deprecated_in_spec": [],
        "stats": {
            "spec_total": len(spec_eps),
            "discovered_total": len(disc_eps),
            "matched": len(matched),
            "shadow": len(shadow),
            "untested": len(untested),
        },
    }

    for norm_key in sorted(matched):
        spec_key = spec_norm[norm_key]
        disc_key = disc_norm[norm_key]
        entry: dict[str, Any] = {
            "spec_endpoint": spec_key,
            "discovered_endpoint": disc_key,
            "status": "matched",
        }
        spec_info = spec_eps[spec_key]
        if spec_info.get("deprecated"):
            entry["warning"] = "deprecated in spec but still reachable"
            results["deprecated_in_spec"].append(entry)
        results["matched"].append(entry)

    for norm_key in sorted(shadow):
        disc_key = disc_norm[norm_key]
        results["shadow_endpoints"].append({
            "endpoint": disc_key,
            "normalized": norm_key,
            "status": "shadow",
            "note": "discovered but not in OpenAPI spec — undocumented/shadow endpoint",
        })

    for norm_key in sorted(untested):
        spec_key = spec_norm[norm_key]
        spec_info = spec_eps[spec_key]
        results["untested_endpoints"].append({
            "endpoint": spec_key,
            "normalized": norm_key,
            "status": "untested",
            "summary": spec_info.get("summary", ""),
            "deprecated": spec_info.get("deprecated", False),
            "requires_auth": spec_info.get("security", False),
        })

    return results


def print_table(results: dict[str, Any]) -> None:
    """Print results as markdown tables."""
    stats = results["stats"]
    print(f"## API Schema Diff")
    print(f"- Spec endpoints: {stats['spec_total']}")
    print(f"- Discovered endpoints: {stats['discovered_total']}")
    print(f"- Matched: {stats['matched']}")
    print(f"- Shadow (undocumented): {stats['shadow']}")
    print(f"- Untested (spec only): {stats['untested']}")
    print()

    if results["shadow_endpoints"]:
        print("### Shadow Endpoints (discovered but NOT in spec)")
        print("| Endpoint | Note |")
        print("|----------|------|")
        for ep in results["shadow_endpoints"]:
            print(f"| `{ep['endpoint']}` | {ep['note']} |")
        print()

    if results["untested_endpoints"]:
        print("### Untested Endpoints (in spec but NOT discovered)")
        print("| Endpoint | Summary | Auth Required | Deprecated |")
        print("|----------|---------|---------------|------------|")
        for ep in results["untested_endpoints"]:
            auth = "yes" if ep.get("requires_auth") else "no"
            dep = "⚠️ yes" if ep.get("deprecated") else "no"
            print(f"| `{ep['endpoint']}` | {ep.get('summary', '')} | {auth} | {dep} |")
        print()

    if results["deprecated_in_spec"]:
        print("### Deprecated but Reachable")
        print("| Spec Endpoint | Discovered As |")
        print("|--------------|---------------|")
        for ep in results["deprecated_in_spec"]:
            print(f"| `{ep['spec_endpoint']}` | `{ep['discovered_endpoint']}` |")
        print()

    if stats["shadow"] > 0:
        print(f"> ⚠️ {stats['shadow']} shadow endpoints found — these are undocumented")
        print("> and may lack input validation, rate limiting, or authorization checks.")
        print("> Prioritize these for testing.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare OpenAPI spec vs discovered endpoints"
    )
    parser.add_argument("--spec", required=True, help="OpenAPI 3.x spec file (JSON/YAML)")
    parser.add_argument("--recon", help="RECON_DB.md file to parse endpoints from")
    parser.add_argument("--discovered", help="Plain text file with METHOD /path per line")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--table", action="store_true", help="Output as markdown table")
    args = parser.parse_args()

    if not args.recon and not args.discovered:
        parser.error("Provide --recon or --discovered as the endpoint source")

    spec = load_spec(args.spec)
    spec_eps = extract_spec_endpoints(spec)

    if args.recon:
        disc_eps = parse_recon_endpoints(args.recon)
    else:
        disc_eps = parse_discovered_endpoints(args.discovered)

    results = match_endpoints(spec_eps, disc_eps)

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.table:
        print_table(results)
    else:
        print_table(results)


if __name__ == "__main__":
    main()
