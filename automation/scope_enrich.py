#!/usr/bin/env python3
"""Automatic scope enrichment via Certificate Transparency logs + DNS.

Reads SCOPE.md, extracts domain entries, queries crt.sh for subdomains,
verifies DNS resolution, and optionally appends new discoveries back to
SCOPE.md. Adapted from Decepticon's roe_materialization.py CT enrichment.

This is PASSIVE reconnaissance — CT logs are public records. No traffic
is sent to the target. DNS resolution uses the operator's resolver.

Usage:
    python3 -I automation/scope_enrich.py --scope <SCOPE.md>
    python3 -I automation/scope_enrich.py --scope <SCOPE.md> --diff
    python3 -I automation/scope_enrich.py --scope <SCOPE.md> --table
    python3 -I automation/scope_enrich.py --scope <SCOPE.md> --update
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

# ── scope parsing (mirrors scope_check.py) ────────────────────────────────


def _parse_yaml_frontmatter(text: str) -> dict | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    block = text[4:end]
    result: dict = {}
    current_key: str | None = None
    current_list: list[str] | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current_key is not None and current_list is not None:
                current_list.append(stripped[2:].strip().strip("\"'"))
            continue
        if ":" in stripped:
            if current_key is not None and current_list is not None:
                result[current_key] = current_list
            current_list = None
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip("\"'")
            if not val:
                current_key = key
                current_list = []
            else:
                current_key = None
                if val.lower() in ("true", "yes"):
                    result[key] = True
                elif val.lower() in ("false", "no"):
                    result[key] = False
                else:
                    result[key] = val
    if current_key is not None and current_list is not None:
        result[current_key] = current_list
    return result if result else None


def _parse_freeform_scope(text: str) -> list[str]:
    entries: list[str] = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("## in") and "scope" in lower:
            in_section = True
            continue
        if stripped.startswith("## "):
            in_section = False
            continue
        if in_section and stripped.startswith("- "):
            entry = stripped[2:].strip().strip("`")
            if entry:
                entries.append(entry)
    return entries


def load_scope_entries(scope_path: Path) -> list[str]:
    text = scope_path.read_text(encoding="utf-8")
    fm = _parse_yaml_frontmatter(text)
    if fm and isinstance(fm.get("in_scope"), list):
        return fm["in_scope"]
    entries = _parse_freeform_scope(text)
    if entries:
        return entries
    return []


# ── domain extraction ─────────────────────────────────────────────────────

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:/\d+)?$"
)
_CIDR6_RE = re.compile(r"^[0-9a-fA-F:]+(?:/\d+)?$")


def extract_domains(entries: list[str]) -> list[str]:
    """Extract root domains from scope entries (skip IPs/CIDRs)."""
    domains: list[str] = []
    for entry in entries:
        entry = entry.strip().rstrip(".")
        if _IP_RE.match(entry) or _CIDR6_RE.match(entry):
            continue
        if entry.startswith("*."):
            entry = entry[2:]
        if "." in entry and not entry.startswith("/"):
            domains.append(entry.lower())
    return sorted(set(domains))


# ── CT lookup ─────────────────────────────────────────────────────────────

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_DELAY = 2.0
REQUEST_TIMEOUT = 10


@dataclass
class SubdomainResult:
    hostname: str
    root_domain: str
    resolved_ips: list[str] = field(default_factory=list)
    resolves: bool = False
    is_new: bool = False

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "root_domain": self.root_domain,
            "resolved_ips": self.resolved_ips,
            "resolves": self.resolves,
            "is_new": self.is_new,
        }


def _query_crtsh(domain: str) -> set[str]:
    """Query crt.sh for subdomains. Best-effort: returns empty on failure."""
    url = CRT_SH_URL.format(domain=domain)
    req = urllib.request.Request(
        url, headers={"User-Agent": "scope-enrich/1.0", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[warn] crt.sh query failed for {domain}: {exc}", file=sys.stderr)
        return set()

    subdomains: set[str] = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name:
                continue
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)
    return subdomains


def _resolve_host(hostname: str) -> list[str]:
    """Resolve hostname to IPs via stdlib. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips: set[str] = set()
        for _family, _type, _proto, _canonname, sockaddr in results:
            ips.add(sockaddr[0])
        return sorted(ips)
    except (socket.gaierror, OSError):
        return []


def discover_subdomains(
    domains: list[str],
    existing_entries: list[str],
    resolve_dns: bool = True,
) -> list[SubdomainResult]:
    """Query CT logs for all domains and optionally verify DNS resolution."""
    existing_normalized: set[str] = set()
    for e in existing_entries:
        e = e.strip().lower().rstrip(".")
        if e.startswith("*."):
            existing_normalized.add(e[2:])
            existing_normalized.add(e)
        else:
            existing_normalized.add(e)

    all_subs: dict[str, str] = {}
    for i, domain in enumerate(domains):
        if i > 0:
            time.sleep(REQUEST_DELAY)
        print(f"[info] querying crt.sh for *.{domain}...", file=sys.stderr)
        subs = _query_crtsh(domain)
        for s in subs:
            if s not in all_subs:
                all_subs[s] = domain

    results: list[SubdomainResult] = []
    for hostname in sorted(all_subs):
        root = all_subs[hostname]
        is_new = hostname not in existing_normalized
        r = SubdomainResult(hostname=hostname, root_domain=root, is_new=is_new)
        if resolve_dns:
            r.resolved_ips = _resolve_host(hostname)
            r.resolves = len(r.resolved_ips) > 0
        results.append(r)
    return results


# ── SCOPE.md update ───────────────────────────────────────────────────────


def update_scope_md(scope_path: Path, new_entries: list[str]) -> int:
    """Append new subdomains to SCOPE.md in_scope list. Returns count added."""
    if not new_entries:
        return 0
    text = scope_path.read_text(encoding="utf-8")
    today = date.today().isoformat()
    comment = f"  # auto-enriched {today}"

    fm = _parse_yaml_frontmatter(text)
    if fm and isinstance(fm.get("in_scope"), list):
        end_marker = text.find("\n---", 3)
        if end_marker < 0:
            return 0
        insert_lines = "".join(
            f'  - "{entry}"{comment}\n' for entry in new_entries
        )
        in_scope_end = _find_in_scope_list_end(text, end_marker)
        updated = text[:in_scope_end] + insert_lines + text[in_scope_end:]
    else:
        in_scope_pos = _find_freeform_in_scope_end(text)
        if in_scope_pos < 0:
            return 0
        insert_lines = "".join(f"- `{entry}`{comment}\n" for entry in new_entries)
        updated = text[:in_scope_pos] + insert_lines + text[in_scope_pos:]

    scope_path.write_text(updated, encoding="utf-8")
    return len(new_entries)


def _find_in_scope_list_end(text: str, fm_end: int) -> int:
    """Find the byte offset after the last `- ...` line under in_scope."""
    in_list = False
    last_item_end = -1
    for match in re.finditer(r"^.*$", text[:fm_end], re.MULTILINE):
        line = match.group().strip()
        if line == "in_scope:":
            in_list = True
            continue
        if in_list:
            if line.startswith("- "):
                last_item_end = match.end() + 1
            elif line and not line.startswith("#"):
                break
    return last_item_end if last_item_end > 0 else fm_end


def _find_freeform_in_scope_end(text: str) -> int:
    """Find byte offset after last `- ...` in ## In Scope section."""
    in_section = False
    last_item_end = -1
    for match in re.finditer(r"^.*$", text, re.MULTILINE):
        line = match.group().strip()
        lower = line.lower()
        if lower.startswith("## in") and "scope" in lower:
            in_section = True
            continue
        if line.startswith("## "):
            if in_section:
                break
            continue
        if in_section and line.startswith("- "):
            last_item_end = match.end() + 1
    return last_item_end


# ── CLI ───────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enrich SCOPE.md with CT subdomain discovery (passive).",
    )
    parser.add_argument("--scope", required=True, help="Path to SCOPE.md")
    parser.add_argument("--diff", action="store_true", help="Show only NEW subdomains")
    parser.add_argument("--table", action="store_true", help="Human-readable table")
    parser.add_argument(
        "--update", action="store_true",
        help="Append new subdomains to SCOPE.md (requires review before active testing)",
    )
    parser.add_argument(
        "--no-resolve", action="store_true",
        help="Skip DNS resolution (faster, CT data only)",
    )
    args = parser.parse_args()

    scope_path = Path(args.scope)
    if not scope_path.is_file():
        print(f"[error] scope file not found: {scope_path}", file=sys.stderr)
        return 2

    entries = load_scope_entries(scope_path)
    if not entries:
        print("[error] no in_scope entries found in SCOPE.md", file=sys.stderr)
        return 2

    domains = extract_domains(entries)
    if not domains:
        print("[info] no domain entries to enrich (IPs/CIDRs only)", file=sys.stderr)
        return 0

    print(
        f"[info] enriching {len(domains)} domain(s): {', '.join(domains)}",
        file=sys.stderr,
    )
    results = discover_subdomains(
        domains, entries, resolve_dns=not args.no_resolve,
    )

    if args.diff:
        results = [r for r in results if r.is_new]

    if not results:
        print("[info] no subdomains discovered", file=sys.stderr)
        return 0

    new_count = sum(1 for r in results if r.is_new)
    resolving_count = sum(1 for r in results if r.resolves)

    if args.table:
        print(f"\n{'Hostname':<50} {'Resolves':<10} {'IPs':<30} {'New':<5}")
        print("-" * 95)
        for r in results:
            ips = ", ".join(r.resolved_ips) if r.resolved_ips else "-"
            res = "yes" if r.resolves else "no"
            new = "NEW" if r.is_new else ""
            print(f"{r.hostname:<50} {res:<10} {ips:<30} {new:<5}")
        print(f"\nTotal: {len(results)} | New: {new_count} | Resolving: {resolving_count}")
    else:
        output = {
            "total": len(results),
            "new": new_count,
            "resolving": resolving_count,
            "subdomains": [r.to_dict() for r in results],
        }
        print(json.dumps(output, indent=2))

    if args.update:
        new_resolving = [r.hostname for r in results if r.is_new and r.resolves]
        if not new_resolving:
            print("[info] no new resolving subdomains to add", file=sys.stderr)
            return 0
        added = update_scope_md(scope_path, new_resolving)
        print(
            f"[info] added {added} subdomain(s) to {scope_path}",
            file=sys.stderr,
        )
        print(
            "\n⚠ Review enriched subdomains before active testing.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
