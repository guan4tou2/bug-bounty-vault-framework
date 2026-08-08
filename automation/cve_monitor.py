#!/usr/bin/env python3
"""CVE Monitor — scan target RECON_DBs for tech stacks and query NVD/GitHub for new CVEs.

Extracts technology/version pairs from RECON_DB.md files, queries the NVD 2.0 API
and GitHub Security Advisories API (both public, no auth required), and outputs
a prioritized list of CVEs relevant to each target.

Usage:
    python3 automation/cve_monitor.py --target gitlab
    python3 automation/cve_monitor.py --all
    python3 automation/cve_monitor.py --all --days 7 --min-cvss 9.0
    python3 automation/cve_monitor.py --target example --dry-run
    python3 automation/cve_monitor.py --all --output json

Rate limits (no API key):
    NVD:    5 requests / 30 seconds
    GitHub: 60 requests / hour

See .claude/agents/cve-monitor.md for the full agent workflow.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS_DIR = ROOT / "01 - Targets"

# ANSI colors
G = "\033[0;32m"
R = "\033[0;31m"
Y = "\033[0;33m"
B = "\033[0;34m"
C = "\033[0;36m"
N = "\033[0m"

# NVD public API (no key required, 5 req/30s)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 6.5  # seconds between requests (safe margin for 5/30s)

# GitHub Advisory API (no auth required, 60 req/hour)
GHSA_API = "https://api.github.com/advisories"
GHSA_DELAY = 2.0

# Common tech keywords to extract from RECON_DB
TECH_PATTERNS = [
    # Web frameworks
    r"(?:Laravel|Django|Flask|Rails|Spring\s*Boot|Express|Next\.js|Nuxt|Angular|React|Vue\.js|Symfony|CodeIgniter|FastAPI|Gin|Echo)\s*[vV]?(\d+\.\d+(?:\.\d+)?)?",
    # Servers
    r"(?:nginx|Apache|IIS|Tomcat|Jetty|Caddy|LiteSpeed|Gunicorn|Uvicorn|Puma)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # Databases
    r"(?:MySQL|MariaDB|PostgreSQL|MongoDB|Redis|Elasticsearch|Memcached|SQLite|CouchDB|Cassandra)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # CMS
    r"(?:WordPress|Drupal|Joomla|Magento|Shopify|Ghost|Strapi|Directus)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # Languages / runtimes
    r"(?:PHP|Python|Node\.js|Ruby|Java|Go|Rust|\.NET)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # JS libraries
    r"(?:jQuery|lodash|moment|axios|webpack|vite|esbuild)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # DevOps / infra
    r"(?:Docker|Kubernetes|Terraform|Ansible|Jenkins|GitLab|Grafana|Prometheus|Consul|Vault)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
    # Networking
    r"(?:OpenSSL|OpenSSH|WireGuard|HAProxy|Traefik|Envoy)\s*[/vV]?(\d+\.\d+(?:\.\d+)?)?",
]

TECH_RE = re.compile("|".join(TECH_PATTERNS), re.IGNORECASE)

# Patterns for version-bearing lines (broader fallback)
VERSION_LINE_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9_.+-]+)\s+[vV]?(\d+\.\d+(?:\.\d+)?)"
)


def find_targets() -> list[Path]:
    """Return list of target directories that contain RECON_DB.md."""
    if not TARGETS_DIR.exists():
        return []
    return sorted(
        d for d in TARGETS_DIR.iterdir()
        if d.is_dir() and (d / "RECON_DB.md").exists()
    )


def extract_tech_stack(recon_path: Path) -> list[dict]:
    """Extract (product, version) pairs from a RECON_DB.md file."""
    try:
        text = recon_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    results = {}

    # Strategy 1: regex for known tech names
    for match in TECH_RE.finditer(text):
        full = match.group(0).strip()
        # Extract product name (first word/phrase) and version
        parts = re.split(r"\s+[vV/]?(?=\d)", full, maxsplit=1)
        product = parts[0].strip().rstrip("/")
        version = parts[1].strip() if len(parts) > 1 else ""
        key = product.lower()
        if key not in results or (version and not results[key]["version"]):
            results[key] = {"product": product, "version": version}

    # Strategy 2: generic "Product vX.Y.Z" lines
    for match in VERSION_LINE_RE.finditer(text):
        product = match.group(1).strip()
        version = match.group(2).strip()
        key = product.lower()
        # Only add if not already found by specific patterns
        if key not in results:
            # Skip noise (generic words, hex strings, etc.)
            if len(product) < 3 or product.lower() in {"the", "for", "and", "this"}:
                continue
            results[key] = {"product": product, "version": version}

    return list(results.values())


def query_nvd(product: str, days_back: int = 30) -> list[dict]:
    """Query NVD 2.0 API for CVEs matching a product keyword."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    params = {
        "keywordSearch": product,
        "resultsPerPage": "20",
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT23:59:59.999"),
    }
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cve-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"  {Y}[WARN]{N} NVD query failed for '{product}': {e}", file=sys.stderr)
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "?")

        # Extract CVSS 3.1 score
        cvss_score = None
        cvss_severity = "N/A"
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "N/A")
                break

        # Description
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break

        # Published date
        published = cve.get("published", "")[:10]

        # References
        refs = [
            r.get("url", "")
            for r in cve.get("references", [])[:3]
        ]

        results.append({
            "cve_id": cve_id,
            "product_query": product,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "description": desc,
            "published": published,
            "references": refs,
            "source": "NVD",
        })

    return results


def query_github_advisories(product: str) -> list[dict]:
    """Query GitHub Advisory Database for advisories affecting a package."""
    params = {
        "affects": product,
        "per_page": "10",
        "sort": "published",
        "direction": "desc",
    }
    url = f"{GHSA_API}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "cve-monitor/1.0",
            "Accept": "application/vnd.github+json",
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"  {Y}[WARN]{N} GitHub Advisory query failed for '{product}': {e}",
              file=sys.stderr)
        return []

    results = []
    for adv in data if isinstance(data, list) else []:
        cve_id = adv.get("cve_id") or adv.get("ghsa_id", "?")
        severity = adv.get("severity", "N/A")

        # Map severity to approximate CVSS
        severity_map = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
        approx_cvss = severity_map.get(severity.lower())

        results.append({
            "cve_id": cve_id,
            "product_query": product,
            "cvss_score": approx_cvss,
            "cvss_severity": severity.upper(),
            "description": (adv.get("summary") or "")[:200],
            "published": (adv.get("published_at") or "")[:10],
            "references": [adv.get("html_url", "")],
            "source": "GHSA",
        })

    return results


def load_known_cves(target_dir: Path) -> set[str]:
    """Load CVE IDs already tracked in FINDINGS_QUICK_REF and Finding files."""
    known = set()
    cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    # Check FINDINGS_QUICK_REF.md
    qref = target_dir / "FINDINGS_QUICK_REF.md"
    if qref.exists():
        for m in cve_re.finditer(qref.read_text(encoding="utf-8", errors="replace")):
            known.add(m.group(0).upper())

    # Check individual Finding files
    findings_dir = target_dir / "Findings"
    if findings_dir.exists():
        for f in findings_dir.glob("*.md"):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in cve_re.finditer(text):
                known.add(m.group(0).upper())

    return known


def score_cve(cve: dict, known_cves: set[str], version_match: str) -> int:
    """Compute priority score for a CVE result."""
    score = 0
    cvss = cve.get("cvss_score")

    # CVSS scoring
    if cvss is not None:
        if cvss >= 9.0:
            score += 40
        elif cvss >= 7.0:
            score += 25
        elif cvss >= 4.0:
            score += 10

    # Version match
    if version_match == "MATCHED":
        score += 30
    elif version_match == "LIKELY":
        score += 15
    else:
        score += 5

    # Recency
    published = cve.get("published", "")
    if published:
        try:
            pub_date = datetime.strptime(published[:10], "%Y-%m-%d")
            days_old = (datetime.now() - pub_date).days
            if days_old <= 7:
                score += 10
            elif days_old <= 30:
                score += 5
        except ValueError:
            pass

    # Known dedup
    cve_id = cve.get("cve_id", "").upper()
    if cve_id in known_cves:
        cve["known"] = True
        score = max(score - 50, 0)
    else:
        cve["known"] = False

    return score


def format_text(target_name: str, results: list[dict]) -> str:
    """Format results as human-readable text."""
    lines = [f"\n{'=' * 60}"]
    lines.append(f"CVE Monitor Report — {target_name} — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"{'=' * 60}\n")

    if not results:
        lines.append("No CVEs found for this target's tech stack.\n")
        return "\n".join(lines)

    # Group by priority tier
    immediate = [r for r in results if r["score"] >= 60 and not r.get("known")]
    queue = [r for r in results if 30 <= r["score"] < 60 and not r.get("known")]
    log_only = [r for r in results if r["score"] < 30 and not r.get("known")]
    known = [r for r in results if r.get("known")]

    if immediate:
        lines.append(f"{R}### IMMEDIATE ACTION (score >= 60){N}\n")
        for r in immediate:
            cvss_str = f"{r['cvss_score']:.1f}" if r["cvss_score"] else "N/A"
            lines.append(f"  {R}[!]{N} {r['cve_id']}  {r['product_query']}  "
                         f"CVSS:{cvss_str} {r['cvss_severity']}  "
                         f"Score:{r['score']}  ({r['source']})")
            lines.append(f"      {r['description'][:120]}")
            if r["references"]:
                lines.append(f"      Ref: {r['references'][0]}")
            lines.append("")

    if queue:
        lines.append(f"{Y}### QUEUE (score 30-59){N}\n")
        for r in queue:
            cvss_str = f"{r['cvss_score']:.1f}" if r["cvss_score"] else "N/A"
            lines.append(f"  {Y}[~]{N} {r['cve_id']}  {r['product_query']}  "
                         f"CVSS:{cvss_str}  Score:{r['score']}")
            lines.append(f"      {r['description'][:120]}")
            lines.append("")

    if log_only:
        lines.append(f"{B}### LOG ONLY (score < 30){N}\n")
        for r in log_only[:10]:  # cap at 10
            cvss_str = f"{r['cvss_score']:.1f}" if r["cvss_score"] else "N/A"
            lines.append(f"  {B}[-]{N} {r['cve_id']}  {r['product_query']}  CVSS:{cvss_str}")
        if len(log_only) > 10:
            lines.append(f"  ... and {len(log_only) - 10} more")
        lines.append("")

    if known:
        lines.append(f"{G}### ALREADY KNOWN ({len(known)} CVEs){N}")
        for r in known[:5]:
            lines.append(f"  {G}[K]{N} {r['cve_id']}  {r['product_query']}")
        if len(known) > 5:
            lines.append(f"  ... and {len(known) - 5} more")
        lines.append("")

    total = len(immediate) + len(queue) + len(log_only)
    lines.append(f"Summary: {len(immediate)} immediate, {len(queue)} queued, "
                 f"{len(log_only)} logged, {len(known)} known.  "
                 f"Total new: {total}")

    return "\n".join(lines)


def run_monitor(
    target_name: str | None,
    all_targets: bool,
    days_back: int,
    min_cvss: float,
    dry_run: bool,
    output_format: str,
) -> int:
    """Main monitoring logic. Returns exit code."""
    # Resolve targets
    if all_targets:
        targets = find_targets()
        if not targets:
            print(f"{R}[ERROR]{N} No targets found in {TARGETS_DIR}", file=sys.stderr)
            return 1
    elif target_name:
        target_dir = TARGETS_DIR / target_name
        if not target_dir.exists():
            # Try case-insensitive match
            for d in TARGETS_DIR.iterdir():
                if d.is_dir() and d.name.lower() == target_name.lower():
                    target_dir = d
                    break
            else:
                print(f"{R}[ERROR]{N} Target '{target_name}' not found in {TARGETS_DIR}",
                      file=sys.stderr)
                return 1
        targets = [target_dir]
    else:
        print(f"{R}[ERROR]{N} Specify --target <name> or --all", file=sys.stderr)
        return 1

    all_results = {}

    for target_dir in targets:
        tname = target_dir.name
        recon_path = target_dir / "RECON_DB.md"
        if not recon_path.exists():
            print(f"{Y}[SKIP]{N} {tname}: no RECON_DB.md")
            continue

        print(f"\n{C}[*]{N} Scanning {tname}...")
        tech_stack = extract_tech_stack(recon_path)

        if not tech_stack:
            print(f"  {Y}[SKIP]{N} No tech stack entries found in RECON_DB.md")
            continue

        print(f"  Found {len(tech_stack)} technologies:")
        for t in tech_stack:
            v = t["version"] or "(no version)"
            print(f"    - {t['product']} {v}")

        if dry_run:
            print(f"\n  {B}[DRY-RUN]{N} Would query NVD/GHSA for:")
            for t in tech_stack:
                print(f"    NVD:  {NVD_API}?keywordSearch={urllib.parse.quote(t['product'])}"
                      f"&resultsPerPage=20")
                print(f"    GHSA: {GHSA_API}?affects={urllib.parse.quote(t['product'])}")
            continue

        # Load known CVEs for dedup
        known_cves = load_known_cves(target_dir)
        if known_cves:
            print(f"  {G}[*]{N} {len(known_cves)} CVEs already tracked")

        results = []

        for tech in tech_stack:
            product = tech["product"]
            version = tech["version"]

            # Query NVD
            print(f"  Querying NVD for '{product}'...", end="", flush=True)
            nvd_results = query_nvd(product, days_back=days_back)
            print(f" {len(nvd_results)} results")
            time.sleep(NVD_DELAY)

            # Query GitHub Advisories
            print(f"  Querying GHSA for '{product}'...", end="", flush=True)
            ghsa_results = query_github_advisories(product)
            print(f" {len(ghsa_results)} results")
            time.sleep(GHSA_DELAY)

            # Combine and deduplicate by CVE ID
            seen_ids = set()
            for r in nvd_results + ghsa_results:
                cve_id = r["cve_id"].upper()
                if cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)

                # Filter by min CVSS
                if r["cvss_score"] is not None and r["cvss_score"] < min_cvss:
                    continue

                # Determine version match
                if version and r.get("description"):
                    if version in r["description"]:
                        version_match = "MATCHED"
                    elif version.split(".")[0] in r["description"]:
                        version_match = "LIKELY"
                    else:
                        version_match = "UNVERIFIED"
                else:
                    version_match = "UNVERIFIED"

                r["version_match"] = version_match
                r["score"] = score_cve(r, known_cves, version_match)
                results.append(r)

        # Sort by score descending
        results.sort(key=lambda x: x["score"], reverse=True)
        all_results[tname] = results

        if output_format == "text":
            print(format_text(tname, results))

    if output_format == "json":
        # Convert to JSON-serializable format
        print(json.dumps(all_results, indent=2, default=str))

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="CVE Monitor — scan RECON_DBs and query NVD/GHSA for new CVEs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --target gitlab              # Scan one target
  %(prog)s --all                        # Scan all targets
  %(prog)s --all --days 7 --min-cvss 9  # Critical CVEs from last week
  %(prog)s --target ex --dry-run        # Show queries without executing
  %(prog)s --all --output json          # JSON output for piping""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Target slug to scan (directory name under 01 - Targets/)")
    group.add_argument("--all", action="store_true", help="Scan all targets with RECON_DB.md")

    parser.add_argument("--days", type=int, default=30,
                        help="How many days back to search (default: 30)")
    parser.add_argument("--min-cvss", type=float, default=0.0,
                        help="Minimum CVSS score to report (default: 0.0, report all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be queried without making requests")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")

    args = parser.parse_args()
    sys.exit(run_monitor(
        target_name=args.target,
        all_targets=args.all,
        days_back=args.days,
        min_cvss=args.min_cvss,
        dry_run=args.dry_run,
        output_format=args.output,
    ))


if __name__ == "__main__":
    main()
