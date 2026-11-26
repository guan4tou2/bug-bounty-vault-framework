#!/usr/bin/env python3
"""Automatic attack chain extension trigger.

Detects chain-extension signals in findings, observations, or tool output
and recommends next steps aligned to ATT&CK tactical phases.  Bridges the
gap between ad-hoc chain analysis and Decepticon-style auto-triggering.

CLI:
  python3 -I automation/chain_trigger.py --finding <path>
  python3 -I automation/chain_trigger.py --json <path_or_->
  python3 -I automation/chain_trigger.py --scan-dir <findings_dir>
  echo "text" | python3 -I automation/chain_trigger.py -
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ── ATT&CK tactical phases ─────────────────────────────────────────────────

ATTACK_STAGES = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
)

# ── Signal categories and their regex detectors ─────────────────────────────

@dataclass
class Signal:
    category: str
    name: str
    stage: str
    excerpt: str
    offset: int = 0

@dataclass
class ChainExtension:
    type: str
    description: str
    next_action: str
    target_stage: str
    confidence: str = "theoretical"
    exploit_chain_questions: list[str] = field(default_factory=list)

@dataclass
class TriggerVerdict:
    signals_detected: list[Signal]
    kill_chain_stage: str
    chain_extensions: list[ChainExtension]
    auto_trigger: bool
    priority: str

# Pattern: (name, regex, category, stage)
_SIGNAL_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    # ── Credential signals ──
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "credential", "credential-access"),
    ("api-key-generic", re.compile(r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*\S{8,}"), "credential", "credential-access"),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"), "credential", "credential-access"),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "credential", "credential-access"),
    ("password-literal", re.compile(r"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{3,64}"), "credential", "credential-access"),
    ("session-cookie", re.compile(r"(?i)(?:session[_-]?id|JSESSIONID|PHPSESSID|connect\.sid|_session)\s*[:=]\s*\S{8,}"), "credential", "credential-access"),
    ("bearer-token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_.\-]{20,}"), "credential", "credential-access"),
    ("ssh-key-path", re.compile(r"(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)"), "credential", "credential-access"),
    ("connection-string", re.compile(r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s]{10,}"), "credential", "credential-access"),
    # ── Access signals ──
    ("internal-ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "access", "discovery"),
    ("admin-panel", re.compile(r"(?i)/(?:admin|manager|dashboard|console|control[_-]?panel|wp-admin|phpmyadmin|adminer)(?:/|\b)"), "access", "discovery"),
    ("debug-endpoint", re.compile(r"(?i)/(?:debug|trace|profiler|actuator|health|metrics|env|configprops|mappings|jolokia|nacos)(?:/|\b)"), "access", "discovery"),
    ("internal-host", re.compile(r"(?i)\b(?:localhost|127\.0\.0\.1|internal|intranet|corp|staging|preprod|dev)\b"), "access", "discovery"),
    ("graphql-introspection", re.compile(r"(?i)(?:__schema|__type|introspection)"), "access", "discovery"),
    # ── Identity signals ──
    ("email-address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "identity", "reconnaissance"),
    ("uuid-guid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "identity", "reconnaissance"),
    ("tenant-id", re.compile(r"(?i)(?:tenant[_-]?id|org[_-]?id|workspace[_-]?id|account[_-]?id)\s*[:=]\s*\S+"), "identity", "reconnaissance"),
    ("user-id-numeric", re.compile(r"(?i)(?:user[_-]?id|uid|member[_-]?id)\s*[:=]\s*\d+"), "identity", "reconnaissance"),
    # ── Trust boundary signals ──
    ("ssrf-indicator", re.compile(r"(?i)(?:ssrf|server[_-]?side[_-]?request|url[_-]?fetch|proxy[_-]?url|redirect[_-]?url|callback[_-]?url)"), "trust-boundary", "lateral-movement"),
    ("cloud-metadata", re.compile(r"(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)"), "trust-boundary", "lateral-movement"),
    ("container-escape", re.compile(r"(?i)(?:docker\.sock|/var/run/docker|container[_-]?escape|breakout|mount\s+--privileged)"), "trust-boundary", "privilege-escalation"),
    # ── Privilege signals ──
    ("auth-bypass", re.compile(r"(?i)(?:auth(?:entication)?[_-]?bypass|unauth(?:enticated)?[_-]?access|broken[_-]?auth|missing[_-]?auth)"), "privilege", "initial-access"),
    ("role-escalation", re.compile(r"(?i)(?:role[_-]?escalat|privilege[_-]?escalat|admin[_-]?access|isAdmin|is_admin|role\s*[:=]\s*admin)"), "privilege", "privilege-escalation"),
    ("idor-indicator", re.compile(r"(?i)(?:idor|insecure[_-]?direct[_-]?object|broken[_-]?access[_-]?control|bac\b|horizontal[_-]?priv)"), "privilege", "privilege-escalation"),
    # ── Data signals ──
    ("source-code-leak", re.compile(r"(?i)(?:\.map\b|source[_-]?map|\.git/|\.svn/|\.env\b|\.DS_Store|web\.config|\.htaccess)"), "data", "collection"),
    ("config-leak", re.compile(r"(?i)(?:config\.(?:json|yml|yaml|xml|ini|toml)|application\.properties|settings\.py|\.env(?:\.local)?)"), "data", "collection"),
    ("env-var-leak", re.compile(r"(?i)(?:AWS_SECRET|DATABASE_URL|DB_PASSWORD|STRIPE_SECRET|SENDGRID_API|SLACK_TOKEN|GITHUB_TOKEN)"), "data", "credential-access"),
    ("database-dump", re.compile(r"(?i)(?:SELECT\s.+FROM|INSERT\s+INTO|CREATE\s+TABLE|pg_dump|mysqldump)"), "data", "collection"),
    # ── Infrastructure signals ──
    ("version-disclosure", re.compile(r"(?i)(?:Server:\s|X-Powered-By:\s|version\s*[:=]\s*\d+\.\d+)"), "infrastructure", "reconnaissance"),
    ("service-fingerprint", re.compile(r"(?i)(?:nginx|apache|tomcat|iis|express|flask|django|spring|rails|laravel|next\.js)\s*/?\s*\d"), "infrastructure", "reconnaissance"),
    ("error-stack-trace", re.compile(r"(?:Traceback \(most recent|at [\w.]+\([\w.]+:\d+\)|Exception in thread|FATAL ERROR|panic:)"), "infrastructure", "discovery"),
]

# ── Chain extension rule engine ─────────────────────────────────────────────

_CHAIN_RULES: list[dict] = [
    # Credential found → test on other systems (Q4) + use directly (Q1)
    {"match_category": "credential", "extensions": [
        ChainExtension("credential-chain", "Credential found — test on other in-scope systems", "Replay credential against other in-scope endpoints and services", "lateral-movement", "theoretical", ["Q1", "Q4"]),
        ChainExtension("access-escalation", "Credential found — test for privilege escalation", "Use credential to access admin/privileged endpoints", "privilege-escalation", "theoretical", ["Q1", "Q5"]),
    ]},
    # Access to admin/debug → privilege escalation (Q2, Q3)
    {"match_names": ["admin-panel", "debug-endpoint"], "extensions": [
        ChainExtension("access-escalation", "Admin/debug endpoint found — check for write operations", "Enumerate actions: config changes, user management, code execution", "privilege-escalation", "theoretical", ["Q2", "Q3"]),
        ChainExtension("config-chain", "Debug endpoint may leak secrets", "Read config/env from debug endpoint, extract credentials", "credential-access", "theoretical", ["Q1", "Q2"]),
    ]},
    # Internal IP/host → lateral movement (Q4)
    {"match_names": ["internal-ip", "internal-host"], "extensions": [
        ChainExtension("lateral-movement", "Internal host/IP discovered — SSRF or proxy pivot opportunity", "If SSRF exists, probe internal host; enumerate internal services", "lateral-movement", "speculative", ["Q4"]),
    ]},
    # SSRF / cloud metadata → lateral movement + credential access
    {"match_names": ["ssrf-indicator", "cloud-metadata"], "extensions": [
        ChainExtension("lateral-movement", "SSRF capability — probe internal services and cloud metadata", "Request 169.254.169.254/latest/meta-data/ via SSRF for cloud credentials", "credential-access", "theoretical", ["Q1", "Q4"]),
        ChainExtension("trust-boundary", "SSRF crosses trust boundary — internal network reachable", "Map internal network via SSRF: common ports, internal APIs", "discovery", "theoretical", ["Q4"]),
    ]},
    # Auth bypass → initial access → escalation (Q5)
    {"match_names": ["auth-bypass"], "extensions": [
        ChainExtension("access-escalation", "Auth bypass — escalate from unauthenticated to authenticated context", "Enumerate all authenticated endpoints; test admin functions", "privilege-escalation", "theoretical", ["Q2", "Q3", "Q5"]),
    ]},
    # IDOR / role escalation → privilege escalation (Q5)
    {"match_names": ["idor-indicator", "role-escalation"], "extensions": [
        ChainExtension("access-escalation", "Access control flaw — test cross-tenant and cross-role boundaries", "Full verb matrix: GET/PUT/PATCH/DELETE across users, roles, tenants", "privilege-escalation", "theoretical", ["Q1", "Q5"]),
    ]},
    # Source code / config leak → credential extraction (Q1, Q2)
    {"match_names": ["source-code-leak", "config-leak", "env-var-leak"], "extensions": [
        ChainExtension("data-chain", "Config/source leak — extract credentials and secrets", "Grep for API keys, passwords, tokens, connection strings in leaked data", "credential-access", "theoretical", ["Q1"]),
        ChainExtension("config-chain", "Config leak — identify internal architecture", "Map internal services, databases, queues from config values", "discovery", "theoretical", ["Q1", "Q3"]),
    ]},
    # Version disclosure → CVE chain
    {"match_names": ["version-disclosure", "service-fingerprint"], "extensions": [
        ChainExtension("config-chain", "Version disclosed — check for known CVEs", "Run bb-version-cve-precheck; search NVD/GHSA for version-specific vulns", "initial-access", "speculative", ["Q1"]),
    ]},
    # Identity leak → account enumeration / takeover (Q1, Q4)
    {"match_category": "identity", "extensions": [
        ChainExtension("data-chain", "Identity info leaked — test for account-level actions", "Use leaked ID/email for password reset, IDOR, or account enumeration", "credential-access", "speculative", ["Q1", "Q4"]),
    ]},
    # Container escape → host compromise
    {"match_names": ["container-escape"], "extensions": [
        ChainExtension("trust-boundary", "Container escape vector — host-level access possible", "Verify container privileges; test escape via docker.sock or mounted volumes", "privilege-escalation", "speculative", ["Q5"]),
    ]},
    # Error / stack trace → information for further exploitation
    {"match_names": ["error-stack-trace"], "extensions": [
        ChainExtension("data-chain", "Stack trace leaks internal paths and framework details", "Extract file paths, class names, library versions from trace", "discovery", "theoretical", ["Q1", "Q6"]),
    ]},
    # Database indicators → data exfiltration
    {"match_names": ["database-dump", "connection-string"], "extensions": [
        ChainExtension("data-chain", "Database access — enumerate sensitive tables", "Query for user credentials, PII, payment data, admin tokens", "collection", "theoretical", ["Q1", "Q2"]),
    ]},
    # GraphQL introspection → full API map
    {"match_names": ["graphql-introspection"], "extensions": [
        ChainExtension("data-chain", "GraphQL introspection enabled — full schema available", "Dump schema; identify mutations, sensitive queries, auth-gated fields", "discovery", "theoretical", ["Q3"]),
    ]},
]

# ── Core detection ──────────────────────────────────────────────────────────

def detect_signals(text: str) -> list[Signal]:
    """Scan text for chain-extension signals."""
    signals: list[Signal] = []
    seen: set[str] = set()
    for name, pattern, category, stage in _SIGNAL_PATTERNS:
        for m in pattern.finditer(text):
            key = (name, m.group(0)[:80])
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            signals.append(Signal(
                category=category, name=name, stage=stage,
                excerpt=text[start:end].replace("\n", " ").strip(),
                offset=m.start(),
            ))
    return signals


def classify_stage(signals: list[Signal]) -> str:
    """Pick the dominant kill chain stage from detected signals."""
    if not signals:
        return "reconnaissance"
    stage_order = {s: i for i, s in enumerate(ATTACK_STAGES)}
    counts: dict[str, int] = {}
    for sig in signals:
        counts[sig.stage] = counts.get(sig.stage, 0) + 1
    best = max(counts, key=lambda s: (counts[s], stage_order.get(s, 0)))
    return best


def recommend_extensions(signals: list[Signal]) -> list[ChainExtension]:
    """Apply chain extension rules to detected signals."""
    extensions: list[ChainExtension] = []
    seen_types: set[str] = set()
    signal_names = {s.name for s in signals}
    signal_categories = {s.category for s in signals}

    for rule in _CHAIN_RULES:
        matched = False
        if "match_category" in rule and rule["match_category"] in signal_categories:
            matched = True
        if "match_names" in rule and signal_names & set(rule["match_names"]):
            matched = True
        if matched:
            for ext in rule["extensions"]:
                key = (ext.type, ext.target_stage)
                if key not in seen_types:
                    seen_types.add(key)
                    extensions.append(ext)
    return extensions


def compute_priority(signals: list[Signal], extensions: list[ChainExtension]) -> str:
    """Determine overall priority based on signal strength."""
    if not signals:
        return "low"
    has_cred = any(s.category == "credential" for s in signals)
    has_priv = any(s.category == "privilege" for s in signals)
    has_trust = any(s.category == "trust-boundary" for s in signals)
    high_value = has_cred or has_priv or has_trust
    multi_category = len({s.category for s in signals}) >= 3
    if high_value and len(extensions) >= 2:
        return "high"
    if high_value or multi_category:
        return "medium"
    return "low"


def analyze(text: str) -> TriggerVerdict:
    """Full analysis pipeline: detect → classify → recommend."""
    signals = detect_signals(text)
    stage = classify_stage(signals)
    extensions = recommend_extensions(signals)
    priority = compute_priority(signals, extensions)
    auto_trigger = priority in ("high", "medium") and len(extensions) > 0
    return TriggerVerdict(
        signals_detected=signals,
        kill_chain_stage=stage,
        chain_extensions=extensions,
        auto_trigger=auto_trigger,
        priority=priority,
    )

# ── Input parsers ───────────────────────────────────────────────────────────

def read_finding_md(path: str) -> str:
    """Read a Finding markdown note and extract text for analysis."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def read_json_input(path: str) -> str:
    """Read JSON input and flatten to text for signal detection."""
    if path == "-":
        raw = sys.stdin.read()
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            parts = []
            for k, v in data.items():
                parts.append(f"{k}: {v}")
            return "\n".join(parts)
        return str(data)
    except json.JSONDecodeError:
        return raw


def scan_findings_dir(dirpath: str) -> list[dict]:
    """Scan a directory of Finding markdown notes."""
    results = []
    p = Path(dirpath)
    if not p.is_dir():
        print(f"error: {dirpath} is not a directory", file=sys.stderr)
        sys.exit(1)
    for md in sorted(p.glob("*.md")):
        text = read_finding_md(str(md))
        verdict = analyze(text)
        results.append({
            "file": md.name,
            "signals": len(verdict.signals_detected),
            "stage": verdict.kill_chain_stage,
            "extensions": len(verdict.chain_extensions),
            "priority": verdict.priority,
            "auto_trigger": verdict.auto_trigger,
            "categories": sorted({s.category for s in verdict.signals_detected}),
        })
    return results


def format_scan_table(results: list[dict]) -> str:
    """Format scan-dir results as an aligned text table."""
    if not results:
        return "No findings found."
    hdr = f"{'File':<40} {'Signals':>7} {'Stage':<22} {'Extensions':>10} {'Priority':<8} {'Auto':>4}  Categories"
    sep = "-" * len(hdr)
    lines = [hdr, sep]
    for r in results:
        cats = ", ".join(r["categories"]) if r["categories"] else "-"
        lines.append(
            f"{r['file']:<40} {r['signals']:>7} {r['stage']:<22} "
            f"{r['extensions']:>10} {r['priority']:<8} {'yes' if r['auto_trigger'] else 'no':>4}  {cats}"
        )
    triggered = sum(1 for r in results if r["auto_trigger"])
    lines.append(sep)
    lines.append(f"Total: {len(results)} findings, {triggered} with auto-trigger chain recommendations")
    return "\n".join(lines)

# ── Serialization ───────────────────────────────────────────────────────────

def verdict_to_dict(v: TriggerVerdict) -> dict:
    """Convert verdict to JSON-serializable dict."""
    return {
        "signals_detected": [asdict(s) for s in v.signals_detected],
        "kill_chain_stage": v.kill_chain_stage,
        "chain_extensions": [asdict(e) for e in v.chain_extensions],
        "auto_trigger": v.auto_trigger,
        "priority": v.priority,
    }

# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Automatic attack chain extension trigger. "
        "Detects chain-extension signals and recommends next steps "
        "aligned to ATT&CK tactical phases.",
    )
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--finding", metavar="PATH", help="Analyze a Finding markdown note")
    group.add_argument("--json", metavar="PATH", dest="json_input", help="Analyze JSON input (use - for stdin)")
    group.add_argument("--scan-dir", metavar="DIR", help="Scan all findings in a directory")
    group.add_argument("stdin_fallback", nargs="?", metavar="FILE_OR_-", help="Read text from file or stdin (- for stdin)")
    ap.add_argument("--table", action="store_true", help="With --scan-dir, output text table instead of JSON")

    args = ap.parse_args()

    if args.scan_dir:
        results = scan_findings_dir(args.scan_dir)
        if args.table:
            print(format_scan_table(results))
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    text: str | None = None
    if args.finding:
        text = read_finding_md(args.finding)
    elif args.json_input:
        text = read_json_input(args.json_input)
    elif args.stdin_fallback:
        if args.stdin_fallback == "-":
            text = sys.stdin.read()
        elif os.path.isfile(args.stdin_fallback):
            with open(args.stdin_fallback, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        else:
            text = args.stdin_fallback
    else:
        ap.print_help()
        sys.exit(0)

    if text is None:
        print("error: no input provided", file=sys.stderr)
        sys.exit(1)

    verdict = analyze(text)
    out = verdict_to_dict(verdict)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    sys.exit(0 if not verdict.auto_trigger else 1)


if __name__ == "__main__":
    main()
