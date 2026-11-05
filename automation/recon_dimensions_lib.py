"""recon_dimensions_lib — single tolerant reader for ASG `recon_dimensions`.

Why this exists: recon_dimensions was read two incompatible ways across the code —
  • dict form   `{passive_osint: {status, items}, ...}`  (schema doc + hunt_autodrive)
  • list form   `[{dim: passive_osint, status, note}, ...]` (real target files +
                 session_start_brief + capability_view)
A reader that assumes one shape silently sees nothing (or crashes) on the other —
exactly the "gate goes quietly dead" failure class. Canonical shape is now
list-of-dict (it matches every real target file and holds both floor dims and
free-text attack directions); dict is still accepted for back-compat. Everything
that reads recon_dimensions should go through here so the two shapes can never
disagree again.

FLOOR is the recon floor a thorough external assessment must cover before moving to
exploitation, aligned with OSCP / OWASP-WSTG / reconftw methodology. CORE is the
subset the recon-completeness gate hard-requires before exploit.
"""
from __future__ import annotations

# Ordered recon floor (OSCP / OWASP-WSTG / reconftw / HackTricks external-recon
# progression). Items are a floor, not a ceiling — targets may add custom dimensions
# freely. See 09 - Knowledge Base/Reference Card - Attack Surface Graph Schema.md for
# the item lists and the methodology cross-reference.
FLOOR = [
    # ── CORE (hard-required before exploit) ──
    "passive_osint",          # before first contact: CT/wayback/github/shodan/passive-dns/disclosed
    "subdomain_enum",         # subfinder/crt/chaos + dns brute + permutations + vhost fuzz + resolve
    "live_host_port",         # nmap/naabu port+service + httpx probe + waf/cdn detect + screenshot
    "url_content_discovery",  # gau/wayback/katana + ffuf dir + JS endpoints + param discovery
    # ── recommended (surfaced, not hard-blocking) ──
    "infra_layer",            # dns cluster / tls SAN / default vhost / cname / reverse dns
    "tech_stack_deep",        # js sourcemaps / spa config / wappalyzer / error-page fingerprint
    "js_analysis",            # sourcemap mining / SecretFinder / xnLinkFinder / bundle endpoint extraction
    "cloud_assets",           # S3/GCS/Azure bucket permutations + cloud_enum (HackTricks §6)
    "asset_scope",            # acquisitions + ASN/IP-range + related domains + favicon pivot (§1-2)
    "employee_osint",         # linkedin / employee repos / email pattern / credential leaks
    "leaked_credentials",     # dehashed / breachcompilation / credential stuffing check
    "waf_cdn_fingerprint",    # wafw00f / CDN detect per live host → bypass strategy
    "screenshot_visual",      # gowitness / aquatone → visual clustering (same UI = same codebase)
]

# Hard-required before exploit (the OSCP essentials + the before-contact line).
CORE = ["passive_osint", "subdomain_enum", "live_host_port", "url_content_discovery"]

# recon TOOL → dimension it produces evidence for. Used by recon_ingest (auto-record a
# command_run into .state/recon_runs.jsonl when a recon tool runs) and by
# check_recon_ingest (flag "scanned but dimension still pending = not ingested = debt").
# nuclei/sqlmap/etc are EXPLOIT-phase, not recon — deliberately absent.
TOOL_DIM = {
    # subdomain_enum
    "subfinder": "subdomain_enum", "amass": "subdomain_enum", "findomain": "subdomain_enum",
    "assetfinder": "subdomain_enum", "puredns": "subdomain_enum", "shuffledns": "subdomain_enum",
    "gotator": "subdomain_enum", "dnsgen": "subdomain_enum", "alterx": "subdomain_enum",
    "dnsx": "subdomain_enum", "massdns": "subdomain_enum", "chaos": "subdomain_enum",
    "github-subdomains": "subdomain_enum", "gitlab-subdomains": "subdomain_enum",
    # live_host_port
    "nmap": "live_host_port", "masscan": "live_host_port", "naabu": "live_host_port",
    "httpx": "live_host_port", "httprobe": "live_host_port", "smap": "live_host_port",
    "rustscan": "live_host_port",
    # screenshot_visual (gowitness/aquatone produce both host evidence and visual clusters)
    "gowitness": "screenshot_visual", "aquatone": "screenshot_visual",
    # url_content_discovery
    "gau": "url_content_discovery", "waybackurls": "url_content_discovery",
    "katana": "url_content_discovery", "hakrawler": "url_content_discovery",
    "ffuf": "url_content_discovery", "feroxbuster": "url_content_discovery",
    "gobuster": "url_content_discovery", "dirsearch": "url_content_discovery",
    "arjun": "url_content_discovery", "linkfinder": "url_content_discovery", "gospider": "url_content_discovery",
    "x8": "url_content_discovery", "paramspider": "url_content_discovery",
    "gf": "url_content_discovery", "qsreplace": "url_content_discovery",
    "unfurl": "url_content_discovery", "uro": "url_content_discovery",
    "cariddi": "url_content_discovery",
    # js_analysis
    "xnLinkFinder": "js_analysis", "xnlinkfinder": "js_analysis",
    "SecretFinder": "js_analysis", "secretfinder": "js_analysis",
    "jsluice": "js_analysis", "getJS": "js_analysis", "getjs": "js_analysis",
    "subjs": "js_analysis", "jsa": "js_analysis",
    # infra_layer
    "dig": "infra_layer", "tlsx": "infra_layer", "dnsrecon": "infra_layer",
    "cero": "infra_layer", "mapcidr": "infra_layer",
    # tech_stack_deep
    "whatweb": "tech_stack_deep", "wappalyzer": "tech_stack_deep",
    # waf_cdn_fingerprint
    "wafw00f": "waf_cdn_fingerprint",
    # cloud_assets
    "cloud_enum": "cloud_assets", "s3scanner": "cloud_assets", "cloudlist": "cloud_assets",
    # asset_scope
    "whois": "asset_scope", "asnmap": "asset_scope", "favfreak": "asset_scope",
    # passive_osint
    "shodan": "passive_osint", "theharvester": "passive_osint", "waymore": "passive_osint",
    "trufflehog": "passive_osint", "gitleaks": "passive_osint", "censys": "passive_osint",
    # leaked_credentials
    "dehashed": "leaked_credentials", "pwndb": "leaked_credentials",
    "h8mail": "leaked_credentials",
    # waf_cdn_fingerprint (wafw00f also maps to tech_stack_deep above — first match wins)
    # screenshot_visual
    # gowitness/aquatone already mapped to live_host_port (they produce host evidence too)
}


def tool_dimension(cmd: str) -> tuple[str, str]:
    """Given a shell command, return (tool, dimension) if it invokes a known recon
    tool, else ('', ''). Matches the tool as a whole word anywhere in the command."""
    import re as _re
    for tool, dim in TOOL_DIM.items():
        if _re.search(r"(?:^|[\s;|&(])" + _re.escape(tool) + r"(?:[\s;|&)]|$)", cmd):
            return tool, dim
    return "", ""

# Which existing skill EXECUTES each dimension. The gate names this so a block tells
# the operator what to run — wiring the floor to procedures instead of duplicating
# them into a new skill (there are already 4 recon skills; a 5th would be shelfware).
SKILL_MAP = {
    "passive_osint":         "bb-surface-mapping (Gate -2)",
    "subdomain_enum":        "web2-recon (Phase 1)",
    "live_host_port":        "web2-recon (Phase 2)",
    "url_content_discovery": "web2-recon (Phase 3)",
    "infra_layer":           "web2-recon (Phase 1.5) + osint-arsenal (DNS/TLS/reverse-DNS)",
    "tech_stack_deep":       "web2-recon (Phase 2) + osint-arsenal + js-sourcemap-miner",
    "js_analysis":           "web2-recon (Phase 4) + js-sourcemap-miner agent",
    "cloud_assets":          "osint-arsenal (bucket) + bb-bucket-ownership",
    "asset_scope":           "osint-arsenal (WHOIS/RDAP/ASN) + favfreak",
    "employee_osint":        "osint-arsenal (identity-fabric)",
    "leaked_credentials":    "web2-recon (Phase 5) — dehashed/h8mail",
    "waf_cdn_fingerprint":   "web2-recon (Phase 2) — wafw00f per live host",
    "screenshot_visual":     "web2-recon (Phase 2) — gowitness + visual clustering",
}

_DONE = {"done", "complete", "completed", "n/a", "na", "not_applicable"}


def is_done(status) -> bool:
    """A dimension/item counts as satisfied when done, n/a, or explicitly skipped."""
    s = str(status or "").strip().lower()
    return s in _DONE or s.startswith("skipped")


def normalize(rd) -> list[dict]:
    """Return recon_dimensions as a list of {name, status, note, items, raw},
    tolerant of both dict and list-of-dict shapes. Unknown shapes → []."""
    out = []
    if isinstance(rd, dict):
        for k, v in rd.items():
            if isinstance(v, dict):
                out.append({"name": k, "status": str(v.get("status", "")).lower(),
                            "note": v.get("note", ""), "items": v.get("items"), "raw": v})
            else:
                out.append({"name": k, "status": str(v or "").lower(),
                            "note": "", "items": None, "raw": v})
    elif isinstance(rd, list):
        for it in rd:
            if isinstance(it, dict):
                # `dimension` is the third spelling found in the wild (observed
                # 2026-10-01). A reader whose whole purpose is tolerance must not go
                # silent on a spelling it does not know: every CORE dimension read as
                # pending even though the file marked them done, which pinned the
                # recon floor to the top of next_work forever and hid everything
                # ranked below it. A missing key here fails as "not done", never as
                # an error, so nothing announced the mismatch.
                name = it.get("dim") or it.get("name") or it.get("dimension") or ""
                out.append({"name": str(name), "status": str(it.get("status", "")).lower(),
                            "note": it.get("note", ""), "items": it.get("items"), "raw": it})
    return out


def get_dim(rd, name: str) -> dict | None:
    """Return the raw mapping for a named dimension (exact or substring match on the
    canonical name), or None. Substring match lets a free-text list entry like
    `dim: "passive_osint — CT logs"` still resolve to passive_osint."""
    name = name.lower()
    exact = None
    for d in normalize(rd):
        n = d["name"].lower()
        if n == name:
            exact = d
            break
        if name in n and exact is None:
            exact = d
    return exact


def dim_status(rd, name: str):
    """Return (status_str, present_bool) for a named dimension across both shapes."""
    d = get_dim(rd, name)
    if d is None:
        return "", False
    return d["status"], True


def floor_pending(rd, names=None) -> list[tuple[str, str]]:
    """Return [(dim_name, status)] for floor dims that are NOT done.
    A dim absent from recon_dimensions counts as pending (status '')."""
    names = names if names is not None else FLOOR
    out = []
    for n in names:
        st, present = dim_status(rd, n)
        if not is_done(st):
            out.append((n, st if present else ""))
    return out
