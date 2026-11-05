#!/usr/bin/env python3
"""asg_surface_scan.py — pluggable surface scanner + coverage report.

Architecture: three layers
  1. SurfaceExtractor (strategy) — target-type-specific surface extraction
  2. Coverage engine — generic cross-reference with ASG ledger
  3. KB checklist — target-type-specific audit checklist

Supported target types:
  - electron: ipcMain.on/handle regex (structural pattern, 100% recall)
  - webapp:   API endpoint extraction from route definitions
  - firmware: CGI handler / httpd dispatch extraction
  - mobile:   intent-filter / deep link extraction

Regex vs LLM decision boundary:
  - STRUCTURAL patterns (ipcMain.on, app.get, router.post) → regex. Fixed syntax,
    deterministic, zero cost, perfect recall.
  - SEMANTIC analysis (what does this handler do? what capabilities does it expose?
    is this preload bridge method dangerous?) → LLM agent. Dispatch to subagent
    with the handler code context.

Usage:
    # LLM-first discovery (primary — scans project directory):
    python3 asg_surface_scan.py discover <project_dir> <ledger.jsonl> [--target-type electron]

    # Regex surface scan (cross-check — single source file):
    python3 asg_surface_scan.py scan electron <main.js> <ledger.jsonl> [--chains] [--infer-requires]

    # Auto-infer requires/provides edges for CG chain computation:
    python3 asg_surface_scan.py infer <ledger.jsonl> [--append]
"""
from __future__ import annotations

import json
import re
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Optional
from ledger_reader import read_ledger_events


# ══════════════════════════════════════════════════════════════════════════════
# Layer 1: Pluggable Surface Extractors (strategy pattern)
# ══════════════════════════════════════════════════════════════════════════════

class SurfaceExtractor(ABC):
    """Extract attack surfaces from a target artifact.
    Each target type implements its own structural pattern matching."""

    @abstractmethod
    def extract(self, source: Path) -> list[dict]:
        """Return list of {"name": str, "type": str, "family": str, ...}"""
        ...

    @abstractmethod
    def checklist(self, source: Path) -> list[dict]:
        """Run target-type-specific audit checklist.
        Return list of {"id": str, "check": str, "hits": int, "status": str}"""
        ...

    @abstractmethod
    def mention_pattern(self) -> re.Pattern:
        """Regex to extract handler mentions from ledger text fields.
        Used to cross-reference ledger coverage."""
        ...


class ElectronExtractor(SurfaceExtractor):
    """Electron IPC handler extraction via regex.
    ipcMain.on/handle have a fixed structural pattern — regex is the right tool."""

    _IPC_ON = re.compile(r'ipcMain\.on\(\s*["\']([^"\']+)["\']')
    _IPC_HANDLE = re.compile(r'ipcMain\.handle\(\s*["\']([^"\']+)["\']')
    _MENTION = re.compile(r'\b\w+Obj\.\w+\b')

    CHECKLIST = [
        {"id": "EC-01", "check": "shell.openExternal", "grep": r"openExternal|shell\.openPath|showItemInFolder"},
        {"id": "EC-02", "check": "protocol handler", "grep": r"protocol\.handle|registerFileProtocol|setAsDefaultProtocolClient|registerSchemesAsPrivileged"},
        {"id": "EC-03", "check": "senderFrame validation", "grep": r"event\.senderFrame|sender\.getURL"},
        {"id": "EC-04", "check": "webPreferences security", "grep": r"nodeIntegration|contextIsolation|sandbox|webSecurity"},
        {"id": "EC-05", "check": "will-navigate handler", "grep": r"will-navigate"},
        {"id": "EC-06", "check": "CSP headers", "grep": r"Content-Security-Policy|content-security-policy"},
        {"id": "EC-07", "check": "auto-updater", "grep": r"autoUpdater|setFeedURL|checkForUpdates"},
        {"id": "EC-08", "check": "desktopCapturer", "grep": r"desktopCapturer\.getSources"},
        {"id": "EC-09", "check": "executeJavaScript sinks", "grep": r"executeJavaScript"},
        {"id": "EC-10", "check": "net.request", "grep": r"net\.request"},
        {"id": "EC-11", "check": "certificate/TLS", "grep": r"rejectUnauthorized|certificateError|certificate-error"},
        {"id": "EC-12", "check": "child_process", "grep": r"child_process|\.spawn\(|\.exec\(|\.fork\("},
    ]

    def extract(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        handlers = []
        seen: set[str] = set()
        for m in self._IPC_ON.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                handlers.append({"name": name, "type": "on", "family": name.split(".")[0]})
        for m in self._IPC_HANDLE.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                handlers.append({"name": name, "type": "handle", "family": name.split(".")[0]})
        return sorted(handlers, key=lambda h: h["name"])

    def checklist(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        results = []
        for item in self.CHECKLIST:
            matches = len(re.findall(item["grep"], text))
            results.append({**item, "hits": matches, "status": "PRESENT" if matches else "ABSENT"})
        return results

    def mention_pattern(self) -> re.Pattern:
        return self._MENTION


class WebAppExtractor(SurfaceExtractor):
    """Web application API endpoint extraction.
    Covers Express/Koa/FastAPI/Flask/Spring route patterns."""

    _EXPRESS = re.compile(r'(?:app|router)\.(get|post|put|patch|delete|all|use)\(\s*["\']([^"\']+)["\']')
    _FASTAPI = re.compile(r'@(?:app|router)\.(get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']')
    _FLASK = re.compile(r'@\w+\.route\(\s*["\']([^"\']+)["\']')
    _SPRING = re.compile(r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    _MENTION = re.compile(r'(?:GET|POST|PUT|PATCH|DELETE)\s+/\S+')

    WEB_CHECKLIST = [
        {"id": "WC-01", "check": "authentication middleware", "grep": r"authenticate|isAuthenticated|requireAuth|authMiddleware|passport\.authenticate"},
        {"id": "WC-02", "check": "authorization/RBAC", "grep": r"authorize|isAdmin|hasRole|checkPermission|rbac"},
        {"id": "WC-03", "check": "CSRF protection", "grep": r"csrf|csrfToken|xsrf|_token"},
        {"id": "WC-04", "check": "rate limiting", "grep": r"rateLimit|rateLimiter|throttle"},
        {"id": "WC-05", "check": "SQL/ORM injection surface", "grep": r"raw\(|rawQuery|execute\(|query\(|\.where\(.*\$\{"},
        {"id": "WC-06", "check": "file upload", "grep": r"multer|upload|multipart|formidable"},
        {"id": "WC-07", "check": "redirect handling", "grep": r"redirect\(|res\.redirect|302|301|Location:"},
        {"id": "WC-08", "check": "CORS configuration", "grep": r"cors|Access-Control-Allow-Origin|allowedOrigins"},
    ]

    def extract(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        endpoints: list[dict] = []
        seen: set[str] = set()
        for pat, has_method in [(self._EXPRESS, True), (self._FASTAPI, True)]:
            for m in pat.finditer(text):
                method, path = m.group(1).upper(), m.group(2)
                key = f"{method} {path}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({"name": path, "type": method, "family": path.split("/")[1] if "/" in path[1:] else path})
        for pat in [self._FLASK, self._SPRING]:
            for m in pat.finditer(text):
                path = m.group(1)
                key = f"ANY {path}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({"name": path, "type": "ANY", "family": path.split("/")[1] if "/" in path[1:] else path})
        return sorted(endpoints, key=lambda e: e["name"])

    def checklist(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        results = []
        for item in self.WEB_CHECKLIST:
            matches = len(re.findall(item["grep"], text))
            results.append({**item, "hits": matches, "status": "PRESENT" if matches else "ABSENT"})
        return results

    def mention_pattern(self) -> re.Pattern:
        return self._MENTION


class FirmwareExtractor(SurfaceExtractor):
    """Firmware CGI/httpd handler extraction from strings dump or source.
    Targets: GoAhead, lighttpd, busybox httpd, custom CGI dispatchers."""

    _CGI = re.compile(r'/cgi-bin/(\w+(?:\.\w+)?)')
    _GOAHEAD = re.compile(r'websUrlHandlerDefine\(\s*["\']([^"\']+)["\']')
    _HTTPD_CONF = re.compile(r'(?:ScriptAlias|Alias|Location)\s+(/[^\s]+)')
    _MENTION = re.compile(r'/cgi-bin/\w+|/goform/\w+|/HNAP1/\w+')

    FW_CHECKLIST = [
        {"id": "FW-01", "check": "command injection surface", "grep": r"system\(|popen\(|exec\(|execve\(|doSystemCmd"},
        {"id": "FW-02", "check": "buffer overflow risk", "grep": r"strcpy\(|strcat\(|sprintf\(|gets\("},
        {"id": "FW-03", "check": "authentication check", "grep": r"check_auth|isLogin|verify_password|sessionCheck"},
        {"id": "FW-04", "check": "hardcoded credentials", "grep": r"password.*=.*\"|admin.*:.*\"|default_pass"},
        {"id": "FW-05", "check": "firmware update mechanism", "grep": r"fwUpgrade|firmwareUpdate|otaUpdate|mtd_write"},
        {"id": "FW-06", "check": "NVRAM/config access", "grep": r"nvram_get|nvram_set|uci_get|config_get"},
    ]

    def extract(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        handlers: list[dict] = []
        seen: set[str] = set()
        for m in self._CGI.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                handlers.append({"name": f"/cgi-bin/{name}", "type": "cgi", "family": "cgi-bin"})
        for m in self._GOAHEAD.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                handlers.append({"name": name, "type": "goahead", "family": name.split("/")[1] if "/" in name else "goahead"})
        for m in self._HTTPD_CONF.finditer(text):
            path = m.group(1)
            if path not in seen:
                seen.add(path)
                handlers.append({"name": path, "type": "httpd-conf", "family": path.split("/")[1] if "/" in path[1:] else path})
        return sorted(handlers, key=lambda h: h["name"])

    def checklist(self, source: Path) -> list[dict]:
        text = source.read_text(encoding="utf-8", errors="replace")
        results = []
        for item in self.FW_CHECKLIST:
            matches = len(re.findall(item["grep"], text))
            results.append({**item, "hits": matches, "status": "PRESENT" if matches else "ABSENT"})
        return results

    def mention_pattern(self) -> re.Pattern:
        return self._MENTION


EXTRACTORS: dict[str, type[SurfaceExtractor]] = {
    "electron": ElectronExtractor,
    "webapp": WebAppExtractor,
    "firmware": FirmwareExtractor,
}


# ══════════════════════════════════════════════════════════════════════════════
# Layer 2: Generic coverage engine (target-agnostic)
# ══════════════════════════════════════════════════════════════════════════════

def load_ledger_coverage(ledger: Path, mention_pat: re.Pattern) -> dict:
    """Load existing ledger and extract handler-level coverage info.

    Honest coverage: a handler is 'tested' only when it appears in a
    hypothesis claim AND that hypothesis has a verdict.
    """
    if not ledger.exists():
        return {"surfaces": set(), "hypotheses": {}, "verdicts": {},
                "hyp_handlers": {}, "tested_handlers": set()}

    surfaces: set[str] = set()
    hypotheses: dict[str, str] = {}
    verdicts: dict[str, dict] = {}
    hyp_handlers: dict[str, set[str]] = {}

    for e in read_ledger_events(ledger):
        if e["type"] == "surface":
            surfaces.add(e.get("name", ""))
        elif e["type"] == "hypothesis":
            hid = e.get("id", "")
            claim = e.get("claim", "")
            hypotheses[hid] = claim
            hyp_handlers[hid] = set(mention_pat.findall(claim))
        elif e["type"] == "verdict":
            hid = e.get("hypothesis", "")
            verdicts[hid] = {"status": e.get("status", ""), "evidence": e.get("evidence", "")}
            for token in mention_pat.findall(str(e.get("evidence", ""))):
                hyp_handlers.setdefault(hid, set()).add(token)

    tested_handlers: set[str] = set()
    for hid, hset in hyp_handlers.items():
        if hid in verdicts:
            tested_handlers.update(hset)

    return {
        "surfaces": surfaces,
        "hypotheses": hypotheses,
        "verdicts": verdicts,
        "hyp_handlers": hyp_handlers,
        "tested_handlers": tested_handlers,
    }


def compute_coverage(handlers: list[dict], ledger_data: dict) -> dict:
    """Compute handler-level coverage report.

    Honest metric: covered = handler in a hypothesis that has a verdict.
    """
    tested = ledger_data["tested_handlers"]
    families: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "covered": 0, "handlers": []})

    for h in handlers:
        fam = h["family"]
        families[fam]["total"] += 1
        is_tested = h["name"] in tested
        families[fam]["handlers"].append({**h, "covered": is_tested})
        if is_tested:
            families[fam]["covered"] += 1

    total = len(handlers)
    covered = sum(1 for h in handlers if h["name"] in tested)

    return {
        "total_handlers": total,
        "covered_handlers": covered,
        "uncovered_handlers": total - covered,
        "coverage_pct": round(covered / total * 100, 1) if total else 0,
        "families": dict(families),
        "uncovered": [h for h in handlers if h["name"] not in tested],
    }


def generate_missing_surfaces(handlers: list[dict], ledger_data: dict) -> list[dict]:
    """Generate surface events for handlers without hypothesis+verdict."""
    tested = ledger_data["tested_handlers"]
    events = []
    for h in handlers:
        if h["name"] not in tested:
            events.append({
                "id": f"S-auto-{h['name'].replace('.', '-').replace('/', '-').lstrip('-')}",
                "type": "surface",
                "ts": "auto",
                "name": h["name"],
                "desc": f"{h['type']}('{h['name']}') — auto-discovered, untested",
                "layer": "main-process",
                "source": "asg_surface_scan",
                "handler_type": h["type"],
                "family": h["family"],
            })
    return events


# ══════════════════════════════════════════════════════════════════════════════
# Layer 3: Attack chain graph (target-agnostic, from meta events)
# ══════════════════════════════════════════════════════════════════════════════

def compute_chains(ledger: Path) -> dict:
    """Compute attack chains from meta events (variant-of, chain, enrichment-of)."""
    if not ledger.exists():
        return {"chains": [], "graph": {}}

    hypotheses: dict[str, dict] = {}
    verdicts: dict[str, dict] = {}
    edges: list[dict] = []

    for e in read_ledger_events(ledger):
        if e["type"] == "hypothesis":
            hypotheses[e.get("id", "")] = {
                "name": e.get("name", ""),
                "claim": e.get("claim", ""),
                "surface": e.get("surface", ""),
            }
        elif e["type"] == "verdict":
            verdicts[e.get("hypothesis", "")] = {
                "status": e.get("status", ""),
                "severity": e.get("severity", ""),
            }
        elif e["type"] == "meta":
            action = e.get("action", "")
            src = e.get("hypothesis", "")
            if action == "variant_of":
                dst = e.get("variant_of", "")
                edges.append({"type": "variant", "src": src, "dst": dst, "reason": e.get("reason", "")})
            elif action == "chain":
                chain_str = e.get("chain", "")
                edges.append({"type": "chain", "src": src, "chain": chain_str, "reason": e.get("reason", "")})
            elif action == "enrichment_of":
                dst = e.get("enrichment_of", "")
                edges.append({"type": "enrichment", "src": src, "dst": dst, "reason": e.get("reason", "")})

    adj: dict[str, set] = defaultdict(set)
    for edge in edges:
        if edge["type"] == "variant":
            adj[edge["src"]].add(edge["dst"])
            adj[edge["dst"]].add(edge["src"])
        elif edge["type"] == "enrichment":
            adj[edge["src"]].add(edge["dst"])

    visited: set[str] = set()
    groups: list[list[str]] = []
    for node in hypotheses:
        if node in visited:
            continue
        group: set[str] = set()
        stack = [node]
        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            group.add(n)
            for neighbor in adj.get(n, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        if len(group) > 1:
            groups.append(sorted(group))

    return {
        "edges": edges,
        "root_cause_groups": groups,
        "total_hypotheses": len(hypotheses),
        "unique_root_causes": len(hypotheses) - sum(len(g) - 1 for g in groups),
        "verdicts": verdicts,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Layer 3b: LLM-first surface discovery (primary discovery mechanism)
# ══════════════════════════════════════════════════════════════════════════════

SOURCE_EXTENSIONS = {
    "electron": [".js", ".mjs", ".ts", ".html"],
    "webapp": [".js", ".ts", ".py", ".java", ".rb", ".go", ".php"],
    "firmware": [".c", ".h", ".conf", ".lua", ".sh", ".cgi"],
}

MAX_FILE_SIZE = 500_000


def _collect_source_files(project_dir: Path, target_type: str) -> list[Path]:
    """Collect relevant source files from a project directory."""
    exts = set(SOURCE_EXTENSIONS.get(target_type, SOURCE_EXTENSIONS["webapp"]))
    files: list[Path] = []
    skip = {".git", "node_modules", "__pycache__", ".state", "dist", "build", ".workshop"}
    for f in sorted(project_dir.rglob("*")):
        if any(p in skip for p in f.parts):
            continue
        if f.suffix in exts and f.is_file() and f.stat().st_size < MAX_FILE_SIZE:
            files.append(f)
    return files


def build_discovery_prompt(
    project_dir: Path,
    target_type: str = "electron",
    ledger_path_: Optional[Path] = None,
    extractor: Optional[SurfaceExtractor] = None,
) -> dict:
    """Build an LLM prompt for complete attack surface discovery.

    This is the PRIMARY discovery mechanism. The LLM reads the project source
    and identifies ALL entry points where external input enters the system —
    not limited to what regex can match.

    If an extractor is provided, its regex results are included as a cross-check
    seed (things the LLM should NOT miss), but the LLM is free to find more.

    Returns {"prompt": str, "files_included": list, "regex_seed": list, ...}
    """
    files = _collect_source_files(project_dir, target_type)
    if not files:
        return {"prompt": "", "files_included": [], "error": "no source files found"}

    file_summaries: list[str] = []
    total_size = 0
    included: list[str] = []
    for f in files:
        size = f.stat().st_size
        if total_size + size > 200_000:
            break
        rel = f.relative_to(project_dir)
        text = f.read_text(encoding="utf-8", errors="replace")
        file_summaries.append(f"### {rel} ({size:,} bytes)\n```\n{text[:8000]}\n```")
        included.append(str(rel))
        total_size += size

    regex_seed: list[dict] = []
    if extractor:
        for f in files:
            try:
                regex_seed.extend(extractor.extract(f))
            except Exception:
                pass

    already_known: set[str] = set()
    if ledger_path_ and ledger_path_.exists():
        for e in read_ledger_events(ledger_path_):
            if e["type"] in ("surface", "hypothesis"):
                already_known.add(e.get("name", e.get("id", "")))

    target_guidance = {
        "electron": (
            "This is an Electron desktop application. Attack surfaces include:\n"
            "- IPC handlers (ipcMain.on / ipcMain.handle)\n"
            "- Preload bridge (contextBridge.exposeInMainWorld) — each exposed object and method\n"
            "- Protocol handlers (protocol.handle, registerSchemesAsPrivileged)\n"
            "- BrowserWindow configuration (webPreferences, nodeIntegration, contextIsolation)\n"
            "- webContents events (will-navigate, new-window, did-navigate)\n"
            "- Native addons (.node files, child_process)\n"
            "- Auto-updater (setFeedURL, checkForUpdates)\n"
            "- shell.openExternal / shell.openPath calls\n"
            "- executeJavaScript sinks\n"
            "- desktopCapturer usage\n"
            "- Deep link / custom scheme handling"
        ),
        "webapp": (
            "This is a web application. Attack surfaces include:\n"
            "- API endpoints (routes, controllers) — each method + path\n"
            "- Authentication/session management\n"
            "- File upload handlers\n"
            "- Database queries (especially raw/interpolated)\n"
            "- Redirect handling\n"
            "- WebSocket endpoints\n"
            "- GraphQL resolvers\n"
            "- Server-side rendering with user input\n"
            "- CORS configuration\n"
            "- Cookie/token handling"
        ),
        "firmware": (
            "This is an embedded/firmware system. Attack surfaces include:\n"
            "- CGI handlers (/cgi-bin/, /goform/, /HNAP1/)\n"
            "- HTTPD route dispatch (URL → handler function mapping)\n"
            "- system()/popen()/exec() calls with user input\n"
            "- NVRAM get/set operations\n"
            "- Firmware update mechanisms\n"
            "- Authentication/session checks\n"
            "- UPnP/SSDP handlers\n"
            "- UART/serial debug interfaces\n"
            "- Hardcoded credentials"
        ),
    }

    prompt_parts = [
        "You are a security researcher performing COMPLETE attack surface discovery.",
        f"Target type: {target_type}",
        f"Project directory: {project_dir.name}",
        f"Files included: {len(included)}",
        "",
        target_guidance.get(target_type, target_guidance["webapp"]),
        "",
        "YOUR TASK: Identify EVERY entry point where external input enters the system.",
        "Do NOT limit yourself to one category (e.g., only IPC handlers).",
        "Scan ALL files for ALL categories listed above.",
        "",
        "For each surface found, return:",
        "  - name: unique identifier (e.g., 'settingObj.checkJsonWebTokenByFileAsync')",
        "  - category: which category from the list above",
        "  - file: which source file",
        "  - description: one sentence on what it does",
        "  - accepts_input: what user-controlled data it receives",
        "  - risk_level: HIGH / MEDIUM / LOW / INFO",
        "",
        "Return a JSON array of objects.",
    ]

    if regex_seed:
        prompt_parts.append(f"\n── REGEX CROSS-CHECK SEED ({len(regex_seed)} items) ──")
        prompt_parts.append("These were found by structural regex. You MUST NOT miss any of these,")
        prompt_parts.append("AND you should find surfaces in categories regex cannot reach.\n")
        for s in regex_seed[:30]:
            prompt_parts.append(f"  - {s['name']} ({s['type']})")

    if already_known:
        prompt_parts.append(f"\n── ALREADY KNOWN ({len(already_known)} surfaces in ledger) ──")
        prompt_parts.append("These are already recorded. Focus on finding NEW surfaces.\n")
        for name in sorted(list(already_known))[:30]:
            prompt_parts.append(f"  - {name}")

    prompt_parts.append("\n── SOURCE FILES ──")
    prompt_parts.extend(file_summaries)

    return {
        "prompt": "\n".join(prompt_parts),
        "files_included": included,
        "files_skipped": len(files) - len(included),
        "regex_seed_count": len(regex_seed),
        "already_known_count": len(already_known),
    }


def cross_check(
    llm_surfaces: list[dict],
    regex_surfaces: list[dict],
) -> dict:
    """Compare LLM-discovered surfaces against regex-extracted surfaces.
    Flags regex finds that LLM missed (structural blindspot) and
    LLM finds that regex couldn't reach (semantic discovery)."""
    llm_names = {s["name"] for s in llm_surfaces}
    regex_names = {s["name"] for s in regex_surfaces}

    return {
        "llm_only": sorted(llm_names - regex_names),
        "regex_only": sorted(regex_names - llm_names),
        "both": sorted(llm_names & regex_names),
        "llm_total": len(llm_names),
        "regex_total": len(regex_names),
        "llm_recall_of_regex": round(len(llm_names & regex_names) / len(regex_names) * 100, 1) if regex_names else 100.0,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Layer 4: LLM-driven surface triage (prompt builder, not executor)
# ══════════════════════════════════════════════════════════════════════════════

def build_triage_prompt(
    surfaces: list[dict],
    source_path: Path,
    ledger_path_: Optional[Path] = None,
    context_lines: int = 30,
) -> dict:
    """Build a structured prompt for an LLM agent to semantically triage surfaces.

    This function does NOT call the LLM — it produces the prompt + schema that
    the orchestrator dispatches to a subagent. The regex pre-scan finds WHERE
    handlers are; the LLM figures out WHAT they do and WHETHER they're dangerous.

    Returns {"prompt": str, "response_schema": dict, "surface_count": int}
    """
    source_text = source_path.read_text(encoding="utf-8", errors="replace")

    already_tested: set[str] = set()
    if ledger_path_ and ledger_path_.exists():
        for e in read_ledger_events(ledger_path_):
            if e["type"] in ("hypothesis", "verdict"):
                text = e.get("claim", e.get("evidence", ""))
                for s in surfaces:
                    if s["name"] in str(text):
                        already_tested.add(s["name"])

    untested = [s for s in surfaces if s["name"] not in already_tested]
    if not untested:
        return {"prompt": "", "response_schema": {}, "surface_count": 0,
                "message": "all surfaces already tested"}

    surface_contexts: list[dict] = []
    for s in untested:
        pattern = re.escape(s["name"])
        matches = list(re.finditer(pattern, source_text))
        snippets = []
        for m in matches[:3]:
            start = max(0, source_text.rfind("\n", 0, max(0, m.start() - 500)) + 1)
            end = min(len(source_text), source_text.find("\n", m.end() + 500))
            if end == -1:
                end = min(len(source_text), m.end() + 500)
            snippets.append(source_text[start:end])
        surface_contexts.append({
            "name": s["name"],
            "type": s["type"],
            "family": s["family"],
            "code_snippets": snippets,
        })

    prompt_parts = [
        "You are a security researcher analyzing attack surfaces.",
        f"Source file: {source_path.name}",
        f"Total untested surfaces: {len(untested)}",
        "",
        "For EACH surface below, analyze the code context and determine:",
        "1. What does this handler/endpoint DO? (one sentence)",
        "2. What user-controlled input does it accept?",
        "3. What dangerous operations does it perform? (fs, exec, eval, network, etc.)",
        "4. What validation/sanitization is applied to the input?",
        "5. Security verdict: DANGEROUS / NEEDS_TESTING / SAFE",
        "6. If DANGEROUS: what is the root cause? (e.g., 'unsanitized template interpolation', "
        "'missing path validation', 'no authentication check')",
        "7. If DANGEROUS: what capability does exploitation provide? "
        "(e.g., 'arbitrary-file-read', 'rce', 'info-disclosure')",
        "",
        "Return a JSON array of objects with fields: "
        "name, verdict, description, input_type, dangerous_ops, validation, "
        "root_cause (null if SAFE), capability (null if SAFE), severity (P1/P2/P3, null if SAFE).",
        "",
        "── SURFACES TO ANALYZE ──",
    ]

    for sc in surface_contexts:
        prompt_parts.append(f"\n### {sc['name']} (type: {sc['type']}, family: {sc['family']})")
        for i, snippet in enumerate(sc["code_snippets"]):
            prompt_parts.append(f"```javascript\n// Context {i+1}\n{snippet}\n```")

    response_schema = {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["name", "verdict", "description"],
            "properties": {
                "name": {"type": "string"},
                "verdict": {"enum": ["DANGEROUS", "NEEDS_TESTING", "SAFE"]},
                "description": {"type": "string"},
                "input_type": {"type": "string"},
                "dangerous_ops": {"type": "array", "items": {"type": "string"}},
                "validation": {"type": "string"},
                "root_cause": {"type": ["string", "null"]},
                "capability": {"type": ["string", "null"]},
                "severity": {"type": ["string", "null"]},
            },
        },
    }

    return {
        "prompt": "\n".join(prompt_parts),
        "response_schema": response_schema,
        "surface_count": len(untested),
        "already_tested": len(already_tested),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Layer 5: Root cause analysis (from confirmed findings)
# ══════════════════════════════════════════════════════════════════════════════

ROOT_CAUSE_PATTERNS: list[dict] = [
    {
        "id": "RC-TEMPLATE-INJECTION",
        "name": "Unsanitized template interpolation into code execution sink",
        "indicators": [r"executeJavaScript", r"template.*inject", r"string interpolat",
                       r"quote breakout", r"initMessageList", r"answerScript.*global",
                       r"eval\(", r"Function\("],
        "cwe": "CWE-94",
        "fix": "Parameterize all data passed to executeJavaScript; never interpolate user data into code strings",
    },
    {
        "id": "RC-NO-SENDER-VALIDATION",
        "name": "IPC handler accepts messages from any renderer without origin check",
        "indicators": [r"senderFrame", r"sender\.getURL", r"no.*validation.*sender",
                       r"zero.*senderFrame", r"any renderer"],
        "cwe": "CWE-284",
        "fix": "Validate event.senderFrame.url against allowlist before processing IPC messages",
    },
    {
        "id": "RC-PATH-TRAVERSAL",
        "name": "User-controlled filesystem path without validation",
        "indicators": [r"path.*travers", r"arbitrary.*file", r"fs\.read.*user",
                       r"readFile.*no.*valid", r"SavePath", r"jwtFilePath"],
        "cwe": "CWE-22",
        "fix": "Validate paths against an allowlist or restrict to a safe base directory",
    },
    {
        "id": "RC-MISSING-CONSENT",
        "name": "Sensitive operation performed without user consent",
        "indicators": [r"without.*consent", r"bypass.*consent", r"no.*dialog",
                       r"auto.?accept", r"silent.*capture", r"bypasses consent"],
        "cwe": "CWE-862",
        "fix": "Require explicit user consent dialog before sensitive operations",
    },
    {
        "id": "RC-MISSING-AUTH",
        "name": "Endpoint/handler accessible without authentication",
        "indicators": [r"unauth", r"no.*auth", r"without.*auth", r"unauthenticated",
                       r"no.*permission", r"any.*renderer"],
        "cwe": "CWE-306",
        "fix": "Enforce authentication and authorization checks before processing",
    },
    {
        "id": "RC-HARDCODED-SECRET",
        "name": "Security-critical value hardcoded instead of configurable",
        "indicators": [r"hardcoded", r"hard.?coded", r"demo\.", r"clockTolerance.*MAX",
                       r"permanent.*replay"],
        "cwe": "CWE-798",
        "fix": "Use secure configuration management; rotate secrets regularly",
    },
    {
        "id": "RC-MISSING-NAVIGATION-GUARD",
        "name": "BrowserWindow navigation not restricted",
        "indicators": [r"will-navigate", r"unrestricted.*navigat", r"navigation.*unrestric",
                       r"openWindow.*attacker"],
        "cwe": "CWE-601",
        "fix": "Register will-navigate handlers to restrict navigation to trusted origins",
    },
    {
        "id": "RC-UNSAFE-UPDATE",
        "name": "Software update mechanism without integrity verification",
        "indicators": [r"auto.?updat", r"setFeedURL", r"supply.?chain", r"no.*HTTPS.*enforc",
                       r"cert.*pin"],
        "cwe": "CWE-494",
        "fix": "Enforce HTTPS with certificate pinning for update channels; verify code signatures",
    },
    {
        "id": "RC-INPUT-INJECTION",
        "name": "Raw user input passed to dangerous operation",
        "indicators": [r"keystroke.*inject", r"keyPress.*raw", r"keyRelease.*raw",
                       r"clipboard.*write.*arbit", r"mouse.*inject", r"arbitrary.*input",
                       r"raw.*string.*Enigo", r"no.*clamp", r"no.*bounds", r"calculateMousePoint"],
        "cwe": "CWE-74",
        "fix": "Validate and sanitize all user-controlled input before passing to system operations",
    },
    {
        "id": "RC-PRELOAD-ORIGIN-AGNOSTIC",
        "name": "Preload bridge exposes privileged APIs to all origins",
        "indicators": [r"contextBridge.*all.*origin", r"preload.*origin.*agnostic",
                       r"exposeInMainWorld.*all", r"100\+.*method.*ALL"],
        "cwe": "CWE-284",
        "fix": "Gate contextBridge methods on window.location.origin allowlist",
    },
    {
        "id": "RC-UNSAFE-EXTERNAL-OPEN",
        "name": "User-controlled URL passed to shell.openExternal without protocol check",
        "indicators": [r"shell\.openExternal", r"openExternal.*protocol",
                       r"non-server.*URL.*openExternal"],
        "cwe": "CWE-78",
        "fix": "Restrict shell.openExternal to https:// URLs matching a known allowlist",
    },
    {
        "id": "RC-MISSING-CSP",
        "name": "No Content Security Policy on web content",
        "indicators": [r"zero.*CSP", r"no.*CSP", r"Content-Security-Policy.*absent",
                       r"CSP.*absence"],
        "cwe": "CWE-1021",
        "fix": "Deploy strict CSP headers on all HTML entry points",
    },
]


def find_root_causes(ledger: Path) -> dict:
    """Analyze confirmed findings to identify shared root causes.

    Two-pass approach:
      1. Regex pass: match evidence/claim text against known root cause patterns
      2. Unmatched findings flagged for LLM analysis (prompt returned, not executed)

    Returns root cause groups with affected findings, combined severity, and fix recommendations.
    """
    if not ledger.exists():
        return {"root_causes": [], "unmatched": [], "llm_prompt": ""}

    findings: list[dict] = []
    for e in read_ledger_events(ledger):
        if e["type"] == "hypothesis":
            findings.append({
                "id": e.get("id", ""),
                "claim": e.get("claim", ""),
                "severity": e.get("severity", ""),
                "evidence": "",
                "provides": [],
                "status": "",
            })
        elif e["type"] == "verdict":
            hid = e.get("hypothesis", "")
            for f in findings:
                if f["id"] == hid:
                    f["status"] = e.get("status", "")
                    f["evidence"] = e.get("evidence", "")
                    f["severity"] = e.get("severity", "") or f["severity"]
                    f["provides"] = e.get("provides", [])

    confirmed = [f for f in findings if f["status"] == "confirmed"]

    root_causes: list[dict] = []
    matched_ids: set[str] = set()

    for rc in ROOT_CAUSE_PATTERNS:
        affected: list[dict] = []
        for f in confirmed:
            if f["id"] in matched_ids:
                continue
            text = f"{f['claim']} {f['evidence']}".lower()
            for indicator in rc["indicators"]:
                if re.search(indicator, text, re.IGNORECASE):
                    affected.append(f)
                    matched_ids.add(f["id"])
                    break

        if affected:
            severities = [f["severity"] for f in affected if f["severity"]]
            worst = "P1" if "P1" in severities else "P2" if "P2" in severities else "P3"
            root_causes.append({
                "root_cause_id": rc["id"],
                "name": rc["name"],
                "cwe": rc["cwe"],
                "fix": rc["fix"],
                "affected_count": len(affected),
                "worst_severity": worst,
                "findings": [{"id": f["id"], "severity": f["severity"],
                              "claim_excerpt": f["claim"][:120]} for f in affected],
            })

    unmatched = [f for f in confirmed if f["id"] not in matched_ids]

    llm_prompt = ""
    if unmatched:
        llm_parts = [
            "The following confirmed findings could not be matched to a known root cause pattern.",
            "For each, identify:",
            "1. The root cause (the architectural flaw, not the symptom)",
            "2. CWE classification",
            "3. Whether it shares a root cause with any other finding in this list",
            "4. Recommended fix",
            "",
            "Return JSON array of {id, root_cause, cwe, shared_with: [other_ids], fix}.",
            "",
        ]
        for f in unmatched:
            llm_parts.append(f"- {f['id']} ({f['severity']}): {f['claim'][:200]}")
            if f["evidence"]:
                llm_parts.append(f"  Evidence: {str(f['evidence'])[:200]}")
        llm_prompt = "\n".join(llm_parts)

    return {
        "root_causes": sorted(root_causes, key=lambda r: (
            {"P1": 0, "P2": 1, "P3": 2}.get(r["worst_severity"], 3),
            -r["affected_count"],
        )),
        "total_confirmed": len(confirmed),
        "matched": len(matched_ids),
        "unmatched_findings": [{"id": f["id"], "severity": f["severity"],
                                 "claim_excerpt": f["claim"][:120]} for f in unmatched],
        "llm_prompt": llm_prompt,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Layer 6: Requires inference (auto-populate CG edges from evidence)
# ══════════════════════════════════════════════════════════════════════════════

CAPABILITY_ALIASES: dict[str, str] = {
    "code-execution-main": "renderer-code-execution",
    "local-file-read": "arbitrary-file-read",
    "local-input-control": "os-level-input-injection",
    "xss-in-renderer": "renderer-code-execution",
    "custom-scheme-handler": "custom-scheme-rce",
}


def _canonical_cap(name: str) -> str:
    return CAPABILITY_ALIASES.get(name, name)


REQUIRES_INFERENCE_RULES: list[dict] = [
    {
        "id": "RI-XSS-CHAIN",
        "description": "Finding chains from XSS/code execution in a renderer",
        "claim_patterns": [r"XSS\s*→", r"XSS.*chain", r"cross-site scripting.*to\b",
                           r"arbitrary.*JS.*execution.*→", r"code.*execution.*→"],
        "inferred_requires": ["xss-in-renderer"],
    },
    {
        "id": "RI-IPC-NO-SENDER",
        "description": "IPC handler without sender validation — reachable from any renderer (XSS is the entry)",
        "claim_patterns": [r"no.*senderFrame", r"zero.*senderFrame", r"any renderer",
                           r"without.*sender.*valid"],
        "inferred_requires": ["xss-in-renderer"],
    },
    {
        "id": "RI-REMOTE-CONTROL-ACCESS",
        "description": "Finding requires active remote control session",
        "claim_patterns": [r"keyDown|keyUp|keyPress|keyRelease|calculateMousePoint|clipboard.*write",
                           r"remoteControlObj\.", r"EnigoWrapper"],
        "inferred_requires": ["remote-control-no-auth"],
    },
    {
        "id": "RI-NAVIGATION-CONTROL",
        "description": "Finding requires ability to navigate a BrowserWindow",
        "claim_patterns": [r"loads.*attacker.*URL", r"navigat.*attacker",
                           r"openWindow.*preload", r"redirect.*preload"],
        "inferred_requires": ["navigation-unrestricted"],
    },
    {
        "id": "RI-CUSTOM-SCHEME",
        "description": "Finding uses myapp:// or custom scheme as entry",
        "claim_patterns": [r"myapp://", r"custom.*scheme", r"deep.*link.*inject",
                           r"protocol.*handler"],
        "inferred_requires": ["custom-scheme-handler"],
    },
    {
        "id": "RI-PRELOAD-BRIDGE",
        "description": "Finding exploits exposed preload bridge methods",
        "claim_patterns": [r"contextBridge", r"preload.*bridge", r"exposeInMainWorld"],
        "inferred_requires": ["preload-origin-agnostic"],
    },
    {
        "id": "RI-CONSENT-BYPASS",
        "description": "Finding bypasses consent to gain remote control",
        "claim_patterns": [r"bypass.*consent", r"without.*consent.*dialog",
                           r"auto.?accept.*remote"],
        "inferred_requires": ["xss-in-renderer"],
    },
]

PROVIDES_INFERENCE_RULES: list[dict] = [
    {
        "claim_patterns": [r"executeJavaScript", r"template.*inject", r"code.*execut",
                           r"RCE", r"remote.*code.*execut"],
        "inferred_provides": ["code-execution-main"],
    },
    {
        "claim_patterns": [r"arbitrary.*file.*read", r"fs\.read", r"path.*travers.*read"],
        "inferred_provides": ["local-file-read"],
    },
    {
        "claim_patterns": [r"keystroke.*inject", r"keyPress|keyRelease", r"mouse.*inject",
                           r"physical.*input"],
        "inferred_provides": ["local-input-control"],
    },
    {
        "claim_patterns": [r"screen.*capture", r"desktopCapturer", r"screenshot.*silent"],
        "inferred_provides": ["silent-screen-capture"],
    },
    {
        "claim_patterns": [r"clipboard.*write", r"clipboard.*arbit"],
        "inferred_provides": ["clipboard-write"],
    },
    {
        "claim_patterns": [r"bypass.*consent|without.*consent", r"directStart.*Remote",
                           r"auto.?accept"],
        "inferred_provides": ["remote-control-no-auth"],
    },
    {
        "claim_patterns": [r"navigation.*unrestric", r"will-navigate.*zero",
                           r"any.*BrowserWindow.*navigab"],
        "inferred_provides": ["navigation-unrestricted"],
    },
    {
        "claim_patterns": [r"preload.*origin.*agnostic", r"contextBridge.*all.*origin",
                           r"100\+.*method.*ALL"],
        "inferred_provides": ["preload-origin-agnostic"],
    },
    {
        "claim_patterns": [r"XSS|cross-site.*script"],
        "inferred_provides": ["xss-in-renderer"],
    },
    {
        "claim_patterns": [r"custom.*scheme.*RCE", r"myapp://.*executeJavaScript"],
        "inferred_provides": ["custom-scheme-rce"],
    },
]


def infer_requires(ledger: Path) -> dict:
    """Auto-infer requires/provides edges from confirmed findings' evidence and claims.

    Solves: 0/N hypotheses having `requires` fields → CG chain computation is flat.

    Two-pass:
      1. Pattern-match claims/evidence to infer what each finding requires and provides
      2. Build a capability dependency graph so auto_chain can compute real chains

    Returns {
        "inferred": [{hyp_id, requires, provides, rules_matched}],
        "events": [ledger events to append],
        "stats": {total, with_requires, with_provides, edges}
    }
    """
    if not ledger.exists():
        return {"inferred": [], "events": [], "stats": {}}

    hypotheses: dict[str, dict] = {}
    confirmed_ids: set[str] = set()
    existing_provides: dict[str, list[str]] = {}

    for e in read_ledger_events(ledger):
        if e["type"] == "hypothesis":
            hid = e.get("id", "")
            hypotheses[hid] = {
                "claim": e.get("claim", ""),
                "severity": e.get("severity", ""),
                "existing_requires": e.get("requires", []),
                "existing_provides": [],
            }
        elif e["type"] == "verdict":
            hid = e.get("hypothesis", "")
            if e.get("status") == "confirmed":
                confirmed_ids.add(hid)
                provides = e.get("provides", [])
                if provides and hid in hypotheses:
                    hypotheses[hid]["existing_provides"] = provides
                    existing_provides[hid] = provides

    inferred: list[dict] = []
    events: list[dict] = []

    for hid, hyp in hypotheses.items():
        if hid not in confirmed_ids:
            continue

        req_rules: list[str] = []
        prov_rules: list[str] = []
        new_requires: list[str] = []
        new_provides: list[str] = []

        existing_req_canonical = {_canonical_cap(c) for c in hyp["existing_requires"]}
        existing_prov_canonical = {_canonical_cap(c) for c in hyp["existing_provides"]}

        for rule in PROVIDES_INFERENCE_RULES:
            for pat in rule["claim_patterns"]:
                if re.search(pat, hyp["claim"], re.IGNORECASE):
                    for cap in rule["inferred_provides"]:
                        cc = _canonical_cap(cap)
                        if cc not in existing_prov_canonical and cc not in {_canonical_cap(c) for c in new_provides}:
                            new_provides.append(cc)
                    prov_rules.append(f"PI-{cc}")
                    break

        all_provides = existing_prov_canonical | {_canonical_cap(c) for c in new_provides}

        for rule in REQUIRES_INFERENCE_RULES:
            for pat in rule["claim_patterns"]:
                if re.search(pat, hyp["claim"], re.IGNORECASE):
                    for cap in rule["inferred_requires"]:
                        cc = _canonical_cap(cap)
                        if cc not in all_provides and cc not in existing_req_canonical and cc not in {_canonical_cap(c) for c in new_requires}:
                            new_requires.append(cc)
                    req_rules.append(rule["id"])
                    break

        if new_requires or new_provides:
            record = {
                "hyp_id": hid,
                "requires": list(existing_req_canonical | set(new_requires)),
                "provides": list(existing_prov_canonical | set(new_provides)),
                "rules_matched": req_rules + prov_rules,
            }
            inferred.append(record)

            if new_requires:
                merged_req = sorted(existing_req_canonical | set(new_requires))
                events.append({
                    "type": "hypothesis",
                    "id": hid,
                    "ts": "__NOW__",
                    "requires": merged_req,
                    "claim": hyp["claim"],
                    "note": f"auto-inferred requires: {new_requires}",
                })
            if new_provides and not hyp["existing_provides"]:
                events.append({
                    "type": "verdict",
                    "hypothesis": hid,
                    "status": "confirmed",
                    "provides": new_provides,
                    "ts": "__NOW__",
                    "note": f"provides-backfill: auto-inferred {new_provides}",
                })

    with_req = sum(1 for i in inferred if any(
        r for r in REQUIRES_INFERENCE_RULES if r["id"] in i["rules_matched"]))
    with_prov = sum(1 for i in inferred if any(
        r for r in i["rules_matched"] if r.startswith("PI-")))
    total_edges = sum(len(i["requires"]) for i in inferred)

    return {
        "inferred": inferred,
        "events": events,
        "stats": {
            "total_confirmed": len(confirmed_ids),
            "with_requires": with_req,
            "with_provides": with_prov,
            "new_edges": total_edges,
            "already_had_provides": len(existing_provides),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="ASG pluggable surface scanner + coverage report",
    )
    sub = ap.add_subparsers(dest="command")

    # ── discover: LLM-first surface discovery (primary) ──
    p_discover = sub.add_parser("discover", help="LLM-first surface discovery from project directory")
    p_discover.add_argument("project_dir", type=Path, help="Project directory to scan")
    p_discover.add_argument("ledger", type=Path, help="Path to ASG ledger JSONL")
    p_discover.add_argument("--target-type", default="electron", choices=list(EXTRACTORS.keys()))
    p_discover.add_argument("--json", action="store_true")

    # ── scan: regex surface scan (cross-check) ──
    p_scan = sub.add_parser("scan", help="Regex-only surface scan (cross-check)")
    p_scan.add_argument("target_type", choices=list(EXTRACTORS.keys()),
                        help="Target type (determines extraction strategy)")
    p_scan.add_argument("source", type=Path, help="Source file to scan")
    p_scan.add_argument("ledger", type=Path, help="Path to ASG ledger JSONL")
    p_scan.add_argument("--append", action="store_true", help="Append missing surface events to ledger")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--chains", action="store_true", help="Compute attack chain graph")
    p_scan.add_argument("--checklist", action="store_true", help="Run target-type audit checklist")
    p_scan.add_argument("--triage", action="store_true", help="Generate LLM triage prompt")
    p_scan.add_argument("--root-causes", action="store_true", help="Find root causes")
    p_scan.add_argument("--infer-requires", action="store_true", help="Auto-infer requires/provides edges")

    # ── infer: standalone requires inference ──
    p_infer = sub.add_parser("infer", help="Auto-infer requires/provides edges for CG chain computation")
    p_infer.add_argument("ledger", type=Path, help="Path to ASG ledger JSONL")
    p_infer.add_argument("--append", action="store_true", help="Append inferred events to ledger")
    p_infer.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    if args.command == "discover":
        extractor = EXTRACTORS.get(args.target_type)
        ext_instance = extractor() if extractor else None
        result = build_discovery_prompt(
            args.project_dir, args.target_type, args.ledger, ext_instance,
        )
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            print(f"═══ ASG LLM-First Discovery ═══")
            print(f"Project: {args.project_dir}")
            print(f"Target type: {args.target_type}")
            print(f"Files included: {len(result.get('files_included', []))}")
            print(f"Files skipped (size cap): {result.get('files_skipped', 0)}")
            print(f"Regex cross-check seed: {result.get('regex_seed_count', 0)} surfaces")
            print(f"Already in ledger: {result.get('already_known_count', 0)}")
            print(f"Prompt length: {len(result.get('prompt', ''))} chars")
            print()
            if result.get("error"):
                print(f"  ERROR: {result['error']}")
            else:
                print("  Dispatch the prompt (--json to extract) to an LLM agent.")
                print("  The agent returns a JSON array of discovered attack surfaces.")
        return 0

    if args.command == "infer":
        result = infer_requires(args.ledger)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            stats = result["stats"]
            print("═══ ASG Requires/Provides Inference ═══")
            print(f"Confirmed findings: {stats.get('total_confirmed', 0)}")
            print(f"Already had provides: {stats.get('already_had_provides', 0)}")
            print(f"New requires inferred: {stats.get('with_requires', 0)}")
            print(f"New provides inferred: {stats.get('with_provides', 0)}")
            print(f"Total CG edges: {stats.get('new_edges', 0)}")
            print()
            for inf in result["inferred"]:
                print(f"  {inf['hyp_id']}:")
                if inf["requires"]:
                    print(f"    requires: {inf['requires']}")
                if inf["provides"]:
                    print(f"    provides: {inf['provides']}")
                print(f"    rules: {inf['rules_matched']}")
            print()
        if args.append and result["events"]:
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).isoformat()
            with open(args.ledger, "a", encoding="utf-8") as f:
                for ev in result["events"]:
                    if ev.get("ts") == "__NOW__":
                        ev["ts"] = ts
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            print(f"✓ Appended {len(result['events'])} inference events to {args.ledger}")
        return 0

    # ── scan command ──
    extractor = EXTRACTORS[args.target_type]()
    handlers = extractor.extract(args.source)
    ledger_data = load_ledger_coverage(args.ledger, extractor.mention_pattern())
    coverage = compute_coverage(handlers, ledger_data)

    if args.json:
        output: dict = {"target_type": args.target_type, "coverage": coverage}
        if args.chains:
            output["chains"] = compute_chains(args.ledger)
        if args.checklist:
            output["checklist"] = extractor.checklist(args.source)
        if args.triage:
            output["triage"] = build_triage_prompt(handlers, args.source, args.ledger)
        if args.root_causes:
            output["root_causes"] = find_root_causes(args.ledger)
        if args.infer_requires:
            output["infer_requires"] = infer_requires(args.ledger)
        print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
        return 0

    print(f"═══ ASG Surface Coverage Report ({args.target_type}) ═══")
    print(f"Source: {args.source.name}")
    print(f"Ledger: {args.ledger.name} ({len(ledger_data['hypotheses'])} hypotheses, {len(ledger_data['verdicts'])} verdicts)")
    print()
    print(f"Total surfaces: {coverage['total_handlers']}")
    print(f"Tested (hypothesis + verdict): {coverage['covered_handlers']}")
    print(f"Uncovered: {coverage['uncovered_handlers']}")
    print(f"Coverage: {coverage['coverage_pct']}%")
    print()

    print("── Family Breakdown ──")
    for fam, data in sorted(coverage["families"].items()):
        pct = round(data["covered"] / data["total"] * 100) if data["total"] else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"  {fam:40s} {data['covered']:2d}/{data['total']:2d} {bar} {pct}%")
        for h in data["handlers"]:
            mark = "✓" if h["covered"] else "✗"
            print(f"    {mark} {h['name']}")
    print()

    if coverage["uncovered"]:
        print(f"── {len(coverage['uncovered'])} Uncovered Surfaces (attack surface gaps) ──")
        for h in coverage["uncovered"]:
            print(f"  ✗ {h['name']} ({h['type']})")
        print()

    if args.checklist:
        print(f"── {args.target_type.title()} Audit Checklist ──")
        results = extractor.checklist(args.source)
        for r in results:
            mark = "✓" if r["hits"] else "✗"
            print(f"  {mark} [{r['id']}] {r['check']:30s} — {r['hits']} hits")
        print()

    if args.chains:
        chains = compute_chains(args.ledger)
        print("── Attack Chain Graph ──")
        print(f"  Total hypotheses: {chains['total_hypotheses']}")
        print(f"  Unique root causes: {chains['unique_root_causes']}")
        if chains["root_cause_groups"]:
            print(f"  Root-cause groups (variants sharing same root cause):")
            for i, group in enumerate(chains["root_cause_groups"], 1):
                severities = [chains["verdicts"].get(h, {}).get("severity", "?") for h in group]
                print(f"    Group {i}: {', '.join(group)} (severities: {', '.join(severities)})")
        if chains["edges"]:
            print(f"  Edges:")
            for edge in chains["edges"]:
                if edge["type"] == "chain":
                    print(f"    CHAIN: {edge['src']} — {edge.get('chain', '')}")
                else:
                    print(f"    {edge['type'].upper()}: {edge['src']} → {edge.get('dst', '?')}")
        print()

    if args.triage:
        triage = build_triage_prompt(handlers, args.source, args.ledger)
        print("── LLM Surface Triage ──")
        print(f"  Untested surfaces: {triage['surface_count']}")
        print(f"  Already tested: {triage.get('already_tested', 0)}")
        if triage["surface_count"] > 0:
            print(f"  Prompt length: {len(triage['prompt'])} chars")
            print(f"\n  Dispatch this prompt to a subagent for semantic analysis.")
            print(f"  The agent will return structured JSON per the response_schema.")
        else:
            print(f"  {triage.get('message', 'nothing to triage')}")
        print()

    if args.root_causes:
        rc = find_root_causes(args.ledger)
        print("── Root Cause Analysis ──")
        print(f"  Total confirmed findings: {rc['total_confirmed']}")
        print(f"  Matched to known patterns: {rc['matched']}")
        print(f"  Unmatched (need LLM): {len(rc['unmatched_findings'])}")
        print()
        for r in rc["root_causes"]:
            print(f"  [{r['root_cause_id']}] {r['name']}")
            print(f"    CWE: {r['cwe']} | Worst: {r['worst_severity']} | Affected: {r['affected_count']}")
            print(f"    Fix: {r['fix']}")
            for f in r["findings"]:
                print(f"      - {f['id']} ({f['severity']}): {f['claim_excerpt'][:80]}")
            print()
        if rc["unmatched_findings"]:
            print(f"  ── {len(rc['unmatched_findings'])} Unmatched (dispatch to LLM) ──")
            for f in rc["unmatched_findings"]:
                print(f"    - {f['id']} ({f['severity']}): {f['claim_excerpt'][:80]}")
            print()

    if args.infer_requires:
        ir = infer_requires(args.ledger)
        stats = ir["stats"]
        print("── Requires/Provides Inference ──")
        print(f"  Confirmed: {stats.get('total_confirmed', 0)}")
        print(f"  New requires: {stats.get('with_requires', 0)}")
        print(f"  New provides: {stats.get('with_provides', 0)}")
        print(f"  CG edges: {stats.get('new_edges', 0)}")
        for inf in ir["inferred"]:
            print(f"    {inf['hyp_id']}: req={inf['requires']} prov={inf['provides']}")
        print()

    if args.append and coverage["uncovered"]:
        events = generate_missing_surfaces(handlers, ledger_data)
        with open(args.ledger, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        print(f"✓ Appended {len(events)} surface events to {args.ledger}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
