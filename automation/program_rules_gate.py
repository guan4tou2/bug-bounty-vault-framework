#!/usr/bin/env python3
"""PreToolUse(Bash) — enforce a program's machine-readable rules on any command that
reaches one of its hosts. Generic scope, scan and registered-egress checks.

The rules apply independently of claim state and do not hardcode a program's domain.

Activation is by *what the command touches*, not by claim state: any SCOPE.md that
carries a `## Program Rules (machine-readable)` yaml block contributes its in-scope hosts
and their registrable-domain suffixes. A command that names one of those hosts — or runs a
script under that target's workshop/poc dir — is held to that program's rules:

  authorization_start / authorization_expiry   outside window → block
  allowed_hours_weekday / allowed_hours_weekend  outside window → block
  auto_scan_approved: false                    scanner binary → block
  host under the program's domain but not listed in SCOPE → block
  registered_ip set                            must route through egress_via → block
  bbp_header complete                          raw remote curl without it → block

Optional SCOPE field `egress_via` (regex, default `ssh|dcurl|bb-curl`) names how the
registered egress is reached. Override for one command: BB_BBP_GATE_SKIP=1 (logged).
Exit 0 allow, 2 block.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path

SCAN_TOOLS = ("nmap", "nuclei", "httpx", "ffuf", "katana", "feroxbuster", "gobuster", "dirsearch",
              "nikto", "wpscan", "sqlmap", "amass", "masscan", "naabu", "dalfox")
DEFAULT_EGRESS = r"(?:^|[\s;&|(`'\"])(?:ssh|dcurl|bb-curl)(?:\s|$)"
_RULES = re.compile(r"##\s*Program Rules \(machine-readable\).*?```ya?ml\n(.*?)```", re.S)
_HOSTCELL = re.compile(r"`?\b([A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+\.[A-Za-z]{2,})\b`?")
_SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "co", "ac"}


def _scalar(block: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*(?:#.*)?$", block, re.M)
    return m.group(1).strip().strip('"').strip("'") if m else ""


def _registrable(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_programs(root: Path) -> list[dict]:
    programs = []
    scope_files = set((root / '01 - Targets').glob('*/SCOPE.md'))
    scope_files.update((root / 'workspace/workshop').glob('*/SCOPE.md'))
    for sc in sorted(scope_files):
        try:
            txt = sc.read_text(errors="replace")
        except OSError:
            continue
        m = _RULES.search(txt)
        if not m:
            continue
        block = m.group(1)
        body = txt[:m.start()] + txt[m.end():]
        # Only sections that *grant* scope. Out-of-scope tables often mention in-scope
        # hosts for reconciliation, so subtracting them drops real assets.
        granting = re.findall(r"##\s*(?:In-Scope|Flat Domain List)[^\n]*\n(.*?)(?=\n##\s(?!#)|\Z)", body, re.S)
        hosts = {h.lower() for sec in granting for h in _HOSTCELL.findall(sec)}
        hosts = {h for h in hosts if not re.search(r"@|\.(md|json|py|sh|txt|png)$", h)}
        if not hosts:
            continue
        programs.append({
            "target": sc.parent.name,
            "hosts": hosts,
            "suffixes": {_registrable(h) for h in hosts},
            "registered_ip": _scalar(block, "registered_ip"),
            "egress_via": _scalar(block, "egress_via"),
            "bbp_header": _scalar(block, "bbp_header"),
            "start": _scalar(block, "authorization_start"),
            "expiry": _scalar(block, "authorization_expiry"),
            "weekday": _scalar(block, "allowed_hours_weekday"),
            "weekend": _scalar(block, "allowed_hours_weekend"),
            "auto_scan": _scalar(block, "auto_scan_approved").lower() == "true",
        })
    return programs


def _cmd_hosts(cmd: str) -> set[str]:
    return {h.lower().rstrip(".") for h in
            re.findall(r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9_-])", cmd)}


_NET_VERB = re.compile(
    r"(?:^|[\s;&|(`'\"/])(?:curl|wget|https?|httpie|dcurl|bb-curl|nc|ncat|nmap|openssl|telnet|ssh"
    r"|python3?|node|ruby|perl|go|deno|bun|" + "|".join(SCAN_TOOLS) + r")(?:\s|$)")


def _touches(cmd: str, prog: dict) -> tuple[set[str], bool]:
    """(hosts of this program the cmd sends traffic to, cmd runs a script from its poc dir).
    A host merely *mentioned* (grep/rg/cat over notes) is not traffic — only count it when
    the command also carries a network verb or an interpreter."""
    hosts = set()
    if _NET_VERB.search(cmd):
        hosts = {h for h in _cmd_hosts(cmd) if any(h == s or h.endswith("." + s) for s in prog["suffixes"])}
    poc = bool(re.search(rf"(?:python3?|node|bash|sh|ruby|go run)\s+\S*{re.escape(prog['target'])}/poc/", cmd))
    return hosts, poc


def _in_window(spec: str, now: _dt.datetime) -> bool:
    m = re.match(r"\s*(\d{1,2}):?\d*\s*-\s*(\d{1,2}):?\d*", spec or "")
    if not m:
        return True
    start, end, h = int(m.group(1)), int(m.group(2)), now.hour
    if start == end or (start == 0 and end == 24):
        return True
    return start <= h < end if start < end else (h >= start or h < end)


def window_remaining_minutes(prog: dict, now: _dt.datetime | None = None) -> float | None:
    """How many minutes until this program's *binding* authorization deadline — the
    TaskClock clamp (artex clampMaxDuration), folding two independent limits into one:
      - authorization_expiry : the last authorized DAY (inclusive → ends 23:59:59).
      - allowed_hours_*      : today's allowed-hours window END (e.g. 09-18 → 18:00).
    The binding deadline is the EARLIER of the two that still lies ahead. Returns None
    when the program carries neither limit (no clock) or we are already past both (the
    PreToolUse gate owns the hard block; this is only the "wrap up soon" signal, so a
    non-positive remaining collapses to 0.0, never a negative). Pure + injectable now()."""
    now = now or _dt.datetime.now()
    candidates: list[_dt.datetime] = []
    exp = prog.get("expiry")
    if exp:
        try:
            d = _dt.date.fromisoformat(exp)
            candidates.append(_dt.datetime.combine(d, _dt.time(23, 59, 59)))
        except ValueError:
            pass
    spec = prog.get("weekend") if now.isoweekday() >= 6 else prog.get("weekday")
    m = re.match(r"\s*(\d{1,2}):?\d*\s*-\s*(\d{1,2}):?\d*", spec or "")
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        # only a window that is open now AND ends later today bounds this run; an
        # all-day (start==end / 0-24) or wrapped overnight window imposes no end today.
        if start != end and not (start == 0 and end == 24) and 0 <= end <= 24 and start < end \
                and start <= now.hour < end:
            candidates.append(_dt.datetime.combine(now.date(), _dt.time(end % 24, 0)))
    if not candidates:
        return None
    remaining = (min(candidates) - now).total_seconds() / 60.0
    return max(0.0, remaining)


def judge(cmd: str, programs: list[dict], now: _dt.datetime | None = None) -> str | None:
    now = now or _dt.datetime.now()
    clean = re.sub(r"(?m)#.*$", "", cmd)
    for p in programs:
        hosts, poc = _touches(clean, p)
        if not hosts and not poc:
            continue
        tag = f"⛔ program-rules-gate [{p['target']}]"
        today = now.date().isoformat()
        if p["start"] and today < p["start"]:
            return f"{tag}: 授權尚未生效（{p['start']}），不得提前測試。"
        if p["expiry"] and today > p["expiry"]:
            return f"{tag}: 授權已於 {p['expiry']} 到期，停止所有對此 program 的流量。"
        if not p["auto_scan"]:
            hit = re.search(rf"(?:^|[\s/;&|(`'\"])({'|'.join(SCAN_TOOLS)})(?:\s|$)", clean)
            if hit:
                return f"{tag}: 自動掃描工具 {hit.group(1)} 未獲核准（auto_scan_approved: false）。改用手動單次請求。"
        unlisted = sorted(h for h in hosts if h not in p["hosts"] and h not in p["suffixes"])
        if unlisted:
            return (f"{tag}: {', '.join(unlisted)} 屬於此 program 的網域，但不在 SCOPE.md In-Scope 清單。"
                    f"先確認授權再測（新子域名要補進 SCOPE）。")
        spec = p["weekend"] if now.isoweekday() >= 6 else p["weekday"]
        if spec and not _in_window(spec, now):
            return f"{tag}: 現在 {now:%H:%M} 不在允許時段 {spec}，等時段開始再送流量。"
        egress = p["egress_via"] or DEFAULT_EGRESS
        if p["registered_ip"] and not re.search(egress, clean):
            return (f"{tag}: 這個指令會從本機出口送出流量，但此 program 要求來源 IP = {p['registered_ip']}。\n"
                    f"本機 curl、本機跑 poc 腳本都算。改走登記出口（{egress}），例：ssh <vps> 'bb-curl ...'。\n"
                    f"出口錯誤會讓報告的來源 IP 與證據對不上，廠商可據此不受理。")
        header = p["bbp_header"]
        header_name = header.split(":", 1)[0].strip() if ":" in header else ""
        header_ready = bool(header_name) and not header.rstrip().endswith(":")
        if (header_ready and re.search(r"(?:^|[\s'\"])(?:curl|wget)\s", clean)
                and not re.search(r"(?:dcurl|bb-curl)", clean) and header_name not in clean):
            return f"{tag}: 對 target 的 curl 沒帶 program 規定的 header（{header}）。用 dcurl/bb-curl 或手動加 -H。"
    return None


def target_from_command(cmd: str, root: Path) -> str | None:
    """Reverse-lookup TARGET from a command's in-scope hosts — for gates whose cwd-based
    TARGET derivation came up empty (phase/engage/roe/recon_completeness silently exit 0).
    Returns the target name iff EXACTLY ONE program's in-scope hosts are touched; returns
    None if zero or ambiguous (same host in >1 scope). Callers MUST fail-open on None, so a
    reverse-lookup can only ADD coverage, never cause a false block from misattribution."""
    hits = set()
    for p in load_programs(root):
        hosts, _poc = _touches(cmd, p)
        if hosts:
            hits.add(p["target"])
    return next(iter(hits)) if len(hits) == 1 else None


def main() -> int:
    # CLI: reverse-lookup target from a command (used by phase/engage/roe/recon gates as a
    # cwd-independent fallback). Prints the single matching target, or nothing (fail-open).
    if len(sys.argv) >= 3 and sys.argv[1] == "--target-from-command":
        root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[1])
        t = target_from_command(sys.argv[2], root)
        if t:
            print(t)
        return 0
    try:
        obj = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0
    if obj.get("tool_name") != "Bash":
        return 0
    cmd = (obj.get("tool_input") or {}).get("command") or ""
    if not cmd.strip():
        return 0
    if os.environ.get("BB_BBP_GATE_SKIP") == "1" or "BB_BBP_GATE_SKIP=1" in cmd:
        sys.stderr.write("⚠️ program-rules-gate: BB_BBP_GATE_SKIP=1 放行（已記錄於 audit log）\n")
        return 0
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[1])
    msg = judge(cmd, load_programs(root))
    if msg:
        sys.stderr.write(msg + "\n緊急放行：前綴 BB_BBP_GATE_SKIP=1（會被記錄）。\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
