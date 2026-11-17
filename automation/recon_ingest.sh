#!/usr/bin/env bash
# PostToolUse(Bash) async — "工具輸出自動 ingest 入圖".
#
# When a recon tool runs (subfinder/httpx/nmap/gau/katana/ffuf/…), record a
# command_run evidence event into <target>/.state/recon_runs.jsonl. This is the SoT
# for "which recon actually happened" — the ASG markdown command_runs[] is its
# projection. Without it a scan stops at the terminal and the next session (and the
# recon-completeness gate) can't tell a real scan from a hand-typed `status: done`.
#
# check_recon_ingest.py then flags "scanned but the dimension is still pending" as
# session-end debt: 沒 ingest 的掃描不算 recon 完成 (msg2 #4).
#
# Advisory telemetry: ALWAYS exit 0 (never blocks). Tool→dimension map is the single
# source in recon_dimensions_lib.TOOL_DIM. nuclei/sqlmap etc. are exploit-phase and
# deliberately not recorded here.
set -uo pipefail

INPUT=$(cat)
[[ "$(printf %s "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)" != "Bash" ]] && exit 0

# --- resolve target from CWD (mirror phase_gate / recon_completeness_gate) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="${VAULT_ROOT:-$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^VAULT_ROOT='\(.*\)'\$/\1/p")}"
[[ -z "$VAULT_ROOT" ]] && exit 0
CWD="${PWD:-$(pwd)}"
TARGET=""
TARGETS_DIR="$VAULT_ROOT/01 - Targets"
if [[ "$CWD" == "$TARGETS_DIR/"* ]]; then rel="${CWD#$TARGETS_DIR/}"; TARGET="${rel%%/*}"; fi
if [[ -z "$TARGET" ]]; then
  WROOT=$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^WORKSHOP_ROOT='\(.*\)'\$/\1/p")
  if [[ -n "$WROOT" && "$CWD" == "$WROOT/"* ]]; then rel="${CWD#$WROOT/}"; TARGET="${rel%%/*}"; fi
fi
[[ -z "$TARGET" ]] && exit 0

export RI_TARGET="$TARGET" RI_VAULT="$VAULT_ROOT" RI_LIB="$SCRIPT_DIR" VAULT_ROOT="$VAULT_ROOT"

read -r -d '' PYSRC <<'PYEOF' || true
import hashlib, json, os, re, sys, time, uuid, fcntl
sys.path.insert(0, os.environ.get("RI_LIB", ""))
try:
    import recon_dimensions_lib as rdl
except Exception:
    sys.exit(0)

try:
    obj = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)
ti = obj.get("tool_input") or {}
cmd = ti.get("command") or ""
if not cmd:
    sys.exit(0)

tool, dim = rdl.tool_dimension(cmd)
if not tool:
    sys.exit(0)

resp = obj.get("tool_response")
out, exit_code = "", None
if isinstance(resp, dict):
    out = resp.get("stdout") or resp.get("output") or resp.get("content") or ""
    exit_code = resp.get("exit_code")
elif isinstance(resp, str):
    out = resp
if not isinstance(out, str):
    out = ""
lines = out.count("\n") + (1 if out and not out.endswith("\n") else 0)

# Program-driven surface ingestion (artex-inspired 2026-10-09): host-emitting recon tools
# fold their discovered IN-SCOPE hosts straight into the ASG as untested surfaces, so the
# graph is fed by the program instead of starving on model discipline. In-scope-only +
# capped + only when a genesis exists (asg.ingest_surfaces enforces the last two).
if dim in ("subdomain_enum", "live_host_port") and out:
    try:
        import asg
        tdir = os.path.join(os.environ["RI_VAULT"], "01 - Targets", os.environ["RI_TARGET"])
        try:
            scope_txt = open(os.path.join(tdir, "SCOPE.md"), encoding="utf-8", errors="replace").read().lower()
        except OSError:
            scope_txt = ""
        _HOST = r'\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b'
        _SEC = {"com", "net", "org", "gov", "edu", "co", "ac"}
        def _reg(h):
            p = h.split(".")
            return ".".join(p[-3:]) if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in _SEC else ".".join(p[-2:])
        suffixes = {_reg(h) for h in re.findall(_HOST, scope_txt)}
        found = re.findall(_HOST, out.lower())
        inscope = [h for h in found if suffixes and any(h == s or h.endswith("." + s) for s in suffixes)]
        if inscope:
            asg.ingest_surfaces(os.environ["RI_TARGET"], inscope, node_type="service",
                                source="recon:" + tool, note="auto-derived from " + tool, cap=100)
    except Exception:
        pass

# Shell snippets, URLs and positional values can all contain credentials. Keep
# only the catalogued tool in ordinary telemetry; the audit is the controlled
# command source, not a second raw argv copy in every view.
short = tool + " <arguments redacted>"

sdir = os.path.join(os.environ["RI_VAULT"], "01 - Targets", os.environ["RI_TARGET"], ".state")
try:
    os.makedirs(sdir, exist_ok=True)
except OSError:
    sys.exit(0)

rec = {"type": "command_run",
       "id": "recon-" + str(obj.get("tool_use_id") or uuid.uuid4()),
       "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "session": (obj.get("session_id") or "")[:8],
       "tool": tool, "dim": dim, "cmd": short,
       "exit_code": exit_code, "out_lines": lines, "out_bytes": len(out.encode()),
       "output_sha256": hashlib.sha256(out.encode()).hexdigest(),
       "status": "succeeded" if exit_code == 0 else "unknown" if exit_code is None else "failed",
       "provenance": "post-tool-telemetry"}
try:
    with open(os.path.join(sdir, "recon_runs.jsonl"), "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
except OSError:
    pass
sys.exit(0)
PYEOF

printf '%s' "$INPUT" | "${PYTHON:-python3}" -c "$PYSRC"
exit 0
