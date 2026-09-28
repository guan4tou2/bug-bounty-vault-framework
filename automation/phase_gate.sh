#!/usr/bin/env bash
# PreToolUse(Bash) hook — enforces phase progression.
#
# Tools are classified into phases; blocks tools that belong to a phase
# the target hasn't reached yet. Chains from engage_gate (which ensures
# genesis exists) and surface_map_gate (which ensures mapping before hunting).
#
# Phase chain per profile (from asg.py PROFILE_CHAINS):
#   web/engagement: engage → osint → recon → map → exploit → foothold → report
#   firmware/source-audit: engage → recon → map → exploit → report
#
# Tool-to-phase classification:
#   osint:   whois, theHarvester, amass (passive), subfinder, crt.sh queries
#   recon:   nmap, masscan, httpx, dig, host, nslookup, dnsx
#   map:     bb-surface-mapping (gated separately by surface_map_gate)
#   exploit: nuclei, ffuf, sqlmap, nikto, gobuster, feroxbuster, dirsearch, wpscan
#            curl POST/PUT/DELETE/PATCH, bbflow hunt
#   foothold: ssh (to VPS for pivoting), reverse shells
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Override: BB_SKIP_PHASE_GATE=1
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Bash" ]] && exit 0
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

if [[ "${BB_SKIP_PHASE_GATE:-0}" == "1" ]] || echo "$CMD" | grep -q 'BB_SKIP_PHASE_GATE=1'; then
  exit 0
fi

# --- classify the command's required phase ---
REQUIRED_PHASE=""

# exploit-phase tools (most restrictive — checked first)
EXPLOIT_TOOLS="nuclei|ffuf|sqlmap|nikto|gobuster|feroxbuster|dirsearch|wpscan|katana"
if echo "$CMD" | grep -qE "(^|[[:space:];|&(])(${EXPLOIT_TOOLS})([[:space:]]|$)"; then
  REQUIRED_PHASE="exploit"
fi

# bbflow hunt = exploit phase
if [[ -z "$REQUIRED_PHASE" ]] && echo "$CMD" | grep -qE 'bbflow(\.sh)?[[:space:]]' && echo "$CMD" | grep -qE '[[:space:]]hunt([[:space:]]|$)'; then
  REQUIRED_PHASE="exploit"
fi

# curl/wget with write methods = exploit phase
if [[ -z "$REQUIRED_PHASE" ]] && echo "$CMD" | grep -qE '(curl|wget|http )[[:space:]]'; then
  if echo "$CMD" | grep -qE -- '-X[[:space:]]*(POST|PUT|DELETE|PATCH)|--data|--data-raw|--data-binary|-d[[:space:]]'; then
    # localhost writes are always allowed
    if ! echo "$CMD" | grep -qE '(localhost|127\.0\.0\.1|\[::1\]|\.localhost|\.test)'; then
      REQUIRED_PHASE="exploit"
    fi
  fi
fi

# recon-phase tools
RECON_TOOLS="nmap|masscan|httpx|dnsx"
if [[ -z "$REQUIRED_PHASE" ]] && echo "$CMD" | grep -qE "(^|[[:space:];|&(])(${RECON_TOOLS})([[:space:]]|$)"; then
  REQUIRED_PHASE="recon"
fi

# osint-phase tools
OSINT_TOOLS="whois|theHarvester|amass|subfinder|gau|waybackurls"
if [[ -z "$REQUIRED_PHASE" ]] && echo "$CMD" | grep -qE "(^|[[:space:];|&(])(${OSINT_TOOLS})([[:space:]]|$)"; then
  REQUIRED_PHASE="osint"
fi

# If no phase requirement matched, allow
[[ -z "$REQUIRED_PHASE" ]] && exit 0

# --- determine target from current directory ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="${VAULT_ROOT:-$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^VAULT_ROOT='\(.*\)'\$/\1/p")}"
[[ -z "$VAULT_ROOT" ]] && exit 0

CWD="${PWD:-$(pwd)}"
TARGET=""
TARGETS_DIR="$VAULT_ROOT/01 - Targets"
if [[ "$CWD" == "$TARGETS_DIR/"* ]]; then
  rel="${CWD#$TARGETS_DIR/}"
  TARGET="${rel%%/*}"
fi

if [[ -z "$TARGET" ]]; then
  WROOT=$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^WORKSHOP_ROOT='\(.*\)'\$/\1/p")
  if [[ -n "$WROOT" && "$CWD" == "$WROOT/"* ]]; then
    rel="${CWD#$WROOT/}"
    TARGET="${rel%%/*}"
  fi
fi

[[ -z "$TARGET" ]] && exit 0

# --- check phase ---
PHASE_JSON=$(python3 "$SCRIPT_DIR/asg.py" phase "$TARGET" 2>/dev/null)
if [[ $? -ne 0 || -z "$PHASE_JSON" ]]; then
  exit 0  # fail-open if asg.py errors
fi

CURRENT_PHASE=$(echo "$PHASE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('phase',''))" 2>/dev/null)
[[ -z "$CURRENT_PHASE" ]] && exit 0

# Check if current phase allows the required phase
ALLOWED=$(python3 -c "
import sys; sys.path.insert(0, '$SCRIPT_DIR')
import asg
print('yes' if asg.phase_allows('$TARGET', '$REQUIRED_PHASE') else 'no')
" 2>/dev/null)

if [[ "$ALLOWED" == "no" ]]; then
  echo "⛔ phase gate: target '$TARGET' is currently at '$CURRENT_PHASE' phase, but this operation requires '$REQUIRED_PHASE' phase." >&2
  echo "" >&2
  echo "Advance the phase:" >&2
  echo "  python3 automation/asg.py advance-phase $TARGET $REQUIRED_PHASE \"<reason>\"" >&2
  echo "" >&2
  echo "Override: BB_SKIP_PHASE_GATE=1" >&2
  exit 2
fi

exit 0
