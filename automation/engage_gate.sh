#!/usr/bin/env bash
# PreToolUse(Bash) hook — blocks active operations when the target has no genesis event.
#
# The genesis event is written by `engage.py` and records the intake questionnaire
# (type, scope, auth window, success criteria, etc.). Without it, active operations
# (curl to external targets, nuclei, ffuf, sqlmap, etc.) are blocked.
#
# This enforces the principle: "engage before you hunt" — no recon or exploit without
# knowing what we're doing, why, and under what authorization.
#
# What PASSES without genesis:
#   - Local file operations (grep, find, cat, ls, wc, etc.)
#   - Git operations
#   - Vault automation scripts (automation/*.sh, automation/*.py)
#   - engage.py itself
#   - init_target.sh
#   - Reading RECON_DB / HANDOFF / SCOPE
#   - kb_retrieval / any knowledge query
#
# What is BLOCKED without genesis:
#   - curl / wget / httpie to non-localhost targets
#   - nuclei / ffuf / sqlmap / nikto / nmap / masscan / gobuster / feroxbuster
#   - bbflow hunt
#   - ssh (to VPS for testing)
#   - Any tool that touches the target's live infrastructure
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Override: BB_SKIP_ENGAGE_GATE=1
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Bash" ]] && exit 0
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

if [[ "${BB_SKIP_ENGAGE_GATE:-0}" == "1" ]] || echo "$CMD" | grep -q 'BB_SKIP_ENGAGE_GATE=1'; then
  exit 0
fi

# --- always-allowed commands (no target interaction) ---
# Local-only tools
for safe in "grep " "find " "cat " "ls " "wc " "head " "tail " "sort " "uniq " \
            "git " "python3 automation/" "bash automation/" "pip " "uv " \
            "engage.py" "init_target.sh" "kb_retrieval" \
            "claim.sh" "release.sh" "check_" "vault_maintenance" \
            "session_start" "session_end" "workspace_layout" \
            "echo " "printf " "mkdir " "cp " "mv " "touch " "chmod " \
            "jq " "yq " "sed " "awk " "tr " "cut " "diff " "tee " \
            "cd " "pwd" "which " "type " "file " "stat "; do
  if echo "$CMD" | grep -qF "$safe"; then
    exit 0
  fi
done

# --- identify active/offensive commands ---
ACTIVE_TOOLS="curl|wget|http |httpie|nuclei|ffuf|sqlmap|nikto|nmap|masscan|gobuster|feroxbuster|dirsearch|wpscan|amass|subfinder|httpx|katana|gau|waybackurls|dnsx|dig |host |nslookup"
if ! echo "$CMD" | grep -qE "(^|[[:space:];|&(])(${ACTIVE_TOOLS})([[:space:]]|$)"; then
  exit 0  # not an active command
fi

# curl/wget to localhost is always allowed
if echo "$CMD" | grep -qE '(curl|wget|http )[[:space:]]' && \
   echo "$CMD" | grep -qE '(localhost|127\.0\.0\.1|\[::1\]|\.localhost|\.test)'; then
  exit 0
fi

# --- determine target from current directory or command context ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="${VAULT_ROOT:-$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^VAULT_ROOT='\(.*\)'\$/\1/p")}"
[[ -z "$VAULT_ROOT" ]] && exit 0

# Try to find the target from pwd
CWD="${PWD:-$(pwd)}"
TARGET=""
TARGETS_DIR="$VAULT_ROOT/01 - Targets"
if [[ "$CWD" == "$TARGETS_DIR/"* ]]; then
  rel="${CWD#$TARGETS_DIR/}"
  TARGET="${rel%%/*}"
fi

# Try workshop path
if [[ -z "$TARGET" ]]; then
  WROOT=$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^WORKSHOP_ROOT='\(.*\)'\$/\1/p")
  if [[ -n "$WROOT" && "$CWD" == "$WROOT/"* ]]; then
    rel="${CWD#$WROOT/}"
    TARGET="${rel%%/*}"
  fi
fi

# If we can't determine the target, allow (can't check genesis)
[[ -z "$TARGET" ]] && exit 0

# --- check for genesis event ---
LEDGER="$TARGETS_DIR/$TARGET/.state/asg-events.jsonl"
if [[ -f "$LEDGER" ]] && grep -q '"type"[[:space:]]*:[[:space:]]*"genesis"' "$LEDGER" 2>/dev/null; then
  exit 0  # genesis exists
fi

# --- BLOCK ---
echo "⛔ engage gate: target has no genesis event." >&2
echo "" >&2
echo "Before active operations, complete the intake questionnaire:" >&2
echo "  python3 automation/engage.py $TARGET --interactive" >&2
echo "" >&2
echo "Or use CLI flags:" >&2
echo "  python3 automation/engage.py $TARGET --type web-app --scope '...' --platform hackerone" >&2
echo "" >&2
echo "Override: BB_SKIP_ENGAGE_GATE=1 (but you should have a reason)" >&2
exit 2
