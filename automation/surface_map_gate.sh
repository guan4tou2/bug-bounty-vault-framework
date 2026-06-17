#!/usr/bin/env bash
# PreToolUse(Bash) hook — scan-time enforcement of the explore-first front gate.
#
# Blocks a pattern-hunt scan (`bbflow [..] hunt <target>` or `hunt-<name>.sh <target>`)
# when the target's RECON_DB has Discovered Paths but an EMPTY Attack Surface Map —
# i.e. scanning before mapping the surface vuln-agnostically (the streetlight effect).
# This promotes the gate from post-hoc audit/session-end WARN to a real-time BLOCK.
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Scope note: only gates hunt invocations with a parseable workshop <target>. It does
# NOT gate bare `nuclei -u <url>` (no reliable url→workshop-target mapping) or `recon`
# (recon is the floor that FEEDS the map, so it must run first).
# Intentional override (loud): prefix the command with  BB_SKIP_SURFACE_GATE=1
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Bash" ]] && exit 0
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# honoured even when set inside the command itself
if [[ "${BB_SKIP_SURFACE_GATE:-0}" == "1" ]] || echo "$CMD" | grep -q 'BB_SKIP_SURFACE_GATE=1'; then
  exit 0
fi

# --- identify a gated scan + its target ---
target=""
if echo "$CMD" | grep -qE 'bbflow(\.sh)?[[:space:]]' && echo "$CMD" | grep -qE '[[:space:]]hunt([[:space:]]|$)'; then
  target=$(echo "$CMD" | sed -E 's/.*[[:space:]]hunt[[:space:]]+//' | awk '{print $1}')
elif echo "$CMD" | grep -qE 'hunt-[a-z0-9-]+\.sh[[:space:]]'; then
  target=$(echo "$CMD" | grep -oE 'hunt-[a-z0-9-]+\.sh[[:space:]]+[^[:space:]]+' | head -1 | awk '{print $2}')
fi
[[ -z "$target" ]] && exit 0          # not a gated hunt / no clear target
[[ "$target" == -* ]] && exit 0       # next token was a flag → unknown target, don't block
[[ "$target" == "--list" ]] && exit 0 # batch over a host list, not a single workshop target

# --- resolve the target's RECON_DB ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WROOT=$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^WORKSHOP_ROOT='\(.*\)'\$/\1/p")
[[ -z "$WROOT" ]] && exit 0
rdb="$WROOT/$target/RECON_DB.md"
[[ -f "$rdb" ]] || exit 0
grep -q "Attack Surface Map" "$rdb" || exit 0   # legacy RECON_DB without the section → don't block

# --- count rows (mirrors audit_workspace.sh _section_rows, BSD-awk safe) ---
_section_rows() {
  awk -F'|' -v sec="$2" '
    /^## /   { inSec = ($0 ~ sec) ? 1 : 0; next }
    inSec && /^\|/ {
      cell=$2; gsub(/^[ \t]+|[ \t]+$/,"",cell)
      if (cell=="") next
      if (cell=="—") next
      if (cell ~ /^-+$/) next
      if (cell=="#" || cell ~ /^URL/ || cell ~ /^Surface element/) next
      c++
    }
    END{ print c+0 }
  ' "$1"
}

sm=$(_section_rows "$rdb" "Attack Surface Map")
dp=$(_section_rows "$rdb" "Discovered Paths")

if [[ "${dp:-0}" -gt 0 && "${sm:-0}" -eq 0 ]]; then
  echo "BLOCKED (surface-map front gate): '$target' has $dp Discovered Path(s) but an EMPTY Attack Surface Map." >&2
  echo "Map the surface vuln-agnostically with bb-surface-mapping into RECON_DB '## 🗺 Attack Surface Map' BEFORE hunting — patterns are a post-mapping backstop, not the start (anti-streetlight)." >&2
  echo "If this is intentional, re-run prefixed with:  BB_SKIP_SURFACE_GATE=1" >&2
  exit 2
fi
exit 0
