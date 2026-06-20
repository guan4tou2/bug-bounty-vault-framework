#!/usr/bin/env bash
# PreToolUse(Bash) hook — static-only mode lock.
#
# Origin: the "Code bugs in parent folder" session — an internal/static source
# audit where the operator had to say "先不要連線挖 只要靜態就好" because the
# assistant drifted toward live testing. There was no enforcement. This gate
# hard-blocks live/network Bash actions WHEN static-only mode is on.
#
# Enable static-only mode (either; file is most reliable — env may not reach hooks):
#   touch automation/.static_only        # flag file (gitignored)
#   export BB_STATIC_ONLY=1              # env (if it propagates to hooks)
# Disable: rm automation/.static_only  (and/or unset BB_STATIC_ONLY)
#
# Per-command override (loud): prefix with  BB_ALLOW_LIVE=1
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Bash" ]] && exit 0
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# static-only active?  env OR flag file
if [[ "${BB_STATIC_ONLY:-0}" != "1" ]] && [[ ! -f "$SCRIPT_DIR/.static_only" ]]; then
  exit 0
fi

# per-command override
if [[ "${BB_ALLOW_LIVE:-0}" == "1" ]] || echo "$CMD" | grep -q 'BB_ALLOW_LIVE=1'; then
  exit 0
fi

# --- live/network actions to block in static-only mode ---
block() {
  echo "🔒 static-only mode (automation/.static_only or BB_STATIC_ONLY=1): blocked live/network action — $1" >&2
  echo "   This session is static-source only. To run it anyway, prefix: BB_ALLOW_LIVE=1 <cmd>" >&2
  echo "   To leave static-only mode: rm automation/.static_only" >&2
  exit 2
}

# active scanners / recon tools
if echo "$CMD" | grep -qwE 'nuclei|httpx|ffuf|nmap|masscan|subfinder|dnsx|katana|gau|waybackurls|amass|dalfox|sqlmap|nikto|gobuster|feroxbuster'; then
  block "scanner/recon tool"
fi
# bbflow live subcommands (hunt/flow/recon reach the network)
if echo "$CMD" | grep -qE 'bbflow(\.sh)?[[:space:]]' && echo "$CMD" | grep -qE '[[:space:]](hunt|flow|recon)([[:space:]]|$)'; then
  block "bbflow hunt/flow/recon (live)"
fi
# external HTTP via curl/wget (allow localhost / file:// / unix socket)
if echo "$CMD" | grep -qwE 'curl|wget|http|https' && echo "$CMD" | grep -qE 'https?://'; then
  if echo "$CMD" | grep -oE 'https?://[^[:space:]"'\'']+' | grep -qvE '://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])'; then
    block "outbound HTTP request to an external host"
  fi
fi

exit 0
