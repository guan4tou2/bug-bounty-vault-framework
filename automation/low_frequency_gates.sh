#!/usr/bin/env bash
# Low-frequency wrapper for expensive/situational Claude Bash gates.
# The wrapper itself is cheap and may be called from PreToolUse(Bash), but it
# only delegates to static_only_gate.sh / surface_map_gate.sh for commit,
# session-close, or explicit verification commands.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEBUG="${BB_LOW_FREQ_GATES_DEBUG:-0}"

if [ "${1:-}" = "--stop" ]; then
  INPUT='{"tool_name":"Bash","tool_input":{"command":"BB_RUN_LOW_FREQ_GATES=1 session_end"}}'
elif [ "${1:-}" = "--verify" ]; then
  INPUT='{"tool_name":"Bash","tool_input":{"command":"BB_RUN_LOW_FREQ_GATES=1 explicit_verify"}}'
else
  INPUT="$(cat)"
fi

json_get() {
  local expr="$1"
  printf '%s' "$INPUT" | jq -r "$expr" 2>/dev/null
}

TOOL="$(json_get '.tool_name // ""')"
[ "$TOOL" = "Bash" ] || exit 0
CMD="$(json_get '.tool_input.command // ""')"
[ -n "$CMD" ] || exit 0

reason=""
if [ "${BB_RUN_LOW_FREQ_GATES:-0}" = "1" ] || [ "${BB_VERIFY_GATES:-0}" = "1" ] || [ "${BB_EXPLICIT_VERIFY:-0}" = "1" ]; then
  reason="explicit-env"
elif printf '%s' "$CMD" | grep -qE '(^|[[:space:];&|])(BB_RUN_LOW_FREQ_GATES|BB_VERIFY_GATES|BB_EXPLICIT_VERIFY)=1([[:space:];&|]|$)'; then
  reason="explicit-command"
elif printf '%s' "$CMD" | grep -qE '(^|[[:space:];&|])git([^;&|]*)[[:space:]]commit([[:space:]]|$)'; then
  reason="pre-commit"
elif printf '%s' "$CMD" | grep -qE '(session_end_checklist|session_end_brief|release)\.sh([[:space:]]|$)'; then
  reason="session-end"
elif printf '%s' "$CMD" | grep -qE '(audit_workspace|static_only_gate|surface_map_gate|low_frequency_gates)\.sh|--verify|verify-gates'; then
  reason="explicit-verify"
fi

if [ -z "$reason" ]; then
  [ "$DEBUG" = "1" ] && echo "[low-frequency-gates] skipping regular Bash command" >&2
  exit 0
fi

[ "$DEBUG" = "1" ] && echo "[low-frequency-gates] running static/surface gates reason=$reason" >&2

run_gate() {
  local gate="$1"
  [ -x "$gate" ] || [ -f "$gate" ] || return 0
  printf '%s' "$INPUT" | bash "$gate"
}

run_gate "$SCRIPT_DIR/static_only_gate.sh"
status=$?
[ "$status" -eq 0 ] || exit "$status"

run_gate "$SCRIPT_DIR/surface_map_gate.sh"
status=$?
[ "$status" -eq 0 ] || exit "$status"

exit 0
