#!/usr/bin/env bash
# Agent Bash-tool audit logger (AGENTS.md §6f)
# Called by the PostToolUse hook — reads the hook JSON payload from stdin.
# Appends one entry per Bash tool call to logs/claude_audit_YYYYMMDD.log.
#
# Captures: the command, an optional description, and the first ~2KB of the
# tool response (truncated to avoid unbounded log growth). Sensitive values
# (cookies, authorization headers, API keys, tokens, passwords) are redacted.

# Resolve LOGS_ROOT via the shared layout resolver when available.
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$_SCRIPT_DIR/workspace_layout.sh" ]; then
  eval "$("$_SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null)" || true
fi
LOGDIR="${LOGS_ROOT:-$_SCRIPT_DIR/../workspace/logs}"
mkdir -p "$LOGDIR"

INPUT=$(cat)
SESSION=$(echo "$INPUT" | jq -r '.session_id // "unknown"' | cut -c1-8)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // "unknown"')
DESC=$(echo "$INPUT" | jq -r '.tool_input.description // ""')
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
LOGFILE="$LOGDIR/claude_audit_$(date -u +%Y%m%d).log"

# The tool response may live under several fields — try common paths.
RESPONSE=$(echo "$INPUT" | jq -r '
  .tool_response.stdout //
  .tool_response.output //
  .tool_response.content //
  (.tool_response | if type == "string" then . else "" end) //
  ""
' 2>/dev/null)

# Truncate to the first 2KB (2048 bytes). Empty stays empty.
# head -c can split a multi-byte UTF-8 character mid-sequence; iconv -c drops
# the trailing incomplete bytes so the output is always valid UTF-8.
RESPONSE_TRUNC=""
RESPONSE_SIZE=0
if [[ -n "$RESPONSE" && "$RESPONSE" != "null" ]]; then
  RESPONSE_SIZE=${#RESPONSE}
  RESPONSE_TRUNC=$(printf "%s" "$RESPONSE" | head -c 2048 | iconv -f utf-8 -t utf-8 -c 2>/dev/null)
fi

# Redact sensitive material: cookies / authorization headers / api keys /
# passwords / tokens / bearer values. Covers HTTP header form (key: value),
# URL/form param form (key=value), and JSON form ("key": "value").
redact() {
  sed -E \
    -e 's/(Cookie:[[:space:]]*[^[:space:]]{8})[^[:space:]]+/\1…REDACTED/gi' \
    -e 's/(Authorization:[[:space:]]+[A-Za-z]+[[:space:]]+)[^[:space:]]{8}[^[:space:]]+/\1…REDACTED/gi' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]{8}[A-Za-z0-9._-]+/\1…REDACTED/gi' \
    -e 's/(cookie[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]{8}[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/(api[_-]?key[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]{8}[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/(access[_-]?token[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]{8}[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/(password[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/(passwd[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/([[:<:]]token[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]{8}[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/(secret[[:space:]]*[=:][[:space:]]*"?)[^"&[:space:],}]{8}[^"&[:space:],}]+/\1…REDACTED/gi' \
    -e 's/((sk|pk|ak|rk)_(live|test)_)[A-Za-z0-9]{8}[A-Za-z0-9]+/\1…REDACTED/g' \
    -e 's/(AKIA)[A-Z0-9]{8}[A-Z0-9]+/\1…REDACTED/g' \
    -e 's/(ghp_|gho_|ghs_|ghu_|github_pat_)[A-Za-z0-9_]{8}[A-Za-z0-9_]+/\1…REDACTED/g'
}
CMD=$(printf "%s" "$CMD" | redact)
RESPONSE_TRUNC=$(printf "%s" "$RESPONSE_TRUNC" | redact)

{
  printf "[%s] [session:%s]\n" "$TIMESTAMP" "$SESSION"
  [[ -n "$DESC" ]] && printf "# %s\n" "$DESC"
  printf "CMD: %s\n" "$CMD"
  if [[ -n "$RESPONSE_TRUNC" ]]; then
    if [[ $RESPONSE_SIZE -gt 2048 ]]; then
      printf "RESPONSE (first 2KB of %d bytes):\n%s\n[...truncated %d bytes...]\n" \
        "$RESPONSE_SIZE" "$RESPONSE_TRUNC" "$((RESPONSE_SIZE - 2048))"
    else
      printf "RESPONSE (%d bytes):\n%s\n" "$RESPONSE_SIZE" "$RESPONSE_TRUNC"
    fi
  fi
  printf -- "---\n"
} >> "$LOGFILE"
