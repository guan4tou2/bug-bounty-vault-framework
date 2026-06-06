#!/usr/bin/env bash
# _session_lib.sh — cross-session communication primitives.
#
# Companion to _lock_lib.sh. Provides:
#   SESSION_LOG       — append-only JSONL event bus at active_sessions/SESSION_LOG.jsonl
#   INBOX_DIR         — per-session message inbox root
#   COMPLETED_DIR     — handoff capsules left when a scope is released
#   log_event TYPE JSON_FIELDS...   — append a single JSON event line
#   current_session_id              — read the caller's session_id from env or
#                                     pick the most-recently-touched lock owned
#                                     by $USER (fallback: 'shell')
#   list_my_locks                   — print lock paths owned by current session_id
#
# Append-only, line-buffered, lock-free: every event is a self-contained JSON
# object on its own line. Multiple sessions appending concurrently rely on
# POSIX `>> file` atomicity for writes shorter than PIPE_BUF (4096 on macOS).
# We cap event payloads accordingly.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lock_lib.sh
source "$SCRIPT_DIR/_lock_lib.sh"

SESSION_LOG="$ACTIVE_DIR/SESSION_LOG.jsonl"
INBOX_DIR="$ACTIVE_DIR/_inbox"
COMPLETED_DIR="$ACTIVE_DIR/_completed"
mkdir -p "$INBOX_DIR" "$COMPLETED_DIR"
[ -f "$SESSION_LOG" ] || : > "$SESSION_LOG"

# Detect current session id. Order:
#   1. $SESSION_ID env (set by claim.sh into the calling shell — opt-in)
#   2. Newest lock owned by $USER on this host
#   3. literal "shell" (out-of-band caller)
current_session_id() {
  if [ -n "${SESSION_ID:-}" ]; then printf '%s' "$SESSION_ID"; return 0; fi
  local newest="" newest_mt=0 lock mt sid host
  for lock in "$ACTIVE_DIR"/*.lock; do
    [ -e "$lock" ] || continue
    host="$(jq -r '.host // empty' "$lock" 2>/dev/null)"
    [ "$host" = "$(hostname -s 2>/dev/null || hostname)" ] || continue
    mt="$(stat -f %m "$lock" 2>/dev/null || stat -c %Y "$lock" 2>/dev/null || echo 0)"
    if [ "$mt" -gt "$newest_mt" ]; then
      newest_mt="$mt"; newest="$lock"
    fi
  done
  if [ -n "$newest" ]; then
    sid="$(jq -r '.session_id // empty' "$newest" 2>/dev/null)"
    if [ -n "$sid" ]; then printf '%s' "$sid"; return 0; fi
  fi
  printf 'shell'
}

list_my_locks() {
  local sid="${1:-$(current_session_id)}"
  local lock
  for lock in "$ACTIVE_DIR"/*.lock; do
    [ -e "$lock" ] || continue
    if [ "$(jq -r '.session_id // empty' "$lock" 2>/dev/null)" = "$sid" ]; then
      printf '%s\n' "$lock"
    fi
  done
}

# log_event TYPE [extra json fragment]
# emits one line: {"ts":"...","session":"...","type":"...","scope":"-",...extra}
log_event() {
  local type="$1"; shift
  local extra="${1:-}"
  local sid; sid="$(current_session_id)"
  local ts; ts="$(now_iso)"
  local line
  if [ -n "$extra" ]; then
    line="$(jq -cn --arg ts "$ts" --arg sid "$sid" --arg type "$type" --argjson extra "$extra" \
      '{ts:$ts, session:$sid, type:$type} + $extra' 2>/dev/null)"
  else
    line="$(jq -cn --arg ts "$ts" --arg sid "$sid" --arg type "$type" \
      '{ts:$ts, session:$sid, type:$type}')"
  fi
  [ -n "$line" ] || return 0
  # Truncate if absurdly long — keep below PIPE_BUF for atomic append.
  if [ "${#line}" -gt 3500 ]; then
    line="${line:0:3490}\"...\"}"
  fi
  printf '%s\n' "$line" >> "$SESSION_LOG"
}

inbox_for() {
  # inbox_for <recipient_id_or_scope>
  local rcpt="$1"
  printf '%s/%s' "$INBOX_DIR" "$(safe_scope "$rcpt")"
}

# unread_for <recipient_id_or_scope>  — print message file paths
unread_for() {
  local rcpt="$1"
  local dir; dir="$(inbox_for "$rcpt")"
  [ -d "$dir" ] || return 0
  find "$dir" -maxdepth 1 -name 'msg-*.md' -not -name '*.read' -type f 2>/dev/null | sort
}
