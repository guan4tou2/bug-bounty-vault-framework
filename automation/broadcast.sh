#!/usr/bin/env bash
# broadcast.sh — drop a message into another session's inbox.
#
# 🧪 STATUS: experimental (2026-06-04). Real usage in first 3h after creation:
# 1 message (smoke test). Kept because multi-session/multi-agent scenarios DO
# happen (opus-4.6 parallel + session-learning pipeline) — base infrastructure
# should exist before the need arises. If you're not sure you need this:
# `automation/status.sh` (heartbeat + current_task) + `automation/session_brief.sh`
# (snapshot) cover most coordination cases without writing files.
#
# Usage:
#   bash automation/broadcast.sh --to=<scope-or-session-id> "<message body>"
#   bash automation/broadcast.sh --to=all "<message body>"           # broadcast to all active scopes
#   bash automation/broadcast.sh --inbox                             # show MY unread messages
#   bash automation/broadcast.sh --ack <msg-path>                    # mark a message read
#
# Inbox layout:
#   automation/active_sessions/_inbox/<scope-or-session>/msg-<ts>-<from>.md
#   reading a message renames it to *.read (or you can `--ack` explicitly).
#
# Why: locks + SESSION_LOG are passive. Sometimes session A needs to tell
# session B something specific — "I'm touching the file you're about to read",
# "the lint hook is broken, --no-verify is fine for the next hour", "I finished
# the KB seed you were waiting on". Mailbox is async + persistent across
# context-window resets.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_session_lib.sh
source "$SCRIPT_DIR/_session_lib.sh"

TO=""
MODE="send"
ACK_PATH=""

while [ $# -gt 0 ]; do
  case "$1" in
    --to=*) TO="${1#--to=}" ;;
    --inbox) MODE="inbox" ;;
    --ack) MODE="ack"; ACK_PATH="${2:-}"; shift ;;
    --help|-h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) BODY="${BODY:-}${BODY:+ }$1" ;;
  esac
  shift
done

case "$MODE" in
  inbox)
    sid="$(current_session_id)"
    echo "=== inbox for session $sid ==="
    found=0
    # check both session-id keyed and scope-keyed inboxes (locks I hold)
    while IFS= read -r msg; do
      [ -z "$msg" ] && continue
      found=1
      echo "---"
      echo "📬 $msg"
      cat "$msg"
      echo
    done < <( {
      unread_for "$sid"
      while IFS= read -r lock; do
        [ -z "$lock" ] && continue
        scp="$(jq -r '.scope' "$lock")"
        unread_for "$scp"
      done < <(list_my_locks "$sid")
    } | sort -u )
    [ "$found" -eq 0 ] && echo "(empty)"
    exit 0
    ;;
  ack)
    if [ -z "$ACK_PATH" ] || [ ! -f "$ACK_PATH" ]; then
      echo "usage: broadcast.sh --ack <msg-path>" >&2; exit 2
    fi
    mv "$ACK_PATH" "${ACK_PATH}.read"
    echo "✅ acked: ${ACK_PATH}.read"
    exit 0
    ;;
esac

if [ -z "$TO" ] || [ -z "${BODY:-}" ]; then
  echo "Usage: bash automation/broadcast.sh --to=<scope|session|all> \"<message>\"" >&2
  exit 2
fi

from="$(current_session_id)"
ts="$(date -u +%Y%m%dT%H%M%SZ)"

deliver() {
  local rcpt="$1"
  local dir; dir="$(inbox_for "$rcpt")"
  mkdir -p "$dir"
  local fn="$dir/msg-${ts}-from-${from:0:8}.md"
  {
    printf '%s\n' "---"
    printf 'from: %s\n' "$from"
    printf 'to: %s\n' "$rcpt"
    printf 'sent: %s\n' "$(now_iso)"
    printf '%s\n\n' "---"
    printf '%s\n' "$BODY"
  } > "$fn"
  echo "📤 → $rcpt   ($fn)"
  log_event broadcast "$(jq -cn --arg to "$rcpt" --arg msg "$BODY" '{to:$to, msg:$msg}')"
}

if [ "$TO" = "all" ]; then
  # deliver to every active scope (not session id) — easiest for humans
  while IFS= read -r lock; do
    [ -z "$lock" ] && continue
    scp="$(jq -r '.scope' "$lock")"
    [ -n "$scp" ] && deliver "$scp"
  done < <(list_active_locks)
else
  deliver "$TO"
fi
