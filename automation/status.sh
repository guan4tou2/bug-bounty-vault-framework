#!/usr/bin/env bash
# status.sh — heartbeat + announce current task to other sessions.
#
# Usage:
#   bash automation/status.sh "<one-line current task>"
#   bash automation/status.sh --scope=<scope> "<task>"   # explicit scope pick
#   bash automation/status.sh --read                     # show my own current status
#
# Effects:
#   1. Updates last_heartbeat + current_task in the chosen lock JSON.
#   2. Appends a `status` event to SESSION_LOG so other sessions tailing the
#      log see what I'm doing in near-real-time.
#
# Why: claim+release alone tell other sessions WHICH scope you hold; status
# tells them WHAT inside that scope. Eliminates the "I'd guess that session is
# working on X but it might be Y" ambiguity.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_session_lib.sh
source "$SCRIPT_DIR/_session_lib.sh"

SCOPE=""
MSG=""
READONLY_MODE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --scope=*) SCOPE="${1#--scope=}" ;;
    --read) READONLY_MODE=1 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    --*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) MSG="$1" ;;
  esac
  shift
done

if [ "$READONLY_MODE" -eq 1 ]; then
  sid="$(current_session_id)"
  echo "session: $sid"
  while IFS= read -r lock; do
    [ -z "$lock" ] && continue
    jq -r '"  \(.scope) — \(.current_task // "(no task set)")  [hb \(.last_heartbeat)]"' "$lock"
  done < <(list_my_locks "$sid")
  exit 0
fi

if [ -z "$MSG" ]; then
  echo "Usage: bash automation/status.sh \"<current task>\"" >&2
  exit 2
fi

# Pick scope: explicit flag > sole lock > error
if [ -z "$SCOPE" ]; then
  # bash 3.2-safe: no mapfile.
  my_locks=()
  while IFS= read -r ml; do
    [ -z "$ml" ] && continue
    my_locks+=("$ml")
  done < <(list_my_locks)
  if [ "${#my_locks[@]}" -eq 0 ]; then
    echo "no active lock owned by this session; pass --scope=<scope>" >&2
    exit 2
  elif [ "${#my_locks[@]}" -gt 1 ]; then
    echo "multiple locks held — pass --scope=<scope>:" >&2
    for l in "${my_locks[@]}"; do jq -r '"  - \(.scope)"' "$l" >&2; done
    exit 2
  fi
  LOCK="${my_locks[0]}"
else
  LOCK="$(lock_path "$SCOPE")"
  if [ ! -f "$LOCK" ]; then
    echo "no lock file for scope: $SCOPE" >&2
    exit 2
  fi
fi

# Update lock JSON atomically (read-modify-write).
ts="$(now_iso)"
tmp="$(mktemp "$LOCK.tmp.XXXXXX")"
jq --arg hb "$ts" --arg task "$MSG" \
   '. + {last_heartbeat:$hb, current_task:$task}' "$LOCK" > "$tmp" && mv "$tmp" "$LOCK"

scope_for_log="$(jq -r '.scope' "$LOCK")"
log_event status "$(jq -cn --arg scope "$scope_for_log" --arg task "$MSG" '{scope:$scope, task:$task}')"

echo "📍 status: $scope_for_log — $MSG"
