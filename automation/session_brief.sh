#!/usr/bin/env bash
# session_brief.sh — the "what's happening across all sessions" snapshot.
#
# Usage:
#   bash automation/session_brief.sh                    # default 30-min window
#   bash automation/session_brief.sh --window=2h        # m / h suffix
#   bash automation/session_brief.sh --window=0         # entire SESSION_LOG
#
# Output sections:
#   1. My session     — id, locks I hold + current_task per lock
#   2. Other active   — every other session's lock(s) + current_task + heartbeat
#   3. My inbox       — unread messages
#   4. Recent events  — SESSION_LOG tail within window (claim/release/status/
#                       broadcast/commit/handoff)
#   5. Recent handoff — _completed/ capsules in window (what other sessions
#                       finished + which files / commits)
#
# Run this at session start (after claim) and any time you need orientation.
# Pairs with session_start_brief.sh (which is target-scoped).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_session_lib.sh
source "$SCRIPT_DIR/_session_lib.sh"

WINDOW="30m"
while [ $# -gt 0 ]; do
  case "$1" in
    --window=*) WINDOW="${1#--window=}" ;;
    --help|-h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# Convert window to seconds (0 = unlimited).
window_seconds() {
  local w="$1"
  case "$w" in
    0|all) echo 0 ;;
    *m) echo $(( ${w%m} * 60 )) ;;
    *h) echo $(( ${w%h} * 3600 )) ;;
    *d) echo $(( ${w%d} * 86400 )) ;;
    *)  echo $(( w )) ;;
  esac
}
WIN_SEC="$(window_seconds "$WINDOW")"
now_epoch="$(date -u +%s)"
cutoff=$(( now_epoch - WIN_SEC ))

iso_to_epoch() {
  local iso="$1"
  date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$iso" +%s 2>/dev/null \
    || date -u -d "$iso" +%s 2>/dev/null \
    || echo 0
}

sid="$(current_session_id)"

echo "════════════════════════════════════════════════════════════"
echo " session_brief — window=$WINDOW   session=$sid"
echo "════════════════════════════════════════════════════════════"

# 1. My locks
echo
echo "▶ My session"
my_locks=()
while IFS= read -r _ml; do
  [ -z "$_ml" ] && continue
  my_locks+=("$_ml")
done < <(list_my_locks "$sid")
if [ "${#my_locks[@]}" -eq 0 ]; then
  echo "  (no active locks for this session)"
else
  for l in "${my_locks[@]}"; do
    jq -r '"  [\(.scope)] \(.current_task // "(no task set)")  hb=\(.last_heartbeat)"' "$l"
  done
fi

# 2. Other active sessions
echo
echo "▶ Other active sessions"
other=0
while IFS= read -r lock; do
  [ -z "$lock" ] && continue
  other_sid="$(jq -r '.session_id' "$lock")"
  [ "$other_sid" = "$sid" ] && continue
  other=1
  jq -r '"  ▸ [\(.scope)] owner=\(.owner)  task=\(.current_task // "—")  hb=\(.last_heartbeat)  exp=\(.expected_release // "—")"' "$lock"
done < <(list_active_locks)
[ "$other" -eq 0 ] && echo "  (none)"

# 3. Inbox
echo
echo "▶ My inbox"
inbox_count=0
{
  unread_for "$sid"
  for l in "${my_locks[@]:-}"; do
    [ -z "$l" ] && continue
    # Guard: lock may have been swept (e.g., parallel session committed
    # the .lock file then it was archived) — skip if file gone.
    [ -f "$l" ] || continue
    unread_for "$(jq -r '.scope' "$l" 2>/dev/null)"
  done
} | sort -u | while IFS= read -r msg; do
  [ -z "$msg" ] && continue
  inbox_count=$((inbox_count+1))
  echo "  📬 $msg"
  jq -r '. // empty' /dev/null 2>/dev/null || true
  sed -n '2,8p' "$msg" | sed 's/^/     /'
done
# We can't tell from the subshell, so just check if any unread exist now.
if [ -z "$( { unread_for "$sid"; for l in "${my_locks[@]:-}"; do [ -z "$l" ] && continue; unread_for "$(jq -r '.scope' "$l")"; done; } | sort -u )" ]; then
  echo "  (empty)"
fi

# 4. Recent events from SESSION_LOG
echo
echo "▶ Recent events"
if [ ! -s "$SESSION_LOG" ]; then
  echo "  (log empty)"
else
  count=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    ts="$(printf '%s' "$line" | jq -r '.ts // empty' 2>/dev/null)"
    [ -z "$ts" ] && continue
    if [ "$WIN_SEC" -ne 0 ]; then
      ep="$(iso_to_epoch "$ts")"
      [ "$ep" -ge "$cutoff" ] || continue
    fi
    count=$((count+1))
    printf '%s' "$line" | jq -r '"  \(.ts)  \(.type)  \(.session[0:8])  \(.scope // .to // .commit // .task // "")"' 2>/dev/null
  done < <(tail -n 200 "$SESSION_LOG")
  [ "$count" -eq 0 ] && echo "  (no events in window)"
fi

# 5. Handoff capsules in window
echo
echo "▶ Recent handoff capsules"
hcount=0
if [ -d "$COMPLETED_DIR" ]; then
  for f in "$COMPLETED_DIR"/*.md; do
    [ -e "$f" ] || continue
    mt="$(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f" 2>/dev/null || echo 0)"
    if [ "$WIN_SEC" -ne 0 ]; then
      [ "$mt" -ge "$cutoff" ] || continue
    fi
    hcount=$((hcount+1))
    bn="$(basename "$f")"
    echo "  📦 $bn"
    sed -n '/^scope:/p;/^released:/p;/^commits:/p;/^files_changed:/p' "$f" 2>/dev/null | sed 's/^/     /'
  done
fi
[ "$hcount" -eq 0 ] && echo "  (none)"

echo
echo "════════════════════════════════════════════════════════════"
