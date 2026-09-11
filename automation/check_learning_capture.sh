#!/usr/bin/env bash
# check_learning_capture.sh — "forgot to capture learnings" detector.
#
# Recurring pain: hunting produces findings/attempts but the reusable lesson never
# gets backfilled. Reminders alone (session_end §15) miss it when you skip the
# checklist. This correlates ACTIVITY (Finding/Attempt/Submission changes) with KB
# CAPTURE (new Lesson/Pattern/Playbook/Checklist) over a recent commit window:
# activity > 0 AND capture == 0  →  flag, proportional to activity.
#
# Read-only, advisory. Single source for session_end §3b + session_brief carryover.
# Usage: bash automation/check_learning_capture.sh [--window N] [--quiet]
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"
cd "$VAULT_ROOT" 2>/dev/null || exit 0

N=5; QUIET=0
while [ $# -gt 0 ]; do case "$1" in
  --window) N="$2"; shift 2;;
  --quiet) QUIET=1; shift;;
  *) shift;; esac; done

git rev-parse "HEAD~$N" >/dev/null 2>&1 || { exit 0; }   # shallow / new repo → skip

act=$(git diff --name-only "HEAD~$N..HEAD" -- "01 - Targets/" 2>/dev/null \
  | grep -cE "/(Finding|Attempt) - |/Submissions/" || true)
cap=$(git diff --name-only "HEAD~$N..HEAD" -- "09 - Knowledge Base/" 2>/dev/null \
  | grep -cE "/(Lessons/LL-|Pattern - |Playbook - |Checklist - )" || true)

if [ "${act:-0}" -gt 0 ] && [ "${cap:-0}" -eq 0 ]; then
  echo "⚠ Forgot to capture? Last $N commits have $act Finding/Attempt/Submission changes but 0 KB backfill"
  echo "   → If you found or tried something, there's a lesson: bb-knowledge-capture skill or lessons-miner agent"
  echo "   → Six types: ①attack technique ②decision tree ③attack chain ④stop-loss judgment ⑤pitfall lesson ⑥Checklist"
  exit 1
fi
[ "$QUIET" = 1 ] || echo "✓ Learning backfill aligned (last $N commits: activity $act / backfill $cap)"
exit 0
