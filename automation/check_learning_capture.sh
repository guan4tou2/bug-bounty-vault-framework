#!/usr/bin/env bash
# check_learning_capture.sh — "忘記整理學習經驗" detector.
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
  echo "⚠ 忘記整理？近 $N commit 有 $act 個 Finding/Attempt/Submission 變動，但 0 KB 回填"
  echo "   → 挖到/試過就有教訓：bb-knowledge-capture skill 或 lessons-miner agent"
  echo "   → 六類：①攻擊手法 ②決策樹 ③攻擊鏈 ④停損判斷 ⑤避坑教訓 ⑥Checklist"
  exit 1
fi
[ "$QUIET" = 1 ] || echo "✓ 學習回填對齊（近 $N commit：活動 $act / 回填 $cap）"
exit 0
