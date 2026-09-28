#!/usr/bin/env bash
# check_pending_workers.sh — advisory gate: list confirmed findings with pending
# mandatory workers (chain, expand).
#
# Usage:
#   bash automation/check_pending_workers.sh [<target>]
#
# Exit 0 = all clear, exit 1 = pending workers exist.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGETS_DIR="$ROOT_DIR/01 - Targets"

targets=()
if [[ -n "${1:-}" ]]; then
  targets+=("$1")
else
  for d in "$TARGETS_DIR"/*/; do
    [[ -f "$d/.state/asg-events.jsonl" ]] && targets+=("$(basename "$d")")
  done
fi

found=0
for target in "${targets[@]}"; do
  pw=$(python3 "$SCRIPT_DIR/asg.py" pending-workers "$target" 2>/dev/null || echo "[]")
  count=$(echo "$pw" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
  if [[ "$count" -gt 0 ]]; then
    echo "WARNING: $target has $count pending worker(s):"
    echo "$pw" | python3 -c "
import json, sys
for w in json.load(sys.stdin):
    print(f\"  - {w.get('finding_id','?')}: {w.get('worker','?')}\")
" 2>/dev/null
    found=$((found + count))
  fi
done

if [[ "$found" -gt 0 ]]; then
  echo ""
  echo "$found total pending worker(s). Complete them before submission."
  exit 1
fi
exit 0
