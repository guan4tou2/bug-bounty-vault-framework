#!/usr/bin/env bash
# run_checks.sh — categorized runner for check_* scripts.
#
# Usage:
#   bash automation/run_checks.sh                    # list categories
#   bash automation/run_checks.sh <category>         # run one category
#   bash automation/run_checks.sh all                # run all
#   bash automation/run_checks.sh <category> <target># some accept a target
#
# Categories group check scripts by when you need them. Each script is called
# with $TARGET as $1 if provided; scripts that don't use it ignore it.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

G="\033[0;32m" Y="\033[0;33m" R="\033[0;31m" B="\033[0;34m" N="\033[0m"

# ── Category definitions ──────────────────────────────────────────────────
# Format: category:description:script1,script2,...
# Scripts are basenames under automation/; .sh/.py auto-detected.
declare -a CATEGORIES=(
  "pre-hunt:Pre-hunt readiness:check_disclosed_preread.sh"
  "asg:ASG integrity:check_vault.py,check_asg_note_contradictions.py"
  "harness:Harness/skill/hook integrity:check_harness_invariants.sh,check_orphan_scripts.sh"
  "kb:KB health:check_kb_health.sh,check_learning_capture.sh"
  "report:Report quality:check_report_quality.sh,check_submission_layout.py,check_docx_package.py"
)

category="${1:-}"
TARGET="${2:-}"

if [[ -z "$category" ]]; then
  echo -e "${B}Available check categories:${N}"
  echo ""
  for entry in "${CATEGORIES[@]}"; do
    IFS=':' read -r cat desc scripts <<< "$entry"
    count=$(echo "$scripts" | tr ',' '\n' | wc -l | tr -d ' ')
    echo -e "  ${G}$cat${N}  ($count scripts) — $desc"
  done
  echo ""
  echo "Usage: bash automation/run_checks.sh <category> [<target>]"
  echo "       bash automation/run_checks.sh all [<target>]"
  exit 0
fi

run_category() {
  local cat="$1" desc="$2" scripts="$3"
  echo ""
  echo -e "${B}━━━ $cat: $desc ━━━${N}"
  local pass=0 fail=0 skip=0
  IFS=',' read -ra arr <<< "$scripts"
  for script in "${arr[@]}"; do
    local path="$SCRIPT_DIR/$script"
    if [[ ! -f "$path" ]]; then
      echo -e "  ${Y}SKIP${N} $script (not found)"
      skip=$((skip + 1))
      continue
    fi
    local runner="bash"
    [[ "$script" == *.py ]] && runner="python3"
    local args=()
    [[ -n "$TARGET" ]] && args+=("$TARGET")
    # bash 3.2 (the system bash on macOS) errors with "unbound variable" when an
    # EMPTY array is expanded under `set -u`, and args is always empty when no
    # TARGET was given -- meaning this runner never finished a single category on
    # macOS. `${a[@]+"${a[@]}"}` is the 3.2-compatible "expand only if non-empty".
    if $runner "$path" ${args[@]+"${args[@]}"} >/dev/null 2>&1; then
      echo -e "  ${G}PASS${N} $script"
      pass=$((pass + 1))
    else
      echo -e "  ${R}FAIL${N} $script"
      # Re-run to show output
      $runner "$path" ${args[@]+"${args[@]}"} 2>&1 | sed 's/^/       /' | head -10
      fail=$((fail + 1))
    fi
  done
  echo -e "  ── $cat: ${G}$pass pass${N} ${R}$fail fail${N} ${Y}$skip skip${N}"
  return $fail
}

total_fail=0
if [[ "$category" == "all" ]]; then
  for entry in "${CATEGORIES[@]}"; do
    IFS=':' read -r cat desc scripts <<< "$entry"
    run_category "$cat" "$desc" "$scripts" || total_fail=$((total_fail + $?))
  done
else
  found=0
  for entry in "${CATEGORIES[@]}"; do
    IFS=':' read -r cat desc scripts <<< "$entry"
    if [[ "$cat" == "$category" ]]; then
      run_category "$cat" "$desc" "$scripts" || total_fail=$?
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    echo "Unknown category: $category" >&2
    echo "Run without args to see available categories." >&2
    exit 1
  fi
fi

echo ""
if [[ "$total_fail" -gt 0 ]]; then
  echo -e "${R}$total_fail check(s) failed.${N}"
  exit 1
else
  echo -e "${G}All checks passed.${N}"
fi
