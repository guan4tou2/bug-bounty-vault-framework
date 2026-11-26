#!/usr/bin/env bash
# dag_gaps.sh — list/count pending DAG edges for a target.
#
# Usage:
#   bash automation/dag_gaps.sh <target> [--kind all|chain|recon|validation|decision|pentest] [--count]
#
# Contract:
#   Parses effectiveness-first edge-list tables:
#   | from | edge | to | status |               (4-column, original)
#   | from | edge | to | status | blocked_by |   (5-column, with dependency)
#   Only the status column is counted; compact parsing is a token-saving side effect.
#   Section headers at ## or ### level are recognized (the Target Work DAG template
#   uses ##).
#
#   Dependency types (optional 5th column, adapted from Decepticon OPPLAN DAG):
#     blocked_by:<edge-id>  — this edge cannot start until <edge-id> is ✅
#     any_of:<id1>,<id2>    — unblocked when ANY listed edge is ✅
#     requires:<fact>       — unblocked when <fact> is established (free-text)
#     (empty)               — no dependency, can start immediately
#
#   The --blocked flag filters to only edges whose blockers are still ⏳.
#
# NOT a scheduler safety proof (C07): this lists pending/reachable edges as an
# ADVISORY. It does not model resource mutexes, rate limits, or shared-account
# contention. "No precedence edge between two items" does NOT mean they are safe to
# run in parallel — enforce resource/mutex checks separately before parallelizing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

TARGET=""
KIND="all"
COUNT_ONLY=0
BLOCKED_ONLY=0
READY_ONLY=0

while [[ $# -gt 0 ]]; do
  case "${1:-}" in
    --kind)
      KIND="${2:-all}"
      shift 2
      ;;
    --count)
      COUNT_ONLY=1
      shift
      ;;
    --blocked)
      BLOCKED_ONLY=1
      shift
      ;;
    --ready)
      READY_ONLY=1
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage:
  bash automation/dag_gaps.sh <target> [--kind all|chain|recon|validation|decision|pentest] [--count] [--blocked] [--ready]

Kinds:
  all         all target markdown files whose filename contains DAG
  chain       exploit-chain DAGs under Attack Chains
  recon       recon/surface/coverage DAGs
  validation  evidence/validation/attempt DAGs
  decision    decision-gate route selection DAGs
  pentest     pentest/route/path DAGs

Dependency filters:
  --blocked   show only ⏳ edges whose blockers are still ⏳ (cannot start yet)
  --ready     show only ⏳ edges with no blockers or all blockers ✅ (can start now)

Dependency types (optional 5th column in DAG table):
  blocked_by:<edge-id>  — blocked until <edge-id> is ✅
  any_of:<id1>,<id2>    — unblocked when ANY listed edge is ✅
  requires:<fact>       — unblocked when <fact> is established

Examples:
  bash automation/dag_gaps.sh <target> --kind chain
  bash automation/dag_gaps.sh <target> --count
  bash automation/dag_gaps.sh <target> --ready          # what can I work on NOW?
  bash automation/dag_gaps.sh <target> --blocked         # what is stuck and why?
USAGE
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

[ -z "$TARGET" ] && { echo "Usage: $0 <target> [--kind all|chain|recon|validation|decision|pentest] [--count]" >&2; exit 1; }

TARGET_DIR="$VAULT_ROOT/01 - Targets/${TARGET}"

if [ ! -d "$TARGET_DIR" ]; then
  [ "$COUNT_ONLY" -eq 1 ] && { echo 0; exit 0; }
  echo "Target directory not found: $TARGET_DIR"
  exit 0
fi

ALL_DAGS=$(mktemp /tmp/dag_gaps_all.XXXXXX)
DAG_FILES=$(mktemp /tmp/dag_gaps_files.XXXXXX)
TMPFILE_RED=$(mktemp /tmp/dag_gaps_red.XXXXXX)
TMPFILE_YLW=$(mktemp /tmp/dag_gaps_ylw.XXXXXX)
TMPFILE_OTH=$(mktemp /tmp/dag_gaps_oth.XXXXXX)
trap 'rm -f "$ALL_DAGS" "$DAG_FILES" "$TMPFILE_RED" "$TMPFILE_YLW" "$TMPFILE_OTH"' EXIT

find "$TARGET_DIR" -type f -name "*.md" -iname "*DAG*" 2>/dev/null | sort > "$ALL_DAGS"

case "$KIND" in
  all)
    cp "$ALL_DAGS" "$DAG_FILES"
    ;;
  chain)
    grep -E '/Attack Chains/' "$ALL_DAGS" > "$DAG_FILES" 2>/dev/null || true
    ;;
  recon)
    grep -Ei '/Recon/|/Notes/|Recon|Surface|Coverage|Target Work' "$ALL_DAGS" > "$DAG_FILES" 2>/dev/null || true
    ;;
  validation)
    grep -Ei '/Attempts/|/Findings/|Validation|Evidence|Attempt|Target Work' "$ALL_DAGS" > "$DAG_FILES" 2>/dev/null || true
    ;;
  decision)
    grep -Ei 'Decision|Gate|Route|Target Work' "$ALL_DAGS" > "$DAG_FILES" 2>/dev/null || true
    ;;
  pentest)
    grep -Ei 'Pentest|Route|Path|Attack Chains|Recon|Target Work' "$ALL_DAGS" > "$DAG_FILES" 2>/dev/null || true
    ;;
  *)
    echo "Unknown kind: $KIND" >&2
    exit 1
    ;;
esac

trim() {
  echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

row_matches_kind() {
  section="$1"
  rel_path="$2"

  case "$KIND" in
    all)
      return 0
      ;;
    chain)
      [[ "$rel_path" == *"/Attack Chains/"* || "$section" =~ [Cc]hain|Exploit ]]
      return $?
      ;;
    recon)
      [[ "$rel_path" =~ /Recon/|/Notes/ || "$section" =~ Recon|Surface|Coverage ]]
      return $?
      ;;
    validation)
      [[ "$rel_path" =~ /Attempts/|/Findings/ || "$section" =~ Validation|Evidence|Attempt ]]
      return $?
      ;;
    decision)
      [[ "$section" =~ Decision|Gate ]]
      return $?
      ;;
    pentest)
      [[ "$section" =~ Pentest|Route|Path ]]
      return $?
      ;;
  esac

  return 1
}

collect_all_statuses() {
  # First pass: collect all edge statuses keyed by "from→to" for dependency resolution
  file="$1"
  in_code_block=0
  while IFS= read -r line; do
    if [[ "$line" =~ ^'```' ]]; then
      [ "$in_code_block" -eq 0 ] && in_code_block=1 || in_code_block=0
      continue
    fi
    [ "$in_code_block" -eq 1 ] && continue
    [[ "$line" == *"|"* ]] || continue
    [[ "$line" != *"---"* ]] || continue
    [[ "$line" != *"status"* ]] || continue
    IFS='|' read -ra cols <<< "$line"
    [ ${#cols[@]} -ge 5 ] || continue
    local k="$(trim "${cols[1]}")→$(trim "${cols[3]}")"
    local s="$(trim "${cols[4]}")"
    # Store in associative array via temp file (bash 3 compat)
    printf "%s\t%s\n" "$k" "$s"
  done < "$file"
}

check_dependency() {
  # Given a dependency string and status lookup file, return:
  #   "ready" — no blocker or all blockers resolved
  #   "blocked:<reason>" — at least one blocker still pending
  local dep="$1"
  local status_file="$2"

  [ -z "$dep" ] && { echo "ready"; return; }

  if [[ "$dep" == blocked_by:* ]]; then
    local blocker="${dep#blocked_by:}"
    local blocker_status
    blocker_status="$(grep -F "$blocker" "$status_file" 2>/dev/null | head -1 | cut -f2)"
    if [[ "$blocker_status" == *"✅"* || "$blocker_status" == *"❌"* ]]; then
      echo "ready"
    else
      echo "blocked:waiting on $blocker"
    fi
  elif [[ "$dep" == any_of:* ]]; then
    local ids="${dep#any_of:}"
    IFS=',' read -ra id_list <<< "$ids"
    for id in "${id_list[@]}"; do
      id="$(trim "$id")"
      local id_status
      id_status="$(grep -F "$id" "$status_file" 2>/dev/null | head -1 | cut -f2)"
      if [[ "$id_status" == *"✅"* ]]; then
        echo "ready"
        return
      fi
    done
    echo "blocked:none of [${ids}] resolved"
  elif [[ "$dep" == requires:* ]]; then
    echo "blocked:requires ${dep#requires:}"
  else
    echo "ready"
  fi
}

parse_dag_file() {
  file="$1"
  rel="${file#$VAULT_ROOT/}"
  current_section=""
  current_priority="other"
  in_code_block=0
  count=0

  # First pass: collect all edge statuses for dependency resolution
  local status_lookup
  status_lookup=$(mktemp /tmp/dag_status.XXXXXX)
  collect_all_statuses "$file" > "$status_lookup"

  while IFS= read -r line; do
    if [[ "$line" =~ ^'```' ]]; then
      [ "$in_code_block" -eq 0 ] && in_code_block=1 || in_code_block=0
      continue
    fi
    [ "$in_code_block" -eq 1 ] && continue

    # Match ## and ### section headers — the Target Work DAG template uses ##
    # (## Validation DAG / ## Decision Gate DAG); matching only ### missed them.
    if [[ "$line" =~ ^"##" ]]; then
      current_section="$line"
      if [[ "$line" == *"🔴"* ]]; then
        current_priority="red"
      elif [[ "$line" == *"🟡"* ]]; then
        current_priority="yellow"
      else
        current_priority="other"
      fi
    fi

    [[ "$line" == *"|"* ]] || continue
    [[ "$line" != *"---"* ]] || continue
    [[ "$line" != *"status"* ]] || continue

    IFS='|' read -ra cols <<< "$line"
    [ ${#cols[@]} -ge 5 ] || continue

    from="$(trim "${cols[1]}")"
    edge="$(trim "${cols[2]}")"
    to="$(trim "${cols[3]}")"
    status="$(trim "${cols[4]}")"
    dep=""
    [ ${#cols[@]} -ge 6 ] && dep="$(trim "${cols[5]}")"

    [[ "$status" == *"⏳"* ]] || continue
    row_matches_kind "$current_section" "$rel" || continue

    # Resolve dependency
    local dep_result
    dep_result="$(check_dependency "$dep" "$status_lookup")"

    # Apply --blocked / --ready filters
    if [ "$BLOCKED_ONLY" -eq 1 ] && [[ "$dep_result" == "ready" ]]; then
      continue
    fi
    if [ "$READY_ONLY" -eq 1 ] && [[ "$dep_result" == blocked:* ]]; then
      continue
    fi

    count=$((count+1))
    [ "$COUNT_ONLY" -eq 1 ] && continue

    case "$current_priority" in
      red)    TMP="$TMPFILE_RED" ;;
      yellow) TMP="$TMPFILE_YLW" ;;
      *)      TMP="$TMPFILE_OTH" ;;
    esac

    printf "    DAG    : %s\n" "$rel" >> "$TMP"
    [ -n "$current_section" ] && printf "    SECTION: %s\n" "$current_section" >> "$TMP"
    printf "    FROM   : %s\n" "$from" >> "$TMP"
    printf "    EDGE   : %s\n" "$edge" >> "$TMP"
    printf "    TO     : %s\n" "$to" >> "$TMP"
    printf "    STATUS : %s\n" "$status" >> "$TMP"
    if [ -n "$dep" ]; then
      printf "    DEPENDS: %s → %s\n" "$dep" "$dep_result" >> "$TMP"
    fi
    printf "\n" >> "$TMP"
  done < "$file"

  rm -f "$status_lookup"
  echo "$count"
}

total=0
while IFS= read -r dag_file; do
  [ -n "$dag_file" ] || continue
  c="$(parse_dag_file "$dag_file")"
  c="${c:-0}"
  total=$((total + c))
done < "$DAG_FILES"

if [ "$COUNT_ONLY" -eq 1 ]; then
  echo "$total"
  exit 0
fi

echo "=== ⏳ DAG Gaps: ${TARGET} / ${KIND} ($(date '+%Y-%m-%d')) ==="
echo ""

if [ ! -s "$DAG_FILES" ]; then
  echo "No ${KIND} DAG markdown files found"
  echo "Suggestion: for multi-system / multi-surface / multi-validation-branch work, use a Target Work DAG to improve coverage and route planning; a single finding can skip it."
  exit 0
fi

if [ "$total" -eq 0 ]; then
  echo "✅ No ⏳ edges — all known DAG edges have been handled"
  exit 0
fi

count_red=$(grep -c "FROM" "$TMPFILE_RED" 2>/dev/null || echo 0)
count_ylw=$(grep -c "FROM" "$TMPFILE_YLW" 2>/dev/null || echo 0)
count_oth=$(grep -c "FROM" "$TMPFILE_OTH" 2>/dev/null || echo 0)

[ -s "$TMPFILE_RED" ] && { echo "━━━ 🔴 Critical / high-ROI DAG edge ($count_red) ━━━"; cat "$TMPFILE_RED"; echo ""; }
[ -s "$TMPFILE_YLW" ] && { echo "━━━ 🟡 Medium / follow-up DAG edge ($count_ylw) ━━━"; cat "$TMPFILE_YLW"; echo ""; }
[ -s "$TMPFILE_OTH" ] && { echo "━━━ Other untested DAG edge ($count_oth) ━━━"; cat "$TMPFILE_OTH"; echo ""; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ $total untested DAG edges total"
echo ""
echo "Status markers:"
echo "  ✅  = tested + works / covered"
echo "  ❌  = tested + dead end"
echo "  ⏳  = untested / pending"
echo "  🔴  = confirmed exploitable / highest ROI"
echo "  ⚠️  = stopped (safety / production / scope)"
echo ""
echo "→ Run this tool at the start of a session, then pick the 1-3 edges with the highest ROI / most uncertainty-reducing potential."
echo "→ Prioritize improving hunting and pentest effectiveness; the compact edge-list just avoids re-reading the entire RECON_DB."
