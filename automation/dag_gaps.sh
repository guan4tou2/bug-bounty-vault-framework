#!/usr/bin/env bash
# dag_gaps.sh — list/count pending DAG edges for a target.
#
# Usage:
#   bash automation/dag_gaps.sh <target> [--kind all|chain|recon|validation|decision|pentest] [--count]
#
# Contract:
#   Parses effectiveness-first edge-list tables:
#   | from | edge | to | status |
#   Only the status column is counted; compact parsing is a token-saving side effect.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

TARGET=""
KIND="all"
COUNT_ONLY=0

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
    -h|--help)
      cat <<'USAGE'
Usage:
  bash automation/dag_gaps.sh <target> [--kind all|chain|recon|validation|decision|pentest] [--count]

Kinds:
  all         all target markdown files whose filename contains DAG
  chain       exploit-chain DAGs under Attack Chains
  recon       recon/surface/coverage DAGs
  validation  evidence/validation/attempt DAGs
  decision    decision-gate route selection DAGs
  pentest     pentest/route/path DAGs

Examples:
  bash automation/dag_gaps.sh <target> --kind chain
  bash automation/dag_gaps.sh <target> --count
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
  echo "找不到 target 目錄: $TARGET_DIR"
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

parse_dag_file() {
  file="$1"
  rel="${file#$VAULT_ROOT/}"
  current_section=""
  current_priority="other"
  in_code_block=0
  count=0

  while IFS= read -r line; do
    if [[ "$line" =~ ^'```' ]]; then
      [ "$in_code_block" -eq 0 ] && in_code_block=1 || in_code_block=0
      continue
    fi
    [ "$in_code_block" -eq 1 ] && continue

    if [[ "$line" =~ ^"###" ]]; then
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

    [[ "$status" == *"⏳"* ]] || continue
    row_matches_kind "$current_section" "$rel" || continue

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
    printf "    STATUS : %s\n\n" "$status" >> "$TMP"
  done < "$file"

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
  echo "找不到 ${KIND} DAG markdown 檔"
  echo "建議：多系統 / 多 surface / 多驗證分支時，用 Target Work DAG 提升 coverage 與 route planning；單 finding 可跳過。"
  exit 0
fi

if [ "$total" -eq 0 ]; then
  echo "✅ 無 ⏳ edge — 所有已知 DAG edge 均已處理"
  exit 0
fi

count_red=$(grep -c "FROM" "$TMPFILE_RED" 2>/dev/null || echo 0)
count_ylw=$(grep -c "FROM" "$TMPFILE_YLW" 2>/dev/null || echo 0)
count_oth=$(grep -c "FROM" "$TMPFILE_OTH" 2>/dev/null || echo 0)

[ -s "$TMPFILE_RED" ] && { echo "━━━ 🔴 Critical / high-ROI DAG edge ($count_red) ━━━"; cat "$TMPFILE_RED"; echo ""; }
[ -s "$TMPFILE_YLW" ] && { echo "━━━ 🟡 Medium / follow-up DAG edge ($count_ylw) ━━━"; cat "$TMPFILE_YLW"; echo ""; }
[ -s "$TMPFILE_OTH" ] && { echo "━━━ 其他未測 DAG edge ($count_oth) ━━━"; cat "$TMPFILE_OTH"; echo ""; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ 共 $total 個未測 DAG edge"
echo ""
echo "狀態標記:"
echo "  ✅  = tested + works / covered"
echo "  ❌  = tested + dead end"
echo "  ⏳  = untested / pending"
echo "  🔴  = confirmed exploitable / highest ROI"
echo "  ⚠️  = stopped (safety / production / scope)"
echo ""
echo "→ session 開頭先跑本工具，挑最高 ROI / 最能解除不確定性的 1-3 條 edge。"
echo "→ 先提升挖洞與滲透效果；compact edge-list 只是避免重讀整個 RECON_DB。"
