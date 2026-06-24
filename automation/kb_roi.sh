#!/usr/bin/env bash
# kb_roi.sh — KB artifact → finding provenance（效果回路 / reverse loop）
#
# 系統一直在 capture（session→KB→template→gate），但從不量測「KB 有沒有幫到挖洞」。
# 每筆 confirmed finding 的 frontmatter `helped_by:` 記錄哪些 KB artifact
# (Pattern/Playbook/Checklist/LL) 促成它。本腳本聚合這些 credit：
#   - 哪些 KB 真的產出 finding（保留/強化）
#   - 哪些 KB 從未被任何 finding 引用（entropy-GC 證據，不再靠猜）
# 把「採用率未驗證」變成可量測。Advisory only（LLM 判斷是否 prune）。
#
# 用法:
#   bash automation/kb_roi.sh                    # credited 排名 + uncredited 統計
#   bash automation/kb_roi.sh --uncredited       # 列所有未被 finding 引用的 KB
#   bash automation/kb_roi.sh --uncredited Pattern   # 只列某類型（Pattern|Playbook|Checklist|LL）
#
# bash 3.2 相容（macOS）
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

KB="$VAULT_ROOT/09 - Knowledge Base"
TARGETS="$VAULT_ROOT/01 - Targets"

MODE="report"
FILTER=""
case "${1:-}" in
  --uncredited) MODE="uncredited"; FILTER="${2:-}" ;;
  "" ) ;;
  * ) echo "unknown arg: $1"; exit 2 ;;
esac

tmp_credit="$(mktemp)"
trap 'rm -f "$tmp_credit"' EXIT

# --- 1. 收集所有 finding 的 helped_by token ----------------------------------
# 支援 inline `helped_by: [a, b]` 與 block list（  - a\n  - b）
finding_files="$(grep -rl '^fileClass: Finding' "$TARGETS" --include='*.md' 2>/dev/null || true)"
n_findings=0
n_with_credit=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  n_findings=$((n_findings+1))
  awk '
    /^helped_by:/ {
      line=$0; sub(/^helped_by:[ \t]*/,"",line)
      if (line ~ /^\[/) {                       # inline form
        gsub(/^\[|\][ \t]*$/,"",line)
        n=split(line,a,",")
        for(i=1;i<=n;i++){ t=a[i]; gsub(/^[ \t"]+|[ \t"]+$/,"",t); if(t!="") print t }
        next
      }
      blk=1; next                                # block form follows
    }
    blk==1 {
      if ($0 ~ /^[ \t]+-[ \t]*/) { t=$0; sub(/^[ \t]+-[ \t]*/,"",t); gsub(/^[ \t"]+|[ \t"]+$/,"",t); if(t!="") print t; next }
      else { blk=0 }
    }
  ' "$f" >> "$tmp_credit.raw" 2>/dev/null || true
done <<EOF
$finding_files
EOF

[ -f "$tmp_credit.raw" ] && sort "$tmp_credit.raw" > "$tmp_credit" && rm -f "$tmp_credit.raw"
[ -f "$tmp_credit" ] || : > "$tmp_credit"
n_with_credit=$(grep -c . "$tmp_credit" 2>/dev/null || true)
n_with_credit=${n_with_credit:-0}

# --- 2. KB inventory（識別字串） ---------------------------------------------
# Pattern/Playbook/Checklist：用檔名去掉副檔名當識別字串。LL：用 LL-NNN。
inventory() {  # $1 = glob prefix
  find "$KB" -name "$1*.md" 2>/dev/null | sed 's#.*/##; s#\.md$##'
}
ll_ids() { find "$KB" -name 'LL-*.md' 2>/dev/null | sed -E 's#.*/(LL-[0-9]+).*#\1#' | sort -u; }

is_credited() {  # $1 = identifier; substring match against any helped_by token
  grep -qiF "$1" "$tmp_credit" 2>/dev/null
}

if [ "$MODE" = "uncredited" ]; then
  echo "# Uncredited KB（從未被任何 finding 的 helped_by 引用 → prune 候選）"
  echo "# advisory：未被引用 ≠ 無用（可能是新的/防禦性/checklist）；LLM 判斷。"
  echo
  for kind in Pattern Playbook Checklist; do
    [ -n "$FILTER" ] && [ "$FILTER" != "$kind" ] && continue
    echo "## $kind"
    while IFS= read -r id; do
      [ -z "$id" ] && continue
      is_credited "$id" || echo "  - $id"
    done < <(inventory "$kind -")
    echo
  done
  if [ -z "$FILTER" ] || [ "$FILTER" = "LL" ]; then
    echo "## LL"
    while IFS= read -r id; do
      [ -z "$id" ] && continue
      is_credited "$id" || echo "  - $id"
    done < <(ll_ids)
  fi
  exit 0
fi

# --- 3. 報告：credited 排名 + uncredited 統計 --------------------------------
echo "# KB ROI — artifact → finding 效果回路"
echo
echo "Findings 掃描：$n_findings 筆；helped_by token：$n_with_credit 條"
echo
if [ "$n_with_credit" -eq 0 ]; then
  echo "⚠️  尚無任何 finding 填寫 helped_by。"
  echo "    → 確認 finding 時在 frontmatter 填 helped_by: [Pattern - X, LL-NNN]"
  echo "    → 累積後本腳本才能量測哪些 KB 真的有效、哪些該 prune。"
else
  echo "## ✅ Credited KB（產出 finding → 保留/強化）"
  sort "$tmp_credit" | uniq -c | sort -rn | sed 's/^/  /'
  echo
fi
echo

# uncredited 統計（各類型有多少從未被引用）
total_prune=0
echo "## ⚠️ Uncredited 統計（prune 候選池大小）"
for kind in Pattern Playbook Checklist; do
  tot=0; un=0
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    tot=$((tot+1)); is_credited "$id" || un=$((un+1))
  done < <(inventory "$kind -")
  total_prune=$((total_prune+un))
  echo "  $kind: $un / $tot 未被任何 finding 引用"
done
lltot=0; llun=0
while IFS= read -r id; do
  [ -z "$id" ] && continue
  lltot=$((lltot+1)); is_credited "$id" || llun=$((llun+1))
done < <(ll_ids)
total_prune=$((total_prune+llun))
echo "  LL: $llun / $lltot 未被任何 finding 引用"
echo
echo "→ 詳細清單：bash automation/kb_roi.sh --uncredited [Pattern|Playbook|Checklist|LL]"
echo "→ uncredited ≠ 無用（新增/防禦性/checklist 本就不直接產 finding）；entropy-GC 前 LLM 判斷。"
