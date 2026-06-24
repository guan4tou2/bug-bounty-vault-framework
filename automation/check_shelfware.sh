#!/usr/bin/env bash
# check_shelfware.sh — template adoption telemetry（量哪些 template 沒人用）
#
# check_orphan_scripts 管「腳本」沒被引用；本腳本管「template」沒被實例化。
# 每個 Template 有 frontmatter marker（subpage:/type:/fileClass:）；實例會複製它。
# 數有多少實例 = 該 template 的真實採用率。0 實例 = shelf-ware（DAG template 曾 0/124
# 就是這種；forward 量測比事後挖 124 個 session 才發現便宜）。
#
# Advisory only（LLM 判斷：0 實例是「該 retire」還是「剛建/季節性」）。
#
# 用法: bash automation/check_shelfware.sh
# bash 3.2 相容（macOS）
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

TPL_DIR="$VAULT_ROOT/07 - Templates"

echo "# Template adoption（實例數 = 真實採用率；0 = shelf-ware 候選）"
echo "# advisory：0 實例 ≠ 該砍（可能剛建/季節性）；LLM 判斷。"
echo

shelf=0
for tpl in "$TPL_DIR"/Template\ -\ *.md; do
  [ -f "$tpl" ] || continue
  name="$(basename "$tpl" .md)"
  # 取主 marker：優先 subpage > type > fileClass（subpage 對 target 子頁最具辨識度）
  key=""; val=""
  for k in subpage type fileClass; do
    line="$(grep -m1 -E "^${k}:" "$tpl" 2>/dev/null || true)"
    if [ -n "$line" ]; then
      key="$k"
      val="$(echo "${line#*:}" | sed 's/^[[:space:]"]*//; s/[[:space:]"]*$//')"
      break
    fi
  done
  if [ -z "$key" ] || [ -z "$val" ]; then
    printf '  %-55s [無 marker — 無法量測]\n' "$name"
    continue
  fi
  # 數 vault 內（排除 07-Templates）有同 marker 的實例檔
  count="$(grep -rl --include='*.md' -E "^${key}:[[:space:]\"]*${val}\"?[[:space:]]*$" "$VAULT_ROOT" 2>/dev/null \
            | grep -vF "/07 - Templates/" | wc -l | tr -d ' ')"
  flag=""
  if [ "$count" -eq 0 ]; then flag="  ⬅ shelf-ware (0 實例)"; shelf=$((shelf+1)); fi
  printf '  %-55s %s=%s  →  %s 實例%s\n' "$name" "$key" "$val" "$count" "$flag"
done

echo
echo "Shelf-ware 候選（0 實例）：$shelf"
[ "$shelf" -gt 0 ] && echo "→ 逐項判斷：retire / 簡化降 friction / 加 session 開頭 nudge（如 dag_gaps）"
exit 0
