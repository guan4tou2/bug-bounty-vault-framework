#!/usr/bin/env bash
# surface_kb.sh — point-of-need KB retrieval（讓對的 KB 自己浮出來）
#
# 問題：KB 有 96 Pattern / 27 Playbook / 23 Checklist / 209 LL，bb_kb_search 是
# 「要記得查」的手動拉。本腳本反過來：偵測 target 的技術指紋 → 自動把相關 KB
# 端到面前。從「要記得查」變「自動浮到眼前」。掛在 recon 輸出後 / session 開頭跑。
#
# 機械偵測 + LLM 判斷：只列候選 KB，不替你決定相關性、不自動套用。
#
# 用法:
#   bash automation/surface_kb.sh <target>          # 讀該 target 的 RECON_DB 抽指紋
#   bash automation/surface_kb.sh --tech laravel,nacos,graphql   # 直接給指紋
#
# bash 3.2 相容（macOS）
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

KB="$VAULT_ROOT/09 - Knowledge Base"
TARGETS="$VAULT_ROOT/01 - Targets"

# 已知技術指紋字典（小寫；可擴充）。偵測到才浮 KB，避免噪音。
TECH_TOKENS="laravel wordpress drupal joomla nacos spring actuator graphql electron \
jenkins confluence jira citrix gitlab ignition horizon clockwork whoops struts \
nginx apache tomcat node express django flask rails s3 bucket azure firebase \
oauth saml jwt cors ssrf idor lfi rce ssti xxe redis mongodb elasticsearch \
kibana grafana prometheus harbor exchange proxyshell hikvision nvr rtsp upnp \
soap cgi firmware websocket cswsh swagger openapi keycloak wso2"

TECHS=""
case "${1:-}" in
  --tech)
    TECHS="$(echo "${2:-}" | tr ',' ' ' | tr 'A-Z' 'a-z')"
    ;;
  "" )
    echo "用法: surface_kb.sh <target>  |  surface_kb.sh --tech a,b,c"; exit 2 ;;
  * )
    target="$1"
    # 找該 target 的 recon 來源（RECON_DB / Recon note）
    src="$(find "$TARGETS" -ipath "*${target}*" \( -iname 'RECON_DB*.md' -o -iname '*recon*.md' \) 2>/dev/null)"
    if [ -z "$src" ]; then
      echo "⚠️  找不到 $target 的 RECON_DB；改用 --tech 手動給指紋。"; exit 1
    fi
    blob="$(cat $src 2>/dev/null | tr 'A-Z' 'a-z')"
    for t in $TECH_TOKENS; do
      echo "$blob" | grep -qF "$t" && TECHS="$TECHS $t"
    done
    ;;
esac

TECHS="$(echo "$TECHS" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
if [ -z "$TECHS" ]; then
  echo "未偵測到字典內的技術指紋。可手動 --tech，或 bb_kb_search 全文檢索。"
  exit 0
fi

echo "# Point-of-need KB — 偵測指紋: $TECHS"
echo "# 機械浮現候選；LLM 判斷哪些真的相關。逐項用 Read 開來看。"
echo
for t in $TECHS; do
  hits="$(grep -rilF "$t" "$KB" --include='Pattern -*.md' --include='Playbook -*.md' --include='Checklist -*.md' 2>/dev/null | sed 's#.*/##; s#\.md$##' | sort -u)"
  [ -z "$hits" ] && continue
  echo "## [$t]"
  echo "$hits" | sed 's/^/  - /'
  echo
done
echo "→ 全文/語意檢索（含 LL/Writeups）：bb_kb_search '<關鍵詞>'"
