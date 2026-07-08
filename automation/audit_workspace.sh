#!/usr/bin/env bash
# Unified workspace audit — checks all the workflow invariants in one place.
# Calls into existing lints where possible; adds new checks for §6f audit log
# integration and §3e.2 unified Finding-style workflow.
#
# Usage:
#   bash automation/audit_workspace.sh              # full audit, exits 1 if any ❌
#   bash automation/audit_workspace.sh --warn-only  # exit 0 always, just report
#   bash automation/audit_workspace.sh <topic>      # only one section
#   bash automation/audit_workspace.sh meta         # rule-docs + skills + audit-log only
#   bash automation/audit_workspace.sh vault        # rule-docs + recon coverage + Vault linter
#   bash automation/audit_workspace.sh portable     # vault-root + external workspace readiness
#   bash automation/audit_workspace.sh target <t>   # target-scoped workshop hygiene
#   bash automation/audit_workspace.sh full         # full audit
#       topics: target-pages | indexes | discovery-log | scope | recon-db |
#               orphans | audit-log | submission-fid | vault-subdirs | workshop-files |
#               firmware-targets | rule-docs | skills | portable | recon-coverage

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=automation/workspace_layout.sh
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"
ROOT_DIR="$PROJECT_ROOT"
TARGETS_ROOT="$VAULT_ROOT/01 - Targets"
KB_ROOT="$VAULT_ROOT/09 - Knowledge Base"
cd "$ROOT_DIR"

WARN_ONLY=0
TOPIC=""
TARGET_ONLY=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --warn-only) WARN_ONLY=1; shift ;;
    full) TOPIC=""; shift ;;
    meta) TOPIC="meta"; shift ;;
    vault) TOPIC="vault"; shift ;;
    portable) TOPIC="portable"; shift ;;
    target) TOPIC="target"; TARGET_ONLY="${2:-}"; shift 2 ;;
    *) TOPIC="$1"; shift ;;
  esac
done

FAIL=0
section() { echo ""; echo "── $1 ──"; }
ok() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
warn() { echo "  ⚠️  $1"; }

want() {
  if [ "$TOPIC" = "meta" ]; then
    [[ "$1" == "rule-docs" || "$1" == "skills" || "$1" == "audit-log" ]]
  elif [ "$TOPIC" = "vault" ]; then
    [[ "$1" == "rule-docs" || "$1" == "recon-coverage" || "$1" == "vault-lint" || "$1" == "kb-purity" || "$1" == "competition-schema" ]]
  elif [ "$TOPIC" = "portable" ]; then
    [[ "$1" == "portable" ]]
  elif [ "$TOPIC" = "target" ]; then
    [[ "$1" == "scope" || "$1" == "recon-db" || "$1" == "workshop-files" ]]
  else
    [[ -z "$TOPIC" || "$TOPIC" == "$1" ]]
  fi
}

target_wanted() {
  local base="$1"
  [[ -z "$TARGET_ONLY" || "$base" == "$TARGET_ONLY" ]]
}

has_vault_target_page() {
  local base="$1"
  [ -f "$TARGETS_ROOT/$base/Target - $base.md" ]
}

is_candidate_workshop_target() {
  local base="$1"
  local dir="$2"
  has_vault_target_page "$base" && return 1
  [ -f "$dir/RECON_DB.md" ]
}

# ─────────────────────────────────────────────────────────────────────────
if want target-pages; then
section "1. Target page 缺漏（§2.1）"
n=0
for t in "$TARGETS_ROOT"/*/; do
  base=$(basename "$t"); [[ "$base" == _* ]] && continue
  if [ ! -f "$t/Target - $base.md" ]; then
    fail "missing: $base/Target - $base.md → bash automation/init_target.sh $base"
    n=$((n+1))
  fi
done
[ $n -eq 0 ] && ok "53 targets 都有 Target - <name>.md"
fi

# ─────────────────────────────────────────────────────────────────────────
if want indexes; then
section "2. Findings/Attempts/Recon/_index.md 缺漏（§2.2 optional UI helper）"
for kind in Findings Attempts Recon; do
  n=0
  for t in "$TARGETS_ROOT"/*/; do
    base=$(basename "$t"); [[ "$base" == _* ]] && continue
    if [ -d "$t$kind" ] && [ ! -f "$t$kind/_index.md" ]; then
      n=$((n+1))
    fi
  done
  warn "$kind/_index.md 缺：${n}（Dataview UI helper，不強制建）"
done
fi

# ─────────────────────────────────────────────────────────────────────────
if want discovery-log; then
section "3. Finding 缺 ## Discovery Log（§3b）"
n=0; samples=""
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! grep -q '^## Discovery Log' "$f"; then
    n=$((n+1))
    [ $n -le 5 ] && samples+="    ${f##*/01 - Targets/}"$'\n'
  fi
done < <(find "$TARGETS_ROOT" -maxdepth 4 -name 'Finding - *.md' 2>/dev/null)
if [ $n -gt 0 ]; then
  warn "$n 個舊 Finding 缺 ## Discovery Log（legacy 技術債；touched 時順手修，見 §3b Migration）"
  echo -n "$samples"
  [ $n -gt 5 ] && echo "    ...(剩 $((n-5)) 個)"
else
  ok "所有 Finding 都有 ## Discovery Log"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want scope; then
section "4. workshop/<t>/SCOPE.md 缺漏（§4.1）"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  if [ ! -f "$d/SCOPE.md" ]; then
    if is_candidate_workshop_target "$base" "$d"; then
      warn "$base candidate target 缺 SCOPE.md（尚無 Vault Target；暫存候選不阻塞 audit，升級前跑 init_target.sh）"
    else
      fail "$base 缺 SCOPE.md"
      n=$((n+1))
    fi
  fi
done
[ $n -eq 0 ] && ok "所有 workshop target 都有 SCOPE.md"
fi

# ─────────────────────────────────────────────────────────────────────────
if want recon-db; then
section "5. workshop/<t>/RECON_DB.md 缺漏（§4.1）"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  if [ ! -f "$d/RECON_DB.md" ]; then
    fail "$base 缺 RECON_DB.md → bash automation/init_target.sh $base"
    n=$((n+1))
  fi
done
[ $n -eq 0 ] && ok "所有 workshop target 都有 RECON_DB.md"
fi

# ─────────────────────────────────────────────────────────────────────────
# Count "real" (non-placeholder) markdown table rows inside a RECON_DB section.
# $1=file  $2=section-header regex
_section_rows() {
  # BSD-awk safe (macOS): no multibyte char classes. Judge by the FIRST data cell ($2).
  awk -F'|' -v sec="$2" '
    /^## /   { inSec = ($0 ~ sec) ? 1 : 0; next }
    inSec && /^\|/ {
      cell=$2; gsub(/^[ \t]+|[ \t]+$/,"",cell)          # trim first data cell
      if (cell=="") next                                 # empty
      if (cell=="—") next                                # em-dash placeholder (byte-literal compare)
      if (cell ~ /^-+$/) next                            # ascii separator ---
      if (cell=="#" || cell ~ /^URL/ || cell ~ /^Surface element/) next  # header rows (ascii)
      c++
    }
    END{ print c+0 }
  ' "$1"
}

if want recon-db; then
section "5b. Attack Surface Map gate（探索優先 — 反路燈效應）"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  rdb="$d/RECON_DB.md"; [ -f "$rdb" ] || continue
  if ! grep -q "Attack Surface Map" "$rdb"; then
    # legacy target: touched-time migration (§3b policy) — warn, don't fail
    warn "$base 無 🗺 Attack Surface Map 區塊（legacy；下次動到時補上）"; continue
  fi
  # section adopted → hard gate enforced
  sm=$(_section_rows "$rdb" "Attack Surface Map")
  dp=$(_section_rows "$rdb" "Discovered Paths")
  if [ "$dp" -gt 0 ] && [ "$sm" -eq 0 ]; then
    fail "$base 有 $dp 個 Discovered Path 但 Surface Map 空 → 先全面測繪再 pattern 掃（勿跳探索）"; n=$((n+1))
  fi
  # Recon-floor soft warn（X1: recon 工具有沒有跑滿 — Checklist - Recon Floor）
  if [ -d "$d/recon" ]; then
    have=0
    for tool in subfinder httpx gau katana waybackurls dnsx nuclei paramspider chaos subzy linkfinder getjs; do
      ls "$d/recon"/*${tool}* >/dev/null 2>&1 && have=$((have+1))
    done
    [ "$have" -lt 4 ] && warn "$base recon/ 只有 ${have}/12 種 recon 工具輸出（floor 建議 ≥4）→ 跑 [[Checklist - Recon Floor]]"
  else
    [ "$sm" -gt 0 ] && warn "$base 無 recon/ 目錄但 Surface Map 已填 → 手動瀏覽? 跑 [[Checklist - Recon Floor]] 補 recon 工具輸出"
  fi
done
[ $n -eq 0 ] && ok "Attack Surface Map gate 通過（探索優先）"
fi

# ─────────────────────────────────────────────────────────────────────────
if want orphans; then
section "6. Submission/FORM orphan 檢查（§3e.2 lint 14；FORM 已搬 Submissions/Forms/）"
_extract_id() {
  echo "$1" | grep -oE '^(Submission|FORM|Finding) - .+ - ([A-Za-z]+-[0-9]+|[0-9]+)' \
            | grep -oE '([A-Za-z]+-[0-9]+|[0-9]+)$'
}
n=0
for t in "$TARGETS_ROOT"/*/; do
  [ -d "$t" ] || continue
  base=$(basename "$t"); [[ "$base" == _* ]] && continue
  sub_dir="$t/Submissions"; fnd_dir="$t/Findings"; forms_dir="$t/Submissions/Forms"
  [ -d "$sub_dir" ] || continue
  # Submission IDs（在 Submissions/）+ FORM IDs（在 Submissions/Forms/）
  sub_ids_raw=$( (ls "$sub_dir" 2>/dev/null) | grep -v '^Forms$' | while read f; do _extract_id "$f"; done)
  form_ids_raw=$( (ls "$forms_dir" 2>/dev/null) | while read f; do _extract_id "$f"; done)
  sub_ids=$(echo -e "$sub_ids_raw\n$form_ids_raw" | grep -v '^$' | sort -u)
  fnd_ids=$( (ls "$fnd_dir" 2>/dev/null) | while read f; do _extract_id "$f"; done | grep -v '^$' | sort -u)
  cleaned=$(echo "$sub_ids" | while read id; do
    if [[ "$id" =~ ^[0-9]+$ ]]; then
      padded=$(printf "%03d" "$id")
      echo "$sub_ids" | grep -qE "^HM-(${padded}|${id})\$" && continue
    fi
    echo "$id"
  done | grep -v '^$' | sort -u)
  orphans=$(comm -23 <(echo "$cleaned") <(echo "$fnd_ids") | grep -v '^$')
  if [ -n "$orphans" ]; then
    fail "$base orphan: $(echo $orphans | tr '\n' ' ') → bash automation/backfill_finding_stubs.sh $base"
    n=$((n+1))
  fi
done
[ $n -eq 0 ] && ok "0 個 Submission/FORM orphan"
fi

# ─────────────────────────────────────────────────────────────────────────
if want audit-log; then
section "7. Audit log 機制（§6f）"
HOOK_SCRIPT="$SCRIPT_DIR/claude_audit_log.sh"
TODAY_LOG="$LOGS_ROOT/claude_audit_$(date -u +%Y%m%d).log"

if [ -x "$HOOK_SCRIPT" ]; then
  ok "hook script 存在且可執行：$HOOK_SCRIPT"
else
  fail "hook script 缺失或不可執行：$HOOK_SCRIPT"
fi

hook_loc=""
for f in ~/.claude/settings.json "$ROOT_DIR/.claude/settings.json" "$ROOT_DIR/.claude/settings.local.json"; do
  [ -f "$f" ] || continue
  if grep -q "claude_audit_log.sh" "$f" 2>/dev/null; then
    hook_loc="$f"; break
  fi
done
if [ -n "$hook_loc" ]; then
  ok "PostToolUse hook 已掛在：$hook_loc"
else
  fail "PostToolUse hook 沒掛在 ~/.claude/settings.json 也不在 .claude/settings.local.json"
fi

# Hook path health: critical Write protection + edit-triggered audit.
PROTECT_SCRIPT="$SCRIPT_DIR/protect_critical_writes.sh"
if [ -x "$PROTECT_SCRIPT" ]; then
  ok "PreToolUse protect script 存在且可執行：$PROTECT_SCRIPT"
else
  fail "PreToolUse protect script 缺失或不可執行：$PROTECT_SCRIPT"
fi

protect_loc=""
write_edit_audit_loc=""
for f in ~/.claude/settings.json "$ROOT_DIR/.claude/settings.json" "$ROOT_DIR/.claude/settings.local.json"; do
  [ -f "$f" ] || continue
  grep -q "protect_critical_writes.sh" "$f" 2>/dev/null && protect_loc="$f"
  grep -q "audit_workspace.sh" "$f" 2>/dev/null && write_edit_audit_loc="$f"
done

if [ -n "$protect_loc" ]; then
  ok "PreToolUse protect hook 已掛在：$protect_loc"
else
  warn "PreToolUse protect hook 未掛 — Write 不受保護"
fi

if [ -n "$write_edit_audit_loc" ]; then
  ok "PostToolUse Write|Edit audit hook 已掛在：$write_edit_audit_loc"
else
  warn "PostToolUse Write|Edit audit hook 未掛 — 編輯後不會自動 audit"
fi

if [ -f "$TODAY_LOG" ]; then
  # 用 entry header（[timestamp] [session:8hex]）精確計數，避開 RESPONSE 內 false positive
  entries=$(grep -cE '^\[2026-[0-9-]+ [0-9:]+ UTC\] \[session:[a-f0-9]{8}\]' "$TODAY_LOG" 2>/dev/null || echo 0)
  sessions=$(grep -oE '^\[2026-[0-9-]+ [0-9:]+ UTC\] \[session:[a-f0-9]{8}\]' "$TODAY_LOG" 2>/dev/null \
             | grep -oE 'session:[a-f0-9]{8}' | sort -u | wc -l | tr -d ' ')
  size=$(du -h "$TODAY_LOG" | cut -f1)
  ok "今日 log 檔存在：${TODAY_LOG}（$entries 筆，$sessions sessions，${size}）"
  # 大小警示（§6f.8）：> 50MB 警告
  size_bytes=$(stat -f%z "$TODAY_LOG" 2>/dev/null || stat -c%s "$TODAY_LOG" 2>/dev/null || echo 0)
  if [ "$size_bytes" -gt 52428800 ]; then
    warn "今日 log > 50MB — 檢查是否有 abnormal loop（hook 自我紀錄）"
  fi
  # UTF-8 valid（§6f.6）
  if iconv -f utf-8 -t utf-8 "$TODAY_LOG" > /dev/null 2>&1; then
    ok "今日 log UTF-8 valid"
  else
    warn "今日 log 含 invalid UTF-8 byte sequence — 可能是 fix 前舊 entries（accept；新 entries 已修）"
  fi
else
  warn "今日尚無 audit log（第一個 Bash 後會自動建立）"
fi

audit_log_ignored=0
today_log_rel="${TODAY_LOG#$ROOT_DIR/}"
if [[ "$TODAY_LOG" != "$ROOT_DIR"/* ]]; then
  # Standard vault-root + external workspace: logs live outside the Vault git repo.
  audit_log_ignored=1
elif (cd "$ROOT_DIR" && git check-ignore -q "$today_log_rel" 2>/dev/null); then
  audit_log_ignored=1
elif grep -q "logs/claude_audit_" "$ROOT_DIR/.gitignore" 2>/dev/null; then
  audit_log_ignored=1
elif [[ "$today_log_rel" == workspace/* ]] && grep -qE '^workspace/?$' "$ROOT_DIR/.gitignore" 2>/dev/null; then
  audit_log_ignored=1
elif [[ "$today_log_rel" == logs/* ]] && grep -qE '^logs/?$' "$ROOT_DIR/.gitignore" 2>/dev/null; then
  audit_log_ignored=1
fi

if [ "$audit_log_ignored" -eq 1 ]; then
  ok ".gitignore 已排除 audit log"
else
  fail ".gitignore 未排除 audit log（避免誤 commit）"
fi

# 90 天舊 log（§6f.8）—— 壓縮歸檔，不直接刪除（證據可回復）
ARCHIVE_DIR="$LOGS_ROOT/archive"
old_logs=$(find "$LOGS_ROOT" -maxdepth 1 -name 'claude_audit_*.log' -mtime +90 2>/dev/null)
if [ -n "$old_logs" ]; then
  mkdir -p "$ARCHIVE_DIR"
  archived=0; failed=0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    if gzip -c "$f" > "$ARCHIVE_DIR/${base}.gz" 2>/dev/null; then
      rm -f "$f"; archived=$((archived+1))
    else
      failed=$((failed+1))
    fi
  done <<< "$old_logs"
  [ "$archived" -gt 0 ] && ok "$archived 個 audit log > 90 天已壓縮進 $ARCHIVE_DIR/（原檔移除，.gz 永久保留）"
  [ "$failed" -gt 0 ] && fail "$failed 個 audit log 壓縮失敗 — 檢查 $ARCHIVE_DIR/ 寫入權限"
else
  ok "無 > 90 天的 audit log 需歸檔"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want submission-fid; then
section "8. Submission 缺 finding_id frontmatter（§3a）"
n=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! grep -qE '^finding_id:' "$f"; then
    n=$((n+1))
    [ $n -le 5 ] && warn "${f##*/01 - Targets/} 缺 finding_id"
  fi
done < <(find "$TARGETS_ROOT" -maxdepth 4 -name 'Submission - *.md' 2>/dev/null)
if [ $n -gt 5 ]; then
  warn "...(剩 $((n-5)) 個)"
fi
[ $n -eq 0 ] && ok "所有 Submission 都有 finding_id"
fi

# ─────────────────────────────────────────────────────────────────────────
if want vault-subdirs; then
section "9. Vault target 10 個必建子資料夾（§3e.2）"
required_dirs=(Findings Submissions "Submissions/Forms" Attempts Recon Services Credentials Notes "Attack Chains" Screenshots)
miss_count=0
for t in "$TARGETS_ROOT"/*/; do
  [ -d "$t" ] || continue
  base=$(basename "$t"); [[ "$base" == _* ]] && continue
  missing=""
  for d in "${required_dirs[@]}"; do
    [ ! -d "$t/$d" ] && missing+="$d "
  done
  if [ -n "$missing" ]; then
    fail "$base 缺：$missing → bash automation/init_target.sh $base"
    miss_count=$((miss_count+1))
  fi
done
[ $miss_count -eq 0 ] && ok "53 targets 都齊 10 個子資料夾"
fi

# ─────────────────────────────────────────────────────────────────────────
if want workshop-files; then
section "10. workshop target 必建檔案（§4.1）"
skip_meta=(firmware_targets _all)
miss_total=0
for t in "$WORKSHOP_ROOT"/*/; do
  [ -d "$t" ] || continue
  base=$(basename "$t"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  [[ " ${skip_meta[*]} " =~ " $base " ]] && continue
  miss=""
  [ ! -f "$t/HANDOFF.md" ] && miss+="HANDOFF "
  [ ! -f "$t/FINDINGS_QUICK_REF.md" ] && miss+="FINDINGS_QUICK_REF "
  if [ -n "$miss" ]; then
    if is_candidate_workshop_target "$base" "$t"; then
      warn "$base candidate target 缺：${miss}（尚無 Vault Target；暫存候選不阻塞 audit，升級前跑 init_target.sh ${base}）"
    else
      fail "$base 缺：$miss → bash automation/init_target.sh $base"
      miss_total=$((miss_total+1))
    fi
  fi
done
[ $miss_total -eq 0 ] && ok "所有 workshop target 都齊必建檔"
fi

# ─────────────────────────────────────────────────────────────────────────
if want firmware-targets; then
section "11. workshop/firmware_targets/<device>/ 必建檔案（§4.6 firmware schema）"
# firmware-specific schema：FINDINGS_QUICK_REF.md + RECON_DB.md（HANDOFF/SCOPE 不強制；
# 韌體分析通常單機線性作業，沒有 multi-session 並行需求）
# 缺檔顯示 warn 而非 fail：firmware_targets/ 在 STRUCTURE §4.6 尚未明確收編，
# 多為歷史 dump（解包/extract artifacts），touched 時順手補 stub；
# 新建 firmware target 請補齊 FQR + RECON_DB。
if [ -d "$WORKSHOP_ROOT/firmware_targets" ]; then
  miss_total=0; n_devices=0; n_ok=0
  for d in "$WORKSHOP_ROOT/firmware_targets"/*/; do
    [ -d "$d" ] || continue
    base=$(basename "$d"); [[ "$base" == _* ]] && continue
    n_devices=$((n_devices+1))
    miss=""
    [ ! -f "$d/FINDINGS_QUICK_REF.md" ] && miss+="FINDINGS_QUICK_REF "
    [ ! -f "$d/RECON_DB.md" ] && miss+="RECON_DB "
    if [ -n "$miss" ]; then
      warn "firmware_targets/$base 缺：$miss"
      miss_total=$((miss_total+1))
    else
      n_ok=$((n_ok+1))
    fi
  done
  if [ $miss_total -eq 0 ]; then
    ok "$n_devices firmware target 都齊必建檔（FQR + RECON_DB）"
  else
    warn "$n_ok/$n_devices firmware target 齊全；$miss_total 個歷史 dump 待補 stub"
  fi
else
  warn "workshop/firmware_targets/ 不存在（無 firmware target，skip）"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want rule-docs; then
section "12. Rule docs drift（root / Vault agent guide 同步）"
if bash "$SCRIPT_DIR/lint_rule_docs.sh"; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want portable; then
section "13. Portable layout readiness（vault-root + external workspace）"
if bash "$SCRIPT_DIR/check_portable_layout.sh"; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want skills; then
section "14. Workspace skills lint（.claude/skills registry）"
if bash "$SCRIPT_DIR/lint_workspace_skills.sh"; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want recon-coverage; then
section "15. Recon coverage（Vault Recon notes / Finding history）"
if python3 "$SCRIPT_DIR/audit_recon_coverage.py" --vault-root "$VAULT_ROOT" --min-findings 3; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want kb-purity; then
section "16b. KB purity（競賽特例不進 KB — 2026-06-04 ed9005e0）"
# 鎖列入 09 - Knowledge Base/ 的檔案不得含競賽 specific 識別碼:
#   - example-competition / example-platform / red-blue / example competition
#   - HT0\d{3,4} 形式的競賽報告編號（不是 vault-internal ID,是平台流水號）
# 既有可接受項目:LL-118 / LL-119 / 教訓 #133 等內文以「抽象化教訓」形式提及
# 競賽,但檔名/標題/tags 不得含競賽識別。這裡只 grep 檔名 + frontmatter tags +
# 標題行(### / #),避免內文 false positive。
kb_dir="$VAULT_ROOT/09 - Knowledge Base"
kb_purity_fail=0
if [ -d "$kb_dir" ]; then
  # 1. 檔名含競賽識別碼
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    fail "KB 檔名含競賽識別:$(basename "$f")"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(find "$kb_dir" -maxdepth 2 -type f -name "*.md" \
    \( -iname "*example-competition*" -o -iname "*example-platform*" -o -iname "*red-blue*" -o -iname "*example competition*" \) 2>/dev/null)
  # 2. frontmatter tags 含 hack-the-tainan / example-platform
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    fail "KB frontmatter tag 含競賽:$f"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(grep -rlE "^tags:.*\b(hack-the-tainan|example-platform|red-blue)\b|- (hack-the-tainan|example-platform|red-blue)$" \
    "$kb_dir" --include="*.md" 2>/dev/null | head -20)
  # 3. 一級/二級標題含 HT0\d{3,4} 流水號(內文 reference 可,標題不可)
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    fail "KB 標題含競賽流水號:$hit"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(grep -rEn "^#{1,2} .*\bHT0[0-9]{3,4}\b" "$kb_dir" --include="*.md" 2>/dev/null | head -10)

  if [ "$kb_purity_fail" -eq 0 ]; then
    ok "KB 純度 OK — 無競賽特例污染"
  fi
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want competition-schema; then
section "16c. Competition target schema（target_kind: competition 必填欄位 + Findings external_id）"
# 對任何 Target 頁有 `target_kind: competition` 的 target,檢查:
#   - frontmatter 必填:competition_id / competition_start / competition_end / scoring_rules
#   - Findings/ 下任何 status: submitted 的 Finding 必須有 external_id
# 不影響非競賽 target。
comp_fail=0
comp_targets=0
for tgt_dir in "$TARGETS_ROOT"/*/; do
  base=$(basename "$tgt_dir"); [[ "$base" == _* ]] && continue
  page="$tgt_dir/Target - $base.md"
  [ -f "$page" ] || continue
  # frontmatter:檢查是否標 competition
  if ! head -30 "$page" 2>/dev/null | grep -qE "^target_kind:[[:space:]]*competition\b"; then
    continue
  fi
  comp_targets=$((comp_targets+1))
  # required frontmatter fields
  for field in competition_id competition_start competition_end scoring_rules; do
    if ! head -30 "$page" | grep -qE "^${field}:[[:space:]]*[\"'A-Za-z0-9]"; then
      fail "$base: Target page 缺 \`${field}:\` 欄位(competition 必填,見 Template - Competition Target.md)"
      comp_fail=$((comp_fail+1))
    fi
  done
  # Findings external_id check
  fdir="$tgt_dir/Findings"
  if [ -d "$fdir" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if head -40 "$f" 2>/dev/null | grep -qE "^status:[[:space:]]*\"?submitted\"?"; then
        if ! head -40 "$f" | grep -qE "^external_id:[[:space:]]*[\"']?[A-Za-z]+-?[0-9]+"; then
          fail "$base: $(basename "$f") status:submitted 但缺 \`external_id:\`(competition 必填)"
          comp_fail=$((comp_fail+1))
        fi
      fi
    done < <(find "$fdir" -name "Finding - *.md" -maxdepth 1 -type f 2>/dev/null)
  fi
done
if [ "$comp_targets" -eq 0 ]; then
  warn "no competition targets found (target_kind: competition);skip"
elif [ "$comp_fail" -eq 0 ]; then
  ok "$comp_targets competition target(s) — schema 全通過"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want vault-lint; then
section "16. Vault lint（Vault schema / KB prefix / legacy folders）"
if bash "$VAULT_ROOT/05 - Tools/lint_vault.sh"; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then
  echo "✅ Audit clean ($FAIL ❌)"
else
  echo "❌ Audit found $FAIL hard violation(s)"
fi
echo "════════════════════════════════════════════════════════════"

[ $WARN_ONLY -eq 1 ] && exit 0
exit $FAIL
