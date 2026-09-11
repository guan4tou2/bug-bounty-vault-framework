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
section "1. Missing Target page (§2.1)"
n=0
for t in "$TARGETS_ROOT"/*/; do
  base=$(basename "$t"); [[ "$base" == _* ]] && continue
  if [ ! -f "$t/Target - $base.md" ]; then
    fail "missing: $base/Target - $base.md → bash automation/init_target.sh $base"
    n=$((n+1))
  fi
done
[ $n -eq 0 ] && ok "all 53 targets have Target - <name>.md"
fi

# ─────────────────────────────────────────────────────────────────────────
if want indexes; then
section "2. Missing Findings/Attempts/Recon/_index.md (§2.2 optional UI helper)"
for kind in Findings Attempts Recon; do
  n=0
  for t in "$TARGETS_ROOT"/*/; do
    base=$(basename "$t"); [[ "$base" == _* ]] && continue
    if [ -d "$t$kind" ] && [ ! -f "$t$kind/_index.md" ]; then
      n=$((n+1))
    fi
  done
  warn "$kind/_index.md missing: ${n} (Dataview UI helper, not required)"
done
fi

# ─────────────────────────────────────────────────────────────────────────
if want discovery-log; then
section "3. Finding missing ## Discovery Log (§3b)"
n=0; samples=""
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! grep -q '^## Discovery Log' "$f"; then
    n=$((n+1))
    [ $n -le 5 ] && samples+="    ${f##*/01 - Targets/}"$'\n'
  fi
done < <(find "$TARGETS_ROOT" -maxdepth 4 -name 'Finding - *.md' 2>/dev/null)
if [ $n -gt 0 ]; then
  warn "$n old Findings missing ## Discovery Log (legacy tech debt; fix in passing when touched, see §3b Migration)"
  echo -n "$samples"
  [ $n -gt 5 ] && echo "    ...($((n-5)) more)"
else
  ok "all Findings have ## Discovery Log"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want scope; then
section "4. Missing workshop/<t>/SCOPE.md (§4.1)"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  if [ ! -f "$d/SCOPE.md" ]; then
    if is_candidate_workshop_target "$base" "$d"; then
      warn "$base candidate target missing SCOPE.md (no Vault Target yet; a staged candidate does not block the audit, run init_target.sh before promoting)"
    else
      fail "$base missing SCOPE.md"
      n=$((n+1))
    fi
  fi
done
[ $n -eq 0 ] && ok "all workshop targets have SCOPE.md"
fi

# ─────────────────────────────────────────────────────────────────────────
if want recon-db; then
section "5. Missing workshop/<t>/RECON_DB.md (§4.1)"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  if [ ! -f "$d/RECON_DB.md" ]; then
    fail "$base missing RECON_DB.md → bash automation/init_target.sh $base"
    n=$((n+1))
  fi
done
[ $n -eq 0 ] && ok "all workshop targets have RECON_DB.md"
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
section "5b. Attack Surface Map gate (exploration-first — counters the streetlight effect)"
n=0
for d in "$WORKSHOP_ROOT"/*/; do
  base=$(basename "$d"); [[ "$base" == _* ]] && continue
  target_wanted "$base" || continue
  rdb="$d/RECON_DB.md"; [ -f "$rdb" ] || continue
  if ! grep -q "Attack Surface Map" "$rdb"; then
    # legacy target: touched-time migration (§3b policy) — warn, don't fail
    warn "$base has no 🗺 Attack Surface Map section (legacy; add it next time you touch this target)"; continue
  fi
  # section adopted → hard gate enforced
  sm=$(_section_rows "$rdb" "Attack Surface Map")
  dp=$(_section_rows "$rdb" "Discovered Paths")
  if [ "$dp" -gt 0 ] && [ "$sm" -eq 0 ]; then
    fail "$base has $dp Discovered Paths but an empty Surface Map → map the full surface before pattern scanning (don't skip exploration)"; n=$((n+1))
  fi
  # Recon-floor soft warn (X1: whether recon tools were run to saturation — Checklist - Recon Floor)
  if [ -d "$d/recon" ]; then
    have=0
    for tool in subfinder httpx gau katana waybackurls dnsx nuclei paramspider chaos subzy linkfinder getjs; do
      ls "$d/recon"/*${tool}* >/dev/null 2>&1 && have=$((have+1))
    done
    [ "$have" -lt 4 ] && warn "$base recon/ has only ${have}/12 recon tool outputs (floor suggests ≥4) → run [[Checklist - Recon Floor]]"
  else
    [ "$sm" -gt 0 ] && warn "$base has no recon/ directory but the Surface Map is filled → manual browsing? Run [[Checklist - Recon Floor]] to add recon tool output"
  fi
done
[ $n -eq 0 ] && ok "Attack Surface Map gate passed (exploration-first)"
fi

# ─────────────────────────────────────────────────────────────────────────
if want orphans; then
section "6. Submission/FORM orphan check (§3e.2 lint 14; FORM moved to Submissions/Forms/)"
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
  # Submission IDs (in Submissions/) + FORM IDs (in Submissions/Forms/)
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
[ $n -eq 0 ] && ok "0 Submission/FORM orphans"
fi

# ─────────────────────────────────────────────────────────────────────────
if want audit-log; then
section "7. Audit log mechanism (§6f)"
HOOK_SCRIPT="$SCRIPT_DIR/claude_audit_log.sh"
TODAY_LOG="$LOGS_ROOT/claude_audit_$(date -u +%Y%m%d).log"

if [ -x "$HOOK_SCRIPT" ]; then
  ok "hook script exists and is executable: $HOOK_SCRIPT"
else
  fail "hook script missing or not executable: $HOOK_SCRIPT"
fi

hook_loc=""
for f in ~/.claude/settings.json "$ROOT_DIR/.claude/settings.json" "$ROOT_DIR/.claude/settings.local.json"; do
  [ -f "$f" ] || continue
  if grep -q "claude_audit_log.sh" "$f" 2>/dev/null; then
    hook_loc="$f"; break
  fi
done
if [ -n "$hook_loc" ]; then
  ok "PostToolUse hook is registered in: $hook_loc"
else
  fail "PostToolUse hook is not registered in ~/.claude/settings.json nor in .claude/settings.local.json"
fi

# Hook path health: critical Write protection + edit-triggered audit.
PROTECT_SCRIPT="$SCRIPT_DIR/protect_critical_writes.sh"
if [ -x "$PROTECT_SCRIPT" ]; then
  ok "PreToolUse protect script exists and is executable: $PROTECT_SCRIPT"
else
  fail "PreToolUse protect script missing or not executable: $PROTECT_SCRIPT"
fi

protect_loc=""
write_edit_audit_loc=""
for f in ~/.claude/settings.json "$ROOT_DIR/.claude/settings.json" "$ROOT_DIR/.claude/settings.local.json"; do
  [ -f "$f" ] || continue
  grep -q "protect_critical_writes.sh" "$f" 2>/dev/null && protect_loc="$f"
  grep -q "audit_workspace.sh" "$f" 2>/dev/null && write_edit_audit_loc="$f"
done

if [ -n "$protect_loc" ]; then
  ok "PreToolUse protect hook is registered in: $protect_loc"
else
  warn "PreToolUse protect hook not registered — Write is unprotected"
fi

if [ -n "$write_edit_audit_loc" ]; then
  ok "PostToolUse Write|Edit audit hook is registered in: $write_edit_audit_loc"
else
  warn "PostToolUse Write|Edit audit hook not registered — no automatic audit after edits"
fi

if [ -f "$TODAY_LOG" ]; then
  # Count precisely by entry header ([timestamp] [session:8hex]) to avoid false positives inside RESPONSE
  entries=$(grep -cE '^\[2026-[0-9-]+ [0-9:]+ UTC\] \[session:[a-f0-9]{8}\]' "$TODAY_LOG" 2>/dev/null || echo 0)
  sessions=$(grep -oE '^\[2026-[0-9-]+ [0-9:]+ UTC\] \[session:[a-f0-9]{8}\]' "$TODAY_LOG" 2>/dev/null \
             | grep -oE 'session:[a-f0-9]{8}' | sort -u | wc -l | tr -d ' ')
  size=$(du -h "$TODAY_LOG" | cut -f1)
  ok "today's log file exists: ${TODAY_LOG} ($entries entries, $sessions sessions, ${size})"
  # Size warning (§6f.8): warn if > 50MB
  size_bytes=$(stat -f%z "$TODAY_LOG" 2>/dev/null || stat -c%s "$TODAY_LOG" 2>/dev/null || echo 0)
  if [ "$size_bytes" -gt 52428800 ]; then
    warn "today's log > 50MB — check for an abnormal loop (hook logging itself)"
  fi
  # UTF-8 valid (§6f.6)
  if iconv -f utf-8 -t utf-8 "$TODAY_LOG" > /dev/null 2>&1; then
    ok "today's log is UTF-8 valid"
  else
    warn "today's log contains invalid UTF-8 byte sequences — likely old entries from before the fix (accept; new entries are fixed)"
  fi
else
  warn "no audit log yet today (created automatically after the first Bash)"
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
  ok ".gitignore excludes the audit log"
else
  fail ".gitignore does not exclude the audit log (to avoid accidental commits)"
fi

# Logs older than 90 days (§6f.8) — compress and archive, don't delete outright (evidence is recoverable)
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
  [ "$archived" -gt 0 ] && ok "$archived audit logs > 90 days compressed into $ARCHIVE_DIR/ (originals removed, .gz kept permanently)"
  [ "$failed" -gt 0 ] && fail "$failed audit logs failed to compress — check write permissions on $ARCHIVE_DIR/"
else
  ok "no audit logs > 90 days need archiving"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want submission-fid; then
section "8. Submission missing finding_id frontmatter (§3a)"
n=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if ! grep -qE '^finding_id:' "$f"; then
    n=$((n+1))
    [ $n -le 5 ] && warn "${f##*/01 - Targets/} missing finding_id"
  fi
done < <(find "$TARGETS_ROOT" -maxdepth 4 -name 'Submission - *.md' 2>/dev/null)
if [ $n -gt 5 ]; then
  warn "...($((n-5)) more)"
fi
[ $n -eq 0 ] && ok "all Submissions have finding_id"
fi

# ─────────────────────────────────────────────────────────────────────────
if want vault-subdirs; then
section "9. Vault target 10 required subfolders (§3e.2)"
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
    fail "$base missing: $missing → bash automation/init_target.sh $base"
    miss_count=$((miss_count+1))
  fi
done
[ $miss_count -eq 0 ] && ok "all 53 targets have the 10 subfolders"
fi

# ─────────────────────────────────────────────────────────────────────────
if want workshop-files; then
section "10. workshop target required files (§4.1)"
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
      warn "$base candidate target missing: ${miss}(no Vault Target yet; a staged candidate does not block the audit, run init_target.sh ${base} before promoting)"
    else
      fail "$base missing: $miss → bash automation/init_target.sh $base"
      miss_total=$((miss_total+1))
    fi
  fi
done
[ $miss_total -eq 0 ] && ok "all workshop targets have the required files"
fi

# ─────────────────────────────────────────────────────────────────────────
if want firmware-targets; then
section "11. workshop/firmware_targets/<device>/ required files (§4.6 firmware schema)"
# firmware-specific schema: FINDINGS_QUICK_REF.md + RECON_DB.md (HANDOFF/SCOPE not required;
# firmware analysis is usually single-machine linear work with no need for parallel multi-session)
# Missing files show a warn rather than a fail: firmware_targets/ is not yet formally
# incorporated in STRUCTURE §4.6, and is mostly historical dumps (unpack/extract artifacts) —
# add the stub in passing when touched; for a new firmware target, add FQR + RECON_DB.
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
      warn "firmware_targets/$base missing: $miss"
      miss_total=$((miss_total+1))
    else
      n_ok=$((n_ok+1))
    fi
  done
  if [ $miss_total -eq 0 ]; then
    ok "all $n_devices firmware targets have the required files (FQR + RECON_DB)"
  else
    warn "$n_ok/$n_devices firmware targets complete; $miss_total historical dumps need stubs"
  fi
else
  warn "workshop/firmware_targets/ does not exist (no firmware targets, skip)"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want rule-docs; then
section "12. Rule docs drift (root / Vault agent guide sync)"
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
section "14. Workspace skills lint (.claude/skills registry)"
if bash "$SCRIPT_DIR/lint_workspace_skills.sh"; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want recon-coverage; then
section "15. Recon coverage (Vault Recon notes / Finding history)"
if python3 "$SCRIPT_DIR/audit_recon_coverage.py" --vault-root "$VAULT_ROOT" --min-findings 3; then
  :
else
  FAIL=$((FAIL+1))
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want kb-purity; then
section "16b. KB purity (competition-specific cases must not enter the KB — 2026-06-04 ed9005e0)"
# Files placed under 09 - Knowledge Base/ must not contain competition-specific identifiers:
#   - example-competition / example-platform / red-blue / example competition
#   - competition report numbers of the form HT0\d{3,4} (not a vault-internal ID, but a platform serial)
# Accepted existing items: LL-118 / LL-119 / Lesson #133 etc. mention competitions in the body as
# "abstracted lessons", but the filename/title/tags must not contain competition identifiers. Here we
# only grep the filename + frontmatter tags + heading lines (### / #), to avoid body false positives.
kb_dir="$VAULT_ROOT/09 - Knowledge Base"
kb_purity_fail=0
if [ -d "$kb_dir" ]; then
  # 1. filename contains a competition identifier
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    fail "KB filename contains competition identifier: $(basename "$f")"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(find "$kb_dir" -maxdepth 2 -type f -name "*.md" \
    \( -iname "*example-competition*" -o -iname "*example-platform*" -o -iname "*red-blue*" -o -iname "*example competition*" \) 2>/dev/null)
  # 2. frontmatter tags contain example-competition / example-platform
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    fail "KB frontmatter tag contains competition: $f"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(grep -rlE "^tags:.*\b(example-competition|example-platform|red-blue)\b|- (example-competition|example-platform|red-blue)$" \
    "$kb_dir" --include="*.md" 2>/dev/null | head -20)
  # 3. H1/H2 heading contains an HT0\d{3,4} serial (a body reference is OK, a heading is not)
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    fail "KB heading contains competition serial: $hit"
    kb_purity_fail=$((kb_purity_fail+1))
  done < <(grep -rEn "^#{1,2} .*\bHT0[0-9]{3,4}\b" "$kb_dir" --include="*.md" 2>/dev/null | head -10)

  if [ "$kb_purity_fail" -eq 0 ]; then
    ok "KB purity OK — no competition-specific contamination"
  fi
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want competition-schema; then
section "16c. Competition target schema (target_kind: competition required fields + Findings external_id)"
# For any target whose Target page has `target_kind: competition`, check:
#   - required frontmatter: competition_id / competition_start / competition_end / scoring_rules
#   - any Finding under Findings/ with status: submitted must have an external_id
# Does not affect non-competition targets.
comp_fail=0
comp_targets=0
for tgt_dir in "$TARGETS_ROOT"/*/; do
  base=$(basename "$tgt_dir"); [[ "$base" == _* ]] && continue
  page="$tgt_dir/Target - $base.md"
  [ -f "$page" ] || continue
  # frontmatter: check whether it is marked as a competition
  if ! head -30 "$page" 2>/dev/null | grep -qE "^target_kind:[[:space:]]*competition\b"; then
    continue
  fi
  comp_targets=$((comp_targets+1))
  # required frontmatter fields
  for field in competition_id competition_start competition_end scoring_rules; do
    if ! head -30 "$page" | grep -qE "^${field}:[[:space:]]*[\"'A-Za-z0-9]"; then
      fail "$base: Target page missing \`${field}:\` field (required for competition, see Template - Competition Target.md)"
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
          fail "$base: $(basename "$f") status:submitted but missing \`external_id:\` (required for competition)"
          comp_fail=$((comp_fail+1))
        fi
      fi
    done < <(find "$fdir" -name "Finding - *.md" -maxdepth 1 -type f 2>/dev/null)
  fi
done
if [ "$comp_targets" -eq 0 ]; then
  warn "no competition targets found (target_kind: competition); skip"
elif [ "$comp_fail" -eq 0 ]; then
  ok "$comp_targets competition target(s) — schema fully passed"
fi
fi

# ─────────────────────────────────────────────────────────────────────────
if want vault-lint; then
section "16. Vault lint (Vault schema / KB prefix / legacy folders)"
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
