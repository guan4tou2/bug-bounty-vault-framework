#!/usr/bin/env bash
# dedup_hints.sh — surface possible duplicates before opening a new Finding.
#
# Usage:
#   bash automation/dedup_hints.sh <target> "<keyword1>" "<keyword2>" ...
#
# Example:
#   bash automation/dedup_hints.sh example-competition "clockwork" "PII"
#
# What it does (cheap grep across known stores):
#   1. Vault Findings: 01 - Targets/<target>/Findings/
#   2. Vault Attempts: 01 - Targets/<target>/Attempts/
#   3. Workshop RECON_DB: $WORKSHOP_ROOT/<target>/RECON_DB.md
#   4. Workshop FINDINGS_QUICK_REF.md
#   5. Memory file: $MEMORY_DIR/project_*<target>*.md
#   6. KB Lessons / Patterns (cross-target similarity)
#
# Output: per-keyword hit list with context line. Caller (or
# `bb-dedup-finding` skill) decides if it's actual dup by root cause.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)" 2>/dev/null || {
  echo "⛔ workspace_layout.sh failed" >&2
  exit 2
}

TARGET="${1:-}"
shift 2>/dev/null || true

if [ -z "$TARGET" ] || [ $# -eq 0 ]; then
  cat >&2 <<EOF
Usage: bash automation/dedup_hints.sh <target> <kw1> [kw2 ...]

For each keyword, greps:
  - Vault Findings/Attempts for <target>
  - Workshop RECON_DB / FINDINGS_QUICK_REF
  - Memory file
  - KB Lessons / Patterns (cross-target signals)

Then prints hit count + first 3 matches per source per keyword.
Decide dup by **root cause**, not just keyword match (see教訓 #112).
EOF
  exit 2
fi

# Search roots
TARGET_DIR="$VAULT_ROOT/01 - Targets/$TARGET"
WS_DIR="$WORKSHOP_ROOT/$TARGET"
KB_DIR="$VAULT_ROOT/09 - Knowledge Base"
MEMORY_GLOB=$MEMORY_DIR/project_*"$TARGET"*.md

echo "═══════════════════════════════════════════════════════════════"
echo " dedup_hints — target: $TARGET"
echo "═══════════════════════════════════════════════════════════════"

for kw in "$@"; do
  echo
  echo "── keyword: '$kw' ──"

  hit_count_findings=0
  hit_count_workshop=0
  hit_count_memory=0
  hit_count_kb=0

  # 1. Vault Findings + Attempts
  if [ -d "$TARGET_DIR/Findings" ] || [ -d "$TARGET_DIR/Attempts" ]; then
    hits="$(grep -rliE "$kw" "$TARGET_DIR/Findings" "$TARGET_DIR/Attempts" 2>/dev/null | head -5)"
    if [ -n "$hits" ]; then
      hit_count_findings="$(echo "$hits" | wc -l | tr -d ' ')"
      echo "  📁 Vault findings/attempts ($hit_count_findings hit):"
      echo "$hits" | sed 's|.*/||' | sed 's/^/      /'
    fi
  fi

  # 2. Workshop
  for f in "$WS_DIR/RECON_DB.md" "$WS_DIR/FINDINGS_QUICK_REF.md"; do
    if [ -f "$f" ]; then
      ws_hits="$(grep -inE "$kw" "$f" 2>/dev/null | head -3)"
      if [ -n "$ws_hits" ]; then
        c="$(echo "$ws_hits" | wc -l | tr -d ' ')"
        hit_count_workshop=$((hit_count_workshop + c))
        echo "  🔧 $(basename "$f") ($c hit):"
        echo "$ws_hits" | sed 's/^/      /' | head -c 600
        echo
      fi
    fi
  done

  # 3. Memory
  for f in $MEMORY_GLOB; do
    if [ -f "$f" ]; then
      m_hits="$(grep -inE "$kw" "$f" 2>/dev/null | head -3)"
      if [ -n "$m_hits" ]; then
        c="$(echo "$m_hits" | wc -l | tr -d ' ')"
        hit_count_memory=$((hit_count_memory + c))
        echo "  🧠 memory: $(basename "$f") ($c hit):"
        echo "$m_hits" | sed 's/^/      /' | head -c 600
        echo
      fi
    fi
  done

  # 4. KB cross-target lessons/patterns
  if [ -d "$KB_DIR" ]; then
    kb_hits="$(grep -rliE "$kw" "$KB_DIR" --include="*.md" 2>/dev/null | grep -E "Lesson|Pattern|Lessons/LL-|WU-" | head -5)"
    if [ -n "$kb_hits" ]; then
      hit_count_kb="$(echo "$kb_hits" | wc -l | tr -d ' ')"
      echo "  📚 KB lessons/patterns ($hit_count_kb hit):"
      echo "$kb_hits" | sed 's|.*/||' | sed 's/^/      /'
    fi
  fi

  total=$((hit_count_findings + hit_count_workshop + hit_count_memory + hit_count_kb))
  if [ "$total" -eq 0 ]; then
    echo "  (no hits — likely novel for this target)"
  fi
done

echo
echo "─────"
echo "Decide dup by **root cause**, not keyword. See 教訓 #112 + bb-dedup-finding skill."
