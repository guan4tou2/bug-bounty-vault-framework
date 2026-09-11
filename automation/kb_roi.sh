#!/usr/bin/env bash
# kb_roi.sh — KB artifact → finding provenance (effectiveness loop / reverse loop)
#
# The system keeps capturing (session→KB→template→gate) but never measures "did
# the KB actually help hunting". Each confirmed finding's frontmatter `helped_by:`
# records which KB artifacts (Pattern/Playbook/Checklist/LL) contributed to it.
# This script aggregates that credit:
#   - which KB actually produced findings (keep/strengthen)
#   - which KB was never cited by any finding (entropy-GC evidence, no longer guessing)
# Turns "unverified adoption" into something measurable. Advisory only (LLM decides
# whether to prune).
#
# Usage:
#   bash automation/kb_roi.sh                    # credited ranking + uncredited stats
#   bash automation/kb_roi.sh --uncredited       # list all KB never cited by a finding
#   bash automation/kb_roi.sh --uncredited Pattern   # list only one type (Pattern|Playbook|Checklist|LL)
#
# bash 3.2 compatible (macOS)
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

# --- 1. Collect helped_by tokens from all findings ---------------------------
# Supports inline `helped_by: [a, b]` and block list (  - a\n  - b)
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

# --- 2. KB inventory (identifier strings) ------------------------------------
# Pattern/Playbook/Checklist: use the filename without extension as the identifier. LL: use LL-NNN.
inventory() {  # $1 = glob prefix
  find "$KB" -name "$1*.md" 2>/dev/null | sed 's#.*/##; s#\.md$##'
}
ll_ids() { find "$KB" -name 'LL-*.md' 2>/dev/null | sed -E 's#.*/(LL-[0-9]+).*#\1#' | sort -u; }

is_credited() {  # $1 = identifier; substring match against any helped_by token
  grep -qiF "$1" "$tmp_credit" 2>/dev/null
}

if [ "$MODE" = "uncredited" ]; then
  echo "# Uncredited KB (never cited by any finding's helped_by → prune candidates)"
  echo "# advisory: not cited != useless (may be new / defensive / checklist); LLM decides."
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

# --- 3. Report: credited ranking + uncredited stats --------------------------
echo "# KB ROI — artifact → finding effectiveness loop"
echo
echo "Findings scanned: $n_findings; helped_by tokens: $n_with_credit"
echo
if [ "$n_with_credit" -eq 0 ]; then
  echo "⚠️  No finding has filled in helped_by yet."
  echo "    → When confirming a finding, fill the frontmatter helped_by: [Pattern - X, LL-NNN]"
  echo "    → Once these accumulate, this script can measure which KB actually work and which to prune."
else
  echo "## ✅ Credited KB (produced findings → keep/strengthen)"
  sort "$tmp_credit" | uniq -c | sort -rn | sed 's/^/  /'
  echo
fi
echo

# uncredited stats (how many of each type are never cited)
total_prune=0
echo "## ⚠️ Uncredited stats (size of the prune candidate pool)"
for kind in Pattern Playbook Checklist; do
  tot=0; un=0
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    tot=$((tot+1)); is_credited "$id" || un=$((un+1))
  done < <(inventory "$kind -")
  total_prune=$((total_prune+un))
  echo "  $kind: $un / $tot never cited by any finding"
done
lltot=0; llun=0
while IFS= read -r id; do
  [ -z "$id" ] && continue
  lltot=$((lltot+1)); is_credited "$id" || llun=$((llun+1))
done < <(ll_ids)
total_prune=$((total_prune+llun))
echo "  LL: $llun / $lltot never cited by any finding"
echo
echo "→ Detailed list: bash automation/kb_roi.sh --uncredited [Pattern|Playbook|Checklist|LL]"
echo "→ uncredited != useless (new / defensive / checklist items don't directly produce findings); LLM decides before entropy-GC."
