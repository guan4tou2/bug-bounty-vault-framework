#!/usr/bin/env bash
# Pattern coverage report (HUNTING loop) — which KB Patterns lack a bbflow
# hunter / nuclei template, so the manual "KB pattern -> detection" work becomes
# a tracked backlog instead of ad-hoc.
#
# HEURISTIC: matches a Pattern's key term against hunter filenames + template ids
# by keyword overlap. A miss is a CANDIDATE for review, not proof of no coverage —
# LLM judgment decides (mechanical detects, LLM judges). Some patterns are
# methodology, not GET-detectable, and correctly have no hunter.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KB="$ROOT/09 - Knowledge Base"
BBFLOW="${BBFLOW_DIR:-$ROOT/../bbflow}"

if [ ! -d "$BBFLOW/hunters" ]; then
  echo "[skip] bbflow not found at $BBFLOW (set BBFLOW_DIR). Pattern coverage needs the tool repo."
  exit 0
fi

# corpus of detection names (hunter filenames + template ids/filenames), lowercased
corpus=$( { ls "$BBFLOW/hunters/" 2>/dev/null; ls "$BBFLOW/nuclei-templates/bb-recon/" 2>/dev/null; } \
  | sed -E 's/\.(sh|yaml)$//; s/^hunt-//' | tr 'A-Z' 'a-z' | tr '\n' ' ')

# stopwords that carry no matching signal
stop=" the a an of to in for and or via with on is no not by - "

total=0; covered=0; missing=0
echo "── Pattern coverage vs bbflow hunters/templates (heuristic) ──"
echo "   bbflow: $(ls "$BBFLOW/hunters/"hunt-*.sh 2>/dev/null | wc -l | tr -d ' ') hunters, $(ls "$BBFLOW/nuclei-templates/bb-recon/"*.yaml 2>/dev/null | wc -l | tr -d ' ') templates"
echo ""
echo "Patterns with NO keyword hit in any hunter/template (review candidates):"

while IFS= read -r p; do
  [ -f "$p" ] || continue
  total=$((total+1))
  name=$(basename "$p" .md | sed -E 's/^Pattern - //')
  # significant tokens from the pattern name (>=4 chars, not stopwords)
  hit=0
  for tok in $(echo "$name" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' ' '); do
    [ "${#tok}" -ge 4 ] || continue
    case "$stop" in *" $tok "*) continue;; esac
    case "$corpus" in *"$tok"*) hit=1; break;; esac
  done
  if [ "$hit" = 1 ]; then covered=$((covered+1)); else
    missing=$((missing+1)); echo "  - $name"
  fi
done < <(find "$KB" -maxdepth 1 -name "Pattern - *.md" | sort)

echo ""
echo "── $covered/$total patterns have a likely hunter/template; $missing review candidates ──"
echo "Next: for a real GET-detectable exposure pattern with no coverage, add a"
echo "catch-all-aware template to guan4tou2/bbflow (or run pull_nuclei_gaps.sh for the"
echo "VPS-side fixed-path detector). Methodology-only patterns need no hunter."
