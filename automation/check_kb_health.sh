#!/usr/bin/env bash
# KB health report (KNOWLEDGE loop) — keeps a large KB (90+ patterns, 160+ lessons)
# from silently rotting: lessons-index completeness, orphan notes, near-duplicate
# titles to review for merge. Advisory (heuristic) — LLM judges what to merge.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KB="$ROOT/09 - Knowledge Base"
issues=0

echo "── KB health ──"
echo "   Patterns: $(ls "$KB/Pattern - "*.md 2>/dev/null | wc -l | tr -d ' ') · Lessons: $(ls "$KB/Lessons/"LL-*.md 2>/dev/null | wc -l | tr -d ' ') · Playbooks: $(ls "$KB/Playbook - "*.md 2>/dev/null | wc -l | tr -d ' ') · Checklists: $(ls "$KB/Checklist - "*.md 2>/dev/null | wc -l | tr -d ' ')"
echo ""

# 1 — lessons-index completeness: every LL-*.md must be linked from Lessons Learned.md
# (the index drives lesson recall; an unlisted lesson is effectively invisible)
idx="$KB/Lessons Learned.md"
missing_idx=0
if [ -f "$idx" ]; then
  echo "Lessons NOT listed in 'Lessons Learned.md' (unsearchable/orphan):"
  for f in "$KB/Lessons/"LL-*.md; do
    [ -f "$f" ] || continue
    id=$(basename "$f" | grep -oE '^LL-[0-9]+')
    [ -z "$id" ] && continue
    grep -q "$id" "$idx" || { echo "  - $id"; missing_idx=$((missing_idx+1)); }
  done
  [ "$missing_idx" = 0 ] && echo "  (none — index complete)"
  [ "$missing_idx" -gt 0 ] && issues=$((issues+1))
else
  echo "  [warn] Lessons Learned.md index not found"
fi
echo ""

# 2 — orphan patterns: Pattern files never [[wiki-linked]] from any other KB file
echo "Orphan Patterns (no [[backlink]] anywhere in KB — consider linking or retiring):"
orphans=0
all=$(grep -rhoE "\[\[[^]]+\]\]" "$KB" 2>/dev/null | tr 'A-Z' 'a-z')
for p in "$KB/Pattern - "*.md; do
  [ -f "$p" ] || continue
  stem=$(basename "$p" .md | tr 'A-Z' 'a-z')
  case "$all" in *"$stem"*) : ;; *) echo "  - $(basename "$p" .md)"; orphans=$((orphans+1));; esac
done
[ "$orphans" = 0 ] && echo "  (none)"
[ "$orphans" -gt 0 ] && issues=$((issues+1))
echo ""

# 2b — patterns NOT registered in Pattern Index (distinct from orphan: a pattern
#      can have backlinks yet be missing from the index MOC, so check membership).
echo "Patterns missing from Pattern Index MOC:"
notidx=0
idx_file="$KB/Pattern Index.md"
if [ -f "$idx_file" ]; then
  indexed=$(grep -oE "\[\[Pattern - [^]]+\]\]" "$idx_file" | sed 's/\[\[Pattern - //;s/\]\]//' | sort -u)
  for p in "$KB/Pattern - "*.md; do
    [ -f "$p" ] || continue
    name=$(basename "$p" .md | sed 's/^Pattern - //')
    printf '%s\n' "$indexed" | grep -qxF "$name" || { echo "  - $name"; notidx=$((notidx+1)); }
  done
  [ "$notidx" = 0 ] && echo "  (none — index complete)"
  [ "$notidx" -gt 0 ] && issues=$((issues+1))
else
  echo "  [warn] Pattern Index.md not found"
fi
echo ""

# 3 — near-duplicate pattern titles (heuristic: same first 2 significant words)
echo "Near-duplicate Pattern titles (review for merge — heuristic):"
dups=$(for p in "$KB/Pattern - "*.md; do
  [ -f "$p" ] || continue
  basename "$p" .md | sed -E 's/^Pattern - //' \
    | awk '{ for(i=1;i<=NF && n<2;i++){ w=tolower($i); if(length(w)>=4){key=key (key?"-":"") w; n++} } print key"\t"$0; key=""; n=0 }'
done | sort | awk -F'\t' '{ if($1==prevk){ if(!shown[prevk]++) print "  ["$1"] "prev; print "  ["$1"] "$2 } prevk=$1; prev=$2 }')
if [ -n "$dups" ]; then echo "$dups"; else echo "  (none)"; fi
echo ""

echo "── KB health: $issues category(ies) with items to review ──"
echo "Advisory only — fix index gaps; merge/retire patterns by judgment."
exit 0
