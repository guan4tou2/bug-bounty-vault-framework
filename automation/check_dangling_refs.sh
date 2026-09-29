#!/usr/bin/env bash
# check_dangling_refs.sh — every automation script named by a skill, agent, or rule
# document must exist.
#
# Why this needs its own check: skills and agents are INSTRUCTIONS THE MODEL FOLLOWS.
# When an instruction names a script that isn't there, the model gets
# "command not found" and then usually invents a substitute — which is exactly the
# improvisation the harness exists to prevent. Nothing else covers this:
#   S1-S4 validate skill frontmatter and counts, never the tools named in the body
#   check_orphan_scripts.sh checks the REVERSE (a script nobody calls)
#   the META block checks golden-rules' own enforcers, not skill/agent bodies
#
# Section 2 covers automation scripts calling each other. That is the class most
# likely to break during a refactor, and the most likely to break SILENTLY: calls
# are routinely written as `bash "$SCRIPT_DIR/x.sh" ... || true`, `2>/dev/null`, or
# behind `[ -x ... ]`, so an archived script degrades with no message at all.
#
# Exemptions:
#   - lines that read as historical notes (struck through, or saying "archived"/"removed")
#   - a `dangling-ref-exempt` marker within the 3 preceding lines, for a call that is
#     deliberately dead (e.g. an `[ -x ]`-guarded branch whose else-branch is a valid
#     fallback). It must sit next to the call so both land in the same diff for review.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || exit 1

SOURCES=(.claude/skills .claude/agents CLAUDE.md AGENTS.md golden-rules.md STRUCTURE.md)
bad=0

echo "-- dangling automation refs (skill/agent/rules -> missing script) --"
for src in "${SOURCES[@]}"; do
  [ -e "$src" ] || continue
  while IFS=: read -r f ln rest; do
    [ -n "${rest:-}" ] || continue
    case "$rest" in
      *archived*|*removed*|*retired*|*"not shipped"*|*~~*) continue ;;
    esac
    for ref in $(printf '%s' "$rest" | grep -oE 'automation/[A-Za-z0-9_/.-]+\.(sh|py)' | sort -u); do
      case "$ref" in automation/_archive/*) continue ;; esac
      if [ ! -f "$ref" ]; then
        echo "  [X] $f:$ln -> $ref"
        bad=$((bad+1))
      fi
    done
  done < <(grep -rn -oE '.*automation/[A-Za-z0-9_/.-]+\.(sh|py).*' "$src" 2>/dev/null)
done
[ "$bad" = 0 ] && echo "  OK - no dangling references"

echo ""
echo "-- section 2: automation scripts calling each other --"
sec2=0
while IFS= read -r line; do
  f="${line%%:*}"; rest="${line#*:}"; ln="${rest%%:*}"; body="${rest#*:}"
  case "$(printf '%s' "$body" | sed 's/^[[:space:]]*//')" in '#'*) continue ;; esac
  case "$body" in *archived*|*removed*|*retired*|*"not shipped"*) continue ;; esac
  prev=$(sed -n "$(( ln > 3 ? ln-3 : 1 )),$((ln))p" "$f" 2>/dev/null)
  case "$prev" in *dangling-ref-exempt*) continue ;; esac
  for ref in $(printf '%s' "$body" \
      | grep -oE '(automation/|\$SCRIPT_DIR/|\$AUTOMATION_ROOT/)[A-Za-z0-9_.-]+\.(sh|py)' \
      | sed -E 's#^\$(SCRIPT_DIR|AUTOMATION_ROOT)/#automation/#' | sort -u); do
    case "$ref" in automation/_archive/*) continue ;; esac
    if [ ! -f "$ref" ]; then
      echo "  [X] $f:$ln -> $ref"
      sec2=$((sec2+1))
    fi
  done
done < <(grep -rnE '(bash|sh|python3|exec) +"?(\$SCRIPT_DIR|\$AUTOMATION_ROOT|automation)/' automation/*.sh automation/*.py 2>/dev/null)
[ "$sec2" = 0 ] && echo "  OK - no dangling calls"
bad=$((bad+sec2))

if [ "$bad" = 0 ]; then
  echo ""
  echo "  OK - all references resolve"
  exit 0
fi
echo ""
echo "  $bad reference(s) point at a missing script. Two valid fixes:"
echo "    a) the capability has a successor -> repoint it"
echo "    b) the capability is gone -> delete the step, or rewrite it as a historical note"
echo "  Do not leave it: a model reading a missing command will invent a replacement."
exit 1
