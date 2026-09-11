#!/usr/bin/env bash
# check_shelfware.sh — template adoption telemetry (measures which templates nobody uses)
#
# check_orphan_scripts tracks "scripts" that are never referenced; this script
# tracks "templates" that are never instantiated.
# Each Template has a frontmatter marker (subpage:/type:/fileClass:); instances copy it.
# Counting how many instances exist = the template's real adoption rate. 0 instances =
# shelf-ware (the DAG template was once 0/124 — this exactly; measuring forward is
# cheaper than only discovering it after digging through 124 sessions).
#
# Advisory only (LLM decides whether 0 instances means "should retire" or "just
# created / seasonal").
#
# Usage: bash automation/check_shelfware.sh
# bash 3.2 compatible (macOS)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"

TPL_DIR="$VAULT_ROOT/07 - Templates"

echo "# Template adoption (instance count = real adoption rate; 0 = shelf-ware candidate)"
echo "# advisory: 0 instances != should delete (may be just created / seasonal); LLM decides."
echo

shelf=0
for tpl in "$TPL_DIR"/Template\ -\ *.md; do
  [ -f "$tpl" ] || continue
  name="$(basename "$tpl" .md)"
  # Pick the primary marker: prefer subpage > type > fileClass (subpage is most distinctive for target subpages)
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
    printf '  %-55s [no marker — cannot measure]\n' "$name"
    continue
  fi
  # Count instance files in the vault (excluding 07-Templates) that share the same marker
  count="$(grep -rl --include='*.md' -E "^${key}:[[:space:]\"]*${val}\"?[[:space:]]*$" "$VAULT_ROOT" 2>/dev/null \
            | grep -vF "/07 - Templates/" | wc -l | tr -d ' ')"
  flag=""
  if [ "$count" -eq 0 ]; then flag="  ⬅ shelf-ware (0 instances)"; shelf=$((shelf+1)); fi
  printf '  %-55s %s=%s  →  %s instances%s\n' "$name" "$key" "$val" "$count" "$flag"
done

echo
echo "Shelf-ware candidates (0 instances): $shelf"
[ "$shelf" -gt 0 ] && echo "→ Decide case by case: retire / simplify to lower friction / add a session-start nudge (like dag_gaps)"
exit 0
