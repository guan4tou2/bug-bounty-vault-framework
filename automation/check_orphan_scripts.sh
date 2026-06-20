#!/usr/bin/env bash
# check_orphan_scripts.sh — tool-layer orphan detection (advisory).
#
# Skills + agents have invariants (S1-4, A1) forcing them to be wired into
# CLAUDE.md. The automation/ tool layer has NO such guard, so scripts can be
# built and then silently never invoked. This lists automation scripts with ZERO
# references anywhere — minus an allowlist of intentionally manual / one-time
# utilities (documented with reasons below).
#
# Advisory only (LLM judges): an orphan is either dead code to retire OR a tool
# to wire/document. Run at periodic maintenance.
#
# Usage: bash automation/check_orphan_scripts.sh
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)"
cd "$VAULT_ROOT" || exit 0

# Intentionally manual / one-time utilities, invoked by a human ad-hoc rather than
# by any script/skill/hook. The corpus below deliberately EXCLUDES automation/
# README.md (the bare index) so this check measures "used by a real consumer", not
# merely "listed". Genuine manual utils therefore land here, with a reason.
ALLOWLIST="
"

is_allowed() { printf '%s' "$ALLOWLIST" | grep -q "^$1|"; }
allow_reason() { printf '%s' "$ALLOWLIST" | grep "^$1|" | head -1 | cut -d'|' -f2; }

# Reference corpus: docs + every other script + skills/agents/hooks + KB + cron.
corpus=$( { cat CLAUDE.md AGENTS.md AGENTS_QUICK.md golden-rules.md STRUCTURE.md VAULT_QUICK.md 2>/dev/null
            cat automation/*.sh automation/*.py 2>/dev/null
            find .claude -type f \( -name '*.md' -o -name '*.json' \) -exec cat {} \; 2>/dev/null
            cat "09 - Knowledge Base/"*.md "10 - Meta/"*.md 2>/dev/null
            crontab -l 2>/dev/null
          } )

orphans=0; allowed=0; total=0
echo "── tool-layer orphan scan (automation/) ──"
for f in automation/*.sh automation/*.py; do
  [ -e "$f" ] || continue
  base=$(basename "$f")
  total=$((total+1))
  # references excluding this file's own definition lines
  hits=$(printf '%s' "$corpus" | grep -F "$base" | grep -vc "^#" || true)
  [ "$hits" -gt 0 ] && continue
  if is_allowed "$base"; then
    allowed=$((allowed+1))
    continue
  fi
  orphans=$((orphans+1))
  echo "  🔴 ORPHAN: $base — wire it (ref in a skill/doc/script) or retire it"
done

echo "  scanned $total · $orphans unexplained orphan(s) · $allowed allowlisted (intentional manual)"
[ "$orphans" -eq 0 ] && echo "  ✓ no unexplained orphan scripts"
exit 0
