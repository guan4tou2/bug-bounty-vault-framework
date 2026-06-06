#!/usr/bin/env bash
# check_disclosed_preread.sh — gate enforcement for Checklist - Disclosed Findings Pre-Read Gate
#
# Usage:
#   bash automation/check_disclosed_preread.sh <target>
#
# Exit codes:
#   0 — evidence file exists + has status: pre_read_complete + non-empty sources
#   1 — missing or incomplete (caller should block lifecycle progression)
#   2 — usage error
#
# Where the file lives:
#   $WORKSHOP_ROOT/<target>/disclosed_pre_read.md
#
# Why this exists:
#   The Pre-Read Gate is the FIRST gate in candidate lifecycle. Without a
#   verifiable evidence file, "I read it" claims can't be checked, and
#   competition / prior-disclosure dups slip through. This is the simplest
#   possible enforcement: a file with specific frontmatter must exist.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
eval "$("$SCRIPT_DIR/workspace_layout.sh" --shell)" 2>/dev/null || {
  echo "⛔ workspace_layout.sh failed" >&2
  exit 2
}

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: bash automation/check_disclosed_preread.sh <target>" >&2
  exit 2
fi

EVIDENCE="$WORKSHOP_ROOT/$TARGET/disclosed_pre_read.md"

if [ ! -f "$EVIDENCE" ]; then
  cat >&2 <<EOF
⛔ $TARGET: Disclosed Pre-Read Gate FAILED

Missing evidence file: $EVIDENCE

Create it per template in:
  09 - Knowledge Base/Checklist - Disclosed Findings Pre-Read Gate.md §4b

Quick template:
  mkdir -p "$WORKSHOP_ROOT/$TARGET"
  cat > "$EVIDENCE" << 'TMPL'
---
type: pre-read-evidence
target: $TARGET
read_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
sources:
  - target_page: 01 - Targets/$TARGET/Target - $TARGET.md
  - external_disclosed: N/A — no public disclosed section
known_findings_count: 0
status: pre_read_complete
---

## Already-Reported Summary
- (none / list known findings)
TMPL
EOF
  exit 1
fi

# Check required frontmatter fields
if ! grep -q "^type: pre-read-evidence" "$EVIDENCE"; then
  echo "⛔ $TARGET: $EVIDENCE missing \`type: pre-read-evidence\` frontmatter" >&2
  exit 1
fi
if ! grep -q "^status: pre_read_complete" "$EVIDENCE"; then
  echo "⛔ $TARGET: $EVIDENCE not marked \`status: pre_read_complete\` (still draft?)" >&2
  exit 1
fi
if ! grep -qE "^  - (external_disclosed|target_page):" "$EVIDENCE"; then
  echo "⛔ $TARGET: $EVIDENCE has empty \`sources:\` list" >&2
  exit 1
fi

COUNT="$(grep -c "^- " "$EVIDENCE" 2>/dev/null || echo 0)"
READ_AT="$(grep -E "^read_at:" "$EVIDENCE" | head -1 | cut -d: -f2- | tr -d ' ')"

echo "✅ $TARGET: pre_read_complete (read_at=$READ_AT, $COUNT items)"
exit 0
