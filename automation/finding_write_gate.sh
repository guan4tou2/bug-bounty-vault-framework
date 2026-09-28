#!/usr/bin/env bash
# PostToolUse(Write|Edit) hook — ensures findings are registered in the ledger.
#
# When a file matching `Findings/Finding - *.md` is written, checks that a
# corresponding `finding` event exists in the target's ledger. If not, warns
# (does not block — PostToolUse can't block, but the warning is visible).
#
# This enforces: create_finding.sh → ledger event → file creation.
# Writing a Finding file without the ledger event means it bypassed the
# intake workflow (dedup hints, ledger registration, etc.).
#
# Exit 0 always (PostToolUse hooks are advisory).
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Write" && "$TOOL" != "Edit" ]] && exit 0

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""' 2>/dev/null)
[[ -z "$FILE_PATH" ]] && exit 0

# Only care about Finding files
if ! echo "$FILE_PATH" | grep -qE 'Findings/Finding - [A-Z]+-[0-9]+'; then
  exit 0
fi

# Extract finding ID from filename
FINDING_ID=$(echo "$FILE_PATH" | grep -oE '[A-Z]+-[0-9]+' | head -1)
[[ -z "$FINDING_ID" ]] && exit 0

# Extract target from path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="${VAULT_ROOT:-$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null | sed -n "s/^VAULT_ROOT='\(.*\)'\$/\1/p")}"
[[ -z "$VAULT_ROOT" ]] && exit 0

TARGETS_DIR="$VAULT_ROOT/01 - Targets"
if [[ "$FILE_PATH" == "$TARGETS_DIR/"* ]]; then
  rel="${FILE_PATH#$TARGETS_DIR/}"
  TARGET="${rel%%/*}"
else
  exit 0
fi

[[ -z "$TARGET" ]] && exit 0

# Check if finding is registered in ledger
LEDGER="$TARGETS_DIR/$TARGET/.state/asg-events.jsonl"
if [[ ! -f "$LEDGER" ]]; then
  echo "⚠️  finding_write_gate: $FINDING_ID written but target has no ledger. Use create_finding.sh." >&2
  exit 0
fi

if ! grep -q "\"finding_id\"[[:space:]]*:[[:space:]]*\"$FINDING_ID\"" "$LEDGER" 2>/dev/null; then
  echo "⚠️  finding_write_gate: $FINDING_ID written but no matching finding event in ledger." >&2
  echo "   Use create_finding.sh (auto-writes ledger)." >&2
  echo "   Or add manually:python3 automation/asg.py record-finding $TARGET $FINDING_ID" >&2
  exit 0
fi

exit 0
