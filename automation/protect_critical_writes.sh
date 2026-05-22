#!/usr/bin/env bash
# PreToolUse hook: block full-file Write on critical workflow files.
# Exit 2 blocks the tool use. Targeted Edit operations stay allowed.

set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""' 2>/dev/null)

[[ "$TOOL" != "Write" ]] && exit 0

PROTECTED=(
  "AGENTS.md"
  "CLAUDE.md"
  "CODEX.md"
  "GEMINI.md"
  "STRUCTURE.md"
  "VAULT_QUICK.md"
  "RECON_DB.md"
  "FINDINGS_QUICK_REF.md"
  "SCOPE.md"
  "HANDOFF.md"
)

for pattern in "${PROTECTED[@]}"; do
  if [[ "$FILE_PATH" == *"$pattern" ]]; then
    echo "BLOCKED: Write (full overwrite) on '$FILE_PATH' is protected." >&2
    echo "Use targeted Edit instead, or update this protection list intentionally." >&2
    exit 2
  fi
done

exit 0
