#!/usr/bin/env bash
# handoff_secret_gate.sh — PreToolUse(Write) gate.
# When writing HANDOFF.md, scan the body for raw secrets (JWT / Bearer / private key).
# Exit 0 = allow, Exit 2 = block with a message.
#
# Override: BB_HANDOFF_OVERRIDE=1 (you confirmed this is illustrative text, not a real secret).

set -euo pipefail

INPUT=$(cat)

# Only HANDOFF.md writes.
FILE_PATH=$(printf '%s' "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" \
  2>/dev/null || true)
[[ "$FILE_PATH" != *HANDOFF.md ]] && exit 0

CONTENT=$(printf '%s' "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('content',''))" \
  2>/dev/null || true)

# Three high-precision patterns (to avoid false positives):
#   1. JWT: three base64url segments split by '.', first starting with eyJ
#   2. Bearer token: Authorization/Bearer followed by a 20+ char token
#   3. PEM private key block
HITS=$(printf '%s' "$CONTENT" | grep -cE \
  'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[Bb]earer [A-Za-z0-9._~+/-]{20,}|-----BEGIN [A-Z ]*(PRIVATE|RSA|EC) KEY-----' \
  2>/dev/null || true)
HITS=${HITS:-0}

if [[ "$HITS" -gt 0 ]]; then
  cat >&2 <<'EOF'
[handoff_secret_gate] ⛔ HANDOFF.md contains a high-entropy string (looks like a JWT /
Bearer token / private key). Write blocked.

Why: HANDOFF.md is cross-session visible text; raw secrets do not belong in it.

→ Instead: use the bb-context-handoff skill.
  1. Load bb-context-handoff
  2. Produce a handoff that carries only codenames (e.g. a finding ID / surface label);
     the raw value stays in the Finding's evidence field.
  3. The next session uses the codename to fetch the value from the Finding file.

If this really is illustrative text (not a real secret): set BB_HANDOFF_OVERRIDE=1 and retry.
EOF
  [[ "${BB_HANDOFF_OVERRIDE:-}" == "1" ]] && exit 0
  exit 2
fi

# Second layer: an In-Progress block with no finding ID ([A-Z]{2,}-[0-9]+) -> warn (no block).
if printf '%s' "$CONTENT" | grep -q 'BEGIN_INPROGRESS'; then
  HAS_IDS=$(printf '%s' "$CONTENT" | grep -cE '[A-Z]{2,}-[0-9]+' 2>/dev/null || true)
  HAS_IDS=${HAS_IDS:-0}
  if [[ "$HAS_IDS" -eq 0 ]]; then
    cat >&2 <<'EOF'
[handoff_secret_gate] ⚠️  HANDOFF.md has an In-Progress block but no finding ID.
  If this session has a confirmed finding, reference it by its ASG finding ID rather than
  descriptive text. bb-context-handoff emits the correct codename format. (Warning only.)
EOF
  fi
fi

exit 0
