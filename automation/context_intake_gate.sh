#!/usr/bin/env bash
# PreToolUse(Read) hook — don't read old deliverables into context during hunting phases.
#
# Why
# ---
# "the model got dumber" is usually not stale knowledge — it's contradictory old files in
# the same window:
#   * HANDOFF prose says "0 submitted" while the ledger says 29 -> the model follows prose
#   * a quick-ref count disagrees with the ASG count -> findings look like they don't exist
#   * 25 old Finding files used as writing examples -> reports grow longer and denser
# A repo sitting on disk costs nothing; it only harms once Read pulls it into context.
#
# So this blocks not "large files" (that is big_read_gate's job) but phase-wrong files:
#   recon / map / exploit phase -> block Findings/, Submissions/, Attempts/, Attack Chains/
#   report / foothold phase     -> allow everything (writing a report needs Findings + examples)
#
# The override is deliberately loud and auditable — without one, people learn to ignore the
# whole warning:
#   BB_CONTEXT_OK=1   I really need this read (logged to .state/context_gate_exempt.log)
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
set -uo pipefail

ROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Read" ]] && exit 0

[[ "${BB_CONTEXT_OK:-0}" == "1" ]] && {
  mkdir -p "$ROOT/.state"
  echo "$(date -u +%FT%TZ) BB_CONTEXT_OK read: $(echo "$INPUT" | jq -r '.tool_input.file_path // ""')" \
    >> "$ROOT/.state/context_gate_exempt.log" 2>/dev/null || true
  exit 0
}

FP=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""' 2>/dev/null)
[[ -z "$FP" ]] && exit 0

# Only target deliverables inside the vault; never touch anything else.
case "$FP" in
  *"01 - Targets/"*) ;;
  *) exit 0 ;;
esac

REL="${FP#*01 - Targets/}"
TARGET="${REL%%/*}"
REST="${REL#*/}"
[[ -z "$TARGET" || "$TARGET" == "$REL" ]] && exit 0

# Phase decides. No phase (no genesis / asg broken) -> allow. A gate that blocks when it
# cannot read state will block at the worst possible moment.
PHASE=$(cd "$ROOT" && python3 automation/asg.py phase "$TARGET" 2>/dev/null \
        | sed -n 's/.*"phase"[: ]*"\([a-z-]*\)".*/\1/p' | head -1)
[[ -z "$PHASE" ]] && exit 0
case "$PHASE" in
  report|foothold) exit 0 ;;   # writing a report needs Findings + examples
esac

# Deliverables that should not enter context in this phase
case "$REST" in
  Findings/*|Submissions/*|Attempts/*|"Attack Chains/"*)
    KIND="${REST%%/*}" ;;
  *) exit 0 ;;
esac

cat >&2 <<EOF
⛔ context intake — current phase is \`$PHASE\`; don't read $KIND/ into context.

  wanted: $FP

  Old deliverables in context during this phase contradict the ledger, and the model
  follows the prose, not the ledger (e.g. HANDOFF says "0 submitted" while the ledger
  disagrees; old Findings used as examples make the report grow).

  Use machine output instead:
    python3 automation/asg.py status $TARGET        the only source for numbers
    python3 automation/asg.py project $TARGET       next_work / untested surfaces
    bash automation/vault_precheck.sh $TARGET "<keyword>"   dedup, don't grep Findings/

  Really need to read it:
    retry after BB_CONTEXT_OK=1 (logged to .state/context_gate_exempt.log)
    or  python3 automation/asg.py advance-phase $TARGET report
EOF
exit 2
