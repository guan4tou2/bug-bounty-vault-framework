#!/usr/bin/env bash
# check_poc_controls.sh — find PoCs that print a verdict but have no control group / validity gate.
#
# Why this exists:
#   A measurement tool that is itself broken is easy to mistake for a finding. Typical shapes:
#     1. a rotating static buffer overwrites the source, so every case in one group fails with ENOENT
#        and gets read as "this input is not supported"
#     2. a probe measures only one thing, so "the label was not attached" and "attached but not inherited"
#        look identical
#     3. the test and the reference run produce identical output, so neither is readable
#     4. a read-back uses the same constant as the write, so it is self-consistent but not correct
#     5. a guessed constant differs from the real one defined in a private header; the setter returns 0
#        but sets nothing
#     6. a probe reports many "HITs", all produced by a cached, older binary
#   Writing the lesson down does not help: prose is not in front of you at the moment you make the mistake.
#   So the rule is enforced here instead.
#
# Rule:
#   A "measuring file" is one that prints a verdict marker (✅ 🔴 ⚠️ PASS FAIL DENY VULNERABLE).
#   A measuring file must contain at least ONE validity marker: a control group, calibration, a
#   positive/negative control, a build/version stamp (BUILD_TAG), or an explicit statement that a
#   negative result is unreadable. Inventory/build/cleanup tools print no verdicts and use the escape hatch.
#
# Escape hatch (explicit and auditable): put one line anywhere in the file
#       no-control-needed: <reason>
#   e.g. `# no-control-needed: pure inventory, makes no judgement`
#   Without a hatch people end up ignoring the whole warning; a hatch that is too wide makes the gate meaningless.
#
# This script's own control (adopt its output only after this passes):
#   python3 -m pytest tests/test_poc_controls_gate.py     (synthetic fixtures)
#   Do NOT point the control at a real file: a control that points at a file that will eventually be fixed is
#   no control at all. A green run on a real corpus only means the corpus is clean, not that the matcher is alive.
#
# Usage:
#   bash automation/check_poc_controls.sh            # scan $WORKSHOP_ROOT; exit 1 on any hit
#   bash automation/check_poc_controls.sh <target>   # one target only ($WORKSHOP_ROOT/<target>)
#   WORKSHOP_ROOT=/some/dir bash automation/check_poc_controls.sh   # override the scan root (tests use this)

set -uo pipefail
RED=$'\033[0;31m'; YEL=$'\033[0;33m'; GRN=$'\033[0;32m'; NC=$'\033[0m'

TARGET=""
for a in "$@"; do
  case "$a" in
    --strict) ;;   # kept for compatibility: the default already fails on a hit
    *) TARGET="$a" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# An explicit WORKSHOP_ROOT wins (tests inject a synthetic workshop); otherwise ask the layout script.
if [ -z "${WORKSHOP_ROOT:-}" ]; then
  eval "$(bash "$SCRIPT_DIR/workspace_layout.sh" --shell 2>/dev/null)"
fi
if [ -z "${WORKSHOP_ROOT:-}" ] || [ ! -d "$WORKSHOP_ROOT" ]; then
  echo "${YEL}SKIP${NC} workshop not found (${WORKSHOP_ROOT:-unset})"; exit 0
fi

SCAN="$WORKSHOP_ROOT"
[ -n "$TARGET" ] && SCAN="$WORKSHOP_ROOT/$TARGET"
[ -d "$SCAN" ] || { echo "${YEL}SKIP${NC} not found: $SCAN"; exit 0; }

# ASCII verdict words need a boundary on BOTH sides, where "boundary" includes start/end of line:
#   `PASSWORD = "x"` is not PASS and `b"DECRYPTION_FAILED"` is not FAIL, but a bare `echo PASS` at the end of a
#   line IS a verdict. (Requiring a non-letter character on each side would miss the most common shell shape.)
VERDICT_RE='🔴|✅|⚠️|(^|[^A-Za-z_])(PASS(ED)?|FAIL(ED)?|DENY|VULNERABLE)([^A-Za-z_]|$)'
# "Says the negative result is unreadable" counts the same as "has a control group": both let a reader tell
# "really nothing there" from "the tool could not see".
# Keep these phrases SPECIFIC. Bare words such as `oracle`, `sanity` or `validity` also appear in unrelated text
# (a product name, "invalidity"), and every false "this file has a control" silently weakens the gate.
CONTROL_RE='control group|control case|positive control|negative control|calibrat|sanity check|unreadable|BUILD_TAG|validity (check|gate)|test oracle|oracle check|one-way test|cannot conclude|only a candidate'
EXEMPT_RE='no-control-needed:'

measured=0; controlled=0; exempt=0
declare -a BAD=()

while IFS= read -r f; do
  grep -qE "$VERDICT_RE" "$f" 2>/dev/null || continue
  if grep -qiE "$EXEMPT_RE" "$f" 2>/dev/null; then exempt=$((exempt+1)); continue; fi
  measured=$((measured+1))
  if grep -qiE "$CONTROL_RE" "$f" 2>/dev/null; then
    controlled=$((controlled+1))
  else
    BAD+=("${f#"$WORKSHOP_ROOT"/}")
  fi
done < <(find "$SCAN" -type f \( -name '*.c' -o -name '*.sh' -o -name '*.py' -o -name '*.m' \) \
          -not -path '*/node_modules/*' -not -path '*/.git/*' \
          -not -path '*/squashfs-root*' -not -path '*rootfs/*' \
          -not -path '*_extracted/*' -not -path '*/fw_batch/*' \
          -not -path '*/.venv*/*' -not -path '*/site-packages/*' 2>/dev/null | sort)
# ↑ Unpacked firmware and third-party trees are not measuring tools you wrote. Leaving them in makes the check
#   mostly noise, and a check that is mostly noise gets ignored — including on the day it catches something real.

echo "PoC validity gate: ${measured} measuring file(s) (plus ${exempt} explicitly exempt), ${controlled} with a control"

if [ "${#BAD[@]}" -gt 0 ]; then
  echo "${RED}🔴 These files print a verdict but contain no control group / calibration / version stamp:${NC}"
  for b in "${BAD[@]}"; do echo "    - $b"; done
  echo "   => their NEGATIVE results cannot be trusted: \"really nothing\" is indistinguishable from \"the tool is broken\"."
  echo "   Fix, one of:"
  echo "     (a) add a control (one case known to hold + one known not to), or a version stamp proving the intended build ran"
  echo "     (b) if it never makes a judgement (inventory / build / cleanup), add one line:"
  echo "         no-control-needed: <reason>"
fi

# Self-discrimination check: a degenerate ratio means the matcher itself may be broken.
if [ "$measured" -ge 5 ]; then
  if [ "$controlled" -eq 0 ] || [ "$controlled" -eq "$measured" ]; then
    echo "${YEL}⚠️  ratio ${controlled}/${measured}: the corpus has no counter-example, so this green run"
    echo "    does NOT prove the matcher is alive. Two causes look identical:"
    echo "      (a) every measuring file really does have a control now"
    echo "      (b) CONTROL_RE was widened to match everything, or VERDICT_RE matches nothing"
    echo "    To tell them apart: python3 -m pytest tests/test_poc_controls_gate.py${NC}"
  fi
fi

if [ "${#BAD[@]}" -eq 0 ]; then echo "${GRN}PASS${NC}"; exit 0; fi

# Fails by default; it is NOT advisory. A runner that prints `PASS` while swallowing every hit is visible,
# decision-free and signal-free — the dead-gate shape this script exists to prevent. Failing by default is
# acceptable because the escape hatch (no-control-needed:) is cheap and auditable: either add a control or
# write the reason down. Both make the state visible.
exit 1
