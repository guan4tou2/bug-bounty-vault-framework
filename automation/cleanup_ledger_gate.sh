#!/usr/bin/env bash
# Stop hook — engagement cleanup ledger gate.
#
# At session end, warns if the current target is an engagement-profile
# target and has no cleanup ledger file, or the ledger status is still "open".
# Advisory (always exit 0), but the warning is loud.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGETS_DIR="$ROOT_DIR/01 - Targets"

# Determine active target from claim or CWD
target=""
if [[ -f "$ROOT_DIR/.state/active_claim.json" ]]; then
  target=$(python3 -c "import json; print(json.load(open('$ROOT_DIR/.state/active_claim.json')).get('scope',''))" 2>/dev/null || true)
fi
if [[ -z "$target" ]]; then
  case "$PWD" in
    *"01 - Targets/"*)
      target=$(echo "$PWD" | sed -E "s|.*01 - Targets/([^/]+).*|\1|")
      ;;
  esac
fi
[[ -z "$target" ]] && exit 0

# Check if this is an engagement-profile target
tdir="$TARGETS_DIR/$target"
[[ -d "$tdir" ]] || exit 0
ledger_file="$tdir/.state/asg-events.jsonl"
[[ -f "$ledger_file" ]] || exit 0

profile=$(python3 -c "
import json, sys
for line in open('$ledger_file'):
    line = line.strip()
    if not line: continue
    ev = json.loads(line)
    if ev.get('type') == 'genesis':
        print(ev.get('profile', ''))
        sys.exit(0)
" 2>/dev/null || true)

[[ "$profile" != "engagement" ]] && exit 0

# Engagement target — check for cleanup ledger
cleanup_file=""
for f in "$tdir"/Cleanup*Ledger*.md "$tdir"/cleanup*ledger*.md; do
  [[ -f "$f" ]] && cleanup_file="$f" && break
done

if [[ -z "$cleanup_file" ]]; then
  echo "" >&2
  echo "WARNING: ENGAGEMENT CLEANUP: '$target' is an engagement target but has NO cleanup ledger." >&2
  echo "   Create one from the template before ending the engagement." >&2
  echo "   Every implant/change in the client environment MUST be recorded before session ends." >&2
  echo "" >&2
  exit 0
fi

# Check status
status=$(grep -m1 'status:' "$cleanup_file" | sed 's/.*status:\s*//' | sed 's/\s*#.*//' | tr -d ' ' 2>/dev/null || echo "unknown")
if [[ "$status" == "open" ]]; then
  echo "" >&2
  echo "WARNING: ENGAGEMENT CLEANUP: '$target' cleanup ledger status is still 'open'." >&2
  echo "   File: $cleanup_file" >&2
  echo "   Before ending engagement, ensure all implants are removed and status is updated." >&2
  echo "" >&2
fi

exit 0
