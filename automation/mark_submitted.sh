#!/usr/bin/env bash
# mark_submitted.sh — after sending a batch, flip its state in one go.
#
# Why
# ---
# "remember to set status to submitted after sending" is a memory task, and memory tasks
# get missed. The cost is not cosmetic: a FORM still at status ready is treated as pending
# by the next batch's gates (check_report_bar / check_docx_package), so the same item gets
# packaged a second time.
#
# This does three things and prints what it did:
#   1. FORM frontmatter status -> submitted, plus a submitted_date
#   2. rename the sent docx folder to <name>-submitted (gates stop checking sent things)
#   3. log an event in the ASG ledger so the numbers have a source
#
# Usage:
#   bash automation/mark_submitted.sh <target> <FORM-id> [FORM-id ...]
#   bash automation/mark_submitted.sh <target> --batch <docx folder> <id ...>
set -uo pipefail

VAULT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-}"
shift || true

BATCH=""
if [ "${1:-}" = "--batch" ]; then BATCH="${2:-}"; shift 2; fi

if [ -z "$TARGET" ] || [ $# -eq 0 ]; then
  echo "usage: bash automation/mark_submitted.sh <target> [--batch <docx folder>] <FORM-id> ..." >&2
  exit 1
fi

FORMS="$VAULT/01 - Targets/$TARGET/Submissions/Forms"
[ -d "$FORMS" ] || { echo "not found: $FORMS" >&2; exit 1; }

TODAY="$(date +%Y-%m-%d)"
changed=0
missing=0

for id in "$@"; do
  f="$(find "$FORMS" -maxdepth 1 -name "FORM - $id*.md" | head -1)"
  if [ -z "$f" ]; then
    echo "WARN no FORM for $id"; missing=$((missing+1)); continue
  fi
  cur="$(grep -m1 '^status:' "$f" | sed 's/status: *//; s/"//g')"
  if [ "$cur" = "submitted" ]; then
    echo "   $id already submitted, skip"; continue
  fi
  # Only touch the first frontmatter status:, never the body (evidence may contain "status").
  python3 - "$f" "$TODAY" <<'PY'
import re, sys
p, today = sys.argv[1], sys.argv[2]
s = open(p, encoding='utf-8').read()
head, sep, body = s.partition('\n---\n')      # frontmatter ends at the first ---
head = re.sub(r'^status:.*$', 'status: "submitted"', head, count=1, flags=re.M)
if 'submitted_date:' not in head:
    head = head.rstrip('\n') + f'\nsubmitted_date: {today}'
open(p, 'w', encoding='utf-8').write(head + sep + body)
PY
  echo "OK $id  $cur -> submitted"
  changed=$((changed+1))
done

# Rename the sent batch folder — with "submitted" in the name the gates stop treating it as pending.
if [ -n "$BATCH" ] && [ -d "$FORMS/$BATCH" ]; then
  case "$BATCH" in
    *submitted*) echo "   $BATCH already marked submitted" ;;
    *) mv "$FORMS/$BATCH" "$FORMS/${BATCH%-docx}-submitted"
       echo "renamed $BATCH -> ${BATCH%-docx}-submitted" ;;
  esac
fi

if [ "$changed" -gt 0 ] && [ -f "$VAULT/automation/asg.py" ]; then
  python3 "$VAULT/automation/asg.py" log-event "$TARGET" submission_sent \
      --data "{\"ids\":\"$*\",\"date\":\"$TODAY\"}" >/dev/null 2>&1 || true
fi

echo
echo "-- $changed marked submitted, $missing not found --"
echo "   Not done yet: per your program's ROE, delete local un-redacted PII copies and confirm."
exit 0
