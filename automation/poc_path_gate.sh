#!/usr/bin/env bash
# PreToolUse(Bash) hook — BLOCKS (exit 2) writing a PoC / source / script file into an
# EPHEMERAL path (/tmp, /private/tmp, /var/folders, $TMPDIR, scratchpad) while a TARGET
# claim is held.
#
# Why (the chain behind fake verification): PoC lands in /tmp/poc.py -> session ends ->
# file is gone -> the finding's poc_ref is empty or points at a ghost -> next round the
# only "evidence" is memory saying "already verified". A PoC that vanishes is no PoC.
# A reproduction file that isn't in a durable, tracked path gets treated by the gate (and
# by the next session) as if it never existed.
#
# Scope: fires ONLY when a target claim is held — a non-underscore *.lock in
# active_sessions (shared scopes _meta/_kb/_automation start with _). So harness/meta work
# is unaffected; the discipline applies while hunting a target.
#
# Sanctioned locations that PASS: the session scratchpad (…/scratchpad/…), /tmp/claude,
# /private/tmp/claude (sandbox-writable throwaways), and pure DATA extensions
# (.bin .pcap .dat .json .csv .log .txt .out) even under /tmp.
#
# Durable PoC belongs in:  $WORKSHOP_ROOT/<target>/poc/   or   01 - Targets/<target>/poc/
#
# Per-command override (loud, stays in the command):  BB_ALLOW_TMP=1 <cmd>
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
set -uo pipefail

INPUT=$(cat)
[[ "$(printf %s "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)" != "Bash" ]] && exit 0
CMD=$(printf %s "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# override
if [[ "${BB_ALLOW_TMP:-0}" == "1" ]] || printf %s "$CMD" | grep -q 'BB_ALLOW_TMP=1'; then
  exit 0
fi

ROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
ACTIVE="$ROOT/automation/active_sessions"

# target claim held? — any *.lock whose name does not start with '_'
claim_held=0
if [[ -d "$ACTIVE" ]]; then
  for lock in "$ACTIVE"/*.lock; do
    [[ -e "$lock" ]] || continue
    base="$(basename "$lock")"
    [[ "$base" == _* ]] && continue
    claim_held=1; break
  done
fi
[[ "$claim_held" -eq 0 ]] && exit 0

# Only care when the command actually WRITES (redirect / tee / cp / mv / heredoc / editors).
writes=0
printf %s "$CMD" | grep -qE '(>>?|[[:space:]]tee[[:space:]]|[[:space:]](cp|mv|install)[[:space:]]|<<[[:space:]]*['"'"'"]?EOF|cat[[:space:]]*>)' && writes=1
[[ "$writes" -eq 0 ]] && exit 0

# ephemeral code path? (exclude sanctioned scratchpad / claude throwaways / data exts)
HIT=$(printf %s "$CMD" | grep -oE '((/private)?/tmp|/var/folders|\$TMPDIR)[^[:space:]"'"'"';|&)]*\.(py|sh|bash|c|cc|cpp|cxx|h|hpp|rb|go|pl|js|ts|php|ps1|rs|java|md)' \
      | grep -vE '/scratchpad/|/tmp/claude|/private/tmp/claude' | head -1 || true)
[[ -z "$HIT" ]] && exit 0

WORKSHOP="${WORKSHOP_ROOT:-}"
if [[ -z "$WORKSHOP" ]] && [[ -x "$ROOT/automation/workspace_layout.sh" ]]; then
  eval "$(bash "$ROOT/automation/workspace_layout.sh" --shell 2>/dev/null || true)"
  WORKSHOP="${WORKSHOP_ROOT:-}"
fi

{
  echo "⛔ POC-PATH GATE: you are writing a script/source file to an ephemeral path while"
  echo "   holding a target claim."
  echo ""
  echo "  matched: $HIT"
  echo ""
  echo "Files in /tmp, \$TMPDIR, /var/folders vanish at session end — the finding's poc_ref"
  echo "then goes empty or points at a ghost, and the next round can only say from memory"
  echo "'already verified'. That is the start of the fake-verification chain."
  echo ""
  echo "A probe not yet tied to a Finding goes in the inbox (harvested to an owner at close):"
  if [[ -n "$WORKSHOP" ]]; then
    echo "  $WORKSHOP/<target>/poc/_inbox/"
  else
    echo "  \$WORKSHOP_ROOT/<target>/poc/_inbox/"
  fi
  echo "  first three lines: # target: <t>  /  # finding: <ID|untagged>  /  # purpose: <one line>"
  echo "A re-runnable PoC for an existing Finding -> 01 - Targets/<target>/poc/<ID>/"
  echo ""
  echo "One-off data (.bin/.pcap/.dat/.json/.csv/.log) in /tmp is fine; scratchpad passes too."
  echo "Really want /tmp (throwaway): prefix the command with  BB_ALLOW_TMP=1"
} >&2
exit 2
