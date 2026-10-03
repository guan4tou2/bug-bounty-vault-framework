#!/usr/bin/env bash
# PreToolUse(Bash) hook — BLOCKS (exit 2) `git add -A` / `git add --all` / `git add .`
#
# Why
# ---
# The rule "never git add -A, stage explicit paths only" is always-loaded, yet it still
# gets violated — because the decision ("which form of git add") happens at the moment of
# acting, not when the rule is being read. That is the LL-317 shape: a prose rule is
# invisible at the instant it is broken. Only a hook is present at that instant.
#
# This vault is a single working tree shared across sessions/targets: at any moment other
# in-flight edits are sitting uncommitted. `git add -A` / `.` stages them too, so the
# commit silently mixes in work that is not yours (and may carry lint violations from a
# half-finished change elsewhere).
#
# Scope (deliberately narrow): blocks only the three "stage everything" forms. Allows
# `git add <explicit-path>`, `git add -p`, `git add -u <path>`, `git reset`. `-A`/`--all`
# is blocked even with a subdir argument, because `git add -A <subdir>` still sweeps in
# untracked files under that subdir.
#
# Loud override: put  BB_ALLOW_GIT_ADD_ALL=1  in the command.
set -uo pipefail

INPUT=$(cat 2>/dev/null)
[[ "$(printf %s "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)" != "Bash" ]] && exit 0
CMD=$(printf %s "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# override
[[ -n "${BB_ALLOW_GIT_ADD_ALL:-}" ]] && exit 0
printf %s "$CMD" | grep -q 'BB_ALLOW_GIT_ADD_ALL=1' && exit 0

# Pull out each `git add …` run (commands may be && chained). Only judge the add subcommand.
# Fires when the add args contain -A / --all / a standalone .
hit=""
while IFS= read -r seg; do
  args="${seg#*add}"
  if printf %s "$args" | grep -qE '(^|[[:space:]])(-A|--all)([[:space:]]|$)'; then
    hit="$seg"; break
  fi
  if printf %s "$args" | grep -qE '(^|[[:space:]])\.([[:space:]]|$)'; then
    hit="$seg"; break
  fi
done < <(printf %s "$CMD" | grep -oE 'git[[:space:]]+add[^&|;]*')

[[ -z "$hit" ]] && exit 0

cat >&2 <<EOF
⛔ git_add_gate: detected a "stage everything" git add.

   matched: ${hit}

   Rule: never git add -A, stage explicit paths only.
   This vault is a single working tree shared across sessions — -A / . will stage
   other sessions' in-flight edits too, and the commit mixes in work that is not yours.

   Instead:
     git add "path/to/file.md" "automation/script.py"
     git status --short    # see exactly what to stage, then list them
     git add -p            # pick hunks

   Really want to stage everything (confirmed the tree holds only your changes):
     BB_ALLOW_GIT_ADD_ALL=1 <original cmd>    # stays in the audit log
EOF
exit 2
