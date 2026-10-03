#!/usr/bin/env bash
# PreToolUse(Bash) hook — BLOCKS (exit 2) shell edits to durable files (`cat > f`,
# heredoc, `sed -i`, `echo >> f`, and `python3 - <<PY` with open(...,'w') inside).
#
# Why: the tool-discipline rule is "write/edit files with the Edit/Write tools, not Bash
# `cat >` / heredoc / `sed -i` / `echo >>`". The rule is always-loaded yet still gets
# violated for speed — because the decision ("which tool") happens at the instant of
# acting, not when the rule is being read (the LL-317 shape). Only a hook is present then.
#
# The rule's own rationale: Bash can't write outside the sandbox or to .claude/ (Edit/Write
# can), it carries more classifier friction, and heredoc bodies get misread by other gates.
#
# Scope (deliberately narrow — a noisy gate gets ignored): blocks only when the target is a
# durable doc/source file. Exempt: data/output extensions (.txt .log .json(l) .csv .tsv …),
# temp paths (/tmp, scratchpad, $TMPDIR), `tee` (evidence is saved with tee), and heredoc
# bodies fed to a command rather than a file (e.g. `git commit -F - <<MSG`).
#
# Loud override (stays in the payload): put  BB_ALLOW_SHELL_WRITE=1  in the command.
set -uo pipefail

INPUT=$(cat)
[[ "$(printf %s "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)" != "Bash" ]] && exit 0
CMD=$(printf %s "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# override
if [[ "${BB_ALLOW_SHELL_WRITE:-0}" == "1" ]] || printf %s "$CMD" | grep -q 'BB_ALLOW_SHELL_WRITE=1'; then
  exit 0
fi

# Durable doc/source extensions. Data/output types are intentionally omitted.
DOC_EXT='md|c|h|cc|cpp|hpp|m|mm|py|sh|bash|zsh|rb|go|rs|js|ts|php|pl|java|swift|plist|yaml|yml|toml|ini|cfg|entitlements|sb'
# Temp / exempt paths
EXEMPT='/scratchpad/|/private/tmp/|(^|[^a-z])/tmp/|\$TMPDIR|/var/folders/|automation/active_sessions|/\.state/'

# ── effective working directory: where you are at the moment of the write ──
# Why (measured from real command logs, not guessed): the first version matched 151 of
# 4110 real commands, of which ~27% were one false-positive shape:
#     cd "$TMPDIR/x" && cat > strip.py <<'EOF'
#     cd <scratchpad> && cat > sets.py <<'PYEOF'
# The target is a RELATIVE filename and EXEMPT only matches absolute paths, so they all
# slipped through. Dropping a one-off script inside a temp dir is not this gate's business;
# 27% false positives would turn the whole warning into background noise.
# Approach: take the LAST cd target as the effective cwd; if it is in a temp area, relative
# targets are exempt (absolute targets still judged, so `cd /tmp && cat > ~/x.md` still blocks).
LAST_CD=$(printf %s "$CMD" | grep -oE '(^|[;&|[:space:]])cd[[:space:]]+("[^"]+"|'"'"'[^'"'"']+'"'"'|[^[:space:];&|]+)' \
          | tail -1 | sed -E "s/.*cd[[:space:]]+//; s/^[\"']//; s/[\"']\$//" || true)

# ── variable expansion ──
# Also measured: after the cwd fix, ~20 false positives remained, all one shape —
#   SP=/private/tmp/.../scratchpad  &&  cat > "$SP/verify.py"
#   TD="$TMPDIR/test"               &&  … > "$TD/x.sh"
# The target is a variable; EXEMPT matches literal paths. Two expansion rounds suffice.
_expand_vars() {
  local s="$1" round name val a
  for round in 1 2; do
    while IFS= read -r a; do
      [[ -z "$a" ]] && continue
      name="${a%%=*}"; val="${a#*=}"
      val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
      s="${s//\$\{$name\}/$val}"
      s="${s//\$$name/$val}"
    done < <(printf %s "$CMD" \
             | grep -oE '(^|[;&[:space:]])[A-Za-z_][A-Za-z0-9_]*=("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:];&|]+)' \
             | sed -E 's/^[;&[:space:]]+//')
  done
  printf %s "$s"
}

# cwd check must come AFTER _expand_vars: for `S=<scratchpad>; cd "$S"` the last cd target
# is a variable and must be expanded to recognise it as a temp area.
CWD_EXEMPT=0
if [[ -n "$LAST_CD" ]] && printf %s "$(_expand_vars "$LAST_CD")" | grep -qE "$EXEMPT"; then
  CWD_EXEMPT=1
fi

# Should this target be exempt? (1) cwd is a temp area and the target is relative, or
# (2) after variable expansion it lands in a temp area.
_exempt_target() {
  local t="$1"
  [[ "$CWD_EXEMPT" -eq 1 && "$t" != /* && "$t" != '~'* ]] && return 0
  printf %s "$(_expand_vars "$t")" | grep -qE "$EXEMPT" && return 0
  return 1
}

REASON=""
HIT=""

# ── strip heredoc bodies before looking for shell redirects ──
# This hole was found when the gate blocked its OWN commit: a `git commit -F - <<'MSG'`
# whose message text quoted a `>` was read as a real redirect. `git commit -F -` writes to
# stdin, not a file. Any heredoc that feeds a doc/message to a command hits this — and gate
# docs, commit messages, and reports are exactly where dangerous syntax gets quoted.
# Detection B wants the opposite (it must see writes INSIDE the body), so only A uses the
# stripped version.
CMD_NOBODY=$(printf %s "$CMD" | awk '
  BEGIN { tag = "" }
  {
    if (tag != "") {                       # inside a heredoc: drop the whole line
      line = $0; gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line == tag) tag = ""
      next
    }
    print
    s = $0
    while (match(s, /<<-?[ \t]*("[^"]+"|'"'"'[^'"'"']+'"'"'|[A-Za-z_][A-Za-z0-9_]*)/)) {
      t = substr(s, RSTART, RLENGTH)
      sub(/^<<-?[ \t]*/, "", t); gsub(/["'"'"']/, "", t)
      tag = t
      s = substr(s, RSTART + RLENGTH)
    }
  }')

# Judge every candidate target, NOT just the first: `> /tmp/a.py && > notes.md` would pass
# on a head -1 because the first is exempt (a classic false-negative factory).
_first_non_exempt() {
  local c
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    _exempt_target "$c" && continue
    printf %s "$c"; return 0
  done
  return 1
}

# ── Detection A: direct shell write to a durable file ──
#   `cat > f`, `... >> f`, `printf ... > f`, `sed -i`
if printf %s "$CMD_NOBODY" | grep -qE '(^|[;&|[:space:]])sed[[:space:]]+(-[a-zA-Z]*i|--in-place)'; then
  cand=$(printf %s "$CMD_NOBODY" | grep -oE "[^[:space:]\"';|&)]+\.($DOC_EXT)\b" \
         | grep -vE "$EXEMPT" | _first_non_exempt || true)
  if [[ -n "$cand" ]]; then REASON="sed -i in-place edit"; HIT="$cand"; fi
fi

if [[ -z "$HIT" ]]; then
  # Unquoted target AND quoted target. Vault paths almost always contain spaces
  # (`01 - Targets/…`, `09 - Knowledge Base/…`), so the quoted branch is the main shape,
  # not an edge case — the first version omitted it and missed 2 of 5 positive fixtures.
  cand=$( { printf %s "$CMD_NOBODY" \
              | grep -oE '>>?[[:space:]]*[^[:space:]"'"'"';|&)]+' \
              | sed -E 's/^>+[[:space:]]*//' ;
            printf %s "$CMD_NOBODY" \
              | grep -oE ">>?[[:space:]]*(\"[^\"]+\"|'[^']+')" \
              | sed -E "s/^>+[[:space:]]*//; s/^[\"']//; s/[\"']\$//" ; } \
          | grep -E "\.($DOC_EXT)\$" | grep -vE "$EXEMPT" | _first_non_exempt || true)
  if [[ -n "$cand" ]]; then REASON="shell redirect writing a durable file"; HIT="$cand"; fi
fi

# ── Detection B: inline interpreter heredoc that writes a file ──
#   `python3 - <<'PY' … open(p,'w') … PY` — the classic way around this gate.
if [[ -z "$HIT" && "$CWD_EXEMPT" -eq 0 ]] \
   && printf %s "$CMD" | grep -qE '(python3?|perl|ruby|node)[[:space:]]+(-[[:space:]]*)?<<' \
   && printf %s "$CMD" | grep -qE "open\([^)]*['\"][wa]['\"]|write_text\(|\.writelines\(|File\.write|fs\.writeFileSync"; then
  REASON="heredoc into an interpreter that writes a file (the classic bypass)"
  HIT="$(printf %s "$CMD" | grep -oE "[^[:space:]\"';(]+\.($DOC_EXT)\b" | grep -vE "$EXEMPT" | head -1 || true)"
  [[ -z "$HIT" ]] && HIT="(path inside the heredoc)"
fi

[[ -z "$HIT" ]] && exit 0

cat >&2 <<EOF
⛔ shell_write_gate: blocked a Bash edit to a durable file.

   detected: $REASON
   target  : $HIT

   Tool discipline: write/edit files with the Edit/Write tools, not
   \`cat >\` / heredoc / \`sed -i\` / \`echo >>\`.
   Why: Bash can't write outside the sandbox or to .claude/ (Edit/Write can), it carries
   more classifier friction, and heredoc bodies get misread by other gates.

   Instead:
     • edit an existing file -> Edit (Read it first)
     • new file / full rewrite -> Write

   Genuinely need a shell write (generated data file, batch output, target in /tmp):
     BB_ALLOW_SHELL_WRITE=1 <original cmd>
   — this stays in the audit log, a deliberately auditable escape hatch.
EOF
exit 2
