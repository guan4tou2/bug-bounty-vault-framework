#!/usr/bin/env bash
# PreToolUse(Read) hook — no whole-file Read of a large file, in ANY context.
#
# Raw tool output is by far the largest consumer of the main (commander) context, and a
# single whole-file Read of a large file is the most common way it balloons. The runtime
# compactor is a black box you cannot steer, so the only lever is intake prevention: read a
# section, not the whole file. (golden-rules F6.)
#
# A PreToolUse hook cannot distinguish the commander from a sub-agent (their hook inputs are
# identical), so this is a UNIVERSAL rule whose remedy works in every context: read the file
# in SECTIONS (offset/limit) or grep it first — nobody needs a huge file in one block.
#
# Blocks Read of a file larger than BB_BIG_READ_BYTES (default 51200 = ~50KB) when NO limit
# is supplied. A bounded read (limit set) always passes.
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Loud override (genuine whole-file need): set BB_BIG_READ_OK=1 in the environment.
set -uo pipefail

THRESH="${BB_BIG_READ_BYTES:-51200}"

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Read" ]] && exit 0

[[ "${BB_BIG_READ_OK:-0}" == "1" ]] && exit 0

FP=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""' 2>/dev/null)
[[ -z "$FP" ]] && exit 0

# a bounded slice is exactly the remedy — always allow it
LIMIT=$(echo "$INPUT" | jq -r '.tool_input.limit // ""' 2>/dev/null)
[[ -n "$LIMIT" ]] && exit 0

# resolve relative paths against the project dir / cwd
if [[ "$FP" != /* ]]; then
  FP="${CLAUDE_PROJECT_DIR:-$PWD}/$FP"
fi
[[ -f "$FP" ]] || exit 0        # missing / non-regular → let Read surface the real error

BYTES=$(wc -c < "$FP" 2>/dev/null | tr -d ' ')
[[ -z "$BYTES" ]] && exit 0
[[ "$BYTES" -le "$THRESH" ]] && exit 0

TOK=$((BYTES/4))
NAME=$(basename "$FP")
# NOTE: quoted heredoc delimiter so backticks / $(...) in the body are NOT expanded.
cat >&2 <<'MSG'
BLOCKED (big-read-gate): a whole-file Read that would flood the main context.
MSG
cat >&2 <<MSG
File "${NAME}" is ~${BYTES} bytes (~${TOK} tokens). Reading it whole floods context.
A hook cannot tell the commander from a sub-agent, so this rule applies to both:

  * Read a section: pass offset/limit to Read (a bounded read always passes) — you rarely
    need the whole file.
  * grep/rg to locate the lines you need, then read just those.
  * For a large data/recon file, delegate a conclusions-only read to a sub-agent.

If you genuinely need the whole file, set  BB_BIG_READ_OK=1  in the environment.
Threshold is configurable via BB_BIG_READ_BYTES (currently ${THRESH}).
MSG
exit 2
