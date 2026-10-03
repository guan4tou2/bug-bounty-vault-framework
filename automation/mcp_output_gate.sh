#!/usr/bin/env bash
# PreToolUse hook — stop MCP tools from flooding the commander line with raw output.
#
# Enforces "the commander stays out of the raw stream" on the MCP side. The Bash side
# already has inline_scan_gate.sh; MCP calls had nothing, and they are a large intake
# source after Read/Bash.
#
# Measured (8 sessions, main-line tool_result chars = 4.7M):
#   Read                                   27%
#   Bash                                   27%
#   mcp__burp__http_send_request           11%   <- this gate
#   mcp__chrome-devtools__evaluate_script   6%   <- this gate
#   mcp__burp__http_send_requests_parallel  6%   <- this gate
# The Burp family alone is 21%, and `max_response_length` already exists on those tools —
# it was simply never passed. One session put 159 full Burp responses into its main context.
#
# What it does:
#   1. Burp send tools WITHOUT `max_response_length` -> BLOCK. Not a cap: a "decide
#      consciously" gate. Want the whole body? pass a large number explicitly (e.g. 200000).
#      Absence of the parameter is what gets blocked.
#   2. chrome-devtools evaluate_script that bulk-dumps the DOM -> BLOCK. Narrow pattern list
#      (outerHTML / body.innerHTML / documentElement dumps). A normal small expression passes.
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Override (loud, per call): add  "_bb_raw_ok": true  to the tool input.

set -uo pipefail
INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ -z "$TOOL" ]] && exit 0

# loud per-call override
if [[ "$(printf '%s' "$INPUT" | jq -r '.tool_input._bb_raw_ok // false' 2>/dev/null)" == "true" ]]; then
  exit 0
fi

case "$TOOL" in
  mcp__burp__http_send_request|mcp__burp__http_send_requests_parallel|mcp__burp__http_send_raw_bytes)
    mrl=$(printf '%s' "$INPUT" | jq -r '.tool_input.max_response_length // empty' 2>/dev/null)
    if [[ -z "$mrl" ]]; then
      echo "BLOCKED (mcp-output-gate): $TOOL did not pass max_response_length." >&2
      echo "" >&2
      echo "The full HTTP response goes straight into the main context — the Burp family was" >&2
      echo "measured at 21% of main-line tool output; one session flooded 159 full responses in." >&2
      echo "" >&2
      echo "This is not a cap, it asks you to decide the size consciously:" >&2
      echo "  • status code / headers / start of body  -> max_response_length: 400" >&2
      echo "  • full body (decompile, source map, big JSON) -> pass a large value, e.g. 200000" >&2
      echo "  • a whole batch of raw responses to analyse -> that is heavy work, dispatch an agent" >&2
      echo "" >&2
      echo "One-off override: add  \"_bb_raw_ok\": true  to the tool input." >&2
      exit 2
    fi
    ;;
  mcp__burp__proxy_history)
    inc=$(printf '%s' "$INPUT" | jq -r '.tool_input.include_response // false' 2>/dev/null)
    mrl=$(printf '%s' "$INPUT" | jq -r '.tool_input.max_response_length // empty' 2>/dev/null)
    if [[ "$inc" == "true" && -z "$mrl" ]]; then
      echo "BLOCKED (mcp-output-gate): proxy_history with include_response but no max_response_length." >&2
      echo "" >&2
      echo "That floods a whole batch of full responses into the main context, when metadata" >&2
      echo "alone is enough to locate what you want." >&2
      echo "" >&2
      echo "  • just finding a request -> drop include_response, filter by host/method/status_code" >&2
      echo "  • need content -> pass max_response_length (e.g. 600), or filter to one entry first" >&2
      echo "" >&2
      echo "One-off override: add  \"_bb_raw_ok\": true  to the tool input." >&2
      exit 2
    fi
    ;;
  mcp__chrome-devtools__evaluate_script)
    src=$(printf '%s' "$INPUT" | jq -r '.tool_input.function // .tool_input.expression // .tool_input.script // ""' 2>/dev/null)
    [[ -z "$src" ]] && exit 0
    # Already reduced (length / slice / match) -> not a dump, allow.
    if printf '%s' "$src" | grep -qE '(outer|inner)HTML[[:space:]]*\.[[:space:]]*(length|slice|substring|substr|match|indexOf|search|split|replace|includes)'; then
      exit 0
    fi
    # Only block an explicit whole-page dump; a normal small expression passes.
    if printf '%s' "$src" | grep -qE 'documentElement\.(outerHTML|innerHTML)|document\.body\.(outerHTML|innerHTML)|document\.all|\.outerHTML[[:space:]]*$|getElementsByTagName\([^)]*\)\][[:space:]]*\.(outerHTML|innerHTML)'; then
      echo "BLOCKED (mcp-output-gate): evaluate_script is dumping the whole DOM." >&2
      echo "" >&2
      echo "A whole page of HTML is one of the most expensive single inputs to the main context" >&2
      echo "(evaluate_script measured at 6%; one session called it 138 times)." >&2
      echo "" >&2
      echo "Return the conclusion, not the raw material:" >&2
      echo "  • length / existence  -> return document.body.innerHTML.length" >&2
      echo "  • a fragment          -> .slice(0, 2000)  or querySelector then read that node" >&2
      echo "  • some fields         -> filter in JS and return an array/object" >&2
      echo "  • genuine full-text analysis -> dispatch an agent, or a get_page_text with a limit" >&2
      echo "" >&2
      echo "One-off override: add  \"_bb_raw_ok\": true  to the tool input." >&2
      exit 2
    fi
    ;;
esac
exit 0
