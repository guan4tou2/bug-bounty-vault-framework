#!/usr/bin/env bash
# PreToolUse(Bash) hook — block hand-rolled INLINE batch-HTTP loops on the commander line.
#
# The OWASP injection matrix / batch payload testing is heavy execution. If the main
# (commander) conversation runs it inline, every raw HTTP response floods the main context,
# causing early loss of focus, wasted tokens, and prompt-cache churn. Such work should be
# delegated to a hunting sub-agent or run via a sanctioned scanner, so the main context only
# ingests conclusions. A hand-written loop of curl/wget over paths/payloads is the signature
# of "running the matrix inline" — this blocks exactly that, and nothing else. (golden-rules F5.)
#
# Deliberately narrow to keep false-positives near zero:
#   - Blocks ONLY a loop construct (for / while / xargs / seq / parallel) combined with a raw
#     fetch (curl / wget). A single curl, or any non-HTTP loop, passes.
#   - PASSES sanctioned scanners + recon tools (they ARE the delegated path, and sub-agents use
#     them): nuclei, ffuf, httpx, katana, gau, waybackurls, feroxbuster, gobuster, dirsearch,
#     subfinder, dnsx, masscan, nmap, sqlmap, wpscan, nikto, amass, hunt-*.sh.
#
# Note: a PreToolUse hook cannot tell the commander from a sub-agent (their hook inputs are
# identical), so this is a universal rule; the remedy (delegate / use a scanner) applies in
# either context.
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Intentional override (loud): prefix the command with  BB_INLINE_SCAN_OK=1
# (use for a genuine one-off single-endpoint probe that happens to loop a tiny list).
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[[ "$TOOL" != "Bash" ]] && exit 0
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[[ -z "$CMD" ]] && exit 0

# loud override, honoured even when set inside the command itself
if [[ "${BB_INLINE_SCAN_OK:-0}" == "1" ]] || echo "$CMD" | grep -q 'BB_INLINE_SCAN_OK=1'; then
  exit 0
fi

# pass sanctioned scanners / recon tools (the delegated path)
if echo "$CMD" | grep -qE '(^|[[:space:]/])(nuclei|ffuf|httpx|katana|gau|waybackurls|feroxbuster|gobuster|dirsearch|subfinder|dnsx|masscan|nmap|sqlmap|wpscan|nikto|amass|hunt-[a-z0-9-]+\.sh)([[:space:]]|$)'; then
  exit 0
fi

# signature: a loop construct + a raw HTTP fetch
has_loop=0
echo "$CMD" | grep -qE '(^|[[:space:];&|`(])(for|while)[[:space:]]' && has_loop=1
echo "$CMD" | grep -qE '(^|[[:space:]|])(xargs|parallel)([[:space:]]|$)'   && has_loop=1
echo "$CMD" | grep -qE '(^|[[:space:]|`(])seq[[:space:]]'                  && has_loop=1

has_fetch=0
echo "$CMD" | grep -qE '(^|[[:space:]|`(])(curl|wget)([[:space:]]|$)' && has_fetch=1

if [[ "$has_loop" == "1" && "$has_fetch" == "1" ]]; then
  cat >&2 <<'MSG'
BLOCKED (inline-scan-gate): a hand-rolled batch HTTP loop (for/while/xargs/seq + curl/wget)
on the main conversation. Batch/matrix testing floods the main context with raw responses.

Do one of these instead:
  * Delegate the batch run to a hunting sub-agent (Agent tool); the main context receives
    only the conclusions (which checks ran / hits / file:line), not every response.
  * Use a sanctioned scanner (ffuf / nuclei / a hunt-*.sh script) — all allowed by this gate.
  * A single-endpoint quick check does not need a loop — just one curl.

If you truly need to run a small inline loop once, prefix the command with:
  BB_INLINE_SCAN_OK=1
MSG
  exit 2
fi

exit 0
