#!/usr/bin/env bash
# PreToolUse(WebSearch|WebFetch) hook — enforces "check KB before web search" discipline.
#
# Before allowing a WebSearch or WebFetch, checks if kb_retrieval has been
# invoked in this session (indicated by a receipt file). This prevents the
# "streetlight effect on the internet" — searching the web for something the
# KB already knows, and missing the local signal in favour of generic results.
#
# Receipt mechanism:
#   kb_retrieval.py writes $TMPDIR/bb_kb_queried when it runs.
#   This gate checks for that file. First WebSearch/WebFetch of a session
#   is blocked until kb_retrieval runs at least once.
#
# What PASSES without receipt:
#   - WebFetch to documentation URLs (*.readthedocs.io, docs.*, developer.*)
#   - WebFetch to CVE/advisory databases (nvd.nist.gov, cve.org, github.com/advisories)
#   - WebFetch to the target's own domain (need target context for this)
#   - Any call after kb_retrieval has been invoked this session
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
# Override: BB_SKIP_WIKI_GATE=1
set -uo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)

# Only gate WebSearch and WebFetch
case "$TOOL" in
  WebSearch|WebFetch) ;;
  *) exit 0 ;;
esac

if [[ "${BB_SKIP_WIKI_GATE:-0}" == "1" ]]; then
  exit 0
fi

# --- always-allowed URLs (documentation & advisory databases) ---
if [[ "$TOOL" == "WebFetch" ]]; then
  URL=$(echo "$INPUT" | jq -r '.tool_input.url // ""' 2>/dev/null)
  if [[ -n "$URL" ]]; then
    # Documentation sites
    if echo "$URL" | grep -qEi '(readthedocs\.io|docs\.|developer\.|devdocs\.io|man7\.org|cppreference|mozilla\.org/en-US/docs|learn\.microsoft\.com)'; then
      exit 0
    fi
    # CVE / advisory databases
    if echo "$URL" | grep -qEi '(nvd\.nist\.gov|cve\.org|cvedetails\.com|github\.com/(advisories|security)|exploit-db\.com|packetstormsecurity|vuldb\.com|snyk\.io/vuln)'; then
      exit 0
    fi
    # GitHub repos (code reference, not search)
    if echo "$URL" | grep -qEi '^https://github\.com/[^/]+/[^/]+/(blob|tree|raw|releases|commit|pull|issues)'; then
      exit 0
    fi
    # HackerOne disclosed reports
    if echo "$URL" | grep -qEi 'hackerone\.com/reports/'; then
      exit 0
    fi
  fi
fi

# --- check for kb_retrieval receipt ---
RECEIPT="${TMPDIR:-/tmp}/bb_kb_queried"
if [[ -f "$RECEIPT" ]]; then
  exit 0  # kb_retrieval has been called this session
fi

# --- BLOCK ---
echo "⛔ wiki-before-web gate: check KB before web search." >&2
echo "" >&2
echo "This session has not queried the Knowledge Base yet. Check local KB first:" >&2
echo "" >&2
echo "  python3 automation/kb_retrieval.py search '<keyword>'" >&2
echo "" >&2
echo "If KB has nothing, then search the web (receipt auto-created)." >&2
echo "Technical docs and CVE database WebFetch are exempt." >&2
echo "" >&2
echo "Override: BB_SKIP_WIKI_GATE=1" >&2
exit 2
