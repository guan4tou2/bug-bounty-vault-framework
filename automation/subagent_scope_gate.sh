#!/usr/bin/env bash
# PreToolUse(Agent|Task) hook — refuse to dispatch a subagent that is being TOLD to send
# packets. Universal default: applies to ALL work, not per-target.
#
# Why (LL-338): in one session two agents ran concurrently, one issuing batch HTTP
# requests against a production OSS. Rate and concurrency were outside the main thread's
# view, the "who hit what, when" audit trail degraded, and a killed agent still reported a
# half-finished "found two leaks" conclusion that cannot be trusted. Keeping raw responses
# out of the main context is a separate concern — the remedy there is `max_response_length`,
# NOT outsourcing the packets.
#
# Detection is deliberately NARROW to keep false positives at zero: it fires only on an
# UNAMBIGUOUS instruction to send (a request-sending Burp MCP tool name, or curl/wget). A
# desk agent told to read `proxy_history`, parse landed files, count data, review a score,
# or draft a report is NOT matched — those are exactly the jobs subagents SHOULD get.
#
# Default is ON for everyone (not gated on a per-target SCOPE.md flag — that would require
# every target to remember to declare it, and new targets would miss it). Loosening is
# per-dispatch and logged: put  BB_SUBAGENT_NET_OK=1  in the prompt.
#
# Exit 0 = allow, Exit 2 = block (stderr shown to the model).
set -uo pipefail

PY=""
for c in python python3; do
  command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
done
if [[ -z "$PY" ]]; then
  echo "⚠️  subagent-scope-gate: no python on PATH — gate failed OPEN (harness invariant X1)" >&2
  exit 0
fi

PYSRC=""
read -r -d '' PYSRC <<'PYGATE'
import json, re, sys

raw = sys.stdin.read()
try:
    obj = json.loads(raw)
except Exception:
    sys.exit(0)

if obj.get("tool_name") not in ("Agent", "Task"):
    sys.exit(0)

ti = obj.get("tool_input") or {}
blob = " ".join(str(ti.get(k, "")) for k in ("prompt", "description", "subagent_type"))
if not blob.strip():
    sys.exit(0)

if "BB_SUBAGENT_NET_OK=1" in blob:
    sys.exit(0)

# Universal default: any send instruction goes to the check below — no SCOPE.md flag needed.
SEND = re.compile(
    r"(?:http_send_request|http_send_requests_parallel|http_send_raw_bytes"
    r"|repeater_send|intruder_send|intruder_send_with_positions|http_fuzz|http_race"
    r"|scanner_start_(?:audit|crawl)|recon_content_discovery"
    r"|(?:^|[\s;&|(){}`'\"])(?:curl|wget)(?:\s))",
    re.I,
)
m = SEND.search(blob)
if not m:
    sys.exit(0)

sys.stderr.write(
    "⛔ subagent-scope-gate: this subagent is being told to **send requests itself**.\n"
    "Default for all work is desk-only — operations that send packets at a target run on "
    "the main thread.\n\n"
    f"matched instruction: {m.group(0).strip()!r}\n\n"
    "In red-team / pentest work, anything that sends packets at the target runs on the "
    "main thread (LL-338).\n"
    "Why: a subagent's rate and concurrency are outside the main thread's view, the audit "
    "chain breaks, mid-run conclusions cannot be trusted, and the authorization boundary "
    "(what is write-semantic, what is irreversible) gets diluted.\n\n"
    "Instead:\n"
    "  • Send from the main thread: `mcp__burp__http_send_requests_parallel` (8-15/batch)\n"
    "    with `max_response_length`. To keep responses out of context, cap the output —\n"
    "    don't outsource the packets.\n"
    "  • Give the subagent desk work: pull captured responses from `proxy_history`, parse\n"
    "    landed files, count data, adversarially review a score, draft a report — those\n"
    "    zero-network tasks are not restricted.\n\n"
    "Genuinely needed: put  BB_SUBAGENT_NET_OK=1  in the prompt (it is logged).\n"
)
sys.exit(2)
PYGATE

exec "$PY" -c "$PYSRC"
