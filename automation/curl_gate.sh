#!/usr/bin/env bash
# PreToolUse(Bash) hook — risk gate for outbound curl/wget/http requests.
# Classifies each request via risk_tier.py: reads/state pass, writes warn, service_impact
# blocks. Logic lives in curl_gate.py; this wrapper only locates python + fails open.
set -uo pipefail
PY=""
for c in python3 python; do
  command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
done
if [[ -z "$PY" ]]; then
  echo "curl-gate: no python on PATH — gate failed OPEN" >&2
  exit 0
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$PY" "$SCRIPT_DIR/curl_gate.py"
