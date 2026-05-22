#!/usr/bin/env bash
# Public-safe compatibility wrapper: print the handoff brief without claiming.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-}"
if [[ -z "$target" ]]; then
  echo "Usage: bash automation/session_start_brief.sh <target> [keyword] [host]" >&2
  exit 1
fi
exec python3 "$ROOT/automation/start_session.py" "$target" --brief-only
