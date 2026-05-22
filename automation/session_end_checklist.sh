#!/usr/bin/env bash
# Public-safe compatibility wrapper for session closeout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/automation/end_session.py" "$@"
