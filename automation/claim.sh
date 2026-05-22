#!/usr/bin/env bash
# Public-safe compatibility wrapper for private Vault workflows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/automation/start_session.py" "$@"
