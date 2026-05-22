#!/usr/bin/env bash
# Public-safe compatibility wrapper for private audit_workspace.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/automation/check_vault.py" "$@"
