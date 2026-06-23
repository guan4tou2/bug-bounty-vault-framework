#!/usr/bin/env bash
# chain_gaps.sh — compatibility wrapper for exploit-chain DAG gaps.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <target>"; exit 1; }

shift || true
exec bash "$SCRIPT_DIR/dag_gaps.sh" "$TARGET" --kind chain "$@"
