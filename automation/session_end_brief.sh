#!/usr/bin/env bash
# Public-safe compatibility wrapper for token-light closeout brief.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scope="${1:-_meta}"

echo "# Session End Brief — $scope"
echo ""
echo "- Run checklist: bash automation/session_end_checklist.sh $scope"
echo "- Or release only: bash automation/release.sh $scope"
echo "- Audit: python3 automation/check_vault.py"
echo ""
exec python3 "$ROOT/automation/check_vault.py"
