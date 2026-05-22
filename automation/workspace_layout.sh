#!/usr/bin/env bash
# Public-safe layout resolver.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$ROOT/workspace"
WORKSHOP_ROOT="$WORKSPACE_ROOT/workshop"
REPORTS_ROOT="$WORKSPACE_ROOT/reports"
LOGS_ROOT="$WORKSPACE_ROOT/logs"
FIRMWARE_ROOT="$WORKSPACE_ROOT/firmware_analysis"
TOOLS_ROOT="$ROOT/tools"

if [[ "${1:-}" == "--shell" ]]; then
  cat <<EOF
PROJECT_ROOT='$ROOT'
VAULT_ROOT='$ROOT'
WORKSPACE_ROOT='$WORKSPACE_ROOT'
WORKSHOP_ROOT='$WORKSHOP_ROOT'
REPORTS_ROOT='$REPORTS_ROOT'
LOGS_ROOT='$LOGS_ROOT'
FIRMWARE_ROOT='$FIRMWARE_ROOT'
TOOLS_ROOT='$TOOLS_ROOT'
LAYOUT_MODE='public-vault-root'
EOF
else
  export PROJECT_ROOT="$ROOT"
  export VAULT_ROOT="$ROOT"
  export WORKSPACE_ROOT
  export WORKSHOP_ROOT
  export REPORTS_ROOT
  export LOGS_ROOT
  export FIRMWARE_ROOT
  export TOOLS_ROOT
  export LAYOUT_MODE="public-vault-root"
fi
