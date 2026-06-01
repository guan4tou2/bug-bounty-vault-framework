#!/usr/bin/env bash
# setup_workspace.sh — Create the local workspace scaffold
# Usage: bash automation/setup_workspace.sh
#
# This creates the .gitignored workspace/ directory tree used for
# operational data (recon, scans, PoCs, logs). Safe to re-run;
# existing files are never overwritten.

set -euo pipefail

# Resolve repo root (parent of automation/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WS="$REPO_ROOT/workspace"

echo "=== Bug Bounty Vault — Workspace Setup ==="
echo "Repo root: $REPO_ROOT"
echo ""

# --- workspace/workshop/ ---
mkdir -p "$WS/workshop/_all/targets"

# --- workspace/reports/ ---
mkdir -p "$WS/reports/drafts" "$WS/reports/exports" "$WS/reports/archive"

# --- workspace/firmware_analysis/ ---
mkdir -p "$WS/firmware_analysis"

# --- workspace/logs/ ---
mkdir -p "$WS/logs"

# --- workspace/tmp/ ---
mkdir -p "$WS/tmp"

# --- .workspace_root marker ---
MARKER="$REPO_ROOT/.workspace_root"
if [ ! -f "$MARKER" ]; then
  echo "workspace/" > "$MARKER"
  echo "Created $MARKER"
fi

# --- .gitignore entry check ---
GITIGNORE="$REPO_ROOT/.gitignore"
if [ -f "$GITIGNORE" ]; then
  if ! grep -q '^workspace/' "$GITIGNORE" 2>/dev/null; then
    echo "" >> "$GITIGNORE"
    echo "# Local workspace (never committed)" >> "$GITIGNORE"
    echo "workspace/" >> "$GITIGNORE"
    echo "Added workspace/ to .gitignore"
  fi
fi

echo ""
echo "Workspace scaffold created:"
echo ""
find "$WS" -type d | sed "s|$REPO_ROOT/||" | sort
echo ""
echo "Done. The workspace/ directory is .gitignored and local-only."
