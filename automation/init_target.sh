#!/usr/bin/env bash
# Initialize a new bug bounty target workspace.
#
# Creates:
#   - Vault: 01 - Targets/<target>/ with subdirectories + Target page
#   - Workspace: workshop/<target>/ with SCOPE.md, RECON_DB.md, HANDOFF.md, FINDINGS_QUICK_REF.md
#
# Usage:
#   bash automation/init_target.sh <target>
#   bash automation/init_target.sh <parent>/<sub>

set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<'USAGE'
Usage: bash automation/init_target.sh <target>
       bash automation/init_target.sh <parent>/<sub>

Creates the standard workspace and vault structure for a new bug bounty target.
USAGE
  exit 1
fi

TARGET="$1"
DATE=$(date '+%Y-%m-%d')
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$SCRIPT_DIR/templates"

# Determine workspace location
if [[ -f "$ROOT/.workspace_root" ]]; then
  WORKSPACE_ROOT=$(cat "$ROOT/.workspace_root")
  # Resolve relative paths
  [[ "$WORKSPACE_ROOT" != /* ]] && WORKSPACE_ROOT="$ROOT/$WORKSPACE_ROOT"
elif [[ -d "$ROOT/workspace" ]]; then
  WORKSPACE_ROOT="$ROOT/workspace"
else
  echo "No workspace found. Run: bash automation/setup_workspace.sh" >&2
  exit 1
fi

WORKSHOP_DIR="$WORKSPACE_ROOT/workshop/$TARGET"

# --- Workshop directory ---
mkdir -p "$WORKSHOP_DIR"/{poc,scan_results,screenshots,hunters,rounds,findings,submissions}

# --- RECON_DB.md ---
RECON_DB="$WORKSHOP_DIR/RECON_DB.md"
if [[ -f "$RECON_DB" ]]; then
  echo "[skip] RECON_DB.md already exists: $RECON_DB"
else
  if [[ -f "$TEMPLATE_DIR/RECON_DB_template.md" ]]; then
    sed -e "s/{{TARGET}}/$TARGET/g" -e "s/{{DATE}}/$DATE/g" \
      "$TEMPLATE_DIR/RECON_DB_template.md" > "$RECON_DB"
  else
    cat > "$RECON_DB" <<EOF
# $TARGET — Recon Database

> Session start reading. Last updated: $DATE

## Status

| Item | Value |
|------|-------|
| Platform | |
| Program URL | |
| Status | active |

## Credentials & Keys

| Type | User | Value | Host | Source | Status |
|------|------|-------|------|--------|--------|

## Known Artifacts

| Report | Type | Identifiers | Notes |
|--------|------|-------------|-------|

## Discovered Paths & Endpoints

| URL / Path | Method | Auth? | Response | Confidence | Notes | Status |
|-----------|--------|-------|----------|-----------|-------|--------|

## Operation Log

| Local Time | UTC Time | Source IP | Method | Target URL | Intent | Result |
|---|---|---|---|---|---|---|

## 🛡️ Pre-flight Checks (version + CVE check before analysis)

> When to fill: after obtaining a concrete target version or identifying a cloud target, before starting analysis — run the version and CVE pre-flight check and record results here. See the bb-version-cve-precheck skill / AGENTS.md section 0g.

| Date | Target + version | Latest stable | Known CVEs / advisories | Decision (proceed / stop) |
|------|------------------|---------------|-------------------------|---------------------------|

## Session Log

### $DATE — Initialized

- RECON_DB created
EOF
  fi
  echo "[ok]   Created $RECON_DB"
fi

# --- SCOPE.md ---
SCOPE="$WORKSHOP_DIR/SCOPE.md"
if [[ -f "$SCOPE" ]]; then
  echo "[skip] SCOPE.md already exists: $SCOPE"
else
  cat > "$SCOPE" <<SCOPE_EOF
# $TARGET — Scope

> Created: $DATE. Fill in program scope details below.

## Platform

- Platform:
- Program URL:
- Bounty range:

## In-Scope Assets

(Fill in from program page)

## Out-of-Scope

(Fill in exclusions)
SCOPE_EOF
  echo "[ok]   Created $SCOPE"
fi

# --- HANDOFF.md ---
HANDOFF="$WORKSHOP_DIR/HANDOFF.md"
if [[ -f "$HANDOFF" ]]; then
  echo "[skip] HANDOFF.md already exists: $HANDOFF"
else
  if [[ -f "$TEMPLATE_DIR/HANDOFF_template.md" ]]; then
    sed -e "s/{{TARGET}}/$TARGET/g" -e "s/{{DATE}}/$DATE/g" \
      "$TEMPLATE_DIR/HANDOFF_template.md" > "$HANDOFF"
  else
    cat > "$HANDOFF" <<EOF
# $TARGET — Session Handoff

## Last Session

- **Date:** $DATE
- **Status:** active

## What I Was Doing

(Fill in)

## Immediate Next Step

\`\`\`bash
# Next command
\`\`\`

## Blockers

- (none)
EOF
  fi
  echo "[ok]   Created $HANDOFF"
fi

# --- FINDINGS_QUICK_REF.md ---
QUICK_REF="$WORKSHOP_DIR/FINDINGS_QUICK_REF.md"
if [[ -f "$QUICK_REF" ]]; then
  echo "[skip] FINDINGS_QUICK_REF.md already exists"
else
  cat > "$QUICK_REF" <<EOF
# $TARGET — Findings Quick Reference

> Auto-generated. One line per finding for dedup checks.

| ID | Title | Severity | Status | Host |
|----|-------|----------|--------|------|
EOF
  echo "[ok]   Created $QUICK_REF"
fi

# --- Vault Target page ---
VAULT_DIR="$ROOT/01 - Targets/$TARGET"
TARGET_BASENAME="${TARGET##*/}"
TARGET_PAGE="$VAULT_DIR/Target - $TARGET_BASENAME.md"

mkdir -p \
  "$VAULT_DIR/Findings" \
  "$VAULT_DIR/Submissions" \
  "$VAULT_DIR/Submissions/Forms" \
  "$VAULT_DIR/Attempts" \
  "$VAULT_DIR/Recon" \
  "$VAULT_DIR/Services" \
  "$VAULT_DIR/Credentials" \
  "$VAULT_DIR/Notes" \
  "$VAULT_DIR/Attack Chains" \
  "$VAULT_DIR/Screenshots"

# .gitkeep in empty dirs
for d in Findings Submissions Submissions/Forms Attempts Recon Services Credentials Notes "Attack Chains" Screenshots; do
  if [ -z "$(ls -A "$VAULT_DIR/$d" 2>/dev/null)" ]; then
    touch "$VAULT_DIR/$d/.gitkeep"
  fi
done

if [[ -f "$TARGET_PAGE" ]]; then
  echo "[skip] Target page already exists: $TARGET_PAGE"
else
  cat > "$TARGET_PAGE" <<EOF
---
type: target
fileClass: Target
target_name: "$TARGET_BASENAME"
category: ""
domain: ""
status: "recon"
risk: "medium"
first_seen: "$DATE"
tags: []
---

# $TARGET_BASENAME

> One-line pitch: what is this product, who uses it, why is it interesting.

## Snapshot

| Item | Value |
|------|-------|
| Domain | |
| Platform | |
| Tech Stack | |
| Status | Recon |
| First Seen | $DATE |

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low/Info | 0 |

## Submission Status

| ID | Platform | Status |
|----|----------|--------|

## Quick Links

- [[SCOPE]]
- [[Kanban - $TARGET_BASENAME]]
EOF
  echo "[ok]   Created $TARGET_PAGE"
fi

# --- Regenerate _INDEX.md ---
INDEX_FILE="$ROOT/01 - Targets/_INDEX.md"
{
  echo "# Target Index"
  echo ""
  echo "> Auto-generated by init_target.sh. $(date '+%Y-%m-%d %H:%M')"
  echo ""
  echo "| Target | Status |"
  echo "|--------|--------|"
  for tdir in "$ROOT/01 - Targets"/*/; do
    [ -d "$tdir" ] || continue
    tname=$(basename "$tdir")
    [[ "$tname" == _* ]] && continue
    tpage="$tdir/Target - $tname.md"
    status=""
    if [ -f "$tpage" ]; then
      status=$(grep -m1 '^status:' "$tpage" 2>/dev/null | sed 's/status: *"\{0,1\}\([^"]*\)"\{0,1\}/\1/' || echo "")
    fi
    echo "| [[$tname]] | $status |"
  done
} > "$INDEX_FILE"
echo "[ok]   Updated _INDEX.md"

echo ""
echo "Target '$TARGET' initialized."
echo "Next steps:"
echo "  1. Fill in $SCOPE"
echo "  2. Fill in $TARGET_PAGE"
echo "  3. python3 automation/start_session.py $TARGET"
