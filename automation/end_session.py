#!/usr/bin/env python3
"""Minimal session end: run checklist + release lock.

Public-safe equivalent of session_end_checklist.sh + release.sh.
Works standalone without the full automation suite.

Usage:
    python3 automation/end_session.py <scope>
    python3 automation/end_session.py gitlab/oauth

See docs/session-lifecycle.md for the full protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE_DIR = ROOT / "automation" / "active_sessions"
EXPIRED_DIR = ACTIVE_DIR / "_expired"
VAULT_DIR = ROOT / "01 - Targets"

# ANSI colors
G = "\033[0;32m"
R = "\033[0;31m"
Y = "\033[0;33m"
N = "\033[0m"


def safe_scope(scope: str) -> str:
    return scope.replace("/", "--")


def lock_path(scope: str) -> Path:
    return ACTIVE_DIR / f"{safe_scope(scope)}.lock"


def find_workspace(target: str) -> Path | None:
    # Default is the in-repo workspace/; an optional external workspace can be
    # set via the VAULT_WORKSPACE env var.
    candidates = [ROOT / "workspace" / "workshop" / target]
    ext = os.environ.get("VAULT_WORKSPACE")
    if ext:
        candidates.append(Path(ext) / "workshop" / target)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def _frontmatter_value(text: str, key: str) -> str:
    """First YAML frontmatter scalar for `key` (quotes/enum-hint stripped), else ''."""
    m = re.search(rf"^{re.escape(key)}:\s*(.+)$", text, re.MULTILINE)
    if not m:
        return ""
    val = m.group(1).strip().strip('"').strip("'").strip()
    # A finding still on the template shows the enum hint ("a | b | c") — treat as unset.
    if "|" in val:
        return ""
    return val


def run_checklist(target: str) -> tuple[int, int]:
    """Run end-of-session checks. Returns (failures, warnings)."""
    failures = 0
    warnings = 0
    now = time.time()

    print(f"\n{'='*50}")
    print(f"  Session End Checklist -- {target}")
    print(f"{'='*50}\n")

    # 1. Vault Target page
    target_basename = target.split("/")[-1]
    target_page = VAULT_DIR / target / f"Target - {target_basename}.md"
    if target_page.exists():
        print(f"{G}[PASS]{N} Target page exists")
    else:
        print(f"{R}[FAIL]{N} Target page missing: Target - {target_basename}.md")
        failures += 1

    # 2. RECON_DB freshness
    ws = find_workspace(target)
    if ws:
        recon_db = ws / "RECON_DB.md"
        if recon_db.exists():
            age_h = int((now - recon_db.stat().st_mtime) / 3600)
            if age_h <= 12:
                print(f"{G}[PASS]{N} RECON_DB.md updated {age_h}h ago")
            else:
                print(f"{Y}[WARN]{N} RECON_DB.md not updated in {age_h}h")
                warnings += 1
        else:
            print(f"{R}[FAIL]{N} RECON_DB.md missing")
            failures += 1

        # 3. HANDOFF.md exists and is non-empty
        handoff = ws / "HANDOFF.md"
        if handoff.exists():
            content = handoff.read_text().strip()
            # Check if any section has been filled (not just template)
            has_content = any(
                line.strip() and not line.startswith("#") and not line.startswith(">") and not line.startswith("-")
                and line.strip() not in ("---", "(none)", "--")
                for line in content.splitlines()[10:]  # skip header
            )
            if has_content:
                print(f"{G}[PASS]{N} HANDOFF.md has content")
            else:
                print(f"{Y}[WARN]{N} HANDOFF.md looks empty (template only?)")
                warnings += 1
        else:
            print(f"{R}[FAIL]{N} HANDOFF.md missing")
            failures += 1

        # 4. FINDINGS_QUICK_REF exists
        qref = ws / "FINDINGS_QUICK_REF.md"
        if qref.exists():
            print(f"{G}[PASS]{N} FINDINGS_QUICK_REF.md exists")
        else:
            print(f"{Y}[WARN]{N} FINDINGS_QUICK_REF.md missing")
            warnings += 1
    else:
        print(f"{Y}[WARN]{N} No workspace found for {target}")
        warnings += 1

    # 5. Uncommitted changes in vault
    try:
        import subprocess
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, cwd=ROOT
        )
        dirty = [l for l in result.stdout.strip().splitlines() if l.strip()]
        if dirty:
            print(f"{Y}[WARN]{N} {len(dirty)} uncommitted file(s) in vault")
            for f in dirty[:5]:
                print(f"       {f}")
            if len(dirty) > 5:
                print(f"       ... and {len(dirty) - 5} more")
            warnings += 1
        else:
            print(f"{G}[PASS]{N} Working tree clean")
    except Exception:
        print(f"{Y}[WARN]{N} Could not check git status")
        warnings += 1

    # 6. Evidence readiness — a finding marked ready/submitted must not rest on
    #    theoretical-only evidence (closed-loop Ring 3 → don't ship unproven).
    findings_dir = VAULT_DIR / target / "Findings"
    finding_files = sorted(findings_dir.glob("*.md")) if findings_dir.is_dir() else []
    unproven = []
    for ff in finding_files:
        text = ff.read_text(errors="ignore")
        status = _frontmatter_value(text, "status")
        if status not in ("ready", "submitted"):
            continue
        ve = _frontmatter_value(text, "verified_evidence")
        if ve in ("", "theoretical"):
            unproven.append(f"{ff.name} (status={status}, verified_evidence={ve or 'unset'})")
    if finding_files:
        if unproven:
            print(f"{R}[FAIL]{N} {len(unproven)} ready/submitted finding(s) lack proven evidence:")
            for u in unproven[:5]:
                print(f"       {u}")
            failures += 1
        else:
            print(f"{G}[PASS]{N} All ready/submitted findings carry proven evidence")

    # 7. Knowledge capture (closed-loop Ring 4) — a session that produced findings
    #    but recorded no Attempts has likely left the loop open (no back-fill).
    if finding_files:
        attempts_dir = VAULT_DIR / target / "Attempts"
        n_attempts = len(list(attempts_dir.glob("*.md"))) if attempts_dir.is_dir() else 0
        if n_attempts == 0:
            print(f"{Y}[WARN]{N} {len(finding_files)} finding(s) but 0 Attempts recorded -- "
                  f"Ring 4 (knowledge capture) may be incomplete; run knowledge-capture before closing")
            warnings += 1
        else:
            print(f"{G}[PASS]{N} Knowledge capture present ({n_attempts} attempt(s) recorded)")

    # Summary
    print(f"\n{'='*50}")
    if failures:
        print(f"{R}  {failures} failure(s), {warnings} warning(s){N}")
    elif warnings:
        print(f"{Y}  0 failures, {warnings} warning(s){N}")
    else:
        print(f"{G}  All checks passed{N}")
    print(f"{'='*50}\n")

    return failures, warnings


def release(scope: str) -> bool:
    """Release a scope lock."""
    EXPIRED_DIR.mkdir(parents=True, exist_ok=True)
    lp = lock_path(scope)

    if not lp.exists():
        print(f"No lock to release: {scope}")
        return True

    data = json.loads(lp.read_text())
    timestamp = int(time.time())
    expired_name = f"{lp.name}.{timestamp}.released"
    lp.rename(EXPIRED_DIR / expired_name)
    print(f"RELEASED: {scope} (was owned by {data.get('owner', '?')})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="End a bug bounty session: checklist + release lock")
    parser.add_argument("scope", help="Scope to release (e.g., 'gitlab', 'gitlab/oauth', '_meta')")
    parser.add_argument("--skip-checklist", action="store_true", help="Skip checklist, just release")
    args = parser.parse_args()

    target = args.scope.split("/")[0]

    if not args.skip_checklist and target != "_meta":
        failures, warnings = run_checklist(target)
        if failures:
            print("Fix failures before releasing. Use --skip-checklist to override.")
            return 1

    release(args.scope)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
