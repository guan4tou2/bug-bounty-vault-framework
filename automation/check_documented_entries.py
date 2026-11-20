#!/usr/bin/env python3
"""Verify that modules listed in docs/public-vs-private.md exist on disk.

Run from either the framework or vault repo root:
    python3 automation/check_documented_entries.py
    python3 automation/check_documented_entries.py --repo vault
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_capability_table(doc: Path) -> list[dict]:
    entries: list[dict] = []
    in_table = False
    headers: list[str] = []
    for line in doc.read_text(encoding="utf-8").splitlines():
        if re.match(r"\|\s*Module\s*\|", line):
            headers = [h.strip() for h in line.split("|")[1:-1]]
            in_table = True
            continue
        if in_table and re.match(r"\|[-| ]+\|$", line):
            continue
        if in_table and line.startswith("|"):
            cols = [c.strip() for c in line.split("|")[1:-1]]
            if len(cols) >= len(headers):
                row = dict(zip(headers, cols))
                m = re.match(r"`([^`]+)`", row.get("Module", ""))
                if m:
                    entries.append({
                        "module": m.group(1),
                        "framework": row.get("Framework", "").strip() == "Y",
                        "vault": row.get("Vault", "").strip() == "Y",
                    })
        elif in_table and not line.startswith("|"):
            in_table = False
    return entries


def check(entries: list[dict], repo: str, auto_root: Path) -> list[str]:
    errors = []
    for e in entries:
        expected = e.get(repo, False)
        path = auto_root / e["module"]
        exists = path.is_file()
        if expected and not exists:
            errors.append(f"MISSING: {e['module']} documented as present in {repo} but not found at {path}")
        elif not expected and exists:
            errors.append(f"UNDOCUMENTED: {e['module']} exists at {path} but docs say {repo} = —")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", choices=["framework", "vault"], default=None,
                    help="Which repo to check (auto-detected from cwd if omitted)")
    ap.add_argument("--doc", type=Path, default=None,
                    help="Path to public-vs-private.md (default: docs/public-vs-private.md)")
    args = ap.parse_args()

    doc = args.doc or ROOT / "docs" / "public-vs-private.md"
    if not doc.is_file():
        print(f"ERROR: capability doc not found: {doc}", file=sys.stderr)
        return 1

    entries = parse_capability_table(doc)
    if not entries:
        print("WARNING: no module entries found in capability table", file=sys.stderr)
        return 1

    repo = args.repo
    if repo is None:
        if (ROOT / "automation" / "gen_handoff_capsule.py").is_file():
            repo = "vault"
        elif (ROOT / "docs" / "private-adapters.md").is_file():
            repo = "framework"
        else:
            repo = "framework"

    auto_root = ROOT / "automation"
    print(f"Repo root: {ROOT}  (detected as: {repo})")
    errors = check(entries, repo, auto_root)

    print(f"Checked {len(entries)} documented entries against {repo} (automation/)")
    if errors:
        for e in errors:
            print(f"  {e}")
        print(f"\n{len(errors)} issue(s) found — update docs/public-vs-private.md or add missing modules")
        return 1
    print("All documented entries verified ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
