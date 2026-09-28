#!/usr/bin/env python3
"""engage.py — target intake questionnaire that writes the ledger genesis event.

The MANDATORY first step before any active operation on a target. Without a
genesis event in the ledger, engage_gate.sh blocks curl/nuclei/ffuf/etc.

Seven intake slots → profile (web|firmware|source-audit|engagement) → genesis.

Usage:
    # Interactive (prompts for each slot):
    python3 automation/engage.py <target> --interactive

    # CLI (all slots via flags):
    python3 automation/engage.py <target> \
        --type web-app \
        --scope "*.example.com" \
        --success "find vulns in the web application" \
        --auth-window "2026-09-23 to 2026-10-10" \
        --assets "https://example.com" \
        --platform hackerone \
        --restrictions "no DoS, no social engineering"

    # Check if genesis exists:
    python3 automation/engage.py <target> --check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import asg

PROFILES = {
    "web-app": "web",
    "api": "web",
    "mobile-app": "web",
    "firmware": "firmware",
    "iot-device": "firmware",
    "source-audit": "source-audit",
    "red-team-engagement": "engagement",
}

VALID_TYPES = list(PROFILES.keys())

VALID_PLATFORMS = [
    "hackerone", "bugcrowd", "intigriti", "yeswehack",
    "twcert", "hitcon-zeroday", "client-engagement", "independent",
]


def has_genesis(target: str) -> dict | None:
    """Return the genesis event if one exists, else None."""
    led = asg.ledger_path(target)
    if not led.exists():
        return None
    for line in led.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev.get("type") == "genesis":
            return ev
    return None


def derive_profile(target_type: str) -> str:
    return PROFILES.get(target_type, "web")


def write_genesis(target: str, *, target_type: str, scope: str,
                  success_criteria: str, auth_window: str, assets: str,
                  platform: str, restrictions: str) -> dict:
    """Write the genesis event to the target's ledger. Idempotent: refuses if
    genesis already exists."""
    existing = has_genesis(target)
    if existing:
        return {"ok": False, "reason": "genesis already exists",
                "existing": existing}

    profile = derive_profile(target_type)
    data = {
        "profile": profile,
        "target_type": target_type,
        "scope": scope,
        "success_criteria": success_criteria,
        "auth_window": auth_window,
        "assets": assets,
        "platform": platform,
        "restrictions": restrictions,
    }
    asg.append_event(target, "genesis", **data)
    return {"ok": True, "profile": profile, "data": data}


def interactive_intake(target: str) -> dict:
    """Prompt for each slot interactively."""
    print(f"\n=== Engage: {target} ===\n")

    print(f"Target types: {', '.join(VALID_TYPES)}")
    target_type = input("1. Target type: ").strip().lower()
    if target_type not in VALID_TYPES:
        print(f"WARNING: '{target_type}' not in known types, defaulting to 'web-app'")
        target_type = "web-app"

    success_criteria = input("2. Success criteria (what counts as a win): ").strip()
    scope = input("3. Scope (domains, IPs, repos, models): ").strip()
    auth_window = input("4. Authorization window (dates or 'open-ended'): ").strip()
    assets = input("5. Assets (URLs, firmware files, source repos): ").strip()

    print(f"Platforms: {', '.join(VALID_PLATFORMS)}")
    platform = input("6. Platform: ").strip().lower()
    if platform not in VALID_PLATFORMS:
        print(f"WARNING: '{platform}' not in known platforms, using as-is")

    restrictions = input("7. Restrictions (off-limits actions): ").strip()

    return {
        "target_type": target_type,
        "scope": scope,
        "success_criteria": success_criteria or "find and report vulnerabilities",
        "auth_window": auth_window or "open-ended",
        "assets": assets,
        "platform": platform or "independent",
        "restrictions": restrictions or "none specified",
    }


def main():
    parser = argparse.ArgumentParser(description="Target intake questionnaire")
    parser.add_argument("target", help="Target name (directory under 01 - Targets/)")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive prompt mode")
    parser.add_argument("--check", action="store_true",
                        help="Check if genesis exists, exit 0 if yes, 1 if no")
    parser.add_argument("--type", dest="target_type", choices=VALID_TYPES)
    parser.add_argument("--scope", default="")
    parser.add_argument("--success", dest="success_criteria", default="")
    parser.add_argument("--auth-window", default="open-ended")
    parser.add_argument("--assets", default="")
    parser.add_argument("--platform", default="independent")
    parser.add_argument("--restrictions", default="none specified")
    parser.add_argument("--json", action="store_true",
                        help="Output result as JSON")
    args = parser.parse_args()

    if args.check:
        g = has_genesis(args.target)
        if g:
            if args.json:
                print(json.dumps(g, ensure_ascii=False))
            else:
                print(f"✓ genesis exists — profile={g.get('profile')}, "
                      f"type={g.get('target_type')}, at={g.get('at', '?')}")
            sys.exit(0)
        else:
            if not args.json:
                print(f"✗ no genesis for {args.target}")
            sys.exit(1)

    if args.interactive:
        slots = interactive_intake(args.target)
    elif args.target_type:
        slots = {
            "target_type": args.target_type,
            "scope": args.scope,
            "success_criteria": args.success_criteria or "find and report vulnerabilities",
            "auth_window": args.auth_window,
            "assets": args.assets,
            "platform": args.platform,
            "restrictions": args.restrictions,
        }
    else:
        parser.error("need --interactive or --type")
        return

    result = write_genesis(args.target, **slots)

    if args.json:
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(0 if result["ok"] else 1)
    elif result["ok"]:
        print(f"\n✓ Genesis written — profile: {result['profile']}")
        print(f"  Target: {args.target}")
        print(f"  Ledger: {asg.ledger_path(args.target)}")
        print(f"\n  Next: run surface mapping → hunting")
    else:
        print(f"\n⚠ {result['reason']}")
        print(f"  Existing genesis at: {result['existing'].get('at', '?')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
