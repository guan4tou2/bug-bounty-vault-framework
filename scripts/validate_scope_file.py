#!/usr/bin/env python3
"""Validate the public bbflow v1 scope file shape without external packages."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REQUIRED_KEYS = {
    "version",
    "name",
    "owner",
    "authorized_until",
    "safety_level",
    "allowed_assets",
    "disallowed_assets",
    "allowed_actions",
    "disallowed_actions",
    "output_dir",
}

ALLOWED_SAFETY_LEVELS = {"passive", "low", "active", "<passive | low | active>"}


def top_level_key(line: str) -> str | None:
    if not line or line.startswith("#") or line[0].isspace() or ":" not in line:
        return None
    return line.split(":", 1)[0].strip()


def scalar_value(text: str, key: str) -> str | None:
    prefix = f"{key}:"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip().strip('"')
    return None


def list_values(text: str, key: str) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []
    in_section = False

    for line in lines:
        if line.startswith(f"{key}:"):
            in_section = True
            continue
        if in_section and line and not line[0].isspace():
            break
        if in_section and line.strip().startswith("- "):
            values.append(line.strip()[2:].strip().strip('"'))

    return values


def validate_scope(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    keys = {key for line in text.splitlines() if (key := top_level_key(line))}
    errors: list[str] = []

    missing = sorted(REQUIRED_KEYS - keys)
    if missing:
        errors.append(f"missing required keys: {', '.join(missing)}")

    version = scalar_value(text, "version")
    if version != "1":
        errors.append("version must be 1")

    safety_level = scalar_value(text, "safety_level")
    if safety_level not in ALLOWED_SAFETY_LEVELS:
        errors.append("safety_level must be passive, low, or active")

    if not list_values(text, "allowed_assets"):
        errors.append("allowed_assets must contain at least one entry")

    if not list_values(text, "allowed_actions"):
        errors.append("allowed_actions must contain at least one entry")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope_file", nargs="?", help="Path to a bbflow v1 scope YAML file")
    parser.add_argument(
        "--allow-no-scope",
        action="store_true",
        help="Return success when no scope file is provided; intended only for bootstrap checks.",
    )
    args = parser.parse_args(argv)

    if not args.scope_file:
        if args.allow_no_scope:
            print("[ok] no scope file provided; allowed by explicit flag")
            return 0
        print("[fail] scope file is required", file=sys.stderr)
        return 2

    path = Path(args.scope_file)
    if not path.exists():
        print(f"[fail] scope file not found: {path}", file=sys.stderr)
        return 2

    errors = validate_scope(path)
    if errors:
        for error in errors:
            print(f"[fail] {error}", file=sys.stderr)
        return 1

    print(f"[ok] valid scope v1: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

