#!/usr/bin/env python3
"""Bootstrap a private vault from this public seed framework."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SEED_PATHS = [
    ".obsidian",
    "agents",
    "bbflow",
    "docs",
    "hooks",
    "prompts",
    "scripts",
    "skills",
    "templates",
    "workspace",
    ".gitignore",
    "LICENSE",
    "README.md",
]

SKIP_PARTS = {".git", ".pytest_cache", "__pycache__"}


def should_skip(path: Path) -> bool:
    return bool(SKIP_PARTS.intersection(path.parts))


def copy_file(src: Path, dst: Path, overwrite: bool) -> str:
    if dst.exists() and not overwrite:
        return "skipped"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return "copied"


def copy_tree(src: Path, dst: Path, overwrite: bool) -> tuple[int, int]:
    copied = 0
    skipped = 0
    for path in src.rglob("*"):
        if should_skip(path):
            continue
        rel = path.relative_to(src)
        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        result = copy_file(path, target, overwrite)
        copied += result == "copied"
        skipped += result == "skipped"
    return copied, skipped


def bootstrap(destination: Path, overwrite: bool) -> tuple[int, int]:
    destination = destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        raise ValueError("destination must be outside the public seed repository")

    copied = 0
    skipped = 0
    destination.mkdir(parents=True, exist_ok=True)

    for rel in SEED_PATHS:
        src = ROOT / rel
        dst = destination / rel
        if src.is_dir():
            c, s = copy_tree(src, dst, overwrite)
            copied += c
            skipped += s
        else:
            result = copy_file(src, dst, overwrite)
            copied += result == "copied"
            skipped += result == "skipped"

    return copied, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="Destination path for the private vault")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing seed files")
    args = parser.parse_args(argv)

    try:
        copied, skipped = bootstrap(Path(args.destination), args.overwrite)
    except ValueError as exc:
        print(f"[fail] {exc}", file=sys.stderr)
        return 2

    print(f"[ok] private vault scaffold ready: {Path(args.destination)}")
    print(f"[ok] copied={copied} skipped={skipped}")
    print("[next] Open the destination as an Obsidian vault root.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
