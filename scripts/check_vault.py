#!/usr/bin/env python3
"""Check that the public vault scaffold still respects the framework boundary."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import verify_public_skeleton


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)

    try:
        result = verify_public_skeleton.main()
    except SystemExit as exc:
        return int(exc.code or 1)

    if result != 0:
        return result

    print("[ok] vault scaffold check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

