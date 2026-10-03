#!/usr/bin/env python3
"""Redact third-party identity from raw responses before they enter version control.

A vault's .gitignore typically excludes *.png but NOT *.txt — so an evidence text file
dropped into Evidence/ gets committed. Raw responses often carry real names, company
names, and tenant identifiers belonging to the program's customers, which should not sit
in your git history.

Redact identity, not structure: total / counts / HTTP status / error codes / field names
are all kept. A "cross-tenant" claim rests on the NUMBER of distinct identifiers, not on
the names themselves.

Usage:
    python3 automation/redact_evidence.py <in> [<in>...] --out <dir>
    python3 automation/redact_evidence.py --self-test
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# JSON-style "key":"value" key names. Case-insensitive.
#
# This list is filled in case by case, so it necessarily lags the real field names. Two
# traps worth knowing: (1) the list had "email" but not "emailAddress", and matching is
# whole-key-equality, so emailAddress slipped through — hence KV_RE also allows a trailing
# plural "s" (contact vs contacts). Do NOT make it a prefix wildcard: that would also mask
# structural fields like appName / fileName and the evidence becomes unreadable.
# (2) key-name matching can never be complete — always ALSO run a format scan (national ID
# / tax ID / phone / card patterns) as a second pass. A real tax ID once survived the
# key-based pass and was only caught by an 18-digit-format scan.
PII_KEYS = [
    "tenantName", "createById", "modifyById", "createByName", "modifyByName",
    "userName", "name", "email", "mail", "phone", "mobile", "goodsName",
    "orderCode", "customerName", "contact", "contactName", "company",
    "companyName", "creditCode", "address", "account", "devKey", "devSecret",
    "createUserId", "createUserName", "updateUserId", "updateUserName",
    "emailAddress", "userId", "operatorName", "applicantName", "costName",
    "examName", "tenantId",
    "licenseNo", "licenceNo", "taxId", "businessId", "customerId", "idNo",
]

MASK = "<redacted>"

# "key":"value" / "key": "value", where value has no unescaped double quote.
KV_RE = re.compile(
    r'("(?:' + "|".join(PII_KEYS) + r')s?"\s*:\s*)"((?:[^"\\]|\\.)*)"',
    re.IGNORECASE,
)

# Nested escaped JSON: a response often stuffs a whole JSON array into a string value, so
# the inner layer becomes:
#   "org":"[{\"id\":\"C01\",\"name\":\"Acme Industries Co Ltd\"}]"
# A top-level "key":"value" match misses this shape entirely — and that is exactly where
# full customer company names tend to live. A tool that claims to redact N spots while
# leaving company names is worse than no tool: it makes people stop checking.
ESC_KV_RE = re.compile(
    r'(\\"(?:' + "|".join(PII_KEYS) + r')\\"\s*:\s*)\\"((?:[^"\\]|\\\\.)*?)\\"',
    re.IGNORECASE,
)

# 10+ consecutive digits = a platform sid. Keep the first 4 for cross-reference, mask rest.
SID_RE = re.compile(r"\b(\d{4})(\d{6,})\b")


def mask_value(value: str) -> str:
    if not value:
        return value
    return f"{value[0]}{MASK}(len={len(value)})"


def redact_text(text: str) -> tuple[str, int]:
    count = 0

    def kv_sub(m):
        nonlocal count
        count += 1
        return f'{m.group(1)}"{mask_value(m.group(2))}"'

    out = KV_RE.sub(kv_sub, text)

    def esc_sub(m):
        nonlocal count
        count += 1
        return f'{m.group(1)}\\"{mask_value(m.group(2))}\\"'

    out = ESC_KV_RE.sub(esc_sub, out)

    def sid_sub(m):
        nonlocal count
        count += 1
        return f"{m.group(1)}{'*' * len(m.group(2))}"

    out = SID_RE.sub(sid_sub, out)
    return out, count


def self_test() -> int:
    """If the redactor itself is wrong, it ships PII into git — so it self-verifies.

    Fixtures are synthetic (no real identities)."""
    cases = [
        # (input, string that MUST vanish, string that MUST remain)
        ('{"createById":"Jane Roe","total":173}', "Jane Roe", "173"),
        ('{"tenantName": "Acme Industries Co Ltd"}', "Acme Industries", "tenantName"),
        ('{"tenantSid":43101328560704}', "43101328560704", "4310"),
        ('{"code":200,"message":"success"}', None, "success"),
        ('{"errorCode":"21002","message":"invalid user or password"}', None, "21002"),
        # nested escaped JSON — a top-level match misses this, and company names live here
        (r'{"org":"[{\"id\":\"C01\",\"name\":\"Acme Industries Co Ltd\"}]"}',
         "Acme Industries", "C01"),
        (r'{"app":"[{\"id\":\"trm-DW\",\"name\":\"Travel Helper 2.0\"}]"}', None, "trm-DW"),
    ]
    failed = 0
    for src, must_vanish, must_keep in cases:
        out, _ = redact_text(src)
        if must_vanish and must_vanish in out:
            print(f"FAIL did not mask {must_vanish!r}: {out}")
            failed += 1
        if must_keep not in out:
            print(f"FAIL over-masked, {must_keep!r} gone: {out}")
            failed += 1
    print("self-test passed" if not failed else f"self-test {failed} case(s) failed")
    return failed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="*", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.inputs or not args.out:
        ap.error("inputs and --out are required")

    args.out.mkdir(parents=True, exist_ok=True)
    for src in args.inputs:
        text = src.read_text(encoding="utf-8", errors="replace")
        out, n = redact_text(text)
        dst = args.out / src.name
        # Files with YAML frontmatter (Finding / FORM / Attempt): do NOT prepend a header.
        # Prepending pushes `---` off line 1, so a frontmatter linter reports "missing YAML
        # frontmatter". The header only makes sense for bare Evidence/ .txt files.
        has_fm = text.lstrip().startswith("---")
        header = "" if has_fm else (
            f"# source: {src.name}\n"
            f"# de-identified: {n} spot(s). Names/company/credentials -> first char + length;"
            f" 10+ digit identifiers keep the first 4.\n"
            f"# What remains (HTTP status, error codes, total, counts, field names) is the"
            f" basis of each report.\n\n"
        )
        dst.write_text(header + out, encoding="utf-8")
        note = " (frontmatter file, no header added)" if has_fm else ""
        print(f"{src.name} -> {dst}  (redacted {n}){note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
