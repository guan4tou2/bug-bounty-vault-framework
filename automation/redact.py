#!/usr/bin/env python3
"""Telemetry redaction — mask target identifiers with stable placeholders.

Adapted from Decepticon's redact.py. Replaces target identifiers with
human-readable, typed, numbered placeholders so session logs, KB entries,
and attack chains can be shared without leaking engagement-specific data.

Three detection layers, highest confidence first:

1. Known engagement targets (from SCOPE.md or --known) — ground truth.
2. Standard PII patterns: IPv4, IPv6, MAC, URL, email.
3. Custom detectors: private keys, JWTs, AWS keys, credentials,
   opaque blobs, glued IPs, bare domains.

Usage:
    python3 -I automation/redact.py --scope SCOPE.md <file>
    python3 -I automation/redact.py --known host1,host2 --mapping <file>
    cat session.log | python3 -I automation/redact.py --scope SCOPE.md -
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ── type aliases ─────────────────────────────────────────────────────────────

Detector = Callable[[str], list[tuple[int, int, str]]]

# ── regex patterns ───────────────────────────────────────────────────────────

# Layer 2: standard PII
_IP4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IP6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_URL = re.compile(r"\bhttps?://[^\s)\]\"'<>]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Layer 3: custom detectors
_KEY = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
)
_AWSKEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_CRED_AT = re.compile(r"\b[\w.-]+:[^\s:@/]{3,}@[\w.-]+")
_CRED_SPECIAL = re.compile(r"\b[\w.-]+:[^\s:@/]*[!@#$%^&*+=][^\s:@/]*")
_CRED_SECRET_KV = re.compile(
    r"(?:password|passwd|pwd|pass|senha|contrase\w+|"
    r"secret|token|api[_-]?key)"
    r"\s*(?:[:=]|\s+(?:is|es)\s+)\s*([^\s,;\"']{3,64})",
    re.IGNORECASE,
)
_CRED_USER_KV = re.compile(
    r"(?:login|username|user)[:=]([^\s,;\"']{3,64})", re.IGNORECASE
)
_CRED_PW_FLAG = re.compile(
    r"(?:^|\s)--?(?:p|pw|pass|passwd|password)[=\s]+"
    r"['\"]?(?![\d,\-]+(?:\s|$|['\"]))([^\s'\"]{3,64})",
    re.IGNORECASE,
)
_CRED_USERPASS_FLAG = re.compile(
    r"(?:^|\s)--?(?:u|user|username)[=\s]+"
    r"['\"]?([^\s'\":]{1,64}:[^\s'\"]{1,64})",
    re.IGNORECASE,
)
_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_IP_GLUED = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b(?!\()",
    re.IGNORECASE,
)

# ── priority map (lower = higher priority) ───────────────────────────────────

_PRIORITY: dict[str, int] = {
    "HOST": 0,
    "KEY": 1,
    "JWT": 1,
    "AWSKEY": 1,
    "CRED": 2,
    "BLOB": 3,
    "IP": 4,
    "MAC": 4,
    "IP6": 5,
    "URL": 6,
    "EMAIL": 7,
    "DOMAIN": 8,
}


# ── helpers ──────────────────────────────────────────────────────────────────


def _regex_detector(pattern: re.Pattern[str]) -> Detector:
    def detect(text: str) -> list[tuple[int, int, str]]:
        return [(m.start(), m.end(), m.group(0)) for m in pattern.finditer(text)]
    return detect


def _group_detector(pattern: re.Pattern[str], group: int = 1) -> Detector:
    def detect(text: str) -> list[tuple[int, int, str]]:
        return [
            (m.start(group), m.end(group), m.group(group))
            for m in pattern.finditer(text)
            if m.group(group)
        ]
    return detect


# ── SCOPE.md parsing (reused pattern from scope_check.py) ───────────────────


def _parse_yaml_frontmatter(text: str) -> dict[str, Any] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    block = text[4:end]
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[str] | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current_key is not None and current_list is not None:
                current_list.append(stripped[2:].strip().strip("\"'"))
            continue
        if ":" in stripped:
            if current_key is not None and current_list is not None:
                result[current_key] = current_list
            current_list = None
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip("\"'")
            if not val:
                current_key = key
                current_list = []
            else:
                current_key = None
                result[key] = val
    if current_key is not None and current_list is not None:
        result[current_key] = current_list
    return result if result else None


def _parse_freeform_scope(text: str) -> list[str]:
    targets: list[str] = []
    capture = False
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("## in") and "scope" in lower:
            capture = True
            continue
        if lower.startswith("## ") and capture:
            break
        if capture and stripped.startswith("- "):
            targets.append(stripped[2:].strip().strip("`\"'"))
    return targets


def _extract_host(entry: str) -> str:
    """Extract hostname/IP from a scope entry (may be URL, CIDR, glob)."""
    if "://" in entry:
        from urllib.parse import urlsplit
        return urlsplit(entry).hostname or entry
    if ":" in entry and not entry.startswith("["):
        host, _, _ = entry.partition(":")
        return host
    if "/" in entry and not entry.startswith("*."):
        base, _, _ = entry.partition("/")
        return base
    return entry.lstrip("*.")


def load_known_from_scope(path: str | Path) -> list[str]:
    """Load known target identifiers from SCOPE.md."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    targets: list[str] = []
    fm = _parse_yaml_frontmatter(text)
    if fm:
        raw = fm.get("in_scope", [])
        if isinstance(raw, list):
            targets.extend(raw)
    if not targets:
        targets = _parse_freeform_scope(text)
    known: list[str] = []
    for t in targets:
        host = _extract_host(t)
        if host:
            known.append(host)
        if t != host:
            known.append(t)
    return known


# ── Redactor ─────────────────────────────────────────────────────────────────


@dataclass
class Redactor:
    """Stateful identifier masker with stable, typed placeholders."""

    _map: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)
    _known: list[tuple[str, str]] = field(default_factory=list)
    _detectors: list[tuple[str, Detector]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self._detectors:
            self._detectors = [
                ("KEY", _regex_detector(_KEY)),
                ("JWT", _regex_detector(_JWT)),
                ("AWSKEY", _regex_detector(_AWSKEY)),
                ("CRED", _regex_detector(_CRED_AT)),
                ("CRED", _regex_detector(_CRED_SPECIAL)),
                ("CRED", _group_detector(_CRED_SECRET_KV)),
                ("CRED", _group_detector(_CRED_USER_KV)),
                ("CRED", _group_detector(_CRED_PW_FLAG)),
                ("CRED", _group_detector(_CRED_USERPASS_FLAG)),
                ("IP", _regex_detector(_IP_GLUED)),
                ("BLOB", _regex_detector(_BLOB)),
                ("IP", _regex_detector(_IP4)),
                ("MAC", _regex_detector(_MAC)),
                ("IP6", _regex_detector(_IP6)),
                ("URL", _regex_detector(_URL)),
                ("EMAIL", _regex_detector(_EMAIL)),
                ("DOMAIN", _regex_detector(_DOMAIN)),
            ]

    def add_known(self, targets: list[str], ptype: str = "HOST") -> None:
        merged = set(self._known)
        merged.update((t, ptype) for t in targets if t)
        self._known = sorted(merged, key=lambda kv: len(kv[0]), reverse=True)

    def _placeholder(self, value: str, ptype: str) -> str:
        existing = self._map.get(value)
        if existing is not None:
            return existing
        n = self._counters.get(ptype, 0) + 1
        self._counters[ptype] = n
        token = f"<{ptype}_{n}>"
        self._map[value] = token
        return token

    def redact(self, text: str) -> str:
        if not text:
            return text
        spans: list[tuple[int, int, str, str]] = []
        for target, ktype in self._known:
            for m in re.finditer(re.escape(target), text, re.IGNORECASE):
                spans.append((m.start(), m.end(), ktype, m.group(0)))
        for ptype, detect in self._detectors:
            for start, end, value in detect(text):
                spans.append((start, end, ptype, value))
        if not spans:
            return text
        spans.sort(
            key=lambda s: (s[0], -(s[1] - s[0]), _PRIORITY.get(s[2], 99))
        )
        chosen: list[tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, ptype, value in spans:
            if start >= last_end:
                chosen.append((start, end, ptype, value))
                last_end = end
        for _, _, ptype, value in chosen:
            self._placeholder(value, ptype)
        out = text
        for start, end, ptype, value in sorted(
            chosen, key=lambda s: s[0], reverse=True
        ):
            out = out[:start] + self._placeholder(value, ptype) + out[end:]
        return out

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._map)


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mask target identifiers with stable typed placeholders."
    )
    parser.add_argument(
        "file", nargs="?", default=None,
        help="File to redact (use '-' for stdin)"
    )
    parser.add_argument("--scope", help="Path to SCOPE.md for known targets")
    parser.add_argument(
        "--known",
        help="Comma-separated known targets (alternative to --scope)",
    )
    parser.add_argument(
        "--in-place", action="store_true",
        help="Overwrite file with redacted content",
    )
    parser.add_argument(
        "--mapping", action="store_true",
        help="Print placeholder-to-original mapping to stderr",
    )
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        sys.exit(0)

    redactor = Redactor()

    if args.scope:
        known = load_known_from_scope(args.scope)
        if known:
            redactor.add_known(known)

    if args.known:
        targets = [t.strip() for t in args.known.split(",") if t.strip()]
        redactor.add_known(targets)

    if args.file == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")

    result = redactor.redact(text)

    if args.in_place and args.file != "-":
        Path(args.file).write_text(result, encoding="utf-8")
    else:
        sys.stdout.write(result)

    if args.mapping:
        for original, placeholder in sorted(
            redactor.mapping.items(), key=lambda kv: kv[1]
        ):
            print(f"{placeholder} = {original}", file=sys.stderr)


if __name__ == "__main__":
    main()
