#!/usr/bin/env python3
"""Programmatic RoE scope validator — machine-readable scope enforcement.

Adapted from Decepticon's roe.py. Parses SCOPE.md (YAML frontmatter or
freeform Markdown sections) and evaluates targets, commands, and time
windows against the declared scope.

Fail-closed: missing or malformed SCOPE.md refuses all gated actions.

Usage:
    python3 -I automation/scope_check.py --target <host> --scope <path>
    python3 -I automation/scope_check.py --command <cmd> --scope <path>
    python3 -I automation/scope_check.py --time-check --scope <path>
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

# ── defaults ────────────────────────────────────────────────────────────────

DEFAULT_FORBIDDEN_DESTS: tuple[str, ...] = (
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",
)

DEFAULT_SENSITIVE_TLDS: tuple[str, ...] = (".gov", ".mil", ".edu", ".int")

# ── data types ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason_code: str
    reason_detail: str
    risk: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "reason_code": self.reason_code,
            "reason_detail": self.reason_detail,
            "risk": self.risk,
        }

    @classmethod
    def allow_default(cls) -> Decision:
        return cls(allow=True, reason_code="OK", reason_detail="no rules matched")

    @classmethod
    def refuse(cls, code: str, detail: str, risk: str = "high") -> Decision:
        return cls(allow=False, reason_code=code, reason_detail=detail, risk=risk)


@dataclass(frozen=True)
class ScopeRule:
    pattern: str
    kind: str = "auto"

    def resolved_kind(self) -> str:
        if self.kind != "auto":
            return self.kind
        try:
            ipaddress.ip_network(self.pattern, strict=False)
            return "cidr"
        except ValueError:
            pass
        if "*" in self.pattern or "?" in self.pattern:
            return "domain-glob"
        first = self.pattern[:1]
        if first and first.isdigit():
            try:
                ipaddress.ip_address(self.pattern)
                return "ip"
            except ValueError:
                pass
        return "host"


@dataclass(frozen=True)
class ScopeConfig:
    configured: bool = True
    in_scope: tuple[ScopeRule, ...] = field(default_factory=tuple)
    out_of_scope: tuple[ScopeRule, ...] = field(default_factory=tuple)
    forbidden_destinations: tuple[str, ...] = field(default_factory=tuple)
    forbidden_commands: tuple[str, ...] = field(default_factory=tuple)
    allow_cloud_metadata: bool = False
    allow_sensitive_tlds: bool = False
    authorized_windows: tuple[tuple[datetime, datetime], ...] = field(
        default_factory=tuple
    )
    blackout_windows: tuple[tuple[datetime, datetime], ...] = field(
        default_factory=tuple
    )

    def effective_forbidden_destinations(self) -> tuple[str, ...]:
        if self.allow_cloud_metadata:
            return self.forbidden_destinations
        return self.forbidden_destinations + DEFAULT_FORBIDDEN_DESTS


# ── normalization (mirrors Decepticon's roe.py) ────────────────────────────


def _normalize_hostname(host: str) -> str:
    value = (host or "").strip().rstrip(".").lower()
    if not value:
        return ""
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return value
    return value


def _looks_like_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return value.count(":") > 1


def normalize_scope_target(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    if "://" in value or value.startswith("//"):
        host = urlsplit(value).hostname
        return _normalize_hostname(host or "")
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    value = value.split("/", 1)[0]
    if "@" in value:
        value = value.rpartition("@")[2]
    if value.startswith("["):
        value = value[1:].partition("]")[0]
    elif ":" in value and not _looks_like_ipv6(value):
        value = value.split(":", 1)[0]
    if set(value) <= {"*", "."}:
        return value
    return _normalize_hostname(value)


_HOST_SCOPE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-*?:")


def _is_dead_pattern(pattern: str) -> bool:
    try:
        ipaddress.ip_network(pattern, strict=False)
        return False
    except ValueError:
        pass
    if not pattern or any(c not in _HOST_SCOPE_CHARS for c in pattern):
        return True
    if pattern.startswith("*."):
        body = pattern[2:]
        return not body or any(part == "" for part in body.split("."))
    if "*" in pattern or "?" in pattern:
        return False
    return any(part == "" for part in pattern.split("."))


# ── matching ────────────────────────────────────────────────────────────────


def matches_domain_glob(pattern: str, candidate: str) -> bool:
    regex = re.escape(pattern).replace(r"\*", "[^.]+").replace(r"\?", "[^.]")
    return re.fullmatch(regex, candidate, re.IGNORECASE) is not None


def _matches_rule(rule: ScopeRule, target: str, *, deny: bool = False) -> bool:
    pattern = rule.pattern
    if pattern.lower().startswith(("http://", "https://")):
        parsed = urlsplit(pattern)
        if not parsed.hostname:
            return False
        pattern = parsed.hostname
    kind = rule.resolved_kind() if pattern == rule.pattern else "host"
    norm_target = target.rstrip(".")
    if kind == "cidr":
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(norm_target) in network
        except ValueError:
            return False
    if kind == "domain-glob":
        return matches_domain_glob(pattern.rstrip("."), norm_target)
    return pattern.rstrip(".").lower() == norm_target.lower()


def _sensitive_tld_match(target: str) -> str | None:
    host = target.strip().lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    base, _, port = host.rpartition(":")
    if base and port.isdigit():
        host = base
    return next((tld for tld in DEFAULT_SENSITIVE_TLDS if host.endswith(tld)), None)


# ── evaluators ──────────────────────────────────────────────────────────────


def evaluate_target(target: str, config: ScopeConfig) -> Decision:
    if not target:
        return Decision.allow_default()
    if not config.configured:
        return Decision.refuse(
            "NO_SCOPE_CONFIG",
            "SCOPE.md missing or malformed — fail-closed",
        )
    for forbidden in config.effective_forbidden_destinations():
        if _matches_rule(ScopeRule(pattern=forbidden), target):
            return Decision.refuse(
                "FORBIDDEN_DESTINATION",
                f"{target!r} matches forbidden destination {forbidden!r}",
            )
    if not config.allow_sensitive_tlds:
        sensitive = _sensitive_tld_match(target)
        if sensitive is not None:
            return Decision.refuse(
                "SENSITIVE_TLD",
                f"{target!r} is on the high-collateral {sensitive!r} TLD; "
                "set allow_sensitive_tlds: true to scope it deliberately",
            )
    for rule in config.out_of_scope:
        if _matches_rule(rule, target, deny=True):
            return Decision.refuse(
                "OUT_OF_SCOPE",
                f"{target!r} matches out-of-scope entry {rule.pattern!r}",
            )
    if config.in_scope:
        for rule in config.in_scope:
            if _matches_rule(rule, target):
                return Decision(
                    allow=True,
                    reason_code="IN_SCOPE",
                    reason_detail=f"{target!r} matches in-scope entry {rule.pattern!r}",
                )
        return Decision.refuse(
            "NOT_IN_SCOPE",
            f"{target!r} matches no in-scope entry",
            risk="medium",
        )
    return Decision.allow_default()


def evaluate_command(command: str, config: ScopeConfig) -> Decision:
    if not command:
        return Decision.allow_default()
    if not config.configured:
        return Decision.refuse(
            "NO_SCOPE_CONFIG",
            "SCOPE.md missing or malformed — fail-closed",
        )
    for pattern in config.forbidden_commands:
        try:
            if re.search(pattern, command):
                return Decision.refuse(
                    "FORBIDDEN_COMMAND",
                    f"command matched forbidden pattern {pattern!r}",
                )
        except re.error:
            continue
    return Decision.allow_default()


def evaluate_time_window(now: datetime, config: ScopeConfig) -> Decision:
    if not config.configured:
        return Decision.refuse(
            "NO_SCOPE_CONFIG",
            "SCOPE.md missing or malformed — fail-closed",
        )
    for start, end in config.blackout_windows:
        if start <= now < end:
            return Decision.refuse(
                "BLACKOUT_WINDOW",
                f"{now.isoformat()} falls inside blackout window "
                f"{start.isoformat()}..{end.isoformat()}",
            )
    if config.authorized_windows:
        for start, end in config.authorized_windows:
            if start <= now < end:
                return Decision(
                    allow=True,
                    reason_code="IN_TESTING_WINDOW",
                    reason_detail=f"{now.isoformat()} is inside authorized window",
                )
        return Decision.refuse(
            "OUTSIDE_TESTING_WINDOW",
            f"{now.isoformat()} is outside all authorized testing windows",
            risk="medium",
        )
    return Decision.allow_default()


# ── SCOPE.md parsing ────────────────────────────────────────────────────────


def _parse_yaml_frontmatter(text: str) -> dict[str, Any] | None:
    """Minimal YAML-subset parser for frontmatter (stdlib only, no PyYAML).

    Handles top-level scalars (key: value) and one-level lists (- item).
    Sufficient for SCOPE.md frontmatter; not a general YAML parser.
    """
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
                if val.lower() in ("true", "yes"):
                    result[key] = True
                elif val.lower() in ("false", "no"):
                    result[key] = False
                else:
                    try:
                        result[key] = int(val)
                    except ValueError:
                        result[key] = val

    if current_key is not None and current_list is not None:
        result[current_key] = current_list
    return result if result else None


def _parse_freeform_scope(text: str) -> tuple[list[str], list[str]]:
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("## in") and "scope" in lower:
            current = in_scope
            continue
        if lower.startswith("## out") and "scope" in lower:
            current = out_of_scope
            continue
        if stripped.startswith("## "):
            current = None
            continue
        if current is not None and stripped.startswith("- "):
            entry = stripped[2:].strip().strip("`")
            if entry:
                current.append(entry)
    return in_scope, out_of_scope


def _parse_windows(items: Any) -> list[tuple[datetime, datetime]]:
    if not isinstance(items, list):
        return []
    windows: list[tuple[datetime, datetime]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            start = datetime.fromisoformat(str(item.get("start", "")))
            end = datetime.fromisoformat(str(item.get("end", "")))
        except (ValueError, TypeError):
            continue
        if end > start:
            windows.append((start, end))
    return windows


def _build_rules(targets: list[str]) -> list[ScopeRule]:
    rules: list[ScopeRule] = []
    for raw in targets:
        norm = normalize_scope_target(raw)
        if not norm or _is_dead_pattern(norm):
            log.warning("dropping scope target %r: no DNS/IP target can match it", raw)
            continue
        rules.append(ScopeRule(pattern=norm))
    return rules


def load_scope(path: str | Path) -> ScopeConfig:
    p = Path(path)
    if not p.exists():
        log.warning("SCOPE.md not found at %s — fail-closed", p)
        return ScopeConfig(configured=False)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("cannot read %s: %s — fail-closed", p, exc)
        return ScopeConfig(configured=False)

    fm = _parse_yaml_frontmatter(text)
    if fm and isinstance(fm, dict):
        raw_in = fm.get("in_scope") or []
        raw_out = fm.get("out_of_scope") or []
        if not isinstance(raw_in, list):
            raw_in = [str(raw_in)]
        if not isinstance(raw_out, list):
            raw_out = [str(raw_out)]
    else:
        raw_in, raw_out = _parse_freeform_scope(text)

    if not raw_in:
        log.warning("no in-scope targets found in %s — fail-closed", p)
        return ScopeConfig(configured=False)

    fm = fm or {}
    return ScopeConfig(
        configured=True,
        in_scope=tuple(_build_rules([str(t) for t in raw_in])),
        out_of_scope=tuple(_build_rules([str(t) for t in raw_out])),
        forbidden_destinations=tuple(fm.get("forbidden_destinations") or ()),
        forbidden_commands=tuple(fm.get("forbidden_commands") or ()),
        allow_cloud_metadata=bool(fm.get("allow_cloud_metadata", False)),
        allow_sensitive_tlds=bool(fm.get("allow_sensitive_tlds", False)),
        authorized_windows=tuple(_parse_windows(fm.get("authorized_windows"))),
        blackout_windows=tuple(_parse_windows(fm.get("blackout_windows"))),
    )


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Programmatic RoE scope validator (fail-closed).",
    )
    parser.add_argument("--scope", required=True, help="Path to SCOPE.md")
    parser.add_argument("--target", help="Host/IP/URL to evaluate")
    parser.add_argument("--command", help="Shell command to evaluate")
    parser.add_argument(
        "--time-check",
        action="store_true",
        help="Evaluate current time against authorized/blackout windows",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not args.target and not args.command and not args.time_check:
        parser.error("at least one of --target, --command, or --time-check is required")

    config = load_scope(args.scope)
    decisions: list[Decision] = []

    if args.target:
        normalized = normalize_scope_target(args.target)
        decisions.append(evaluate_target(normalized or args.target, config))
    if args.command:
        decisions.append(evaluate_command(args.command, config))
    if args.time_check:
        decisions.append(evaluate_time_window(datetime.now().astimezone(), config))

    blocked = [d for d in decisions if not d.allow]
    final = blocked[0] if blocked else decisions[0]

    if args.json:
        print(json.dumps(final.to_dict(), ensure_ascii=False))
    else:
        status = "BLOCKED" if not final.allow else "ALLOWED"
        print(f"[{status}] {final.reason_code}: {final.reason_detail} (risk={final.risk})")

    sys.exit(0 if final.allow else 1)


if __name__ == "__main__":
    main()
