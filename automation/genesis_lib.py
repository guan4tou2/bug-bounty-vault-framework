"""genesis_lib — single canonical reader for a target's genesis, on TWO axes.

The whole "one vault, no fork" directive rests on this: everything downstream READS
these fields, nobody re-derives them. Two orthogonal axes live in genesis:

  engagement_type : bounty | cve | pentest | redteam | client   (why / success model)
  profile         : web | firmware | source-audit | apk         (target shape)

Derived, not stored twice:
  capability_model : finding-finding | foothold   (redteam ⇒ foothold, else finding-finding)
  osint_applies    : recon floor applies?         (web/apk ⇒ yes; firmware/source-audit ⇒ no)
  roe_required     : must ROE be signed first?    (pentest/redteam/client ⇒ yes)

Backward compatibility: older genesis events carry a single `profile` field with values
{web, firmware, source-audit, engagement}. This module normalizes those into the two-axis
model so old targets keep working and consumers never branch on legacy vocab.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

CANON_ENGAGEMENT = ("bounty", "cve", "pentest", "redteam", "client")
CANON_PROFILE = ("web", "firmware", "source-audit", "apk", "native")

# legacy single `profile` field  →  (engagement_type, profile-shape)
_LEGACY = {
    "web": ("bounty", "web"),
    "firmware": ("bounty", "firmware"),
    "source-audit": ("cve", "source-audit"),
    "native": ("cve", "native"),
    "engagement": ("redteam", "web"),
}
# legacy target_type → profile shape (finer than the legacy profile)
_TYPE_SHAPE = {
    "web-app": "web", "api": "web", "mobile-app": "apk",
    "firmware": "firmware", "iot-device": "firmware",
    "desktop-app": "native", "native-app": "native", "native-binary": "native",
    "source-audit": "source-audit", "red-team-engagement": "web",
}
_OSINT_PROFILES = {"web", "apk"}
_ROE_ENGAGEMENTS = {"pentest", "redteam", "client"}
# capability_model → the ONE chain worker the hunt loop runs on each finding. Picked
# at engage time by profile, not two defaults loaded at once (directive 5).
_WORKER_SKILL = {"finding-finding": "bb-exploit-chain", "foothold": "bb-web-foothold"}


def _vault_root() -> Path:
    return Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[1])


def genesis_event(target: str) -> dict | None:
    """Return the raw genesis event dict for a target, or None."""
    led = _vault_root() / "01 - Targets" / target / ".state" / "asg-events.jsonl"
    from ledger_reader import read_ledger_events
    return next((ev for ev in read_ledger_events(led) if ev.get("type") == "genesis"), None)


def read(target: str) -> dict:
    """Normalized two-axis view. Empty dict-with-None fields if no genesis."""
    ev = genesis_event(target) or {}
    return normalize_genesis(ev)


def normalize_genesis(ev: dict) -> dict:
    """Normalize an already-read event so projections share one ledger revision."""
    data = ev.get("data") if isinstance(ev.get("data"), dict) else ev

    et = data.get("engagement_type")
    # New writers set profile_shape; legacy events only have `profile`.
    prof = data.get("profile_shape") or data.get("profile")
    legacy_prof = data.get("profile") if data.get("profile") in _LEGACY else None
    if not et or prof not in CANON_PROFILE:
        leg_et, leg_shape = _LEGACY.get(legacy_prof or prof or "", ("bounty", "web"))
        if not et:
            et = leg_et
        if prof not in CANON_PROFILE:
            prof = _TYPE_SHAPE.get(data.get("target_type", ""), leg_shape)

    cap = data.get("capability_model")
    if cap not in ("finding-finding", "foothold"):
        cap = "foothold" if et == "redteam" else "finding-finding"

    return {
        "engagement_type": et,
        "profile": prof,
        "capability_model": cap,
        "worker_skill": ("bb-exploit-chain" if cap == "foothold" and prof not in ("web", "apk")
                         else _WORKER_SKILL.get(cap, "bb-exploit-chain")),
        "success": data.get("success") or data.get("success_criteria") or "",
        "osint_applies": prof in _OSINT_PROFILES,
        "roe_required": et in _ROE_ENGAGEMENTS,
        "has_genesis": bool(ev),
    }


def auto_risk(target: str) -> "frozenset[str]":
    """Which action risk tiers the unattended loop may auto-execute for this target — the
    ONE place both runner entry points (hunt_run, hunt_cli) compute it, so they cannot drift.

    reads_only + state_query always auto-run. writes_data is added only for a pentest/redteam
    engagement whose ROE is signed (the ROE is the human authorization). service_impact is
    never auto — always deferred to needs_human_go. bounty/cve stay read-only regardless.
    """
    tiers = {"reads_only", "state_query"}
    try:
        g = read(target)
        if g.get("engagement_type") in ("pentest", "redteam") and roe_signed(target):
            tiers.add("writes_data")
    except Exception:
        pass
    return frozenset(tiers)


def roe_signed(target: str) -> bool:
    """True if the target's ROE is marked signed/active. Checks Engagement/ROE.md
    then ROE.md; a missing ROE counts as NOT signed."""
    tdir = _vault_root() / "01 - Targets" / target
    for rel in ("Engagement/ROE.md", "ROE.md"):
        p = tdir / rel
        try:
            head = p.read_text(encoding="utf-8")[:1500]
        except OSError:
            continue
        import re
        m = re.search(r"(?im)^\s*status\s*:\s*[\"']?\s*(signed|active|approved)\b", head)
        if m:
            return True
    return False


def derive(engagement_type: str, profile: str) -> dict:
    """Compute the derived fields for a fresh genesis (used by engage.py)."""
    et = engagement_type if engagement_type in CANON_ENGAGEMENT else "bounty"
    prof = profile if profile in CANON_PROFILE else "web"
    return {
        "engagement_type": et,
        "profile": prof,
        "capability_model": "foothold" if et == "redteam" else "finding-finding",
    }
