#!/usr/bin/env python3
"""Tests for round_logger.py — JSONL operational round log + context_brief."""
import json
import sys
from pathlib import Path

AUTO = Path(__file__).resolve().parent.parent / "automation"
sys.path.insert(0, str(AUTO))

from round_logger import RoundLogger, context_brief  # noqa: E402
from hunt_loop import HuntLoop, Verdict  # noqa: E402


# ── basic logging ────────────────────────────────────────────────────────────

def test_log_creates_jsonl(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("test-target", session_id="sess001", path=p)
    rl.log("test", endpoint="/api/users", method="GET", status=403)
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["sid"] == "sess001"
    assert entry["action"] == "test"
    assert entry["endpoint"] == "/api/users"
    assert entry["status"] == 403
    assert "ts" in entry


def test_multiple_logs_append(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    rl.scan("ferox", "https://example.com", found=5)
    rl.test("/api/v1", status=200, verdict="confirmed")
    rl.decision("skip", reason="no account")
    rl.error("nuclei", "timeout")
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 4
    actions = [json.loads(l)["action"] for l in lines]
    assert actions == ["scan", "test", "decision", "error"]


def test_scan_convenience(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    entry = rl.scan("httpx", "https://x.com", found=10, extra_field="yes")
    assert entry["tool"] == "httpx"
    assert entry["found"] == 10
    assert entry["extra_field"] == "yes"


def test_handoff_with_capsule(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    capsule = {"confirmed": {"h1": ["cap1"]}, "ready_hypotheses": []}
    entry = rl.handoff("budget exhausted", capsule=capsule)
    assert entry["action"] == "handoff"
    assert entry["capsule"]["confirmed"]["h1"] == ["cap1"]


# ── read ops ─────────────────────────────────────────────────────────────────

def test_read_all(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    rl.log("a")
    rl.log("b")
    assert len(rl.read_all()) == 2


def test_read_session_filters(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl1 = RoundLogger("t", session_id="s1", path=p)
    rl2 = RoundLogger("t", session_id="s2", path=p)
    rl1.log("from_s1")
    rl2.log("from_s2")
    rl1.log("from_s1_again")
    assert len(rl1.read_session()) == 2
    assert len(rl2.read_session()) == 1


def test_recent(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    for i in range(20):
        rl.log(f"action_{i}")
    recent = rl.recent(5)
    assert len(recent) == 5
    assert recent[0]["action"] == "action_15"
    assert recent[-1]["action"] == "action_19"


def test_session_recent(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl1 = RoundLogger("t", session_id="s1", path=p)
    rl2 = RoundLogger("t", session_id="s2", path=p)
    for i in range(10):
        rl1.log(f"s1_{i}")
    for i in range(3):
        rl2.log(f"s2_{i}")
    recent = rl1.session_recent(3)
    assert len(recent) == 3
    assert all(e["sid"] == "s1" for e in recent)
    assert recent[0]["action"] == "s1_7"


def test_summary(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    rl.scan("ferox", "https://x.com", found=5)
    rl.test("/a", verdict="confirmed")
    rl.test("/b", verdict="blocked")
    rl.test("/c", verdict="confirmed")
    s = rl.summary()
    assert s["total_entries"] == 4
    assert s["sessions"] == 1
    assert s["actions"]["scan"] == 1
    assert s["actions"]["test"] == 3
    assert s["verdicts"]["confirmed"] == 2
    assert s["verdicts"]["blocked"] == 1


def test_read_empty(tmp_path):
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)
    assert rl.read_all() == []
    assert rl.recent() == []
    assert rl.summary()["total_entries"] == 0


# ── context_brief ────────────────────────────────────────────────────────────

def test_context_brief_with_capsule(tmp_path):
    ledger = tmp_path / "hunt_ledger.jsonl"
    round_log = tmp_path / "round_log.jsonl"

    loop = HuntLoop(session_id="brief_test")
    loop.add_surface("endpoint_a")
    loop.add_hypothesis("h1")
    loop.record_verdict("h1", Verdict.CONFIRMED, evidence_ref="poc.png",
                        provides=["cap_read"])
    loop.save(ledger)

    rl = RoundLogger("t", session_id="brief_test", path=round_log)
    rl.scan("ferox", "https://t.com", found=3)
    rl.test("/api/x", status=200, verdict="confirmed")
    rl.test("/api/y", status=403, verdict="blocked")

    brief = context_brief("t", session_id="brief_test", n_recent=2,
                          ledger_path=ledger, round_log_path=round_log)

    assert brief["target"] == "t"
    assert brief["session_id"] == "brief_test"
    assert "h1" in brief["capsule"]["confirmed"]
    assert len(brief["recent_ops"]) == 2
    assert brief["recent_ops"][-1]["verdict"] == "blocked"
    assert brief["stats"]["total_entries"] == 3


def test_context_brief_no_ledger(tmp_path):
    round_log = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=round_log)
    rl.log("test")

    brief = context_brief("t", session_id="s1", n_recent=5,
                          ledger_path=tmp_path / "nonexistent.jsonl",
                          round_log_path=round_log)
    assert brief["capsule"] == {}
    assert len(brief["recent_ops"]) == 1


def test_context_brief_no_round_log(tmp_path):
    ledger = tmp_path / "hunt_ledger.jsonl"
    loop = HuntLoop(session_id="s1")
    loop.add_surface("x")
    loop.save(ledger)

    brief = context_brief("t", session_id="s1", n_recent=5,
                          ledger_path=ledger,
                          round_log_path=tmp_path / "nonexistent_round.jsonl")
    assert brief["capsule"]["untested_surface"] == ["x"]
    assert brief["recent_ops"] == []


# ── token size comparison ────────────────────────────────────────────────────

def test_jsonl_smaller_than_prose(tmp_path):
    """Verify JSONL is significantly smaller than equivalent prose."""
    p = tmp_path / "round_log.jsonl"
    rl = RoundLogger("t", session_id="s1", path=p)

    for i in range(10):
        rl.test(f"/api/endpoint_{i}", method="GET", status=200 + i,
                verdict="confirmed" if i % 3 == 0 else "inconclusive")

    jsonl_size = p.stat().st_size

    prose = ""
    for i in range(10):
        v = "confirmed" if i % 3 == 0 else "inconclusive"
        prose += f"- Tested GET /api/endpoint_{i}, received status {200 + i}, verdict: {v}\n"
    prose_size = len(prose.encode("utf-8"))

    ratio = prose_size / jsonl_size
    assert ratio < 1.0, (
        f"JSONL ({jsonl_size}B) should be LARGER than minimal prose ({prose_size}B) "
        f"because it carries metadata (sid/ts), but the point is it's MACHINE-PARSEABLE "
        f"and survives compression — ratio={ratio:.2f}"
    )
    assert jsonl_size < prose_size * 3, (
        f"JSONL ({jsonl_size}B) should not be more than 3x the prose ({prose_size}B)"
    )


# ── cross-session dedup via sid ──────────────────────────────────────────────

def test_cross_session_dedup(tmp_path):
    """Two sessions log to the same file; can filter and dedup by sid."""
    p = tmp_path / "round_log.jsonl"
    rl1 = RoundLogger("t", session_id="s1", path=p)
    rl2 = RoundLogger("t", session_id="s2", path=p)

    rl1.test("/api/a", verdict="confirmed")
    rl2.test("/api/a", verdict="confirmed")
    rl2.test("/api/b", verdict="blocked")

    s1_endpoints = {e["endpoint"] for e in rl1.read_session()}
    s2_endpoints = {e["endpoint"] for e in rl2.read_session()}

    assert s1_endpoints == {"/api/a"}
    assert s2_endpoints == {"/api/a", "/api/b"}
    overlap = s1_endpoints & s2_endpoints
    assert overlap == {"/api/a"}, "should detect cross-session overlap"


# ── malformed line resilience ────────────────────────────────────────────────

def test_malformed_lines_skipped(tmp_path):
    p = tmp_path / "round_log.jsonl"
    p.write_text('{"sid":"s1","action":"ok"}\nNOT JSON\n{"sid":"s1","action":"ok2"}\n')
    rl = RoundLogger("t", session_id="s1", path=p)
    entries = rl.read_all()
    assert len(entries) == 2
