"""Ledger single-writer lock — the mechanical half of the concurrency fix.

The failure this prevents: two sessions/processes both save() the same ledger and
lose each other's appends. These cases pin acquire/verify/guarded_save + TTL
takeover (a crashed holder must never wedge the ledger forever).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop  # noqa: E402
from hunt_lock import (  # noqa: E402
    acquire, verify, heartbeat, release, guarded_save, ConcurrentWriter,
)


def test_acquire_then_second_owner_is_blocked(tmp_path):
    led = tmp_path / "l.jsonl"
    t1 = acquire(led, "session-A", now=1000)
    assert verify(led, t1)
    with pytest.raises(ConcurrentWriter):
        acquire(led, "session-B", now=1000)          # still live -> blocked


def test_expired_holder_is_taken_over(tmp_path):
    led = tmp_path / "l.jsonl"
    acquire(led, "session-A", ttl_s=1800, now=1000)
    # A crashed; 40 min later B may take over (past TTL) rather than wedge forever
    t2 = acquire(led, "session-B", now=1000 + 2400)
    assert verify(led, t2)


def test_guarded_save_refuses_after_takeover_no_clobber(tmp_path):
    led = tmp_path / "l.jsonl"
    tA = acquire(led, "A", ttl_s=100, now=0)
    lpA = HuntLoop(); lpA.add_hypothesis("hA")
    guarded_save(lpA, led, tA)                        # A holds it -> ok
    assert HuntLoop.load(led).capsule()["ready_hypotheses"] == ["hA"]

    # B takes over after A's TTL and writes
    tB = acquire(led, "B", now=1000)
    lpB = HuntLoop.load(led); lpB.add_hypothesis("hB")
    guarded_save(lpB, led, tB)

    # A, unaware, tries to save stale state -> refused, B's work not clobbered
    lpA.add_hypothesis("hA2")
    with pytest.raises(ConcurrentWriter):
        guarded_save(lpA, led, tA)
    assert set(HuntLoop.load(led).capsule()["ready_hypotheses"]) == {"hA", "hB"}


def test_heartbeat_extends_hold(tmp_path):
    led = tmp_path / "l.jsonl"
    t = acquire(led, "A", ttl_s=100, now=0)
    assert heartbeat(led, t, now=90)                  # still ours -> extends
    # now expiry is measured from 90, so at 150 (only 60s later) it is NOT expired
    with pytest.raises(ConcurrentWriter):
        acquire(led, "B", now=150)


def test_release_frees_and_allows_reacquire(tmp_path):
    led = tmp_path / "l.jsonl"
    t = acquire(led, "A", now=0)
    assert release(led, t)
    assert not verify(led, t)
    t2 = acquire(led, "B", now=1)                     # freely re-acquired
    assert verify(led, t2)
    assert not release(led, "not-the-holder-token")   # only the holder can release


def test_verify_false_for_wrong_token(tmp_path):
    led = tmp_path / "l.jsonl"
    acquire(led, "A", now=0)
    assert not verify(led, "bogus")
