"""Changed-condition retries preserve old results and all execution boundaries."""
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from failure_memory import reopen_dead_end, same_failure_scope
from hunt_autodrive import record_dead_end
from hunt_loop import HuntLoop, Verdict
from logic_vuln_loop import Env, LogicHypothesis


def setup_failure(tmp_path):
    loop = HuntLoop()
    hyp = LogicHypothesis("old", "roles", "a member cannot read another owner's object", Env("1", "member", "fixture"),
                          "known account", "owner succeeds", "GET member object", "GET own object", "private-data")
    loop.add_hypothesis("old")
    loop.record_verdict("old", Verdict.REFUTED)
    record_dead_end(loop, hyp, "refuted", "a known role, version or required capability changes")
    proof = tmp_path / "conditions.txt"
    proof.write_text("Controlled fixture changed from target version 1 to 2; no target action performed.")
    return loop, hyp, str(proof)


def test_new_condition_requires_explicit_current_fact_and_keeps_old_verdict(tmp_path):
    loop, old, proof = setup_failure(tmp_path)
    new = replace(old, hyp_id="new", applies_env=Env("2", "member", "fixture"))
    with pytest.raises(ValueError, match="no evidenced"):
        reopen_dead_end(loop, "old", new, reason="version changed", condition_evidence=proof)
    loop.append("evidence_context", context={"version": "2", "role": "admin", "environment": "fixture"})
    with pytest.raises(ValueError, match="no evidenced"):
        reopen_dead_end(loop, "old", new, reason="version changed but current role differs", condition_evidence=proof)
    loop.append("evidence_context", context={"version": "2", "role": "member", "environment": "fixture"})
    assert reopen_dead_end(loop, "old", new, reason="version 2 has a different ownership guard",
                           condition_evidence=proof) == "new"
    assert loop.capsule()["refuted"] == ["old"]
    assert "new" in loop.capsule()["ready_hypotheses"]
    lineage = next(event for event in loop.events if event["type"] == "failure_path_reopened")
    assert lineage["changed_fields"] == ["version"] and lineage["evidence"]["sha256"]
    assert not same_failure_scope(next(event for event in loop.events if event["type"] == "dead_end"), new)
    assert not any(event["type"] == "action_started" for event in loop.events)


def test_same_conditions_reason_or_new_id_cannot_alone_reopen(tmp_path):
    loop, old, proof = setup_failure(tmp_path)
    new = replace(old, hyp_id="new")
    with pytest.raises(ValueError, match="no evidenced"):
        reopen_dead_end(loop, "old", new, reason="try again", condition_evidence=proof)
    with pytest.raises(ValueError, match="requires a reason"):
        reopen_dead_end(loop, "old", new, reason="", condition_evidence=proof)
    assert same_failure_scope(next(event for event in loop.events if event["type"] == "dead_end"), old)


def test_declined_authorization_and_unresolved_effects_cannot_be_bypassed(tmp_path):
    loop, old, proof = setup_failure(tmp_path)
    new = replace(old, hyp_id="new", applies_env=Env("2", "member", "fixture"))
    loop.append("evidence_context", context={"version": "2"})
    loop.append("action_started", action_id="still-running", hyp_id="old")
    with pytest.raises(ValueError, match="reconciliation"):
        reopen_dead_end(loop, "old", new, reason="version changed", condition_evidence=proof)
    record_dead_end(loop, old, "declined", "obtain the original authorization")
    with pytest.raises(ValueError, match="declined authorization"):
        reopen_dead_end(loop, "old", new, reason="version changed", condition_evidence=proof)


def test_new_required_capability_must_be_actually_acquired(tmp_path):
    loop, old, proof = setup_failure(tmp_path)
    new = replace(old, hyp_id="new", requires=["cap:role"])
    with pytest.raises(ValueError, match="no evidenced"):
        reopen_dead_end(loop, "old", new, reason="role capability acquired", condition_evidence=proof)
    loop.record_verdict("capability-proof", Verdict.CONFIRMED, evidence=proof, provides=["cap:role"])
    assert reopen_dead_end(loop, "old", new, reason="role capability acquired",
                           condition_evidence=proof) == "new"
