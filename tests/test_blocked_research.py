"""Obstruction contracts: bounded alternatives, waiting and protected boundaries."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
import blocked_research as br
import work_cards as wc
from hunt_loop import HuntLoop


def artifact(path):
    return {
        "kind": "artifact",
        "path": str(path),
        "applicability": {
            "version": "fixture-v1",
            "role": "member",
            "settings": {},
            "environment": "fixture",
            "observed_at": datetime.now(UTC).isoformat(),
        },
    }


def setup(tmp_path, cause="waf", normal="succeeds"):
    loop = HuntLoop(base_path=tmp_path)
    loop.add_hypothesis("h")
    loop.append(
        "evidence_context",
        context={"version": "fixture-v1", "role": "member", "settings": {}, "environment": "fixture"},
    )
    proof = tmp_path / "normal.txt"
    proof.write_text("owned fixture normal same-role request succeeds; alternate route blocked")
    br.record(
        loop,
        "b",
        "h",
        cause=cause,
        layer="fixture gateway",
        explanation="observed fixture denial",
        normal=normal,
        evidence=artifact(proof),
        recovery="new route or valid session",
        limit=2,
    )
    return loop, artifact(proof)


def proposal(loop, proof, aid="a"):
    br.propose(
        loop,
        "b",
        aid,
        condition="entry",
        before="ui",
        after=aid,
        rationale="compare parser paths",
        comparison="same role/object with normal CONTROL",
        information_value=4,
        impact="low",
        evidence=proof,
    )


def test_work_card_closed_loop_alternative_and_observed_impact(tmp_path):
    loop, proof = setup(tmp_path, cause="unknown", normal="unknown")
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    assert card["next_action"] == "establish_normal_control"
    card = wc.apply(
        loop,
        card,
        "diagnose",
        {
            "cause": "waf",
            "layer": "fixture gateway",
            "explanation": "normal same-role operation succeeds",
            "normal": "succeeds",
            "evidence": proof,
            "recovery": "authorized alternative entry",
        },
    )
    assert card["next_action"] == "assess_alternatives_or_stop"
    old = card
    card = wc.apply(
        loop,
        card,
        "propose",
        {
            "alternative_id": "a",
            "condition": "entry",
            "before": "ui",
            "after": "api",
            "rationale": "same semantic operation",
            "comparison": "hold role/object/state constant",
            "information_value": 4,
            "impact": "low",
            "evidence": proof,
        },
    )
    assert card["alternative"]["alternative_id"] == "a"
    with pytest.raises(ValueError, match="stale"):
        wc.apply(loop, old, "close", {"reason": "cost", "recovery": "budget", "untested_reason": "cost"})
    test = tmp_path / "test.txt"
    test.write_text("original intended fixture behavior and impact observed")
    args = {
        "alternative_id": "a",
        "result": "behavior_observed",
        "observation": "fixture data retrieved",
        "excluded": "not a public marker",
        "recovery": "independent validation",
        "test_evidence": artifact(test),
        "control_evidence": proof,
        "normal_succeeds": True,
        "behavior_observed": True,
        "impact_observed": True,
    }
    card = wc.apply(loop, card, "attempt", args)
    assert card["next_action"] == "validate_original_claim"
    assert loop.capsule()["confirmed"] == {} and loop.capsule()["refuted"] == []


def test_baseline_and_cause_discrimination_are_separate_cards(tmp_path):
    loop, proof = setup(tmp_path, cause="unknown", normal="unknown")
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    assert card["next_action"] == "establish_normal_control"
    card = wc.apply(
        loop,
        card,
        "diagnose",
        {
            "cause": "unknown",
            "layer": "undetermined",
            "explanation": "same-role normal operation succeeds; denial cause remains ambiguous",
            "normal": "succeeds",
            "evidence": proof,
            "recovery": "discriminate competing explanations",
        },
    )
    assert card["next_action"] == "discriminate_obstruction"
    with pytest.raises(ValueError, match="not a valid next transition"):
        wc.apply(loop, card, "propose", {})
    assert len(br.PROMPT.encode()) < 500


def test_final_failed_comparison_automatically_persists_budget_stop(tmp_path):
    loop, proof = setup(tmp_path)
    proposal(loop, proof, "a")
    proposal(loop, proof, "b")
    test = tmp_path / "result.txt"
    test.write_text("owned fixture denial")
    for aid in ("a", "b"):
        br.attempt(
            loop,
            "b",
            aid,
            result="blocked",
            observation="denied",
            excluded="entry alone insufficient",
            recovery="new evidenced prerequisite",
            test_evidence=artifact(test),
            control_evidence=proof,
            normal_succeeds=True,
        )
    row = br.project(loop.events, tmp_path)[0]
    assert row["state"] == "waiting" and row["stop_reason"] == "exhausted"
    assert row["next"] == "wait_for_recovery" and wc.obstruction_card(row)["budget_remaining"] == 0
    assert loop.capsule()["refuted"] == []


def test_failed_normal_control_blocks_further_alternatives(tmp_path):
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    test = tmp_path / "result.txt"
    test.write_text("different response while normal baseline also failed")
    br.attempt(
        loop,
        "b",
        "a",
        result="inconclusive",
        observation="comparison unavailable",
        excluded="normal baseline failed",
        recovery="restore normal operation",
        test_evidence=artifact(test),
        control_evidence=proof,
        normal_succeeds=False,
    )
    row = br.project(loop.events, tmp_path)[0]
    assert row["normal"] == "fails" and row["next"] == "establish_normal_control"
    with pytest.raises(ValueError, match="normal baseline"):
        proposal(loop, proof, "b")


def test_new_names_or_rewording_cannot_reset_same_condition_failure(tmp_path):
    loop, proof = setup(tmp_path, cause="unknown", normal="succeeds")
    with pytest.raises(ValueError, match="no new diagnostic"):
        br.diagnose(
            loop,
            "b",
            cause="unknown",
            layer="different wording",
            explanation="try again",
            normal="succeeds",
            evidence=proof,
            recovery="retry",
        )
    with pytest.raises(ValueError, match="without resetting budget"):
        br.record(
            loop,
            "new-name",
            "h",
            cause="waf",
            layer="gateway",
            explanation="same hypothesis",
            normal="succeeds",
            evidence=proof,
            recovery="try alternate path",
        )
    br.diagnose(
        loop,
        "b",
        cause="waf",
        layer="gateway",
        explanation="diagnosis from existing evidence",
        normal="succeeds",
        evidence=proof,
        recovery="bounded comparison",
    )
    with pytest.raises(ValueError, match="no new diagnostic"):
        br.diagnose(
            loop,
            "b",
            cause="unknown",
            layer="gateway",
            explanation="cycle back",
            normal="succeeds",
            evidence=proof,
            recovery="repeat",
        )


@pytest.mark.parametrize("cause", sorted(br.HARD))
def test_scope_and_approval_are_never_bypass_targets(tmp_path, cause):
    loop, proof = setup(tmp_path, cause)
    assert br.project(loop.events, tmp_path)[0]["next"] == "original_authorization_path"
    with pytest.raises(ValueError, match="cannot be bypassed"):
        proposal(loop, proof)
    with pytest.raises(ValueError, match="original authorization"):
        br.diagnose(
            loop,
            "b",
            cause="waf",
            layer="new",
            explanation="relabel",
            normal="succeeds",
            evidence=proof,
            recovery="retry",
        )


def test_no_feasible_route_records_waiting_not_refutation(tmp_path):
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    test = tmp_path / "test.txt"
    test.write_text("fixture remains blocked")
    br.attempt(
        loop,
        "b",
        "a",
        result="blocked",
        observation="denial",
        excluded="entry alone insufficient",
        recovery="valid prerequisite",
        test_evidence=artifact(test),
        control_evidence=proof,
        normal_succeeds=True,
    )
    br.close(loop, "b", reason="exhausted", recovery="changed prerequisite", untested_reason="no evidenced alternative")
    row = br.project(loop.events, tmp_path)[0]
    assert row["next"] == "wait_for_recovery" and row["conclusion"] == "inconclusive"
    assert loop.capsule()["refuted"] == []


def test_missing_control_duplicate_budget_and_response_only_success_rejected(tmp_path):
    loop, proof = setup(tmp_path, normal="fails")
    with pytest.raises(ValueError, match="normal baseline"):
        proposal(loop, proof)
    br.diagnose(
        loop,
        "b",
        cause="waf",
        layer="gateway",
        explanation="baseline restored",
        normal="succeeds",
        evidence=proof,
        recovery="valid fixture",
    )
    proposal(loop, proof)
    with pytest.raises(ValueError, match="duplicate"):
        proposal(loop, proof)
    proposal(loop, proof, "b")
    with pytest.raises(ValueError, match="budget"):
        proposal(loop, proof, "c")
    with pytest.raises(ValueError, match="response changes"):
        br.attempt(
            loop,
            "b",
            "a",
            result="behavior_observed",
            observation="200",
            excluded="none",
            recovery="inspect",
            test_evidence=proof,
            control_evidence=proof,
            normal_succeeds=True,
        )
    Path(proof["path"]).write_text("changed")
    assert br.project(loop.events, tmp_path)[0]["next"] == "revalidate_evidence"


def test_exploration_proposal_does_not_execute_or_grant_capabilities(tmp_path):
    loop, proof = setup(tmp_path)
    wc.propose_exploration(
        loop,
        question="none of these routes discriminate",
        reason="different product premise",
        evidence=proof,
        requires=["missing"],
    )
    assert len(loop.capsule()["ready_hypotheses"]) == 1
    assert loop.capsule()["capabilities"] == []


def test_real_executor_receipts_and_result_return_to_same_asg(tmp_path, monkeypatch):
    import program_rules_gate

    monkeypatch.setattr(program_rules_gate, "judge", lambda *_: None)
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    ledger = tmp_path / "ledger.jsonl"
    loop.save(ledger)

    def interpret(test, control):
        assert test.read_text().strip() == "test-behavior"
        assert control.read_text().strip() == "normal-control"
        return {
            "observation": "owned fixture behavior observed",
            "excluded": "response alone insufficient",
            "recovery": "independent validation",
            "normal_succeeds": True,
            "behavior_observed": True,
            "impact_observed": True,
        }

    updated = wc.execute_alternative(
        loop,
        ledger,
        card,
        comparison_hyp_id="h",
        test_argv=[sys.executable, "-c", 'print("test-behavior")'],
        control_argv=[sys.executable, "-c", 'print("normal-control")'],
        output_dir=tmp_path / "output",
        scope_ref="owned:fixture",
        interpret=interpret,
    )
    assert updated["next_action"] == "validate_original_claim"
    assert len([e for e in loop.events if e["type"] == "action_finished"]) == 2
    assert HuntLoop.load(ledger).capsule()["confirmed"] == {}


def test_gate_rejection_stops_alternative_and_cannot_record_success(tmp_path, monkeypatch):
    import program_rules_gate

    monkeypatch.setattr(program_rules_gate, "judge", lambda *_: "fixture prohibition")
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    with pytest.raises(PermissionError, match="gate blocked"):
        wc.execute_alternative(
            loop,
            tmp_path / "ledger",
            card,
            comparison_hyp_id="h",
            test_argv=["tool", "test"],
            control_argv=["tool", "normal"],
            output_dir=tmp_path / "output",
            scope_ref="owned:fixture",
            interpret=lambda *_: {},
        )
    assert not any(e["type"] in {"action_started", "obstruction_attempt", "verdict"} for e in loop.events)


def test_worker_failure_automatically_becomes_diagnosis_work_not_refutation(tmp_path):
    from logic_vuln_loop import Observation

    loop, _ = setup(tmp_path)
    loop.add_hypothesis("other")
    br.capture_worker_block(
        loop,
        "other",
        Observation("test", False, error="unclassified denial"),
        Observation("normal", False, error="baseline unavailable"),
    )
    row = next(r for r in br.project(loop.events, tmp_path) if r["hyp_id"] == "other")
    assert row["cause"] == "unknown" and row["next"] == "establish_normal_control"
    assert Path(row["evidence"]["path"]).stat().st_mode & 0o777 == 0o600
    assert loop.capsule()["refuted"] == []


def test_completed_tools_resume_interpretation_without_repeating_effects(tmp_path, monkeypatch):
    import program_rules_gate

    monkeypatch.setattr(program_rules_gate, "judge", lambda *_: None)
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    options = {
        "comparison_hyp_id": "h",
        "test_argv": [sys.executable, "-c", 'print("test")'],
        "control_argv": [sys.executable, "-c", 'print("control")'],
        "output_dir": tmp_path / "output",
        "scope_ref": "owned:fixture",
    }

    def unavailable(*_):
        raise RuntimeError("interpretation interrupted after tool completion")

    with pytest.raises(RuntimeError):
        wc.execute_alternative(loop, tmp_path / "ledger", card, interpret=unavailable, **options)
    assert len([e for e in loop.events if e["type"] == "action_started"]) == 2
    with pytest.raises(ValueError, match="binding changed"):
        wc.execute_alternative(
            loop, tmp_path / "ledger", card, interpret=unavailable, **{**options, "scope_ref": "changed"}
        )
    updated = wc.execute_alternative(
        loop,
        tmp_path / "ledger",
        card,
        **options,
        interpret=lambda *_: {
            "observation": "different response only",
            "excluded": "no impact established",
            "recovery": "inspect protected behavior",
            "normal_succeeds": True,
            "behavior_observed": False,
            "impact_observed": False,
        },
    )
    assert updated["next_action"] == "assess_alternatives_or_stop"
    assert len([e for e in loop.events if e["type"] == "action_started"]) == 2
    assert loop.capsule()["confirmed"] == {}


def test_failed_control_stops_before_test_and_waits_for_recovery(tmp_path, monkeypatch):
    import program_rules_gate

    monkeypatch.setattr(program_rules_gate, "judge", lambda *_: None)
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    card = wc.obstruction_card(br.project(loop.events, tmp_path)[0])
    result = wc.execute_alternative(
        loop,
        tmp_path / "ledger",
        card,
        comparison_hyp_id="h",
        test_argv=[sys.executable, "-c", 'print("must not run")'],
        control_argv=[sys.executable, "-c", "raise SystemExit(3)"],
        output_dir=tmp_path / "output",
        scope_ref="owned:fixture",
        interpret=lambda *_: pytest.fail("failed control must not be interpreted as success"),
    )
    assert result["state"] == "execution_blocked"
    assert len([e for e in loop.events if e["type"] == "action_started"]) == 1
    assert br.project(loop.events, tmp_path)[0]["next"] == "reconcile_execution"


def test_resume_preserves_attempt_history_and_consumed_budget(tmp_path):
    loop, proof = setup(tmp_path)
    proposal(loop, proof)
    test = tmp_path / "test.txt"
    test.write_text("fixture blockage")
    br.attempt(
        loop,
        "b",
        "a",
        result="blocked",
        observation="denied",
        excluded="entry alone insufficient",
        recovery="changed premise",
        test_evidence=artifact(test),
        control_evidence=proof,
        normal_succeeds=True,
    )
    br.close(loop, "b", reason="exhausted", recovery="new premise", untested_reason="no useful route yet")
    new = tmp_path / "new.txt"
    new.write_text("owned fixture prerequisite repaired and previous effects inspected")
    br.resume(loop, "b", changed_condition="new valid prerequisite", evidence=artifact(new), recovery="normal baseline")
    row = br.project(loop.events, tmp_path)[0]
    assert row["next"] == "establish_normal_control" and len(row["history_alternatives"]) == 1
    assert wc.obstruction_card(row)["budget_remaining"] == 1
