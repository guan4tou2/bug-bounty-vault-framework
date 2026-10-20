"""Research provenance must influence the public runner without replacing it."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "automation"))

from asg_research import append_to_loop, project
from hunt_autodrive import Budget, autodrive
from hunt_loop import HuntLoop, RunState, Verdict, confidence_is_dynamic
from hunt_session import resume_brief
from hunt_worker import render_worker_prompt
from ledger_reader import LedgerReadError
from logic_vuln_loop import Env, LogicHypothesis, Observation


def research_loop(tmp_path):
    loop = HuntLoop(session_id="public-research-session", base_path=tmp_path)
    loop.append("objective", text="Evaluate the controlled example")
    append_to_loop(loop, "research_node", node_kind="goal", id="G1", text="Check the rule",
                   criteria=[{"id": "C1", "text": "Record direct evidence of the result"}],
                   purpose="validation")
    return loop


def intent(loop, identifier="I1", **fields):
    append_to_loop(loop, "research_node", node_kind="intent", id=identifier,
                   text="Compare the test against its known-good control", goals=["goal:G1"], **fields)


def hypothesis():
    return LogicHypothesis(
        hyp_id="H1", dimension="roles", invariant="Anonymous access must be denied",
        applies_env=Env(), precondition="none", expected_normal="denied",
        test_action="GET https://example.com/test", control_action="GET https://example.com/control",
        violation_outcome="200", expected_normal_outcome="403", provides=["read:example"],
    )


def test_public_session_identity_and_confidence_contract_survive_research(tmp_path):
    loop = research_loop(tmp_path)
    intent(loop)
    loop.add_hypothesis("static")
    loop.record_verdict("static", Verdict.CONFIRMED, "legacy-proof", ["read:legacy"], confidence="static")
    loop.add_hypothesis("dynamic")
    loop.record_verdict("dynamic", Verdict.CONFIRMED, "legacy-proof", [], confidence="reproduced")
    cap = loop.capsule()
    assert cap["static_only"] == ["static"]
    assert cap["capabilities"] == ["read:legacy"]
    assert confidence_is_dynamic(cap["confidence"]["dynamic"])
    assert all(event["sid"] == "public-research-session" and event["ts"] for event in loop.events)
    ledger = tmp_path / ".state" / "asg-events.jsonl"
    loop.save(ledger)
    restored = HuntLoop.load(ledger)
    assert restored.base_path == tmp_path
    assert restored.events == loop.events
    assert restored.capsule() == cap
    restored.append("note", text="New run retains its own identity")
    assert restored.events[-1]["sid"] == restored.session_id
    assert restored.events[-1]["ts"]


def test_completion_requires_acceptance_not_an_empty_frontier(tmp_path):
    loop = research_loop(tmp_path)
    assert loop.run_state() == RunState.REPLANNING
    with pytest.raises(ValueError, match="accepted goals"):
        loop.complete("No test hypotheses remain")
    intent(loop)
    assert loop.run_state() == RunState.RUNNING
    assert resume_brief(loop)["next_action"].startswith("RUN research intent 'intent:I1'")
    append_to_loop(loop, "research_state", ref="intent:I1", state="running", reason="Starting bounded work")
    assert resume_brief(loop)["next_action"].startswith("RESUME research")
    loop.append("action_started", action_id="pending", hyp_id="H1")
    assert resume_brief(loop)["next_action"].startswith("RECONCILE")


def test_bound_hypothesis_respects_intent_capability_prerequisites(tmp_path):
    loop = research_loop(tmp_path)
    loop.add_hypothesis("H1")
    intent(loop, hypothesis="hypothesis:H1", requires=["account:example"])
    assert loop.capsule()["ready_hypotheses"] == []
    assert loop.capsule()["blocked_hypotheses"] == ["H1"]
    loop.add_hypothesis("account")
    loop.record_verdict("account", Verdict.CONFIRMED, "legacy-proof", ["account:example"])
    assert loop.capsule()["ready_hypotheses"] == ["H1"]
    loop.revoke_capability("account:example", "Account revoked")
    assert loop.capsule()["ready_hypotheses"] == []


@pytest.mark.parametrize("selection", ["propose", "templater", "ready_hyp"])
@pytest.mark.parametrize("goal_state,intent_state", [
    ("met", "missing"), ("abandoned", "missing"),
    ("met", "paused"), ("met", "stopped"), ("met", "done"), ("met", "running"),
])
def test_dispatch_boundary_cannot_bypass_bound_intent(tmp_path, selection, goal_state, intent_state):
    loop = research_loop(tmp_path)
    append_to_loop(loop, "research_node", node_kind="fact", id="F1", text="Independent controlled result",
                   basis="observed", evidence={"kind": "observation", "text": "Controlled rule observation"})
    append_to_loop(loop, "goal_proof", goal="goal:G1", criterion="C1", source="fact:F1",
                   reason="The independent observation satisfies this criterion")
    if goal_state == "abandoned":
        append_to_loop(loop, "research_state", ref="goal:G1", state="abandoned", reason="Scope changed")
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    intent(loop, hypothesis="hypothesis:H1", requires=["account:missing"] if intent_state == "missing" else [])
    if intent_state in {"paused", "stopped"}:
        append_to_loop(loop, "research_state", ref="intent:I1", state=intent_state, reason="Lifecycle fixture")
    elif intent_state in {"done", "running"}:
        append_to_loop(loop, "research_state", ref="intent:I1", state="running", reason="Lifecycle fixture")
        if intent_state == "done":
            append_to_loop(loop, "research_node", node_kind="fact", id="F2", intent="intent:I1",
                           text="Prior output", basis="unknown")
            append_to_loop(loop, "research_state", ref="intent:I1", state="done", reason="Prior work settled")
    selected, dispatched = [], []

    def choose(*_):
        selected.append(hyp.hyp_id)
        return hyp

    options = {"propose": choose if selection == "propose" else lambda *_: None}
    if selection == "templater":
        options["templater"] = choose
    elif selection == "ready_hyp":
        # A reconstruction callback must not be able to substitute a different,
        # blocked ID for the ready ID offered by the capsule.
        loop.add_hypothesis("selector")
        options["ready_hyp"] = choose
    before = len(loop.events)
    report = autodrive(loop, current_env=Env(), dispatch=lambda task: dispatched.append(task),
                       budget=Budget(1, 1), **options)
    assert not dispatched
    assert report.rounds == 0 and report.interventions == 0
    assert len(selected) <= 1  # a rejected proposal cannot loop indefinitely
    assert "intent:I1" in report.handoff_reason
    if intent_state == "missing":
        assert "account:missing" in report.handoff_reason
    assert not any(event["type"] in {"execution", "logic_verdict"} for event in loop.events[before:])


def test_dispatch_rechecks_capability_revoked_by_selection_callback(tmp_path):
    loop = research_loop(tmp_path)
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    loop.add_hypothesis("account")
    loop.record_verdict("account", Verdict.CONFIRMED, "legacy-proof", ["account:example"])
    intent(loop, hypothesis="hypothesis:H1", requires=["account:example"])
    dispatched = []

    def select(_):
        loop.revoke_capability("account:example", "Account lost during work selection")
        return hyp

    report = autodrive(loop, current_env=Env(), dispatch=lambda task: dispatched.append(task),
                       propose=lambda *_: None, ready_hyp=select, budget=Budget(1, 1))
    assert not dispatched
    assert "intent:I1" in report.handoff_reason and "account:example" in report.handoff_reason
    assert report.rounds == 0 and report.interventions == 0


def test_native_research_returns_to_runner_without_operator_intervention(tmp_path):
    loop = research_loop(tmp_path)
    intent(loop)
    calls = []
    report = autodrive(loop, current_env=Env(), dispatch=lambda task: calls.append(task),
                       propose=lambda *_: calls.append("propose"), budget=Budget(2, 2))
    assert not calls
    assert report.interventions == 0
    assert report.rounds == 0
    assert report.handoff_reason == "native research work pending: intent:I1"


@pytest.mark.parametrize("test_ok,control_ok,expected_state,basis", [
    (True, True, "done", "observed"),
    (False, True, "blocked", "unknown"),
    (True, False, "blocked", "unknown"),
])
def test_bound_worker_receives_lineage_and_records_actual_outcome(tmp_path, test_ok, control_ok, expected_state, basis):
    loop = research_loop(tmp_path)
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    intent(loop, hypothesis="hypothesis:H1")
    append_to_loop(loop, "research_node", node_kind="hint", id="N1", intent="intent:I1",
                   text="Retain both control and test evidence")
    evidence = tmp_path / "response.txt"
    evidence.write_text("Controlled example response", encoding="utf-8")
    captured = []

    def dispatch(task):
        captured.append(render_worker_prompt(task))
        return (Observation(hyp.test_action, test_ok, "200" if test_ok else None,
                            evidence_ref=str(evidence), error=None if test_ok else "timeout"),
                Observation(hyp.control_action, control_ok, "403", evidence_ref=str(evidence),
                            error=None if control_ok else "timeout"))

    persisted = []
    report = autodrive(loop, current_env=Env(), dispatch=dispatch, propose=lambda *_: None,
                       ready_hyp=lambda _: hyp, budget=Budget(3, 1), persist=lambda lp: persisted.append(len(lp.events)))
    assert len(captured) == 1
    assert "acceptance C1:" in captured[0]
    assert "Retain both control and test evidence" in captured[0]
    assert "not new authorization" in captured[0]
    graph = project(loop.events, loop.base_path, cap=loop.capsule())
    nodes = {node["ref"]: node for node in graph["nodes"]}
    assert nodes["intent:I1"]["state"] == expected_state
    facts = [node for node in graph["nodes"] if node["kind"] == "fact"]
    assert len(facts) == 1 and facts[0]["basis"] == basis
    assert "CONTROL=403" in facts[0]["text"]
    assert nodes["goal:G1"]["effective_state"] == "open"
    assert not any(event["type"] in {"finding", "goal_proof"} for event in loop.events)
    assert persisted
    assert report.interventions == 0
    if not (test_ok and control_ok):
        assert loop.capsule()["refuted"] == []
        assert loop.capsule()["capabilities"] == []
        assert "verdict=inconclusive" in facts[0]["text"]
        # An artifact from a failed execution remains traceable, but cannot
        # establish a result even when the file itself is valid evidence.
        assert facts[0]["evidence"]["kind"] == "comparison"
        assert facts[0]["evidence"]["test"]["path"] == str(evidence)
        with pytest.raises(ValueError, match="eligible, resolvable evidence"):
            append_to_loop(loop, "goal_proof", goal="goal:G1", criterion="C1",
                           source=facts[0]["ref"], reason="A timeout does not establish the rule")


def test_refuted_comparison_retains_both_artifacts_for_acceptance_and_replay(tmp_path):
    loop = research_loop(tmp_path)
    hyp = hypothesis()
    loop.add_hypothesis(hyp.hyp_id)
    intent(loop, hypothesis="hypothesis:H1")
    test_file, control_file = tmp_path / "test.txt", tmp_path / "control.txt"
    test_file.write_text("403: test resource denied", encoding="utf-8")
    control_file.write_text("403: known-good baseline denied", encoding="utf-8")

    def dispatch(_):
        return (Observation(hyp.test_action, True, "403", str(test_file)),
                Observation(hyp.control_action, True, "403", str(control_file)))

    report = autodrive(loop, current_env=Env(), dispatch=dispatch, propose=lambda *_: None,
                       ready_hyp=lambda _: hyp, budget=Budget(3, 1))
    graph = project(loop.events, loop.base_path, cap=loop.capsule())
    fact = next(node for node in graph["nodes"] if node["kind"] == "fact")
    assert report.rounds == 1 and report.interventions == 0
    assert fact["basis"] == "observed" and fact["evidence_valid"]
    assert "verdict=refuted" in fact["text"]
    assert fact["evidence"]["test"]["path"] == str(test_file)
    assert fact["evidence"]["control"]["path"] == str(control_file)
    assert loop.capsule()["refuted"] == ["H1"]
    assert not loop.capsule()["confirmed"] and not loop.capsule()["capabilities"]
    append_to_loop(loop, "goal_proof", goal="goal:G1", criterion="C1", source=fact["ref"],
                   reason="Both archived responses demonstrate this controlled denial")
    assert loop.capsule()["research"]["met_goals"] == ["goal:G1"]
    ledger = tmp_path / ".state" / "asg-events.jsonl"
    loop.save(ledger)
    assert HuntLoop.load(ledger).capsule() == loop.capsule()
    # Neither side of the comparison may silently change after acceptance.
    control_file.write_text("Changed baseline", encoding="utf-8")
    restored = HuntLoop.load(ledger)
    assert restored.capsule()["research"]["open_goals"] == ["goal:G1"]
    restored_graph = project(restored.events, restored.base_path, cap=restored.capsule())
    restored_fact = next(node for node in restored_graph["nodes"] if node["kind"] == "fact")
    assert not restored_fact["evidence_valid"]


def test_next_work_cli_reads_same_ledger_and_keeps_goal_review(tmp_path, monkeypatch):
    import asg
    import next_work
    target = tmp_path / "01 - Targets" / "example"
    target.mkdir(parents=True)
    loop = research_loop(target)
    intent(loop)
    loop.save(target / ".state" / "asg-events.jsonl")
    monkeypatch.setattr(asg, "vault_root", lambda: tmp_path)
    work = next_work.compute(target)
    assert work["items"][0]["kind"] == "research-intent"
    assert work["items"][0]["ref"] == "intent:I1"
    append_to_loop(loop, "research_state", ref="intent:I1", state="stopped", reason="Reconsider approach")
    loop.save(target / ".state" / "asg-events.jsonl")
    work = next_work.compute(target)
    assert work["items"][0]["kind"] == "goal-review"
    result = subprocess.run([sys.executable, str(ROOT / "automation" / "next_work.py"), str(target)],
                            capture_output=True, text=True, timeout=30, env={**os.environ, "VAULT_ROOT": str(tmp_path)})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["items"][0]["kind"] == "goal-review"


def test_corrupt_ledger_is_not_an_empty_resume_or_work_queue(tmp_path):
    ledger = tmp_path / "loop.jsonl"
    ledger.write_text('{"type":"objective","text":"Example"}\nnot json\n', encoding="utf-8")
    with pytest.raises(LedgerReadError, match="invalid JSON"):
        HuntLoop.load(ledger)
