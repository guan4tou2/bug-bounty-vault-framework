"""No-progress stops are explicit and never become negative research evidence."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_autodrive import Budget, autodrive
from hunt_loop import HuntLoop
from logic_vuln_loop import Env, LogicHypothesis, Observation
from research_progress import progress_keys


def test_repeated_comparison_stops_without_refuting_or_exhausting_hypothesis():
    env = Env(version="1", role="member", host="fixture")
    hyp = LogicHypothesis(hyp_id="h", dimension="roles", invariant="Forbidden content stays private",
                          applies_env=env, precondition="owned fixture", expected_normal="denied",
                          test_action="GET /test", control_action="GET /control",
                          violation_outcome="private", expected_normal_outcome="denied")
    loop = HuntLoop()
    loop.asg = {"findings": [], "recon_dimensions": {"passive_osint": {"status": "completed"}}}
    loop.add_hypothesis("h")
    proof = {"kind": "observation", "text": "Controlled response had the fixed undecidable marker"}

    def dispatch(task):
        return (Observation(task.hyp.test_action, True, "unexpected", evidence_ref=proof),
                Observation(task.hyp.control_action, True, "denied", evidence_ref=proof))

    report = autodrive(loop, current_env=env, dispatch=dispatch, ready_hyp=lambda _: hyp,
                       propose=lambda *_: None,
                       budget=Budget(20, 20, max_retries_per_hyp=10, max_no_progress_rounds=2),
                       max_rounds=20)
    assert "no evidence progress" in report.handoff_reason
    assert report.terminal_class().startswith('no-progress:')
    assert report.rounds == 3
    assert loop.capsule()["refuted"] == []
    assert not any(e["type"] == "dead_end" for e in loop.events)
    assert loop.events[-1]["type"] == "research_progress"
    assert loop.events[-1]["unchanged_rounds"] == 2


def test_new_action_ids_and_failed_executions_are_not_research_progress():
    loop = HuntLoop()
    before = progress_keys(loop)
    loop.append("action_started", action_id="one", hyp_id="h")
    loop.append("action_finished", action_id="one", exit_ok=False, status="timed_out")
    loop.append("logic_verdict", hyp_id="h", verdict="inconclusive", execution="failed",
                evidence={"kind": "observation", "text": "A failed tool is not a target result"})
    assert progress_keys(loop) == before
    loop.append("surface", name="newly observed fixture")
    assert progress_keys(loop) - before == {("surface", "newly observed fixture")}


def test_renamed_hypothesis_with_same_claim_conditions_and_evidence_is_not_progress():
    loop = HuntLoop()
    proof = {"kind": "comparison", "test": {"kind": "observation", "text": "fixed undecidable marker"},
             "control": {"kind": "observation", "text": "fixed normal denial"}}

    def comparison(hid, role):
        loop.append('logic_hypothesis', hyp_id=hid, invariant='One owner only', dimension='roles',
                    applies_env={'version': '1', 'role': role, 'host': 'fixture'})
        loop.append('logic_verdict', hyp_id=hid, verdict='inconclusive', execution='ok', evidence=proof,
                    test_outcome='unexpected', control_outcome='denied')

    comparison('one', 'member')
    baseline = progress_keys(loop)
    comparison('renamed', 'member')
    assert progress_keys(loop) == baseline
    comparison('different-context', 'admin')
    assert len(progress_keys(loop) - baseline) == 1
