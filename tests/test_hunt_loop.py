"""Controlled-case tests for the minimal hunt-loop spine (automation/hunt_loop.py).

Each test is one of the failure modes the user called out: tool failure, evidence
contradiction, mid-run compaction/handover, and the "pending==0 != done" trap.
These are the acceptance cases that must hold before expanding to multi-agent /
routing / fuller graph.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop, ExecutionResult, Verdict, RunState, step_execute_and_judge  # noqa: E402


# I1 / gap 1: a clean execution does NOT confirm a vuln or grant a capability.
def test_execution_success_does_not_confirm_or_grant():
    lp = HuntLoop()
    lp.add_hypothesis("h1", requires=[])
    lp.record_execution(ExecutionResult("a1", exit_ok=True, output_ref="poc/out.txt"))
    cap = lp.capsule()
    assert cap["capabilities"] == []          # nothing granted from exit_ok
    assert "h1" not in cap["confirmed"]
    assert cap["ready_hypotheses"] == ["h1"]  # still open


# I1 positive: only a CONFIRMED verdict WITH evidence grants the capability.
def test_confirmed_with_evidence_grants_capability():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.CONFIRMED, evidence_ref="poc/proof.txt",
                      provides=["P:read=config"])
    cap = lp.capsule()
    assert cap["capabilities"] == ["P:read=config"]
    assert "h1" in cap["confirmed"]


# I1 guard: CONFIRMED without evidence must NOT grant a capability.
def test_confirmed_without_evidence_grants_nothing():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.CONFIRMED, evidence_ref=None,
                      provides=["P:exec=shell"])
    assert lp.capsule()["capabilities"] == []


# I6 / gap 5: a failed tool run is INCONCLUSIVE, never auto not_vulnerable — and
# the step backstop refuses to let a failed run confirm.
def test_failed_execution_is_inconclusive_not_confirmed():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    v = step_execute_and_judge(
        lp, "h1",
        run_tool=lambda: ExecutionResult("a1", exit_ok=False, error="timeout"),
        judge=lambda r: (Verdict.CONFIRMED, "poc/x", ["P:exec=shell"]),  # judge wrong
    )
    assert v == Verdict.INCONCLUSIVE
    cap = lp.capsule()
    assert cap["capabilities"] == []
    assert "h1" not in cap["confirmed"] and "h1" not in cap["refuted"]  # not refuted either


# I3 / gap 5: conflicting confirmed + refuted -> DISPUTED, both retained, neither
# silently wins.
def test_contradiction_marks_disputed():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.CONFIRMED, evidence_ref="poc/a", provides=["P:x"])
    lp.record_verdict("h1", Verdict.REFUTED, evidence_ref="poc/b")
    cap = lp.capsule()
    assert cap["disputed"] == ["h1"]
    assert "h1" not in cap["confirmed"]
    # capability from the disputed confirm must not stand
    assert cap["capabilities"] == []


# I4 / gap 6: save -> reload -> identical capsule (survives compaction / handover).
def test_reload_recovers_identical_capsule(tmp_path):
    lp = HuntLoop()
    lp.add_surface("ep1", untested=True)
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.CONFIRMED, evidence_ref="poc/a", provides=["P:x"])
    before = lp.capsule()
    f = tmp_path / "loop.jsonl"
    lp.save(f)
    reloaded = HuntLoop.load(f).capsule()
    assert reloaded == before


# I5: revoking a capability invalidates the hypothesis that required it.
def test_revoke_blocks_dependent():
    lp = HuntLoop()
    lp.add_hypothesis("gain", )
    lp.record_verdict("gain", Verdict.CONFIRMED, evidence_ref="poc/a", provides=["P:admin"])
    lp.add_hypothesis("use", requires=["P:admin"])
    assert "use" in lp.capsule()["ready_hypotheses"]
    lp.revoke_capability("P:admin", reason="token rotated")
    cap = lp.capsule()
    assert "P:admin" not in cap["capabilities"]
    assert "use" in cap["blocked_hypotheses"]
    assert "use" not in cap["ready_hypotheses"]


# I2 / gap 2: no ready hypotheses but untested surface remains -> REPLANNING,
# NOT completed.
def test_no_ready_but_untested_surface_is_replanning():
    lp = HuntLoop()
    lp.add_surface("ep_unmapped", untested=True)
    assert lp.capsule()["ready_hypotheses"] == []
    assert lp.run_state() == RunState.REPLANNING


# I2: disputed work also keeps us out of COMPLETED.
def test_disputed_is_not_completed():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.CONFIRMED, evidence_ref="poc/a")
    lp.record_verdict("h1", Verdict.REFUTED, evidence_ref="poc/b")
    assert lp.run_state() == RunState.REPLANNING


# I2 positive: only genuine exhaustion -> COMPLETED.
def test_true_exhaustion_is_completed():
    lp = HuntLoop()
    lp.add_surface("ep1", untested=False)      # mapped/tested
    lp.add_hypothesis("h1")
    lp.record_verdict("h1", Verdict.REFUTED, evidence_ref="poc/a")
    assert lp.run_state() == RunState.REPLANNING
    lp.complete("declared controlled-case coverage evaluated")
    assert lp.run_state() == RunState.COMPLETED


# stop-state precedence: needs_input / waiting_external override running.
def test_needs_input_and_waiting_override():
    lp = HuntLoop()
    lp.add_hypothesis("h1")
    assert lp.run_state() == RunState.RUNNING
    assert lp.run_state(needs_input=True) == RunState.NEEDS_INPUT
    assert lp.run_state(waiting_external=True) == RunState.WAITING_EXTERNAL


def test_revocation_invalidates_confirmed_descendants():
    lp = HuntLoop()
    lp.add_hypothesis('root')
    lp.record_verdict('root', Verdict.CONFIRMED, 'a', ['admin'])
    lp.add_hypothesis('child', ['admin'])
    lp.record_verdict('child', Verdict.CONFIRMED, 'b', ['write'])
    lp.add_hypothesis('leaf', ['write'])
    lp.revoke_capability('admin', 'expired')
    assert lp.capsule()['capabilities'] == []
    assert 'child' in lp.capsule()['invalidated_hypotheses']
    assert 'leaf' in lp.capsule()['blocked_hypotheses']


def test_independent_support_survives_dispute():
    lp = HuntLoop()
    for h in ('a', 'b'):
        lp.add_hypothesis(h)
        lp.record_verdict(h, Verdict.CONFIRMED, h, ['read'])
    lp.record_verdict('a', Verdict.REFUTED, 'control')
    assert lp.capsule()['capabilities'] == ['read']


def test_failed_tool_cannot_refute_and_exceptions_are_recorded():
    lp = HuntLoop()
    lp.add_hypothesis('h')
    def crash():
        raise TimeoutError()
    verdict = step_execute_and_judge(lp, 'h', crash,
                                    lambda r: (Verdict.REFUTED, 'x', []))
    assert verdict == Verdict.INCONCLUSIVE
    assert lp.capsule()['refuted'] == []
    assert lp.events[-2]['error'] == 'TimeoutError'
