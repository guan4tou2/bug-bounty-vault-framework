"""hunt_autodrive — the orchestrator runs the loop autonomously over ONE ASG state.

Acceptance (the metrics the operator actually cares about):
  - runs multiple rounds with ZERO human interventions until a clear hand-back;
  - after a reload it self-continues and does NOT re-run completed/refuted/dead-ended
    work (dead_end_reruns == 0, 0 fresh dispatches on reload);
  - a BLOCKED hypothesis reopens when its precondition capability lands;
  - INCONCLUSIVE is retried up to a bounded budget then parked (no infinite retry);
  - failure paths are recorded, distinguished by cause, and never re-proposed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop  # noqa: E402
from hunt_autodrive import autodrive, Budget, WorkerTask  # noqa: E402
from logic_vuln_loop import Env, LogicHypothesis, Observation  # noqa: E402

ENV = Env(version="1", role="unauth", host="t")


# requires is tracked on the ledger (add_hypothesis), NOT on the dataclass.
REQUIRES: dict[str, list] = {}


def _hyp(hid, surface, requires, provides):
    REQUIRES[hid] = requires
    return LogicHypothesis(
        hyp_id=hid, dimension="roles", invariant=f"unauth {surface} must be denied",
        applies_env=ENV, precondition="none", expected_normal="denied",
        test_action=f"GET {surface}", control_action=f"GET {surface} (baseline)",
        violation_outcome="200", provides=provides, surface_id=surface,
        expected_normal_outcome="302")


# controlled outcomes per hypothesis (the "tool")
def _outcomes(hid):
    return {
        "a-config":  ("200", "302"),         # CONFIRMED -> provides cap:config
        "b-public":  ("302", "302"),         # REFUTED (test == control)
        "c-flaky":   (None, "302"),          # INCONCLUSIVE (test env error)
        "d-chained": ("200", "302"),         # CONFIRMED (only reachable after cap:config)
        "e-variant": ("302", "302"),         # replan variant -> REFUTED
    }[hid]


def _build():
    loop = HuntLoop()
    reg = {
        "a-config":  _hyp("a-config", "/api/config", [], ["cap:config"]),
        "b-public":  _hyp("b-public", "/api/public", [], []),
        "c-flaky":   _hyp("c-flaky", "/api/flaky", [], []),
        "d-chained": _hyp("d-chained", "/api/chained", ["cap:config"], ["cap:chain"]),
    }
    # pre-register with real `requires` so d-chained starts BLOCKED then reopens.
    for h in reg.values():
        loop.add_hypothesis(h.hyp_id, requires=REQUIRES[h.hyp_id])
    return loop, reg


def _make_dispatch(reg, counter):
    def dispatch(task: WorkerTask):
        counter["n"] += 1
        hid = task.hyp.hyp_id
        t_out, c_out = _outcomes(hid)
        test = Observation(action_id=task.hyp.test_action, ok=(t_out is not None),
                           outcome=t_out, evidence_ref=f"ev:{hid}",
                           error=None if t_out is not None else "timeout")
        ctrl = Observation(action_id=task.hyp.control_action, ok=True, outcome=c_out,
                           evidence_ref=f"ctl:{hid}")
        return test, ctrl
    return dispatch


def _make_propose(reg, variants):
    # auto-replan brain: hand out queued variants, then None (nothing left).
    def propose(loop, cap):
        return variants.pop(0) if variants else None
    return propose


def test_orchestrator_runs_autonomously_then_hands_back_cleanly():
    loop, reg = _build()
    counter = {"n": 0}
    variant = _hyp("e-variant", "/api/variant", [], [])
    reg["e-variant"] = variant
    rep = autodrive(
        loop, current_env=ENV,
        dispatch=_make_dispatch(reg, counter),
        propose=_make_propose(reg, [variant]),
        ready_hyp=lambda hid: reg[hid],
        budget=Budget(max_actions=50, max_replans=5, max_retries_per_hyp=2),
    )
    # confirmed both the direct and the chained (reopened) surface
    assert set(rep.confirmed) == {"/api/config", "/api/chained"}
    # exactly ONE hand-back, and it is a clean autonomous-exhaustion reason
    assert rep.interventions == 1
    assert "no autonomous next step" in rep.handoff_reason
    # d-chained was BLOCKED then reopened by cap:config
    assert rep.reopens >= 1
    # bounded INCONCLUSIVE retry: c-flaky ran at most the retry budget, never looped
    c_runs = sum(1 for hid, v, _ in rep.trace if hid == "c-flaky")
    assert c_runs == 2                                  # exactly the bounded budget
    # refuted path proposed at most once, never re-proposed
    assert sum(1 for hid, v, _ in rep.trace if hid == "b-public") == 1
    # a dead-end was recorded for the refuted + the exhausted-inconclusive, scoped
    dead = [e for e in loop.events if e["kind"] == "dead_end"]
    causes = {e["hyp_id"]: e["cause"] for e in dead}
    assert causes.get("b-public") == "refuted"
    assert causes.get("c-flaky") == "inconclusive-exhausted"
    assert all("role" in e["scope"] for e in dead)     # scoped, not generalised


def test_reload_self_continues_without_rerunning_dead_ends():
    # run once, persist, reload, run again -> must NOT re-dispatch terminal work.
    loop, reg = _build()
    variant = _hyp("e-variant", "/api/variant", [], [])
    reg["e-variant"] = variant
    autodrive(loop, current_env=ENV,
              dispatch=_make_dispatch(reg, {"n": 0}),
              propose=_make_propose(reg, [variant]),
              ready_hyp=lambda hid: reg[hid],
              budget=Budget(max_actions=50, max_replans=5))

    tmp = Path(__file__).resolve().parents[1] / "tests" / "_autodrive_reload.jsonl"
    try:
        loop.save(str(tmp))
        reloaded = HuntLoop.load(str(tmp))
        counter2 = {"n": 0}
        rep2 = autodrive(
            reloaded, current_env=ENV,
            dispatch=_make_dispatch(reg, counter2),
            propose=_make_propose(reg, []),      # nothing new to propose
            ready_hyp=lambda hid: reg[hid],
            budget=Budget(max_actions=50, max_replans=5),
        )
        # self-continues to a clean stop with NO fresh tool dispatch and NO reruns
        assert counter2["n"] == 0
        assert rep2.dead_end_reruns == 0
        assert rep2.confirmed == []                 # nothing new confirmed on reload
        assert rep2.interventions == 1              # recognises it is done, hands back
    finally:
        tmp.unlink(missing_ok=True)


def test_blocked_reopens_only_when_precondition_lands():
    # d-chained requires cap:config; with a-config removed it stays blocked forever
    # and the loop hands back (missing precondition) rather than spinning.
    loop = HuntLoop()
    d = _hyp("d-chained", "/api/chained", ["cap:config"], [])
    loop.add_hypothesis(d.hyp_id, requires=REQUIRES[d.hyp_id])
    rep = autodrive(
        loop, current_env=ENV,
        dispatch=_make_dispatch({"d-chained": d}, {"n": 0}),
        propose=lambda l, c: None,                  # no replan available
        ready_hyp=lambda hid: d,
        budget=Budget(max_actions=50, max_replans=2),
    )
    assert rep.confirmed == []                       # never ran (precondition unmet)
    assert rep.interventions == 1
    assert "no autonomous next step" in rep.handoff_reason
