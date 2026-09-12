"""Controlled logic-vuln research-loop cases (step 1 completion standard).

On a controlled ORDER flow, the loop must distinguish three outcomes and propose
a reasonable next step for each:
  (a) a real rule violation           -> CONFIRMED
  (b) suspicious-but-actually-normal   -> REFUTED (by design)
  (c) environment failure              -> INCONCLUSIVE (never "not vulnerable")

Plus the local designs: environment identification (mismatch blocks), the
evidence-verdict contract (200/success alone never confirms — the control does),
and interrupted-action reconciliation (no blind re-run).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop, Verdict, ExecutionResult  # noqa: E402
from logic_vuln_loop import (  # noqa: E402
    Env, Observation, LogicHypothesis, judge_logic, research_step, reconcile,
    Invariant, record_invariant, resolve_invariant, judge_state_transition,
)

PROD = Env(version="1.0", role="user", host="shop.example")


def _hyp(**kw):
    base = dict(
        hyp_id="H", dimension="invariant",
        invariant="an unpaid order must never yield goods",
        applies_env=PROD, precondition="order created, not paid",
        expected_normal="fulfilment refuses until payment settled",
        test_action="fulfil_unpaid", control_action="fulfil_normal_path",
        violation_outcome="fulfilled",
    )
    base.update(kw)
    return LogicHypothesis(**base)


# (a) REAL violation: unpaid order gets fulfilled; control shows normal path
#     requires payment. test != control, test hits the forbidden outcome.
def test_real_violation_is_confirmed():
    lp = HuntLoop()
    r = research_step(
        lp, _hyp(), PROD,
        run_test=lambda: Observation("fulfil_unpaid", ok=True, outcome="fulfilled", evidence_ref="poc/a"),
        run_control=lambda: Observation("fulfil_normal_path", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.CONFIRMED
    assert lp.capsule()["confirmed"]        # confirmed carried evidence
    assert r["next"]                        # proposes an extension (延伸新假設)


# (b) SUSPICIOUS but NORMAL: cross-user GET returns 200, but the control (a
#     different principal) ALSO gets 200 — the object is public by design.
#     200 == 200 -> REFUTED, NOT an IDOR.
def test_suspicious_but_normal_is_refuted():
    lp = HuntLoop()
    hyp = _hyp(hyp_id="H2", dimension="roles",
               invariant="user A cannot read user B's object",
               test_action="read_as_other_user", control_action="read_as_anonymous",
               violation_outcome="other_users_data")
    r = research_step(
        lp, hyp, PROD,
        run_test=lambda: Observation("read_as_other_user", ok=True, outcome="200_public"),
        run_control=lambda: Observation("read_as_anonymous", ok=True, outcome="200_public"),
    )
    assert r["verdict"] == Verdict.REFUTED
    assert lp.capsule()["capabilities"] == []   # nothing granted


# (c) ENV FAILURE: the test action cannot run -> INCONCLUSIVE, and the next step
#     is to fix the environment, NEVER "not vulnerable".
def test_env_failure_is_inconclusive_not_safe():
    lp = HuntLoop()
    r = research_step(
        lp, _hyp(hyp_id="H3"), PROD,
        run_test=lambda: Observation("fulfil_unpaid", ok=False, error="503 upstream"),
        run_control=lambda: Observation("fulfil_normal_path", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.INCONCLUSIVE
    assert any("do NOT mark safe" in n or "re-run" in n for n in r["next"])
    assert lp.capsule()["confirmed"] == {}


# evidence-verdict contract guard: "test returned 200/success" alone must NOT
# confirm — if the control is also the violation outcome, it's normal.
def test_success_alone_does_not_confirm():
    hyp = _hyp()
    v, _ = judge_logic(
        hyp,
        Observation("t", ok=True, outcome="fulfilled"),
        Observation("c", ok=True, outcome="fulfilled"),   # control also "fulfilled"
    )
    assert v == Verdict.REFUTED   # same as control -> by design, not a bug


# environment identification: a hypothesis for a different version must not run
# against the current env — BLOCKED, result never mis-attributed.
def test_env_mismatch_blocks_execution():
    lp = HuntLoop()
    hyp = _hyp(hyp_id="H4", applies_env=Env(version="2.0"))   # current is 1.0
    ran = {"test": False}
    r = research_step(
        lp, hyp, PROD,
        run_test=lambda: (ran.__setitem__("test", True) or Observation("x", ok=True, outcome="fulfilled")),
        run_control=lambda: Observation("c", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.BLOCKED
    assert ran["test"] is False                    # never executed against wrong env
    assert "acquire" in " ".join(r["next"]).lower()


# interrupted-action reconciliation: a prior completed execution for the test
# action is reused, not blindly re-run.
def test_interrupted_action_is_reconciled_not_rerun():
    lp = HuntLoop()
    # simulate a mid-run interrupt: the test execution was already recorded.
    lp.record_execution(ExecutionResult("fulfil_unpaid", exit_ok=True, output_ref="poc/prior"))
    assert reconcile(lp, "fulfil_unpaid") is not None
    reran = {"n": 0}
    research_step(
        lp, _hyp(hyp_id="H5"), PROD,
        run_test=lambda: (reran.__setitem__("n", reran["n"] + 1) or Observation("fulfil_unpaid", ok=True, outcome="fulfilled")),
        run_control=lambda: Observation("c", ok=True, outcome="payment_required"),
    )
    assert reran["n"] == 0     # reused the prior execution, did not re-run


# the loop keeps distinct verdicts distinct across a batch (no cross-contamination).
def test_three_cases_are_distinguished_in_one_ledger():
    lp = HuntLoop()
    verdicts = []
    # unique action_ids per experiment (the reconcile contract keys on action_id).
    for hid, ta, ca, t, c in [
        ("V", "tV", "cV", Observation("tV", True, "fulfilled", "poc/x"), Observation("cV", True, "payment_required")),
        ("N", "tN", "cN", Observation("tN", True, "200_public"), Observation("cN", True, "200_public")),
        ("E", "tE", "cE", Observation("tE", False, error="timeout"), Observation("cE", True, "payment_required")),
    ]:
        r = research_step(lp, _hyp(hyp_id=hid, test_action=ta, control_action=ca), PROD,
                          run_test=lambda t=t: t, run_control=lambda c=c: c)
        verdicts.append(r["verdict"])
    assert verdicts == [Verdict.CONFIRMED, Verdict.REFUTED, Verdict.INCONCLUSIVE]


# vault-97 friction #3b: a CONFIRMED verdict grants the hypothesis's declared caps.
def test_confirmed_grants_declared_provides():
    lp = HuntLoop()
    r = research_step(
        lp, _hyp(provides=["P:read=config"]), PROD,
        run_test=lambda: Observation("fulfil_unpaid", ok=True, outcome="fulfilled", evidence_ref="poc/a"),
        run_control=lambda: Observation("fulfil_normal_path", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.CONFIRMED
    assert lp.capsule()["capabilities"] == ["P:read=config"]     # no longer always empty


# vault-97 friction #3c: a terminal verdict marks the exercised surface tested,
# so resume advances instead of looping on replanning forever.
def test_terminal_verdict_marks_surface_tested():
    lp = HuntLoop()
    lp.add_surface("ep1", untested=True)
    research_step(
        lp, _hyp(surface_id="ep1"), PROD,
        run_test=lambda: Observation("fulfil_unpaid", ok=True, outcome="fulfilled", evidence_ref="poc/a"),
        run_control=lambda: Observation("fulfil_normal_path", ok=True, outcome="payment_required"),
    )
    assert "ep1" not in lp.capsule()["untested_surface"]        # marked tested


# vault-97 gap #2: two-unauth-200 must NOT be judged by-design. With a normative
# expected_normal_outcome, a control that doesn't match it is suspect -> INCONCLUSIVE.
def test_control_anomalous_is_inconclusive_not_refuted():
    hyp = _hyp(hyp_id="Hn", violation_outcome="200", expected_normal_outcome="401")
    v, reason = judge_logic(hyp, Observation("t", ok=True, outcome="200"),
                            Observation("c", ok=True, outcome="200"))
    assert v == Verdict.INCONCLUSIVE and "control is itself anomalous" in reason


def test_validated_control_still_refutes_and_confirms():
    hyp = _hyp(hyp_id="Hn2", violation_outcome="200", expected_normal_outcome="401")
    # both properly deny (401) -> genuinely normal -> REFUTED
    v1, _ = judge_logic(hyp, Observation("t", True, "401"), Observation("c", True, "401"))
    assert v1 == Verdict.REFUTED
    # control validated (401), test breaks it (200) -> CONFIRMED
    v2, _ = judge_logic(hyp, Observation("t", True, "200"), Observation("c", True, "401"))
    assert v2 == Verdict.CONFIRMED


# ── invariant provenance gate (don't let the agent invent the rule) ─────────
def test_confirmed_against_inferred_invariant_is_downgraded():
    """A perfect differential (test breaks rule, control doesn't) must NOT confirm
    when the RULE itself is only the agent's own inference — establish it first."""
    lp = HuntLoop()
    record_invariant(lp, Invariant("INV-made-up", "agent's guessed rule", source="inferred"))
    r = research_step(
        lp, _hyp(hyp_id="H", invariant_ref="INV-made-up"), PROD,
        run_test=lambda: Observation("t", ok=True, outcome="fulfilled"),
        run_control=lambda: Observation("c", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.INCONCLUSIVE          # would be CONFIRMED without the gate
    assert "self-inferred rule" in r["reason"]
    assert lp.capsule()["capabilities"] == []            # no capability from an invented rule


def test_established_invariant_allows_confirmation():
    lp = HuntLoop()
    # doc-sourced rule (or one re-recorded as 'observed' after establishing it)
    record_invariant(lp, Invariant("INV-unpaid", "unpaid order must not yield goods",
                                    source="doc", confidence="stated"))
    r = research_step(
        lp, _hyp(hyp_id="H", invariant_ref="INV-unpaid", provides=["P:order=fulfilled"]), PROD,
        run_test=lambda: Observation("t", ok=True, outcome="fulfilled", evidence_ref="poc/x"),
        run_control=lambda: Observation("c", ok=True, outcome="payment_required"),
    )
    assert r["verdict"] == Verdict.CONFIRMED
    assert lp.capsule()["capabilities"] == ["P:order=fulfilled"]


def test_inferred_invariant_becomes_established_by_reobservation():
    lp = HuntLoop()
    record_invariant(lp, Invariant("INV-x", "rule", source="inferred"))
    assert not resolve_invariant(lp, "INV-x").established()
    # establishing it = observe that the rule normally holds, re-record as observed
    record_invariant(lp, Invariant("INV-x", "rule", source="observed",
                                    confidence="observed", evidence_refs=["poc/normal"]))
    assert resolve_invariant(lp, "INV-x").established()   # latest-wins


# ── state-transition adjudicator (pre -> action -> post) ────────────────────
def test_state_transition_confirms_only_with_valid_precondition_and_differential():
    hyp = _hyp(hyp_id="H", precondition="member removed",
               violation_outcome="read_new_data", expected_normal_outcome="denied")
    pre = Observation("pre", ok=True, outcome="member_removed")          # precondition holds
    post = Observation("post", ok=True, outcome="read_new_data")         # test crossed the line
    control = Observation("ctl", ok=True, outcome="denied")              # proper subject is denied
    v, _ = judge_state_transition(hyp, pre, post, control)
    assert v == Verdict.CONFIRMED


def test_state_transition_precondition_absent_is_inconclusive():
    hyp = _hyp(hyp_id="H", precondition="member removed", violation_outcome="read_new_data")
    pre = Observation("pre", ok=True, outcome="precondition_absent")     # never actually removed
    post = Observation("post", ok=True, outcome="read_new_data")
    control = Observation("ctl", ok=True, outcome="denied")
    v, reason = judge_state_transition(hyp, pre, post, control)
    assert v == Verdict.INCONCLUSIVE and "precondition" in reason


def test_state_transition_failed_pre_read_is_inconclusive():
    hyp = _hyp(hyp_id="H", violation_outcome="read_new_data")
    pre = Observation("pre", ok=False, error="timeout")
    v, _ = judge_state_transition(hyp, pre, Observation("p", True, "read_new_data"),
                                  Observation("c", True, "denied"))
    assert v == Verdict.INCONCLUSIVE
