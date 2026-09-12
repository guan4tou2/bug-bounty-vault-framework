"""hunt_worker — dispatch wired to a real isolated subagent with model-tiering.

The `spawn(prompt, model)` primitive is the only Agent-tool boundary; here it is faked
so the deterministic pieces (tier routing, prompt contract, result parsing, and the
compose into orchestrator dispatch) are fully tested.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "automation"))
from hunt_loop import HuntLoop, Verdict  # noqa: E402
from hunt_autodrive import autodrive, Budget, WorkerTask  # noqa: E402
from hunt_worker import (model_for_tier, render_worker_prompt,  # noqa: E402
                         parse_worker_result, make_dispatch)
from logic_vuln_loop import Env, LogicHypothesis, judge_logic  # noqa: E402

ENV = Env(version="2.6", role="unauth", host="wms-r1")


def _hyp(hid="h1", surface="/api/config"):
    return LogicHypothesis(
        hyp_id=hid, dimension="roles", invariant=f"unauth {surface} must be denied",
        applies_env=ENV, precondition="none", expected_normal="denied",
        test_action=f"GET {surface} (no creds)", control_action=f"GET {surface} (baseline)",
        violation_outcome="200", provides=[f"cap:{hid}"], surface_id=surface,
        expected_normal_outcome="302")


def _task(tier="strong", failed=None):
    return WorkerTask(hyp=_hyp(), goal="unauth /api/config must be denied",
                      evidence_refs=["cap:prior"], failed_paths=failed or [],
                      stop_conditions=["patient PII", "auth boundary"], model_tier=tier)


def test_model_tier_routes_by_difficulty():
    assert model_for_tier("cheap").startswith("claude-haiku")
    assert model_for_tier("strong") == "claude-sonnet-5"
    assert model_for_tier("max") == "claude-opus-5"
    assert model_for_tier("unknown") == model_for_tier("strong")   # safe default


def test_prompt_is_bounded_and_scope_injected():
    p = render_worker_prompt(_task(failed=["h0: refuted (reopen: different role)"]))
    assert "curl_probe" in p and "GET/HEAD only" in p              # GET-only enforced
    assert "GET /api/config (no creds)" in p and "baseline" in p   # both actions
    assert "version=2.6 role=unauth host=wms-r1" in p              # scope injected
    assert "h0: refuted" in p                                      # failed path to avoid
    assert "patient PII" in p                                      # stop condition
    assert "```json" in p and "verdict is NOT yours" in p          # structured contract


def test_result_roundtrip_feeds_the_oracle():
    task = _task()
    spawn = lambda prompt, model: (                                # worker returns a block
        'ran it.\n```json\n{"test": {"ok": true, "outcome": "200", "evidence_ref": "f1"},'
        ' "control": {"ok": true, "outcome": "302", "evidence_ref": "f2"}}\n```')
    dispatch = make_dispatch(spawn)
    test_obs, ctrl_obs = dispatch(task)
    assert test_obs.ok and test_obs.outcome == "200" and test_obs.evidence_ref == "f1"
    verdict, _ = judge_logic(task.hyp, test_obs, ctrl_obs)
    assert verdict == Verdict.CONFIRMED                            # 200 vs 302 baseline


def test_garbled_result_is_env_failure_not_not_vulnerable():
    task = _task()
    t, c = make_dispatch(lambda p, m: "the worker rambled with no json")(task)
    assert not t.ok and "no structured result" in (t.error or "")
    v, _ = judge_logic(task.hyp, t, c)
    assert v == Verdict.INCONCLUSIVE                               # never REFUTED on garble


def test_dict_result_also_parses():
    task = _task()
    obj = {"test": {"ok": True, "outcome": "302"}, "control": {"ok": True, "outcome": "302"}}
    t, c = make_dispatch(lambda p, m: obj)(task)
    v, _ = judge_logic(task.hyp, t, c)
    assert v == Verdict.REFUTED                                    # test == control (by design)


def test_orchestrator_runs_with_real_dispatch_shape():
    # the orchestrator drives end-to-end through make_dispatch, and model tier is
    # actually consulted per task (recorded by the fake spawn).
    loop = HuntLoop()
    h = _hyp("a", "/api/config")
    loop.add_hypothesis(h.hyp_id, requires=[])
    seen_models = []

    def spawn(prompt, model):
        seen_models.append(model)
        return {"test": {"ok": True, "outcome": "200", "evidence_ref": "e"},
                "control": {"ok": True, "outcome": "302", "evidence_ref": "c"}}

    rep = autodrive(
        loop, current_env=ENV,
        dispatch=make_dispatch(spawn),
        propose=lambda l, c: None,
        ready_hyp=lambda hid: h,
        budget=Budget(max_actions=5, max_replans=1),
    )
    assert rep.confirmed == ["/api/config"]                        # ran via real dispatch
    assert seen_models == ["claude-sonnet-5"]                      # strong tier consulted


def test_orchestrator_tiers_up_for_chain_judgement():
    # a cross-flow (composed chain) hypothesis must get the strongest model.
    loop = HuntLoop()
    h = LogicHypothesis(
        hyp_id="cf", dimension="cross-flow", invariant="refund+coupon must not stack",
        applies_env=ENV, precondition="none", expected_normal="rejected",
        test_action="POST stack", control_action="POST single",
        violation_outcome="200", surface_id="/checkout", expected_normal_outcome="409")
    loop.add_hypothesis(h.hyp_id, requires=[])
    seen = []

    def spawn(prompt, model):
        seen.append(model)
        return {"test": {"ok": True, "outcome": "200", "evidence_ref": "ev"},
                "control": {"ok": True, "outcome": "409", "evidence_ref": "c"}}

    autodrive(loop, current_env=ENV, dispatch=make_dispatch(spawn),
              propose=lambda l, c: None, ready_hyp=lambda hid: h,
              budget=Budget(max_actions=5, max_replans=1))
    assert seen == ["claude-opus-5"]                              # max tier for chain
