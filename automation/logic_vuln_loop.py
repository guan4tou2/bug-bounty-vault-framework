#!/usr/bin/env python3
"""logic_vuln_loop.py — the logic-vulnerability research closed loop.

Step 1 of the implementation plan: a controlled business-flow research loop that
can DISTINGUISH three outcomes on a rule and propose a reasonable next step:
  (a) a real rule violation,
  (b) suspicious-but-actually-normal (by-design) behaviour,
  (c) environment failure -> undecidable (never "not vulnerable").

Built ON TOP of the hunt_loop ledger (automation/hunt_loop.py) — no new store.

The core (the thing a scanner/200-check cannot do): a logic-vuln verdict is
decided by a CONTROL COMPARISON, not by "the test action returned 200 / the tool
succeeded." A test outcome only CONFIRMS a broken invariant when the control run
shows the system normally does NOT reach that outcome. If test == control, the
"suspicious" behaviour is just how the system behaves for everyone -> by design.

Local designs implemented here (with tests), per the plan:
  - environment identification: a hypothesis declares `applies_env`; it will not
    run against a mismatched env (BLOCKED, next = acquire matching env), so a
    result is never mis-attributed across versions/roles/hosts.
  - evidence-verdict contract: judge_logic() below — control comparison + explicit
    inconclusive-on-error; success/200 alone never confirms.
  - interrupted-action reconciliation: reconcile() checks the ledger for an
    already-recorded execution before re-running, so a mid-run interrupt does not
    cause a blind re-run (idempotent by action_id).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from hunt_loop import HuntLoop, Verdict


# ── environment + observation ───────────────────────────────────────────────
@dataclass(frozen=True)
class Env:
    """Which environment a result is valid for. Identity matters: a result on a
    different version/role/host is not evidence about this one."""
    version: str = "*"
    role: str = "*"
    host: str = "*"

    def matches(self, other: "Env") -> bool:
        def ok(a, b):
            return a == "*" or b == "*" or a == b
        return ok(self.version, other.version) and ok(self.role, other.role) and ok(self.host, other.host)


@dataclass
class Observation:
    """Result of running one action. `ok` = ran without environment error.
    `outcome` = a normalized rule-relevant token (NOT a raw HTTP code by itself)."""
    action_id: str
    ok: bool
    outcome: Optional[str] = None      # e.g. "fulfilled", "payment_required", "403", "200_public"
    evidence_ref: Optional[str] = None
    error: Optional[str] = None        # env/timeout/etc when ok is False


# ── invariant (a first-class, provenanced business rule) ────────────────────
# A hypothesis tests whether a business rule can be broken. The RULE itself must
# be a stored object with provenance, so the agent cannot invent a rule and then
# "confirm" the product violates its own invention. Ownership / state-machine /
# trust-boundary are NOT separate node types — they are expressed AS invariants
# (statement + scope), keeping the model domain-agnostic (web/desktop/mobile).
INVARIANT_SOURCES = {"doc", "code", "observed", "inferred"}
# A violation may be claimed only against an ESTABLISHED rule. `inferred` is the
# agent's own guess — it must first be established (found in doc/code, or shown to
# hold by a normal-behaviour observation) before a violation of it is trusted.
ESTABLISHED_SOURCES = {"doc", "code", "observed"}


@dataclass
class Invariant:
    inv_id: str
    statement: str                     # "removed member cannot read org data created after removal"
    scope: dict = field(default_factory=dict)   # {resource, subject_role, applies_env, ...}
    source: str = "inferred"           # doc | code | observed | inferred (provenance)
    confidence: str = "speculative"    # stated | observed | speculative
    evidence_refs: list[str] = field(default_factory=list)

    def established(self) -> bool:
        return self.source in ESTABLISHED_SOURCES


def record_invariant(loop: HuntLoop, inv: Invariant) -> None:
    if inv.source not in INVARIANT_SOURCES:
        raise ValueError(f"invalid invariant source {inv.source!r}; use {sorted(INVARIANT_SOURCES)}")
    loop.append("invariant", inv_id=inv.inv_id, statement=inv.statement, scope=inv.scope,
                source=inv.source, confidence=inv.confidence, evidence_refs=inv.evidence_refs)


def resolve_invariant(loop: HuntLoop, inv_id: str) -> Optional[Invariant]:
    """Latest-wins: establishing an inferred rule = record it again with source
    'observed' (+ the normal-behaviour evidence that shows it holds)."""
    latest = None
    for e in loop.events:
        if e.get("kind") == "invariant" and e.get("inv_id") == inv_id:
            latest = Invariant(inv_id=e["inv_id"], statement=e.get("statement", ""),
                               scope=e.get("scope", {}), source=e.get("source", "inferred"),
                               confidence=e.get("confidence", "speculative"),
                               evidence_refs=e.get("evidence_refs", []))
    return latest


def guard_invariant_provenance(inv: Optional[Invariant], verdict: Verdict,
                               reason: str) -> tuple[Verdict, str]:
    """Anti-hallucination on the RULE side: a CONFIRMED violation is only trusted
    when the invariant it breaks is an established rule. An unestablished
    (inferred/speculative) rule downgrades to INCONCLUSIVE — establish the rule
    first, don't claim a violation of a rule the agent just made up."""
    if verdict == Verdict.CONFIRMED and inv is not None and not inv.established():
        return Verdict.INCONCLUSIVE, (
            f"invariant {inv.inv_id} is {inv.source}/{inv.confidence}, not an established rule; "
            f"a violation cannot be claimed against a self-inferred rule. First establish it "
            f"(cite doc/code, or observe that the rule normally holds), then re-test. ({reason})")
    return verdict, reason


# ── hypothesis (every field is required to be a *verifiable* claim) ─────────
@dataclass
class LogicHypothesis:
    hyp_id: str
    dimension: str                     # invariant | roles | state | trust | cross-flow
    invariant: str                     # the business rule that must always hold (statement)
    applies_env: Env                   # version/role/host this claim is about
    precondition: str                  # required prior state
    expected_normal: str               # what a correct system does (the control's expectation)
    test_action: str                   # the action that would break the rule
    control_action: str                # the baseline / normal path for comparison
    violation_outcome: str             # the outcome token that means the rule was broken
    # a plain-language description of the observation that would prove breakage
    violation_signal: str = ""
    # capabilities a CONFIRMED verdict grants (threaded to the ledger so capsule
    # capabilities are not always empty — vault-97 friction #3b)
    provides: list[str] = field(default_factory=list)
    # precondition capabilities this hypothesis needs (CG chaining): a hyp whose
    # requires are unmet is BLOCKED in the capsule until an upstream CONFIRMED finding
    # provides them — enabling unauth capability chains without any account.
    requires: list[str] = field(default_factory=list)
    # the surface node this hypothesis exercises; a terminal verdict marks it
    # tested so resume stops looping on replanning (friction #3c)
    surface_id: Optional[str] = None
    # NORMATIVE baseline: the outcome a CORRECT system MUST produce for the control
    # action (e.g. "401"). When set, the control is only trusted as a by-design
    # witness if it actually matches this — otherwise test==control cannot prove
    # "normal" (two-unauth-200 problem, vault-97 gap #2).
    expected_normal_outcome: Optional[str] = None
    # the established rule this hypothesis tests (provenance gate). When set,
    # research_step downgrades a CONFIRMED against an unestablished invariant.
    invariant_ref: Optional[str] = None
    # generation lens (heuristic tag only, NOT graph structure): role-swap |
    # state-order | entry-diff | lifecycle | composition | exploratory
    lens: Optional[str] = None
    # STATE-TRANSITION adjudication (pre -> action -> post). Optional reads that
    # capture the state before/after the action, so the verdict compares a real
    # state change against the rule, not just a single response outcome.
    pre_read_action: Optional[str] = None
    post_read_action: Optional[str] = None
    # explanations that must be ruled out before CONFIRMED is trusted
    alternative_explanations: list[str] = field(default_factory=list)


# ── evidence-verdict contract (the heart) ───────────────────────────────────
def judge_logic(hyp: LogicHypothesis, test_obs: Observation, control_obs: Observation) -> tuple[Verdict, str]:
    """Decide a logic-vuln verdict from a test run + its control. Returns
    (verdict, reason). 200/tool-success alone is never enough — the control
    decides."""
    # (c) environment failure on either side -> undecidable, never not-vulnerable.
    if not test_obs.ok:
        return Verdict.INCONCLUSIVE, f"test action failed to run ({test_obs.error or 'env error'}); cannot decide"
    if not control_obs.ok:
        return Verdict.INCONCLUSIVE, f"control action failed to run ({control_obs.error or 'env error'}); no baseline"

    # NORMATIVE guard (vault-97 gap #2): a by-design conclusion requires a control
    # that is itself CORRECT. If the hypothesis declares what a correct system must
    # yield for the control and the observed control does not match it, the control
    # is suspect — two matching-but-broken outcomes (e.g. both unauth 200) must not
    # be read as "normal". Escalate to INCONCLUSIVE and demand a validated control.
    if hyp.expected_normal_outcome:
        # expected_normal_outcome may be a single token or a set of acceptable
        # denial outcomes (systems vary: 401 / 403 / 302-redirect-to-login / ...).
        normal = ({hyp.expected_normal_outcome} if isinstance(hyp.expected_normal_outcome, str)
                  else set(hyp.expected_normal_outcome))
        if control_obs.outcome not in normal:
            return Verdict.INCONCLUSIVE, (
                f"control is itself anomalous: outcome '{control_obs.outcome}' not in expected-normal "
                f"{sorted(normal)}. A matching-but-broken control cannot prove 'by design' "
                f"(two-unauth-200 trap). Get a validated known-good control before deciding."
            )

    # (b) test behaves exactly like the control -> the behaviour is normal/by-design.
    if test_obs.outcome == control_obs.outcome:
        return Verdict.REFUTED, (
            f"test outcome '{test_obs.outcome}' == control outcome; the behaviour is "
            f"how the system responds normally (by design), not a broken invariant"
        )

    # (a) real violation: test reached the forbidden outcome AND the control did NOT
    # (so the system normally prevents it) -> the invariant is broken.
    if test_obs.outcome == hyp.violation_outcome and control_obs.outcome != hyp.violation_outcome:
        return Verdict.CONFIRMED, (
            f"invariant broken: test reached '{hyp.violation_outcome}' which the invariant forbids, "
            f"while the control shows the system normally yields '{control_obs.outcome}' — "
            f"differential proves the rule can be crossed"
        )

    # test differs from control but not in the forbidden way -> not decisive yet.
    return Verdict.INCONCLUSIVE, (
        f"test '{test_obs.outcome}' vs control '{control_obs.outcome}' differ but test did not reach the "
        f"violation outcome '{hyp.violation_outcome}'; need a sharper discriminating experiment"
    )


# ── state-transition adjudicator (pre -> action -> post vs the rule) ────────
def judge_state_transition(hyp: LogicHypothesis, pre_obs: Observation,
                           post_obs: Observation, control_obs: Observation) -> tuple[Verdict, str]:
    """Richer oracle for lifecycle/ownership invariants where the response is a
    normal 200 and only the STATE change reveals the break. `pre_obs` establishes
    the precondition actually held; `post_obs` is the state after the action;
    `control_obs` is the post-state a PROPERLY-constrained subject reaches.

    CONFIRMED only when: the precondition held, the test's post-state crosses the
    forbidden boundary, AND the control (properly constrained) does NOT — i.e. the
    system normally prevents it. Reuses judge_logic's differential + normative
    guard on (post vs control), adding the precondition check on top."""
    if not pre_obs.ok:
        return Verdict.INCONCLUSIVE, f"pre-read failed ({pre_obs.error or 'env error'}); precondition unverified — cannot decide"
    if pre_obs.outcome is not None and hyp.precondition and pre_obs.outcome == "precondition_absent":
        return Verdict.INCONCLUSIVE, ("precondition did not hold at pre-read (e.g. the subject was not "
                                      "actually removed); the test never exercised the rule")
    # delegate the post-vs-control differential to the audited outcome oracle
    return judge_logic(hyp, post_obs, control_obs)


# ── the research step (env gate + reconciliation + judge + next steps) ──────
def env_gate(hyp: LogicHypothesis, current_env: Env) -> Optional[str]:
    """Return a block-reason if this hypothesis must not run against current_env."""
    if not hyp.applies_env.matches(current_env):
        return (f"env mismatch: hypothesis targets {hyp.applies_env} but current is {current_env}; "
                f"acquire the matching environment before running (result would be mis-attributed)")
    return None


def reconcile(loop: HuntLoop, action_id: str) -> Optional[dict]:
    """Interrupted-action reconciliation: if the ledger already has a completed
    execution for action_id, return it so we DON'T blindly re-run. Returns None if
    it should run fresh."""
    for e in reversed(loop.events):
        if e.get("kind") == "execution" and e.get("action_id") == action_id:
            return e
    return None


def next_hypotheses(hyp: LogicHypothesis, verdict: Verdict) -> list[str]:
    """Extend the research (延伸新假設) from a result — reasonable next step, not a stop."""
    if verdict == Verdict.CONFIRMED:
        # a broken invariant almost always has siblings across the other dimensions
        sibs = {
            "state": ["roles: same skip as another tenant?", "cross-flow: does cancel+refund re-open it?"],
            "roles": ["state: can the same actor skip a required step?"],
            "invariant": ["state: reach the forbidden state via a different transition"],
            "trust": ["cross-flow: does a background job re-validate the same field?"],
            "cross-flow": ["invariant: is a second invariant broken by the same composition?"],
        }
        return sibs.get(hyp.dimension, ["probe the adjacent dimension for the same object"])
    if verdict == Verdict.INCONCLUSIVE:
        return ["fix the environment / sharpen the control, then re-run — do NOT mark safe"]
    if verdict == Verdict.REFUTED:
        return ["drop this path; try a different dimension or object"]
    return []


def research_step(loop: HuntLoop, hyp: LogicHypothesis, current_env: Env,
                  run_test, run_control, invariant: Optional[Invariant] = None) -> dict:
    """One full logic-vuln research step. `run_test`/`run_control` are callables
    returning an Observation (injected, so controlled cases are testable).
    Records everything to the ledger and returns a structured result.

    `invariant` (or hyp.invariant_ref resolved from the ledger) enables the
    provenance gate: a CONFIRMED violation of an unestablished (self-inferred)
    rule is downgraded to INCONCLUSIVE — the rule must be established first."""
    # register the hypothesis on the ledger with its declared requires (CG chaining):
    # capsule keeps the first-seen requires (setdefault), so a pre-registered hyp is
    # unaffected while a freshly-proposed one now carries its precondition capabilities.
    loop.add_hypothesis(hyp.hyp_id, requires=hyp.requires)
    loop.append("logic_hypothesis", hyp_id=hyp.hyp_id, dimension=hyp.dimension,
                invariant=hyp.invariant, expected_normal=hyp.expected_normal,
                invariant_ref=hyp.invariant_ref, lens=hyp.lens,
                applies_env={"version": hyp.applies_env.version, "role": hyp.applies_env.role,
                             "host": hyp.applies_env.host})

    block = env_gate(hyp, current_env)
    if block:
        loop.record_verdict(hyp.hyp_id, Verdict.BLOCKED, evidence_ref=None)
        return {"verdict": Verdict.BLOCKED, "reason": block, "next": ["acquire matching environment"]}

    # interrupted-action reconciliation for the test action
    prior = reconcile(loop, hyp.test_action)
    test_obs = _obs_from_event(prior) if prior else run_test()
    if not prior:
        loop.record_execution(_exec_result(test_obs))
    control_obs = run_control()
    loop.record_execution(_exec_result(control_obs))

    verdict, reason = judge_logic(hyp, test_obs, control_obs)
    # provenance gate: a violation is only trusted against an ESTABLISHED rule.
    inv = invariant if invariant is not None else (
        resolve_invariant(loop, hyp.invariant_ref) if hyp.invariant_ref else None)
    verdict, reason = guard_invariant_provenance(inv, verdict, reason)
    # I1: only a CONFIRMED verdict carries evidence + grants the hypothesis's
    # declared capabilities to the ledger's capability layer.
    loop.record_verdict(hyp.hyp_id, verdict,
                        evidence_ref=(test_obs.evidence_ref if verdict == Verdict.CONFIRMED else None),
                        provides=(hyp.provides if verdict == Verdict.CONFIRMED else []))
    # bookkeeping: a terminal verdict (confirmed/refuted) marks the exercised
    # surface tested, so resume advances instead of looping on replanning.
    if hyp.surface_id and verdict in (Verdict.CONFIRMED, Verdict.REFUTED):
        loop.add_surface(hyp.surface_id, untested=False)
    loop.append("logic_verdict", hyp_id=hyp.hyp_id, verdict=verdict.value, reason=reason,
                test_outcome=test_obs.outcome, control_outcome=control_obs.outcome)
    return {"verdict": verdict, "reason": reason, "next": next_hypotheses(hyp, verdict),
            "reused_prior_execution": bool(prior)}


# ── small adapters between Observation and the hunt_loop execution event ────
def _exec_result(o: Observation):
    from hunt_loop import ExecutionResult
    return ExecutionResult(action_id=o.action_id, exit_ok=o.ok, output_ref=o.evidence_ref, error=o.error)


def _obs_from_event(e: dict) -> Observation:
    return Observation(action_id=e.get("action_id"), ok=bool(e.get("exit_ok")),
                       evidence_ref=e.get("output_ref"), error=e.get("error"),
                       outcome=e.get("outcome"))
