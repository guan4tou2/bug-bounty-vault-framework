#!/usr/bin/env python3
"""hunt_autodrive.py — the ORCHESTRATOR that runs the hunt loop autonomously.

Corrects the over-demotion: the execution loop is the GOAL (auto-hunt, minimise
human intervention), not opt-in. What is cut is duplicate *input* (four hand-kept
docs, per-finding CGT tagging, history backfill) — never the loop. State lives in
ONE place: the hunt_loop ledger (the ASG projection). DAG/CG/DT are views of it
(capsule.ready = DAG; capsule.capabilities/confirmed = CG; next_hypotheses = DT).

The orchestrator cycle:
  read ASG -> select executable & valuable work -> dispatch a worker -> collect
  evidence -> judge by control -> update ASG -> next round.
Hand back to the human ONLY on clear conditions (authorization boundary, missing
account/info, risk boundary, budget/replan exhausted) — otherwise auto-replan.

Design corrections baked in:
  1. Tool execution is auto-logged but NEVER auto-grants a capability — only an
     evidence-backed CONFIRMED verdict does (delegated to research_step/judge_logic).
  2. A worker's task is a bounded STRUCTURE (WorkerTask), not free-form thinking;
     memory stays in the ASG, not the worker.
  3. Empty backlog -> bounded AUTO-REPLAN over uncovered surface / reopened-blocked /
     inconclusive-under-budget, not an immediate "continue?" question.

Failure paths are first-class and DISTINGUISHED (so a worker-switch or a reload does
not re-tread a dead end). refuted/blocked are already excluded/gated by the capsule;
this module adds bounded INCONCLUSIVE retry and SCOPED dead-end records
(scope/env/cause/reopen-condition) so "this role can't" is never generalised to
"no role can".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from hunt_loop import HuntLoop, Verdict
from logic_vuln_loop import Env, LogicHypothesis, Observation, reconcile, research_step


# ── worker contract (the isolation boundary; memory stays in the ASG) ────────
@dataclass
class WorkerTask:
    """A bounded task handed to an isolated worker. Carries only what the worker
    needs — goal, evidence to build on, preconditions, ALREADY-FAILED paths (so it
    does not repeat them), stop conditions — and a model tier by difficulty."""
    hyp: LogicHypothesis
    goal: str
    evidence_refs: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    failed_paths: list[str] = field(default_factory=list)   # scoped dead-ends to avoid
    stop_conditions: list[str] = field(default_factory=list)
    model_tier: str = "strong"      # "cheap" for format/fixed-checks, "strong" for
    #                                 logic-vuln hypotheses / contradictory evidence
    knowledge: list[str] = field(default_factory=list)      # LL/KB actually fed in


@dataclass
class Budget:
    max_actions: int
    max_replans: int
    max_retries_per_hyp: int = 2    # bounded INCONCLUSIVE retry (no infinite retry)
    actions: int = 0
    replans: int = 0
    def actions_left(self) -> int: return max(0, self.max_actions - self.actions)
    def exhausted(self) -> bool: return self.actions >= self.max_actions
    def replans_left(self) -> int: return max(0, self.max_replans - self.replans)


@dataclass
class DriveReport:
    rounds: int = 0
    interventions: int = 0          # times control returned to the human
    replans: int = 0                # autonomous path-switches
    reopens: int = 0                # blocked work re-armed by a new precondition
    dead_end_reruns: int = 0        # MUST stay 0 (reconcile + dead-end records)
    confirmed: list[str] = field(default_factory=list)
    handoff_reason: str = ""
    trace: list[tuple] = field(default_factory=list)


# ── scoped dead-end record (distinguished by cause; never over-generalised) ──
def record_dead_end(loop: HuntLoop, hyp: LogicHypothesis, cause: str,
                    reopen_when: str) -> None:
    """A terminal non-CONFIRMED outcome, recorded WITH its scope so a later worker/
    reload does not re-tread it AND does not over-generalise it. `cause` is one of
    inconclusive-exhausted / refuted / blocked / disputed / invalidated."""
    loop.append("dead_end", hyp_id=hyp.hyp_id, cause=cause,
                scope={"version": hyp.applies_env.version, "role": hyp.applies_env.role,
                       "host": hyp.applies_env.host},
                surface_id=hyp.surface_id, reopen_when=reopen_when)


def _dead_ended(loop: HuntLoop) -> dict:
    """hyp_id -> the last dead_end record (used to skip re-proposing it)."""
    out: dict[str, dict] = {}
    for e in loop.events:
        if e.get("kind") == "dead_end":
            out[e["hyp_id"]] = e
    return out


def _inconclusive_count(loop: HuntLoop, hyp_id: str) -> int:
    return sum(1 for e in loop.events if e.get("kind") == "logic_verdict"
               and e.get("hyp_id") == hyp_id and e.get("verdict") == Verdict.INCONCLUSIVE.value)


# generation lenses the replan brain should cover — reserve exploration here
# (anti-streetlight): a replan should prefer an UNCOVERED dimension over replaying
# a known-successful pattern. Ranking (below) handles ready work; this steers propose.
REPLAN_DIMENSIONS = ["invariant", "roles", "state", "trust", "cross-flow"]

_CHAIN_RANK = {"high": 0, "medium": 1, "low": 2, None: 3}


def value_rank(ready: list[str], cap: dict, loop: HuntLoop) -> list[str]:
    """Deterministic, explainable selection policy (decision ①): the LLM GENERATES
    candidate hypotheses; THIS orders the ready ones — no fake precise scores.
    Priority: higher chain/unlock potential > an uncovered dimension (breadth /
    anti-streetlight) > a fresh test before a retry > discovery order."""
    dim: dict[str, str] = {}
    chain: dict[str, str] = {}
    order: dict[str, int] = {}
    tested_dims: set = set()
    for i, e in enumerate(loop.events):
        k = e["kind"]
        if k == "hypothesis":
            order.setdefault(e["hyp_id"], i)
        elif k == "logic_hypothesis":
            dim[e["hyp_id"]] = e.get("dimension")
        elif k == "bbflow_candidate":
            chain[e["hyp_id"]] = (e.get("candidate", {}) or {}).get("chain_potential")
        elif k == "logic_verdict" and e.get("verdict") in ("confirmed", "refuted"):
            tested_dims.add(dim.get(e.get("hyp_id")))
    inconclusive = cap.get("inconclusive", {})

    def key(h: str):
        return (_CHAIN_RANK.get(chain.get(h), 3),
                0 if dim.get(h) not in tested_dims else 1,   # uncovered dimension first
                1 if inconclusive.get(h, 0) else 0,           # fresh before retry
                order.get(h, 1 << 30), h)

    return sorted(ready, key=key)


def _tier_for(hyp: LogicHypothesis, cap: dict) -> str:
    """Model tier by task difficulty (corr. #2): the hardest judgements — reconciling
    contradictory evidence, or composed attack-chain reasoning — get the strongest
    model; a straightforward access-control differential is fine on the strong tier;
    cheap is reserved for format/fixed-check work items (not produced here)."""
    if hyp.hyp_id in cap.get("disputed", []):
        return "max"                                   # contradictory evidence
    if hyp.dimension in ("cross-flow",):
        return "max"                                   # composed chain judgement
    return "strong"                                    # normal logic-vuln hypothesis


# ── the orchestrator ────────────────────────────────────────────────────────
def autodrive(
    loop: HuntLoop,
    *,
    current_env: Env,
    dispatch: Callable[[WorkerTask], tuple[Observation, Observation]],
    propose: Callable[[HuntLoop, dict], Optional[LogicHypothesis]],
    budget: Budget,
    ready_hyp: Optional[Callable[[str], LogicHypothesis]] = None,
    human_gate: Optional[Callable[[HuntLoop, dict], Optional[str]]] = None,
    kb_tags: Optional[list[str]] = None,
    kb_dir=None,
    rank: Optional[Callable[[list[str], dict, HuntLoop], list[str]]] = None,
    persist: Optional[Callable[[HuntLoop], None]] = None,
    max_rounds: int = 200,
) -> DriveReport:
    """Run the loop until a clear hand-back condition. Callables:
      dispatch(task)   -> (test_obs, control_obs); runs the isolated worker/tools.
      propose(loop,cap)-> a NEW hypothesis (auto-replan brain) or None if nothing
                          valuable is left to try autonomously.
      ready_hyp(id)    -> reconstruct the LogicHypothesis for a ready capsule id
                          (needed after a reload, when the object isn't in memory).
      human_gate(loop,cap) -> a reason string to hand back (auth/account/risk), else None.
    """
    rep = DriveReport()
    prev_caps: set = set()

    while rep.rounds < max_rounds:
        cap = loop.capsule()

        # reopen bookkeeping: a blocked hyp becomes ready when a new capability lands
        caps_now = set(cap["capabilities"])
        if caps_now - prev_caps and cap["ready_hypotheses"]:
            rep.reopens += sum(1 for _ in (caps_now - prev_caps))
        prev_caps = caps_now

        # 1) clear hand-back conditions FIRST (authorization / account / risk)
        if human_gate:
            reason = human_gate(loop, cap)
            if reason:
                rep.interventions += 1
                rep.handoff_reason = reason
                break
        if budget.exhausted():
            rep.interventions += 1
            rep.handoff_reason = f"action budget exhausted ({budget.max_actions})"
            break

        # 2) select executable work: a ready hyp not dead-ended / not over retry budget.
        # `rank` (decision ①) orders ready work by value; default = capsule order.
        dead = _dead_ended(loop)
        ready_ids = rank(cap["ready_hypotheses"], cap, loop) if rank else cap["ready_hypotheses"]
        hyp: Optional[LogicHypothesis] = None
        for hid in ready_ids:
            if hid in dead:                               # scoped dead-end -> skip
                continue
            if _inconclusive_count(loop, hid) >= budget.max_retries_per_hyp:
                if hid not in dead:
                    # bounded retry reached -> park as a scoped dead-end, do not loop
                    h = ready_hyp(hid) if ready_hyp else None
                    if h:
                        record_dead_end(loop, h, "inconclusive-exhausted",
                                        "fix the environment / sharpen the control")
                continue
            hyp = ready_hyp(hid) if ready_hyp else None
            if hyp:
                break

        # 3) empty backlog -> bounded AUTO-REPLAN (not an immediate question)
        was_replan = False
        if hyp is None:
            if budget.replans_left() <= 0:
                rep.interventions += 1
                rep.handoff_reason = "replan budget exhausted (bounded; avoids infinite retry)"
                break
            hyp = propose(loop, cap)
            budget.replans += 1
            was_replan = True
            if hyp is None:
                rep.interventions += 1
                rep.handoff_reason = ("no autonomous next step — uncovered surface, "
                                      "blocked work and pending hypotheses are all "
                                      "exhausted; needs new surface/auth/scope")
                break

        # 3b) re-tread guard (problem #3): never dispatch a path already recorded
        # dead — whether it slipped through as ready after a reload, or the replan
        # brain re-proposed it. Count the caught re-tread and skip; the ONLY
        # legitimate way back in is a scoped reopen (a precondition/capability
        # landing that makes a fresh, differently-scoped hypothesis).
        if hyp is not None and hyp.hyp_id in dead:
            rep.dead_end_reruns += 1
            continue

        # 4) KB/LL in-loop BEFORE the task, and actually FEED it to the worker (the
        # earlier bug: retrieval ran AFTER the task was built and its result was
        # discarded — knowledge was logged, never used). A retrieval failure is a
        # recorded knowledge_retrieval event, never a silent swallow, so "thought we
        # had prior experience but started from zero" is visible in the capsule.
        knowledge: list[str] = []
        if kb_tags:
            # ensure the hypothesis exists on the ledger so ledger-lesson retrieval
            # (which requires a known hyp) works for a freshly-proposed one too.
            if hyp.hyp_id not in {e.get("hyp_id") for e in loop.events if e["kind"] == "hypothesis"}:
                loop.add_hypothesis(hyp.hyp_id)
            try:
                from kb_connector import retrieve_all
                hits = retrieve_all(loop, hyp.hyp_id, kb_tags, kb_dir=kb_dir)
                for h in hits.get("ledger", []):
                    knowledge.append(f"LL {h.get('lesson_id')}: {h.get('rule', '')}".strip())
                for h in hits.get("kb", []):
                    knowledge.append(f"{h.get('lesson_id')}: {h.get('title', '')}".strip())
                loop.append("knowledge_retrieval", hyp_id=hyp.hyp_id,
                            status="success" if knowledge else "degraded",
                            query=sorted(set(kb_tags)),
                            selected_ids=[h.get("lesson_id") for h in hits.get("ledger", [])]
                            + [h.get("lesson_id") for h in hits.get("kb", [])])
            except Exception as exc:
                loop.append("knowledge_retrieval", hyp_id=hyp.hyp_id, status="failed",
                            query=sorted(set(kb_tags)), selected_ids=[], reason=type(exc).__name__)

        # 5) build the bounded worker task (memory stays in the ASG, not the worker),
        # NOW carrying the retrieved knowledge so it actually shapes the worker.
        task = WorkerTask(
            hyp=hyp, goal=hyp.invariant,
            evidence_refs=[c for cs in cap["confirmed"].values() for c in cs][:8],
            preconditions=list(hyp.provides and [] or []),
            failed_paths=[f"{d['hyp_id']}: {d['cause']} (reopen: {d['reopen_when']})"
                          for d in dead.values()],
            stop_conditions=["patient PII observed", "service impact", "auth boundary"],
            model_tier=_tier_for(hyp, cap),   # tiered by difficulty (corr. #2)
            knowledge=knowledge,
        )

        # 6) execute + judge. research_step reconciles the test action, so a reload /
        #    worker-switch mid-flight does NOT blindly re-run (dead_end_reruns stays 0).
        prior = reconcile(loop, hyp.test_action)
        pair: dict = {}

        def _run_test():
            t, c = dispatch(task)
            pair["c"] = c
            return t

        def _run_control():
            if "c" in pair:
                return pair["c"]
            return dispatch(task)[1]

        res = research_step(loop, hyp, current_env, _run_test, _run_control)
        if prior:
            rep.dead_end_reruns += 0        # reconcile prevented a blind re-run
        v = res["verdict"]

        # 7) update failure-path memory, distinguished by cause
        if v == Verdict.CONFIRMED and hyp.surface_id:
            rep.confirmed.append(hyp.surface_id)
        elif v == Verdict.REFUTED:
            record_dead_end(loop, hyp, "refuted",
                            "a DIFFERENT env/role/version, or a new precondition")
        elif v == Verdict.BLOCKED:
            record_dead_end(loop, hyp, "blocked", "the missing precondition is acquired")
        # INCONCLUSIVE: left retryable until the bounded count is hit (handled above).

        rep.replans += 1 if was_replan else 0
        rep.trace.append((hyp.hyp_id, v.value, res["reason"][:70]))
        budget.actions += 1
        rep.rounds += 1

        # durable per-round: heartbeat + lock-guarded save (the run-entry supplies
        # persist). Raises ConcurrentWriter if another writer took the ledger over.
        if persist:
            persist(loop)

    return rep
