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

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from hunt_loop import HuntLoop, Verdict
from logic_vuln_loop import Env, LogicHypothesis, Observation, reconcile, research_step
from failure_memory import same_failure_scope as _same_failure_scope
import recon_dimensions_lib as rdl


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
    # Genesis capability_model decides what SUCCESS means for this engagement, so the
    # worker orients its next-hop thinking correctly: finding-finding (bounty/cve) chains
    # a confirmed invariant into the next finding via bb-exploit-chain; foothold (redteam)
    # translates it into a privilege/access rung via bb-web-foothold. Carried, not derived
    # here — the map lives once in genesis_lib.
    capability_model: str = "finding-finding"
    worker_skill: str = "bb-exploit-chain"
    research_context: list[str] = field(default_factory=list)
    flow_context: dict = field(default_factory=dict)


@dataclass
class Budget:
    max_actions: int
    max_replans: int
    max_retries_per_hyp: int = 2    # bounded INCONCLUSIVE retry (no infinite retry)
    # Bounded retry for actions that never RAN. Separate from the line above on
    # purpose: exhausting it parks the hypothesis for THIS RUN only and never writes
    # a dead end, because the environment can be fixed before the next run.
    max_exec_failures_per_hyp: int = 2
    max_no_progress_rounds: int = 3
    actions: int = 0
    replans: int = 0
    # artex TaskClock (2026-10-09): an OPTIONAL wall-clock deadline for the whole run,
    # folded in by the CALLER (e.g. program_rules_gate.window_remaining_minutes → epoch)
    # so this module stays decoupled from scope rules — the Budget just carries a number.
    # Within `wrapup_margin_min` of it, the loop stops opening NEW exploration and hands
    # back for a FINAL wrap-up (deliver in-hand) rather than being hard-cut mid-probe at
    # the authorization boundary. 0/None = no clock (behaves exactly as before).
    deadline_epoch: Optional[float] = None
    wrapup_margin_min: float = 30.0
    def actions_left(self) -> int: return max(0, self.max_actions - self.actions)
    def exhausted(self) -> bool: return self.actions >= self.max_actions
    def replans_left(self) -> int: return max(0, self.max_replans - self.replans)
    def wrapping_up(self, now_epoch: Optional[float] = None) -> bool:
        """True once the run is within wrapup_margin_min of its wall-clock deadline."""
        if not self.deadline_epoch:
            return False
        return (self.deadline_epoch - (now_epoch if now_epoch is not None else time.time())) \
            <= self.wrapup_margin_min * 60


@dataclass
class DriveReport:
    rounds: int = 0
    interventions: int = 0          # times control returned to the human
    replans: int = 0                # autonomous path-switches
    reopens: int = 0                # blocked work re-armed by a new precondition
    dead_end_reruns: int = 0        # MUST stay 0 (reconcile + dead-end records)
    exec_failures: int = 0          # actions that never ran (environment/tool trouble)
    # artex-inspired terminal taxonomy (2026-10-09): the next session must know WHY a
    # hypothesis stopped, because the three reasons want opposite follow-ups —
    #   parked_blocked : the action never RAN (expired login / flaky host / missing tool).
    #                    No dead end written; fix the environment and RE-RUN — it is
    #                    retryable, not refuted.
    #   dead_ended     : actually tried and did not hold (refuted / inconclusive-exhausted /
    #                    blocked-precondition / declined). Do NOT re-tread.
    #   budget exhausted (handoff_reason) : progress was real, just out of actions/replans —
    #                    RESUME to continue, same work is still valid.
    # Surfacing this mechanically (instead of leaving the operator to read the trace)
    # stops "tool failed" from being misread as "vuln absent".
    parked_blocked: list[str] = field(default_factory=list)   # hyp ids parked, env-retryable
    dead_ended: list[str] = field(default_factory=list)       # hyp ids retired this run
    confirmed: list[str] = field(default_factory=list)
    # the authorization window is closing — the loop stopped opening new work and handed
    # back for a FINAL wrap-up (artex TaskClock `Final` round). Most time-urgent terminal.
    window_closing: bool = False
    handoff_reason: str = ""
    trace: list[tuple] = field(default_factory=list)
    # actions the loop deferred because their risk tier is not auto-authorized
    # (writes_data / service_impact) — the human-go queue. The read-only loop keeps
    # running past these; they are surfaced for a human to authorize, NOT a global stop.
    needs_human_go: list[dict] = field(default_factory=list)

    def terminal_class(self) -> str:
        """One-line, machine-chosen next action for the handoff (artex terminal taxonomy).
        Ordered by what the next session should do FIRST."""
        if self.window_closing:
            # most time-urgent: once the window shuts nothing can run, so finalise in-hand
            # NOW — ahead of needs-human-go (authorization you cannot use after it closes).
            return ("window-closing: authorization window near its end — FINALISE in-hand "
                    "(report/submit confirmed), do NOT open new exploration")
        if self.needs_human_go:
            return (f"needs-human-go: {len(self.needs_human_go)} write/impact action(s) "
                    f"wait for authorization (bb_authorize)")
        if self.parked_blocked:
            return (f"env-blocked: {len(set(self.parked_blocked))} hypothesis parked because "
                    f"the action never RAN (fix env: login/host/tool) then RE-RUN — not refuted")
        if "budget exhausted" in self.handoff_reason or "selection budget" in self.handoff_reason:
            return "budget-exhausted: progress was real, RESUME to continue the same work"
        if "no evidence progress" in self.handoff_reason:
            return "no-progress: identify a missing discriminator or prerequisite before another bounded comparison"
        if self.dead_ended and not self.confirmed:
            return (f"dead-ended: {len(set(self.dead_ended))} hypothesis retired this run "
                    f"(refuted/inconclusive-exhausted) — do NOT re-tread; replan a new angle")
        return "clean: read-only work exhausted; review the queue"


# ── risk-tiered action gating (the two-loop split: reads auto, writes wait) ───
# The unattended loop may run any action it can positively classify as read-only; a
# write / destructive / service-impacting action is deferred to the needs_human_go
# queue instead of executed, and the loop continues to the next read-only work. The
# worker's own stop_conditions ("unknown side effects require a concrete question")
# are the backstop for anything this cheap pre-filter misclassifies.
import risk_tier  # the single workspace risk classifier (shared with the interactive gate)

RISK_TIERS = risk_tier.RISK_TIERS


def human_go_decisions(loop) -> "tuple[set, set]":
    """(authorized, declined) hyp_id sets from human_go ledger events (bb_authorize.py).
    Latest decision per hyp_id wins, so a decline can be reversed by a later go."""
    latest: dict[str, str] = {}
    for e in loop.events:
        if e.get("type") == "human_go" and e.get("hyp_id"):
            d = str(e.get("decision", "")).strip()
            if d in ("go", "decline"):
                latest[str(e["hyp_id"])] = d
    go = {h for h, d in latest.items() if d == "go"}
    decline = {h for h, d in latest.items() if d == "decline"}
    return go, decline


def action_risk(hyp) -> str:
    """Risk tier of a hypothesis's action, for the auto/defer gate. Prefers an explicit
    `action_risk`/`verification_risk` field if the hypothesis carries one; otherwise
    derives it from the test/control action text. Comparison probes (the bulk of logic-vuln
    hypotheses) are reads by design → default reads_only; only a positively-matched write
    or service-impacting verb escalates."""
    explicit = getattr(hyp, "action_risk", None) or getattr(hyp, "verification_risk", None)
    text = f"{getattr(hyp, 'test_action', '')} {getattr(hyp, 'control_action', '')}"
    return risk_tier.classify_text(text, explicit=explicit)


# ── scoped dead-end record (distinguished by cause; never over-generalised) ──
def record_dead_end(loop: HuntLoop, hyp: LogicHypothesis, cause: str,
                    reopen_when: str) -> None:
    """A terminal non-CONFIRMED outcome, recorded WITH its scope so a later worker/
    reload does not re-tread it AND does not over-generalise it. `cause` is one of
    inconclusive-exhausted / refuted / blocked / disputed / invalidated."""
    loop.append("dead_end", hyp_id=hyp.hyp_id, cause=cause,
                scope={"version": hyp.applies_env.version, "role": hyp.applies_env.role,
                       "host": hyp.applies_env.host},
                available_capabilities=sorted(loop.capsule()["capabilities"]),
                surface_id=hyp.surface_id, reopen_when=reopen_when)


def _dead_ended(loop: HuntLoop) -> dict:
    """hyp_id -> the last dead_end record (used to skip re-proposing it)."""
    out: dict[str, dict] = {}
    for e in loop.events:
        if e.get("type") == "dead_end":
            out[e["hyp_id"]] = e
    return out


def _inconclusive_count(loop: HuntLoop, hyp_id: str) -> int:
    """INCONCLUSIVE verdicts that actually DECIDED nothing — execution failures excluded.

    Only this count may retire a hypothesis as a dead end. An action that never ran
    (login expired, SSH timeout, worker returned unparseable output) tells us about
    the environment, not about the hypothesis, so counting it here would convert
    infrastructure trouble into a permanently-skipped attack surface. Those are
    tracked per-run instead (see `exec_failures` in autodrive) and stay retryable.

    Events written before `execution` existed carry no field; they are treated as
    "ok" so historical behaviour is unchanged.
    """
    return sum(1 for e in loop.events if e.get("type") == "logic_verdict"
               and e.get("hyp_id") == hyp_id and e.get("verdict") == Verdict.INCONCLUSIVE.value
               and e.get("execution", "ok") == "ok")


def _exec_failure_count(loop: HuntLoop, hyp_id: str) -> int:
    """How often this hypothesis failed to RUN (diagnostic; never retires anything)."""
    return sum(1 for e in loop.events if e.get("type") == "logic_verdict"
               and e.get("hyp_id") == hyp_id and e.get("execution") == "failed")


def _last_execution_failed(loop: HuntLoop, hyp_id: str) -> bool:
    """Did the most recent attempt on this hypothesis fail to execute?"""
    for e in reversed(loop.events):
        if e.get("type") == "logic_verdict" and e.get("hyp_id") == hyp_id:
            return e.get("execution") == "failed"
    return False


# generation lenses the replan brain should cover — reserve exploration here
# (anti-streetlight): a replan should prefer an UNCOVERED dimension over replaying
# a known-successful pattern. Ranking (below) handles ready work; this steers propose.
REPLAN_DIMENSIONS = ["invariant", "roles", "state", "trust", "cross-flow"]

# Reconnaissance dimensions (LL-336, 2026-09-26): orthogonal to testing dimensions.
# These track which CATEGORIES of information gathering have been performed.
# When active probing stalls, the propose() function should prefer an untried
# recon dimension over deeper probing in the same one.
# Floor dimensions checked in priority order. version_cve is auto (event-driven).
# Targets may add custom dimensions to ASG recon_dimensions — those are picked up
# dynamically by pending_recon_dimensions() and appended after these.
# The recon floor lives in recon_dimensions_lib (single source of truth, shared
# with recon_completeness_gate). Kept as an alias for readers of this module.
_RECON_DIMENSION_FLOOR = rdl.FLOOR


def pending_recon_dimensions(loop: HuntLoop) -> list[str]:
    """Return recon dimensions that are still pending, in priority order.

    Checks the floor dimensions first, then any custom dimensions the target
    added to its ASG (e.g., regulatory_filings, supply_chain_deps). Tolerant of
    both recon_dimensions shapes (dict and list-of-dict) via recon_dimensions_lib.
    """
    asg = getattr(loop, "asg", None) or {}
    rd = asg.get("recon_dimensions")
    all_dims = list(_RECON_DIMENSION_FLOOR)
    for d in rdl.normalize(rd):
        n = d["name"]
        if n and n not in all_dims and n != "version_cve":
            all_dims.append(n)
    return [n for n, _ in rdl.floor_pending(rd, all_dims)]


def stall_detected(loop: HuntLoop, threshold: int = 3) -> bool:
    """True if the last `threshold` test rounds produced no new findings.

    Only counts 'refuted' verdicts as stall evidence.  'blocked' verdicts
    (e.g., needs account) are not stall — they need a capability, not a
    dimension jump.
    """
    recent_verdicts = [
        e for e in loop.events
        if e.get("type") == "logic_verdict"
    ][-threshold:]
    if len(recent_verdicts) < threshold:
        return False
    return all(
        e.get("verdict") not in ("confirmed", "blocked")
        for e in recent_verdicts
    )


def passive_osint_incomplete(loop: HuntLoop) -> bool:
    """True if passive_osint is still pending — hard block on Stage 5.
    Shape-tolerant (dict or list-of-dict) via recon_dimensions_lib."""
    asg = getattr(loop, "asg", None) or {}
    status, _ = rdl.dim_status(asg.get("recon_dimensions"), "passive_osint")
    return not rdl.is_done(status)


def version_cve_stale(loop: HuntLoop) -> list[dict]:
    """Return nodes with version info discovered >1 round ago but not yet CVE-searched."""
    asg = getattr(loop, "asg", None) or {}
    vc = rdl.get_dim(asg.get("recon_dimensions"), "version_cve") or {}
    vc_raw = vc.get("raw") if isinstance(vc, dict) else {}
    checked = {
        e["component"]: e
        for e in ((vc_raw or {}).get("checked") or [])
        if isinstance(e, dict) and "component" in e
    }
    stale = []
    for node in asg.get("nodes", []):
        ver = node.get("version")
        comp = node.get("identifier", "")
        if ver and comp not in checked:
            stale.append({"node_id": node.get("id"), "component": comp,
                          "version": ver})
    return stale

def discovery_feedback(loop: HuntLoop, pre_node_count: int) -> list[dict]:
    """Detect new ASG nodes added during the last test round (Stage 5→0/1 feedback).

    Compare current ASG node count against pre_node_count (snapshotted before the
    test). Returns new nodes that should trigger re-OSINT on the new scope.
    """
    asg = getattr(loop, "asg", None) or {}
    nodes = asg.get("nodes", [])
    if len(nodes) <= pre_node_count:
        return []
    return nodes[pre_node_count:]


def capability_gap_analysis(loop: HuntLoop) -> list[dict]:
    """Return R: tags sorted by how many blocked nodes they would unblock.

    This answers "what capability should I acquire next to unlock the most
    attack surface?" — feeding into Stage 4 prioritization.
    """
    asg = getattr(loop, "asg", None) or {}
    cap_state = {c.get("cap", "") for c in asg.get("capability_state", [])}
    blocker_count: dict[str, int] = {}
    for finding in asg.get("findings", []):
        requires = finding.get("requires", [])
        for req in requires:
            if req not in cap_state:
                blocker_count[req] = blocker_count.get(req, 0) + 1
    return sorted(
        [{"tag": tag, "blocked_count": count} for tag, count in blocker_count.items()],
        key=lambda x: -x["blocked_count"],
    )


def verification_debt_report(loop: HuntLoop) -> dict:
    """Shared validator; missing context is unavailable, never a clean result."""
    from verification_debt import validate
    return validate(loop.asg, getattr(loop, 'asg_base', None))


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
        k = e["type"]
        if k == "hypothesis":
            order.setdefault(e["id"], i)
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


def _required_evidence(loop, requires, cap):
    import json
    latest = {e['hypothesis']: e for e in loop.events if e.get('type') == 'verdict'}
    evidence = [latest[h]['evidence'] for h, cs in cap['confirmed'].items()
                if set(cs) & set(requires) and latest.get(h, {}).get('evidence')]
    return list(dict.fromkeys(json.dumps(e, ensure_ascii=False, sort_keys=True)
                             if isinstance(e, dict) else e for e in evidence))


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
    round_log: Optional[Callable[[dict], None]] = None,
    templater: Optional[Callable[[HuntLoop, dict], Optional[LogicHypothesis]]] = None,
    capability_model: str = "finding-finding",
    worker_skill: str = "bb-exploit-chain",
    auto_risk: "frozenset[str]" = frozenset({"reads_only", "state_query"}),
    stop_at: Optional[str] = None,
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
    # Per-RUN parking for hypotheses whose actions never ran. Deliberately in-memory:
    # the environment (expired login, flaky host, missing tool) can be repaired before
    # the next run, so this must not survive into the ledger as a dead end.
    exec_failures: dict = {}
    from research_progress import progress_keys
    known_progress = progress_keys(loop)
    no_progress_rounds = 0

    for _selection_attempt in range(max_rounds):
        # --until review_pending: early-stop the moment there is ANYTHING for a human —
        # a confirmed finding to review or a deferred write awaiting authorization. Default
        # (stop_at=None) instead exhausts read-only work and hands back the full queue.
        if stop_at == "review_pending" and (rep.confirmed or rep.needs_human_go):
            rep.handoff_reason = ("--until review_pending: reached the first human-actionable "
                                  "item (confirmed finding / needs_human_go)")
            break
        cap = loop.capsule()
        # Expose the engagement's success model to the injected brains (propose/rank/
        # human_gate read it off the capsule) so a foothold engagement replans toward the
        # next privilege rung, not just the next vuln class.
        cap["capability_model"] = capability_model
        cap["worker_skill"] = worker_skill

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
        # artex TaskClock: inside the wrap-up margin of the authorization window, stop
        # opening NEW exploration and hand back for a FINAL round. Confirmed findings in
        # hand are kept; this is a clean time-bound stop, not an environment failure.
        if budget.wrapping_up():
            rep.interventions += 1
            rep.window_closing = True
            rep.handoff_reason = (f"authorization window closing (≤{budget.wrapup_margin_min:g}min) "
                                  f"— FINAL wrap-up, no new exploration")
            break

        # Research work uses the native runner's existing web/file tools. Never
        # silently skip it or turn a plain-language intent into an arbitrary shell.
        from asg_research import project as research_graph, worker_context, append_to_loop, settle_test_intent
        research = research_graph(loop.events, loop.base_path, cap=cap)
        rnodes = {n["ref"]: n for n in research["nodes"]}
        rsummary = research["summary"]
        native = [r for r in rsummary["ready_intents"] if not rnodes[r].get("hypothesis")]
        if rsummary["running_intents"] or native:
            refs = rsummary["running_intents"] or native
            rep.handoff_reason = "native research work pending: " + ", ".join(refs)
            break
        if rsummary["open_goals"] and not cap["ready_hypotheses"] and not rsummary["ready_intents"]:
            rep.handoff_reason = "goal acceptance or research prerequisites pending: " + ", ".join(rsummary["open_goals"])
            break

        # 2) select executable work: a ready hyp not dead-ended / not over retry budget.
        # `rank` (decision ①) orders ready work by value; default = capsule order.
        dead = _dead_ended(loop)
        _hg_go, _hg_decline = human_go_decisions(loop)
        ready_ids = rank(cap["ready_hypotheses"], cap, loop) if rank else cap["ready_hypotheses"]
        hyp: Optional[LogicHypothesis] = None
        for hid in ready_ids:
            from blocked_research import project as blocked_project
            if any(r['hyp_id'] == hid for r in blocked_project(loop.events, loop.base_path)):
                # Work cards diagnose and compare alternatives; do not automatically
                # replay the original failed action while that research is unresolved.
                continue
            if hid in dead:                               # scoped dead-end -> skip
                continue
            if exec_failures.get(hid, 0) >= budget.max_exec_failures_per_hyp:
                # Could not RUN this one enough times in this run — park it for now.
                # No dead end is written: nothing was learned about the hypothesis,
                # only about the environment, and the environment may be fixed by
                # the next run. It stays ready and will be picked up again then.
                if hid not in rep.parked_blocked:
                    rep.parked_blocked.append(hid)      # env-blocked, retryable (artex)
                continue
            if _inconclusive_count(loop, hid) >= budget.max_retries_per_hyp:
                if hid not in dead:
                    # bounded retry reached -> park as a scoped dead-end, do not loop
                    h = ready_hyp(hid) if ready_hyp else None
                    if h:
                        record_dead_end(loop, h, "inconclusive-exhausted",
                                        "fix the environment / sharpen the control")
                        rep.dead_ended.append(hid)
                continue
            cand = ready_hyp(hid) if ready_hyp else None
            if not cand:
                continue
            # human_go authorization (bb_authorize.py, clicked in operator UI) overrides the
            # risk tier per-action: `decline` skips it for good, `go` runs it despite tier.
            if hid in _hg_decline:
                if hid not in dead:
                    record_dead_end(loop, cand, "declined",
                                    "human declined this write via bb_authorize; re-authorize to reopen")
                    rep.dead_ended.append(hid)
                continue
            # risk-tier gate: a write/service-impact action is deferred to the human-go
            # queue (not executed) and the loop keeps scanning read-only work. This is the
            # unattended-loop boundary — reads run all night, writes wait for a human.
            tier = action_risk(cand)
            if tier not in auto_risk and hid not in _hg_go:
                if not any(q["hyp_id"] == hid for q in rep.needs_human_go):
                    rep.needs_human_go.append(
                        {"hyp_id": hid, "risk": tier, "action": cand.test_action,
                         "surface": cand.surface_id, "invariant": cand.invariant})
                    rep.trace.append(("needs_human_go", hid, f"{tier}: deferred (not auto-authorized)"))
                    # Persist to the ledger (SoT) so next_work/operator UI surface the queue —
                    # once per hyp_id; a later verdict clears it in the projection.
                    if not any(e.get("type") == "needs_human_go" and e.get("hyp_id") == hid
                               for e in loop.events):
                        loop.append("needs_human_go", hyp_id=hid, risk=tier,
                                    action=cand.test_action, surface=cand.surface_id,
                                    invariant=cand.invariant)
                continue
            hyp = cand
            break

        # 2a) passive_osint hard block: cannot proceed to testing if OSINT
        # is still pending. Force the loop to do OSINT first.
        if getattr(loop, 'asg', None) and passive_osint_incomplete(loop):
            rep.trace.append(("osint_block", "passive_osint",
                              "passive OSINT still pending — must complete before testing"))
            pending_rd = pending_recon_dimensions(loop)
            if pending_rd:
                rep.trace.append(("dimension_jump", pending_rd[0],
                                  "redirecting to passive_osint"))
            rep.interventions += 1
            rep.handoff_reason = 'recon context missing or passive OSINT incomplete; load context and complete reconnaissance'
            break

        # 2a.1) version_cve stale check: any node with version info that
        # hasn't been CVE-searched yet → fire immediately.
        stale_versions = version_cve_stale(loop)
        if stale_versions:
            rep.trace.append(("version_cve_stale", stale_versions,
                              "components with version info not yet CVE-searched"))

        # 2b) dimension stall check (LL-336): if active probing is stalling,
        # suggest jumping to an untried recon dimension BEFORE burning a replan.
        # This is the structural escape from tunnel vision — it forces the loop
        # to consider "did I gather info from all channels?" not just "did I test
        # all endpoints in this channel?".
        if hyp is None and stall_detected(loop):
            pending_rd = pending_recon_dimensions(loop)
            if pending_rd:
                rep.trace.append(("dimension_jump", pending_rd[0],
                                  "stall detected, jumping to untried recon dimension"))

        # 3) empty backlog -> bounded AUTO-REPLAN (not an immediate question)
        was_replan = False
        if hyp is None:
            if budget.replans_left() <= 0:
                rep.interventions += 1
                rep.handoff_reason = "replan budget exhausted (bounded; avoids infinite retry)"
                break
            # DETERMINISTIC coverage first: seed hypotheses for a held capability (Gap 3)
            # or the next untested surface (Gap 1/2) from templates; only fall back to the
            # LLM brain for what the templates do not cover. Template seeding does not burn
            # a replan (it is free + exhaustive), so untested surface can never sit idle.
            hyp = templater(loop, cap) if templater else None
            # LL-336 dimension jump: if templates produce nothing, check if there are
            # untried recon dimensions before asking the LLM brain to propose within
            # the same testing dimension. Pass pending_recon_dimensions to propose()
            # so it can prioritize a dimension jump over deeper same-dimension work.
            if hyp is None:
                pending_rd = pending_recon_dimensions(loop)
                cap["pending_recon_dimensions"] = pending_rd
                hyp = propose(loop, cap)
                budget.replans += 1
            was_replan = True
            if hyp is None:
                rep.interventions += 1
                if rep.needs_human_go:
                    # the read-only loop ran itself dry; what remains is write/impact
                    # work waiting on human authorization — this is the intended
                    # "stop at review_pending / needs-human-go" resting state.
                    tiers = sorted({q["risk"] for q in rep.needs_human_go})
                    rep.handoff_reason = (
                        f"read-only surface exhausted; {len(rep.needs_human_go)} action(s) "
                        f"deferred for human authorization ({', '.join(tiers)}) — review the "
                        f"needs_human_go queue")
                else:
                    rep.handoff_reason = ("no autonomous next step — uncovered surface, "
                                          "blocked work and pending hypotheses are all "
                                          "exhausted; needs new surface/auth/scope")
                break

        # Check the actual hypothesis at dispatch, including reconstructed ready work.
        # Replanning may return an existing hypothesis whose research intent was
        # excluded from ready_hypotheses. Recheck the binding itself so proposing
        # the same ID cannot bypass its work state or prerequisite capabilities.
        from asg_research import project as project_research
        research = project_research(loop.events, loop.base_path, cap=loop.capsule())
        rnodes = {n["ref"]: n for n in research["nodes"]}
        rsummary = research["summary"]
        bound = [n for n in rnodes.values() if n["kind"] == "intent"
                 and n.get("hypothesis") == f"hypothesis:{hyp.hyp_id}"]
        if any(n["effective_state"] != "open" or n.get("missing") for n in bound):
            rep.trace.append((hyp.hyp_id, "research-blocked", "bound intent is not dispatchable"))
            rep.handoff_reason = 'research intent prerequisites pending: ' + '; '.join(
                f"{n['ref']} [{n['effective_state']}] missing={n.get('missing', [])}" for n in bound
                if n['effective_state'] != 'open' or n.get('missing'))
            break
        if hyp and not set(hyp.requires).issubset(cap['capabilities']):
            loop.add_hypothesis(hyp.hyp_id, requires=list(hyp.requires))
            rep.trace.append((hyp.hyp_id, 'blocked', 'missing capability'))
            continue

        # 3b) re-tread guard (problem #3): never dispatch a path already recorded
        # dead — whether it slipped through as ready after a reload, or the replan
        # brain re-proposed it. Count the caught re-tread and skip; the ONLY
        # legitimate way back in is a scoped reopen (a precondition/capability
        # landing that makes a fresh, differently-scoped hypothesis).
        if hyp is not None and hyp.hyp_id in dead:
            rep.dead_end_reruns += 1
            continue

        # 4) ensure hypothesis is on the ledger (with strategy for the feedback loop)
        _registered = {e.get("id") for e in loop.events if e["type"] == "hypothesis"}
        _strategy = getattr(hyp, "strategy", None)
        if hyp.hyp_id not in _registered:
            loop.add_hypothesis(hyp.hyp_id, requires=hyp.requires, strategy=_strategy)
        elif _strategy and not any(
                e.get("id") == hyp.hyp_id and e.get("strategy")
                for e in loop.events if e["type"] == "hypothesis"):
            # Registered WITHOUT a strategy (a hand-written or migrated hypothesis), and
            # this run learned which thinking move it was. Step 4's original guard only
            # tagged hypotheses it had never seen, so a pre-registered one dropped the
            # tag and its verdict became invisible to `compute_strategy_stats` — the
            # loop silently stopped feeding itself. Append-only ledger, so append a new
            # hypothesis event carrying the tag (stats read the latest, not the first).
            loop.add_hypothesis(hyp.hyp_id, requires=hyp.requires, strategy=_strategy)

        # 4b) KB/LL in-loop BEFORE the task, and actually FEED it to the worker (the
        # earlier bug: retrieval ran AFTER the task was built and its result was
        # discarded — knowledge was logged, never used). A retrieval failure is a
        # recorded knowledge_retrieval event, never a silent swallow, so "thought we
        # had prior experience but started from zero" is visible in the capsule.
        knowledge: list[str] = []
        if kb_tags:
            try:
                from kb_connector import retrieve_all
                # 假說本身是散文（invariant = 「這條業務規則必須成立」的陳述），
                # 把它一起送進去才用得到語意通道；kb_tags 只做得到字面比對。
                kb_query = " ".join(x for x in (getattr(hyp, "invariant", ""),
                                                 getattr(hyp, "test_action", "")) if x)
                hits = retrieve_all(loop, hyp.hyp_id, kb_tags, kb_dir=kb_dir, query=kb_query)
                for h in hits.get("ledger", []):
                    knowledge.append(f"LL {h.get('lesson_id')}: {h.get('rule', '')}".strip())
                for h in hits.get("kb", []):
                    knowledge.append(f"{h.get('lesson_id')}: {h.get('title', '')}".strip())
                for h in hits.get("kb_docs", []):
                    summary = f" — {h.get('summary', '')}" if h.get("summary") else ""
                    knowledge.append(f"{h.get('doc_id')}: {h.get('title', '')}{summary}".strip())
                loop.append("knowledge_retrieval", hyp_id=hyp.hyp_id,
                            status="success" if knowledge else "degraded",
                            query=sorted(set(kb_tags)),
                            selected_ids=[h.get("lesson_id") for h in hits.get("ledger", [])]
                            + [h.get("lesson_id") for h in hits.get("kb", [])]
                            + [h.get("doc_id") for h in hits.get("kb_docs", [])])
            except Exception as exc:
                loop.append("knowledge_retrieval", hyp_id=hyp.hyp_id, status="failed",
                            query=sorted(set(kb_tags)), selected_ids=[], reason=type(exc).__name__)

        # 5) build the bounded worker task (memory stays in the ASG, not the worker),
        # NOW carrying the retrieved knowledge so it actually shapes the worker.
        from flow_model import context_for_hypothesis
        task = WorkerTask(
            hyp=hyp, goal=hyp.invariant,
            evidence_refs=_required_evidence(loop, hyp.requires, cap),
            preconditions=list(hyp.requires),
            failed_paths=[f"{d['hyp_id']}: {d['cause']} (same conditions; reopen: {d['reopen_when']})"
                          for d in dead.values() if _same_failure_scope(d, hyp)],
            stop_conditions=["unexpected third-party sensitive data observed", "service impact", "outside authorized accounts/resources or unknown side effects"],
            model_tier=_tier_for(hyp, cap),   # tiered by difficulty (corr. #2)
            knowledge=knowledge,
            capability_model=capability_model,
            worker_skill=worker_skill,
            flow_context=context_for_hypothesis(loop.events, hyp.hyp_id, loop.base_path),
        )
        bound_intent = next((rnodes[r] for r in rsummary["ready_intents"]
                             if rnodes[r].get("hypothesis") == f"hypothesis:{hyp.hyp_id}"), None)
        if bound_intent:
            task.research_context = worker_context(research, bound_intent)
            append_to_loop(loop, "research_state", ref=bound_intent["ref"], state="running",
                           reason="Bounded ASG test runner dispatch")

        # 5.5) snapshot ASG node count for discovery feedback detection
        pre_test_node_count = len((getattr(loop, "asg", None) or {}).get("nodes", []))

        # 6) execute + judge. research_step reconciles the test action, so a reload /
        #    worker-switch mid-flight does NOT blindly re-run (dead_end_reruns stays 0).
        prior = reconcile(loop, hyp.test_action)
        pair: dict = {}

        def _run_test():
            t, c = dispatch(task)
            pair["t"] = t
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
        if v == Verdict.BLOCKED or any(not o.ok for o in (pair.get('t'), pair.get('c')) if o is not None):
            from blocked_research import capture_worker_block
            capture_worker_block(loop, hyp.hyp_id, pair.get('t'), pair.get('c'))
        if bound_intent:
            settle_test_intent(loop, bound_intent, hyp.hyp_id, v)

        # 7) update failure-path memory, distinguished by cause
        if v == Verdict.CONFIRMED and hyp.surface_id:
            rep.confirmed.append(hyp.surface_id)
        elif v == Verdict.REFUTED:
            record_dead_end(loop, hyp, "refuted",
                            "a DIFFERENT env/role/version, or a new precondition")
            rep.dead_ended.append(hyp.hyp_id)
        elif v == Verdict.BLOCKED:
            record_dead_end(loop, hyp, "blocked", "the missing precondition is acquired")
            rep.dead_ended.append(hyp.hyp_id)
        # INCONCLUSIVE splits on the execution axis (logic_vuln_loop.execution_status):
        #  - execution ok     -> a genuine undecided result; retryable until the bounded
        #                        count retires it as a dead end (handled in selection).
        #  - execution failed -> the action never ran. Counted per-RUN only; it never
        #                        approaches a dead end, because the next run may face a
        #                        repaired environment. Surfaced in the trace so a broken
        #                        environment is visible rather than silently absorbed.
        if v == Verdict.INCONCLUSIVE and _last_execution_failed(loop, hyp.hyp_id):
            exec_failures[hyp.hyp_id] = exec_failures.get(hyp.hyp_id, 0) + 1
            rep.exec_failures += 1

        rep.replans += 1 if was_replan else 0
        rep.trace.append((hyp.hyp_id, v.value, res["reason"][:70]))
        budget.actions += 1
        rep.rounds += 1
        if round_log:
            round_log({'round': rep.rounds, 'hyp_id': hyp.hyp_id, 'verdict': v.value,
                       'reason': res['reason'][:200], 'tier': task.model_tier,
                       'dimension': getattr(hyp, 'dimension', None),
                       'knowledge_count': len(knowledge), 'was_replan': was_replan})
        current_progress = progress_keys(loop)
        added_progress = current_progress - known_progress
        no_progress_rounds = 0 if added_progress else no_progress_rounds + 1
        known_progress = current_progress
        loop.append("research_progress", hyp_id=hyp.hyp_id, new_evidence_or_claims=len(added_progress),
                    unchanged_rounds=no_progress_rounds)

        # 7b) discovery feedback (Stage 5→0/1): if testing revealed new ASG
        # nodes (new subdomain, IP, endpoint, credential), trace it so the
        # next round can re-OSINT the new scope before going deeper.
        new_nodes = discovery_feedback(loop, pre_test_node_count)
        if new_nodes:
            rep.trace.append(("discovery_feedback", len(new_nodes),
                              "new nodes from testing — re-OSINT on new scope"))

        # durable per-round: heartbeat + lock-guarded save (the run-entry supplies
        # persist). Raises ConcurrentWriter if another writer took the ledger over.
        if persist:
            persist(loop)
        if no_progress_rounds >= budget.max_no_progress_rounds:
            rep.handoff_reason = ("no evidence progress: inspect the missing discriminator or prerequisites; "
                                  "no hypothesis was refuted by this stop")
            break

    if not rep.handoff_reason:
        rep.interventions += 1
        rep.handoff_reason = 'selection budget exhausted; inspect blocked or unchanged work'
    # Always end the handoff with the machine-chosen next action, so the operator/next
    # session reads "what to do" instead of inferring it from the trace (artex terminal
    # taxonomy: resume vs fix-env-and-retry vs don't-re-tread).
    rep.trace.append(("terminal", rep.terminal_class(), rep.handoff_reason[:60]))
    return rep
