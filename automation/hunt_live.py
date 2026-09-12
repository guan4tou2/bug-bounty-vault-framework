#!/usr/bin/env python3
"""hunt_live.py — run autodrive as a TRUE autonomous live driver.

Until now the live hunts were dispatched by a human/main-session spawning subagents.
This wires the orchestrator to drive ITSELF: the autodrive loop selects work, spawns
a headless `claude -p` worker for each hypothesis, ingests the structured result,
adjudicates by control comparison, replans on an empty queue, and hands back only on
a genuine stop condition — no human in the loop.

    autodrive( dispatch = make_dispatch(spawn),   # spawn = headless `claude -p`
               propose  = llm_propose,            # `claude -p` generates the next hypothesis
               ready_hyp = reconstruct-from-ledger,
               rank = value_rank, persist = heartbeat + lock-guarded save,
               human_gate = safety hand-back )

Boundary (honest): the WORKER's probing still depends on the headless `claude -p`
having the pentest-proxy MCP + GET-only permissions wired; where it does not, a worker
returns no structured block and the oracle records INCONCLUSIVE (never a fake result).
So this driver is autonomous by construction; its reach is bounded by the headless
worker's tool access, not by the loop.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Callable, Optional

from hunt_loop import HuntLoop
from hunt_lock import acquire, release, heartbeat, guarded_save
from hunt_autodrive import autodrive, value_rank, Budget, DriveReport
from hunt_worker import make_dispatch, subprocess_spawn
from logic_vuln_loop import Env, LogicHypothesis

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_json(text: str) -> dict:
    m = _JSON_RE.search(text if isinstance(text, str) else str(text))
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except (ValueError, TypeError):
        return {}


def make_llm_propose(scope_desc: str, hosts: list[str], env: Env,
                     spawn: Callable[[str, str], object], model: str = "claude-sonnet-5",
                     registry: Optional[dict] = None,
                     kb_tags: Optional[list[str]] = None, kb_dir=None) -> Callable:
    """A `propose(loop, cap)` that asks a headless model for the SINGLE next testable
    hypothesis over uncovered ASG dimensions, or a stop. Registers each returned
    hypothesis so ready_hyp can reconstruct it. Structured-field enforcement here;
    creativity/correctness is judged by the downstream evidence, not by this call.

    DEPTH: when `kb_tags` name the target's tech stack / vuln classes, the vault KB's
    matching deep-pattern lessons (WRITE-5, SECRET-USE, state-transition, chaining, …)
    are fed INTO the proposal prompt — so the loop proposes hypotheses that instantiate
    a known deep pattern for this stack, not generic checklist items. This is the same
    KB the worker already consults, wired one step earlier (at the decision, not just
    the execution)."""
    registry = registry if registry is not None else {}
    # Cross-cutting method lessons (how to VERIFY, how to avoid false positives, how to
    # cover a technique fully) apply on every stack — always fold them in so the LL 思路
    # travels, not just stack-specific pattern names.
    _METHOD_TAGS = ["methodology", "verification", "adversarial-verification", "false-positive"]
    kb_patterns: list[str] = []
    if kb_tags:
        try:
            from kb_connector import kb_lessons
            hits = kb_lessons(list(dict.fromkeys(list(kb_tags) + _METHOD_TAGS)), kb_dir)
            # inject the lesson's 思路 (summary/body rule), not just its title
            kb_patterns = [
                (f"{h['lesson_id']}: {h['title']} — {h['summary']}" if h.get("summary")
                 else f"{h['lesson_id']}: {h['title']}")
                for h in hits
            ][:15]
        except Exception:
            kb_patterns = []

    def propose(loop: HuntLoop, cap: dict) -> Optional[LogicHypothesis]:
        state = {
            "untested_surface": cap["untested_surface"][:20],
            "ready": cap["ready_hypotheses"][:20],
            "blocked": cap["blocked_hypotheses"][:20],
            "refuted": cap["refuted"][:20],
            "capabilities": cap["capabilities"],
        }
        depth_hint = (
            "KNOWN DEEP PATTERNS for this stack (prefer INSTANTIATING one of these into a "
            "concrete testable hypothesis over a generic checklist item like 'unauth reads "
            "admin' — depth beats breadth):\n" + "\n".join(f"  - {p}" for p in kb_patterns) + "\n\n"
        ) if kb_patterns else ""
        prompt = (
            "You are the planning brain of an autonomous bug-bounty loop. Given the ASG "
            "state, propose the SINGLE most valuable NEXT testable hypothesis (GET-only, "
            f"in-scope hosts: {hosts}; scope: {scope_desc}). Prefer an uncovered role / "
            "state-transition / trust-boundary / business-invariant over replaying a "
            "refuted path.\n"
            + depth_hint +
            "CAPABILITY CHAINING (important): if `capabilities` below is non-empty, a "
            "prior finding just unlocked something — prefer a hypothesis that LEVERAGES a "
            "held capability (set `requires` to it) to chain deeper. Set `provides` to the "
            "capability THIS hypothesis would grant if confirmed (e.g. \"P:cred=api\", "
            "\"P:read=config\", \"P:token=jwt\", \"P:ssrf=internal\") so the next round can "
            "chain off it. Capabilities can be earned UNAUTHENTICATED (a leaked cred/token, "
            "SSRF, an exposed config) — no account required.\n"
            "Reply with ONLY one JSON object:\n"
            '{"dimension":"invariant|roles|state|trust|cross-flow",'
            '"invariant":"the rule that must hold","precondition":"",'
            '"expected_normal":"what a correct system does","test_action":"exact GET action",'
            '"control_action":"the normal/baseline GET","violation_outcome":"token meaning broken",'
            '"expected_normal_outcome":"correct control outcome (e.g. 401/403)",'
            '"provides":["capability this grants if confirmed, or empty"],'
            '"requires":["held capability this needs, or empty"]}\n'
            'OR {"stop":true,"reason":"why nothing valuable remains"} if the surface is '
            "genuinely exhausted.\n\n"
            f"ASG state:\n{json.dumps(state, ensure_ascii=False)}"
        )
        obj = _parse_json(spawn(prompt, model))
        if not obj or obj.get("stop") or "test_action" not in obj:
            return None
        hid = "auto:" + uuid.uuid4().hex[:12]
        hyp = LogicHypothesis(
            hyp_id=hid, dimension=obj.get("dimension", "invariant"),
            invariant=obj.get("invariant", ""), applies_env=env,
            precondition=obj.get("precondition", ""),
            expected_normal=obj.get("expected_normal", ""),
            test_action=obj["test_action"], control_action=obj.get("control_action", ""),
            violation_outcome=obj.get("violation_outcome", "violation"),
            expected_normal_outcome=obj.get("expected_normal_outcome"),
            provides=[c for c in (obj.get("provides") or []) if c],
            requires=[c for c in (obj.get("requires") or []) if c],
            surface_id=obj.get("test_action"))
        registry[hid] = hyp
        return hyp

    return propose


def default_human_gate(loop: HuntLoop, cap: dict) -> Optional[str]:
    """Hand back on the genuine conditions — never mid-flow. (Budget/replan handled
    by autodrive.) Extend per engagement (e.g. missing account already surfaces as a
    blocked hypothesis, which autodrive drains to replan, not a hard stop.)"""
    return None


def run_live(
    ledger,
    *,
    owner: str,
    scope_desc: str,
    hosts: list[str],
    env: Env,
    budget: Optional[Budget] = None,
    model: str = "claude-sonnet-5",
    spawn: Optional[Callable[[str, str], object]] = None,
    propose: Optional[Callable] = None,
    ready_hyp: Optional[Callable] = None,
    human_gate: Optional[Callable] = None,
    ttl_s: int = 1800,
    max_rounds: int = 40,
    kb_tags: Optional[list[str]] = None,
    kb_dir=None,
) -> tuple[DriveReport, HuntLoop]:
    """Acquire the ledger and let autodrive self-drive to a clean hand-back.
    `spawn` defaults to headless `claude -p` (subprocess_spawn) — the real driver.
    Inject a stub `spawn` to test the loop without live workers.
    `kb_tags` (the target's stack / vuln classes) prime the proposal with the vault
    KB's matching deep-pattern lessons — the depth lever."""
    spawn = spawn or subprocess_spawn
    budget = budget or Budget(max_actions=12, max_replans=4, max_retries_per_hyp=2)
    registry: dict = {}
    propose = propose or make_llm_propose(scope_desc, hosts, env, spawn, model, registry,
                                          kb_tags=kb_tags, kb_dir=kb_dir)

    def _ready(hid: str) -> Optional[LogicHypothesis]:
        if ready_hyp:
            return ready_hyp(hid)
        return registry.get(hid)

    token = acquire(ledger, owner, ttl_s=ttl_s)
    try:
        loop = HuntLoop.load(ledger)

        def persist(lp: HuntLoop) -> None:
            heartbeat(ledger, token)
            guarded_save(lp, ledger, token)

        rep = autodrive(
            loop, current_env=env, dispatch=make_dispatch(spawn), propose=propose,
            ready_hyp=_ready, budget=budget, human_gate=human_gate or default_human_gate,
            rank=value_rank, persist=persist, max_rounds=max_rounds)
        guarded_save(loop, ledger, token)
        # policy A — auto-DRAFT LL candidates from what the loop just learned (refuted
        # paths / dead-ends), staged for human promotion. Best-effort: closing the
        # experience->KB loop must never fail the hunt, and stub/tmp ledgers that do not
        # resolve under 01 - Targets/ simply skip.
        try:
            from lesson_candidates import write_candidates
            write_candidates(Path(ledger).resolve().parent.parent)
        except Exception:
            pass
        return rep, loop
    finally:
        release(ledger, token)
