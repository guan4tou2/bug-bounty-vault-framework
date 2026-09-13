#!/usr/bin/env python3
"""hunt_run.py — the ONE run entry that composes the autonomous hunt loop.

Wires the pieces built separately into a single lock-guarded, KB-consulting,
value-ranked, durable run:

    acquire ledger lock (fine, hunt_lock)     # coarse = claim.sh, a prerequisite
      -> load ASG state (hunt_loop ledger)
      -> autodrive( dispatch = make_dispatch(spawn),   # subagent boundary
                    rank     = value_rank,              # decision ① selection
                    propose / ready_hyp,                # LLM candidate generation
                    kb_tags  -> retrieve_all in-loop,   # knowledge consulted before testing
                    persist  = heartbeat + guarded_save ) # durable per round
      -> final guarded_save
      -> release lock

The Python/Claude boundary (honest): `spawn(prompt, model)` is the only piece that
crosses into the Agent tool. In an interactive session it is Claude invoking Agent;
headless it can be hunt_worker.subprocess_spawn. `propose`/`ready_hyp` are the LLM's
hypothesis generation. Everything else here is deterministic and unit-testable with
a stub spawn — no live target required to test the wiring; a live target is required
only to PROVE new-bug discovery (the forward test).

Coarse lock (session/scope) is NOT reimplemented: run `bash automation/claim.sh
<scope>` before a real run. `claim_scope()` is a best-effort helper for that.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Optional

from hunt_loop import HuntLoop
from hunt_lock import acquire, release, heartbeat, guarded_save
from hunt_autodrive import autodrive, value_rank, Budget, DriveReport
from hunt_worker import make_dispatch
from logic_vuln_loop import Env, LogicHypothesis, Observation


def claim_scope(scope: str, owner: str = "hunt-run", eta_minutes: int = 120) -> bool:
    """Best-effort coarse session/scope claim via the existing claim.sh. Returns
    whether the claim succeeded; a real run should claim before writing. Never
    raises on a missing script — the fine ledger lock still protects the file."""
    script = Path(__file__).resolve().parent / "claim.sh"
    if not script.exists():
        return False
    try:
        p = subprocess.run(["bash", str(script), scope, f"--owner={owner}",
                            f"--eta-minutes={eta_minutes}"], capture_output=True,
                           text=True, timeout=30)
        return p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_hunt(
    ledger: str | Path | None = None,
    *,
    target: str | None = None,
    owner: str,
    current_env: Env,
    spawn: Callable[[str, str], object],
    propose: Callable[[HuntLoop, dict], Optional[LogicHypothesis]],
    ready_hyp: Callable[[str], LogicHypothesis],
    budget: Budget,
    human_gate: Optional[Callable[[HuntLoop, dict], Optional[str]]] = None,
    kb_tags: Optional[list[str]] = None,
    kb_dir=None,
    ttl_s: int = 1800,
    max_rounds: int = 200,
) -> tuple[DriveReport, HuntLoop]:
    """Acquire the ledger, drive the loop to a clean hand-back, release, then refresh
    the projections. Address by `target` (resolved through the single asg resolver)
    or by an explicit `ledger` path. Returns the DriveReport + final loop state.

    Raises hunt_lock.ConcurrentWriter if another live writer holds the ledger."""
    import asg
    if target is not None:
        ledger = asg.ledger_path(target)
    if ledger is None:
        raise ValueError("run_hunt needs a target= or an explicit ledger=")

    token = acquire(ledger, owner, ttl_s=ttl_s)
    try:
        loop = HuntLoop.load(ledger)
        dispatch = make_dispatch(spawn)

        def persist(lp: HuntLoop) -> None:
            heartbeat(ledger, token)
            guarded_save(lp, ledger, token)   # refuses if we lost the lock (no clobber)

        rep = autodrive(
            loop, current_env=current_env, dispatch=dispatch, propose=propose,
            ready_hyp=ready_hyp, budget=budget, human_gate=human_gate,
            kb_tags=kb_tags, kb_dir=kb_dir, rank=value_rank, persist=persist,
            max_rounds=max_rounds,
        )
        guarded_save(loop, ledger, token)     # final durable state
    finally:
        release(ledger, token)
    # projections are one-way and lock-free (read the just-saved ledger)
    if target is not None:
        asg.project_all(target)
    return rep, loop
