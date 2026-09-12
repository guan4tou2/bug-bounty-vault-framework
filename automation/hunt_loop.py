#!/usr/bin/env python3
"""hunt_loop.py — minimal, verifiable execution-loop spine (NOT the full ASG core).

The smallest runnable slice of:
    restore state -> select hypothesis -> execute tool -> save evidence
      -> decide verdict -> update next-step/learning -> continue or STOP

Deliberately deterministic + tool-agnostic: tool execution is INJECTED (a callable
returning an ExecutionResult), so controlled cases (tool failure, contradictory
evidence, mid-run compaction/reload) can be tested without a live target. Real
tool/bbflow wiring is a separate layer that calls `record_execution`.

Design invariants it ENFORCES (the point of building the spine bottom-up):
  I1  execution success != vulnerability confirmed != capability acquired.
      A capability is granted ONLY by an explicit CONFIRMED verdict carrying
      evidence — never auto-derived from exit_code == 0.
  I2  stop != (pending == 0). No ready actions but untested surface -> REPLANNING.
      Only explicit completion / blocked / needs_input / waiting ends active work.
  I3  contradictory verdicts on one hypothesis -> DISPUTED; both are kept, neither
      silently overwrites the other.
  I4  state is an append-only event log; the capsule is a deterministic projection.
      Reload -> identical capsule (compaction / handover survives).
  I5  a revoked capability invalidates the actions that required it.
  I6  a failed / errored execution is INCONCLUSIVE, never auto "not_vulnerable".
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Callable, Optional


# ── verdict + run-state taxonomies ──────────────────────────────────────────
class Verdict(str, Enum):
    CONFIRMED = "confirmed"        # proven by evidence -> may grant capability
    REFUTED = "refuted"            # normal-control explains it away
    INCONCLUSIVE = "inconclusive"  # tool failed / no oracle / not reproduced
    BLOCKED = "blocked"            # precondition unmet, cannot run
    DISPUTED = "disputed"          # conflicting confirmed/refuted evidence


class RunState(str, Enum):
    RUNNING = "running"
    REPLANNING = "replanning"
    WAITING_EXTERNAL = "waiting_external"
    NEEDS_INPUT = "needs_input"
    BLOCKED = "blocked"
    COMPLETED = "completed"


# ── events (append-only) ────────────────────────────────────────────────────
@dataclass
class ExecutionResult:
    """What a tool run actually produced. exit_ok is NOT a verdict."""
    action_id: str
    exit_ok: bool                       # did the command run cleanly?
    output_ref: Optional[str] = None    # artifact path (evidence)
    error: Optional[str] = None         # environment/timeout/etc.


def _event(kind: str, **data) -> dict:
    return {"kind": kind, **data}


# ── the loop core ───────────────────────────────────────────────────────────
class HuntLoop:
    def __init__(self, events: Optional[list[dict]] = None):
        self.events: list[dict] = list(events or [])

    # --- persistence (I4: atomic event-log snapshot, deterministic reload) ---
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".hunt-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for e in self.events:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @classmethod
    def load(cls, path: str | Path) -> "HuntLoop":
        evs: list[dict] = []
        p = Path(path)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    evs.append(json.loads(line))
        return cls(evs)

    def append(self, kind: str, **data) -> None:
        self.events.append(_event(kind, **data))

    # --- domain ops ---
    def add_surface(self, node_id: str, untested: bool = True) -> None:
        self.append("surface", node_id=node_id, untested=untested)

    def add_hypothesis(self, hyp_id: str, requires: Optional[list[str]] = None) -> None:
        self.append("hypothesis", hyp_id=hyp_id, requires=requires or [])

    def record_execution(self, r: ExecutionResult) -> None:
        # I1/I6: an execution is just an event. It never, by itself, grants a
        # capability or confirms a hypothesis.
        self.append("execution", action_id=r.action_id, exit_ok=r.exit_ok,
                    output_ref=r.output_ref, error=r.error)

    def record_verdict(self, hyp_id: str, verdict: Verdict,
                       evidence_ref: Optional[str] = None,
                       provides: Optional[list[str]] = None) -> None:
        # I1: CONFIRMED must carry evidence to be trusted for a capability grant.
        self.append("verdict", hyp_id=hyp_id, verdict=verdict.value,
                    evidence_ref=evidence_ref, provides=provides or [])

    def revoke_capability(self, cap: str, reason: str) -> None:
        self.append("revoke", cap=cap, reason=reason)

    def complete(self, reason: str) -> None:
        cap = self.capsule()
        if not reason.strip() or any(cap[k] for k in (
                "ready_hypotheses", "blocked_hypotheses", "untested_surface",
                "disputed", "invalidated_hypotheses")):
            raise ValueError("completion requires a reason and no unresolved work")
        self.append("completion", reason=reason)

    # --- materialization (I3/I4/I5: pure projection over the event log) ---
    def capsule(self) -> dict:
        surfaces: dict[str, bool] = {}          # node_id -> untested?
        hyp_requires: dict[str, list[str]] = {}
        confirmed: dict[str, list[str]] = {}    # hyp_id -> provides (CONFIRMED)
        refuted: set[str] = set()
        disputed: set[str] = set()
        capabilities: set[str] = set()
        revoked: set[str] = set()

        for e in self.events:
            k = e["kind"]
            if k == "surface":
                surfaces[e["node_id"]] = e.get("untested", True)
            elif k == "hypothesis":
                hyp_requires.setdefault(e["hyp_id"], e.get("requires", []))
            elif k == "verdict":
                hid, v = e["hyp_id"], e["verdict"]
                if v == Verdict.CONFIRMED.value:
                    if hid in refuted:                      # I3: conflict
                        disputed.add(hid); refuted.discard(hid)
                    elif hid in disputed:
                        pass
                    else:
                        # I1: capability only from a CONFIRMED verdict WITH evidence.
                        if e.get("evidence_ref"):
                            confirmed[hid] = e.get("provides", [])
                elif v == Verdict.REFUTED.value:
                    if hid in confirmed:                    # I3: conflict
                        disputed.add(hid); confirmed.pop(hid, None)
                    else:
                        refuted.add(hid)
                # INCONCLUSIVE/BLOCKED do not change confirmed/refuted state.
            elif k == "revoke":
                revoked.add(e["cap"])

        # Capabilities are DERIVED from currently-confirmed hypotheses (minus
        # revoked) — never maintained incrementally. So a hypothesis that later
        # becomes disputed/refuted (I3) automatically withdraws its capability,
        # and a revoke (I5) removes it too.
        # Least fixed point: downstream confirmations cannot bootstrap themselves
        # or survive loss of their required capabilities. Independent support stays.
        supported = {}
        while True:
            newly_supported = {
                h: cs for h, cs in confirmed.items()
                if all(r in capabilities for r in hyp_requires.get(h, []))
            }
            next_caps = {c for cs in newly_supported.values() for c in cs} - revoked
            if next_caps == capabilities:
                supported = newly_supported
                break
            capabilities = next_caps
        invalidated = sorted(set(confirmed) - set(supported))
        confirmed = supported

        # I5: an action/hypothesis whose required cap was revoked is blocked.
        ready, blocked = [], []
        for hid, reqs in hyp_requires.items():
            if hid in confirmed or hid in refuted or hid in disputed:
                continue
            missing = [r for r in reqs if r not in capabilities]
            revoked_dep = [r for r in reqs if r in revoked]
            if revoked_dep or missing:
                blocked.append(hid)
            else:
                ready.append(hid)

        untested_surface = [n for n, ut in surfaces.items() if ut]
        return {
            "event_cursor": len(self.events),
            "invalidated_hypotheses": invalidated,
            "capabilities": sorted(capabilities),
            "confirmed": confirmed,
            "refuted": sorted(refuted),
            "disputed": sorted(disputed),          # I3
            "ready_hypotheses": sorted(ready),
            "blocked_hypotheses": sorted(blocked), # I5
            "untested_surface": sorted(untested_surface),
        }

    # --- stop state machine (I2) ---
    def run_state(self, needs_input: bool = False,
                  waiting_external: bool = False) -> RunState:
        cap = self.capsule()
        if needs_input:
            return RunState.NEEDS_INPUT
        if waiting_external:
            return RunState.WAITING_EXTERNAL
        if cap["ready_hypotheses"]:
            return RunState.RUNNING
        # I2: no ready work, but untested surface / disputed / blocked-with-hope
        # remains -> REPLANNING, never silently COMPLETED.
        if cap["untested_surface"] or cap["disputed"]:
            return RunState.REPLANNING
        if cap["blocked_hypotheses"]:
            return RunState.BLOCKED
        if self.events and self.events[-1]["kind"] == "completion":
            return RunState.COMPLETED
        return RunState.REPLANNING


# helper for the "execute -> record -> verdict" step, keeping I1/I6 explicit.
def step_execute_and_judge(loop: HuntLoop, hyp_id: str,
                           run_tool: Callable[[], ExecutionResult],
                           judge: Callable[[ExecutionResult], tuple[Verdict, Optional[str], list[str]]]) -> Verdict:
    """One step. `run_tool` performs the (possibly failing) execution; `judge`
    maps the result to a verdict. Enforces I1/I6: if the tool errored, the judge
    must not be able to return CONFIRMED from nothing — we downgrade to
    INCONCLUSIVE here as a backstop."""
    try:
        r = run_tool()
    except Exception as exc:
        r = ExecutionResult(hyp_id, False, error=type(exc).__name__)
    if not r.exit_ok or r.error:
        loop.record_execution(r)
        loop.record_verdict(hyp_id, Verdict.INCONCLUSIVE)
        return Verdict.INCONCLUSIVE
    loop.record_execution(r)
    verdict, evidence_ref, provides = judge(r)
    if not r.exit_ok or r.error:
        # I6 backstop: a failed execution can never confirm.
        verdict, evidence_ref, provides = Verdict.INCONCLUSIVE, None, []
    loop.record_verdict(hyp_id, verdict, evidence_ref=evidence_ref, provides=provides)
    return verdict
