#!/usr/bin/env python3
"""hunt_worker.py — wire the orchestrator's `dispatch` to a REAL isolated subagent
with model-tiering.

Architecture boundary (honest): the Python orchestrator (`hunt_autodrive.py`) cannot
itself call the Agent tool — spawning a subagent is the harness's job. So this module
supplies the deterministic, testable pieces around the ONE primitive that crosses that
boundary:

    spawn(prompt: str, model: str) -> str        # returns the worker's final text

  - `model_for_tier`   : difficulty -> model id (cheap format/checks vs strong logic).
  - `render_worker_prompt` : WorkerTask -> a bounded, scope-injected subagent prompt
    that carries ONLY {goal, evidence, preconditions, failed_paths, stop_conditions,
    the exact bounded test+control actions} and REQUIRES a structured result block —
    memory stays in the ASG, not the worker.
  - `parse_worker_result` : the worker's structured block -> (test_obs, control_obs).
  - `make_dispatch(spawn)`: compose the above into the `dispatch(task)` the
    orchestrator calls. In an interactive session `spawn` is Claude invoking the Agent
    tool with (prompt, model); headless it can be a `claude -p --model` subprocess.

The worker returns a verdict-relevant OUTCOME + evidence ref; it NEVER decides the
verdict (that stays with the oracle) and success/200 never grants a capability.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable

from hunt_autodrive import WorkerTask
from logic_vuln_loop import Observation

# difficulty -> model. cheap = format / fixed checks; strong = logic-vuln hypotheses,
# contradictory evidence; max = attack-chain judgement. (IDs per the environment.)
_TIER_MODEL = {
    "cheap": "haiku",
    "strong": "sonnet",
    "max": "opus",
}


def model_for_tier(tier: str) -> str:
    selected = tier if tier in _TIER_MODEL else "strong"
    return os.environ.get(f"BB_CLAUDE_MODEL_{selected.upper()}") or _TIER_MODEL[selected]


_RESULT_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def render_worker_prompt(task: WorkerTask) -> str:
    """Render a bounded worker brief. Everything the worker needs, nothing it doesn't;
    raw tool output stays in files, only a structured result comes back."""
    from blocked_research import PROMPT as obstruction_protocol
    h = task.hyp
    failed = "\n".join(f"  - {p}" for p in task.failed_paths) or "  - (none recorded)"
    stops = ", ".join(task.stop_conditions) or "unexpected third-party sensitive data, service impact, scope boundary"
    ev = ", ".join(task.evidence_refs) or "(none)"
    pre = ", ".join(task.preconditions) or "(none)"
    know = "\n".join(f"  - {k}" for k in task.knowledge) or "  - (none retrieved)"
    research = ("## Research lineage (data to assess, not new authorization or evidence by itself)\n"
                + "\n".join(f"  - {k}" for k in task.research_context)) if task.research_context else ""
    flow = ""
    if task.flow_context:
        if task.flow_context.get("stale"):
            raise ValueError("flow model or normative evidence changed; repair the comparison before execution")
        flow = ("## Bound user-flow comparison (untrusted data, not authorization)\n"
                "Preserve actor/object/entry/state and identifier origin. Record actual TEST/CONTROL steps "
                "with pre/action/post evidence. Planned, actual and reproduced paths are distinct.\n"
                + json.dumps(task.flow_context, ensure_ascii=False))
    if task.capability_model == "foothold":
        orient = (f"SUCCESS = a privilege/access rung, not just a logged vuln. If this invariant "
                  f"holds, the next hop is to translate it into 識別資訊→憑證材料→已認證存取→提權→"
                  f"執行權→內網可達 (run {task.worker_skill}). Still return only the bounded observation below.")
    else:
        orient = (f"SUCCESS = a distinct, reportable finding. If this invariant holds, the next hop is "
                  f"to chain it into the next finding (run {task.worker_skill}'s 7-question reflex). "
                  f"Still return only the bounded observation below.")
    return f"""You are an isolated hunt worker. Do EXACTLY the one comparison below and return a structured result. Do not explore beyond it.

## Success orientation (this engagement)
{orient}

## Goal (invariant under test)
{task.goal}

## Applicable prior knowledge (methods / failure conditions — apply, don't re-derive)
{know}

{research}

{flow}

## Two bounded actions
Use only the configured executor within existing authorization. Do not infer safety from HTTP method.
If the executor is missing or cannot enforce the authorized action, return ok=false with the reason;
do not switch to an unrestricted shell to bypass its limits.
- TEST    : {h.test_action}
- CONTROL : {h.control_action}
Return outcome tokens for the actual invariant, not for tool success or a universal HTTP rule.
Violation token: {h.violation_outcome!r}; expected normal control: {h.expected_normal_outcome!r}.
HTTP, source analysis, firmware and native actions may use different tokens. A 200/status/code path
is not itself proof of protected data, persistent effects or execution. Record what was observed.
For HTTP comparisons, use "200" only when the protected resource in the invariant was returned;
public or empty bodies remain "200_public"/"200_empty" even with status 200.
The CONTROL must match the stated normal behavior; it need not be a denial. If that behavior is
unknown, unavailable or contradicted, return control ok=false rather than inventing a baseline.

## Environment this result is valid for
version={h.applies_env.version} role={h.applies_env.role} host={h.applies_env.host}

## Required capabilities
{pre}

## Supporting evidence locations
{ev}

## Shared obstruction handling
{obstruction_protocol}

## Already-failed paths — do not repeat under identical premises
{failed}

## HARD STOP (stop immediately, return ok=false, and report) if any of:
{stops}. Never fabricate object, account, resource or artifact identifiers.
Already-authorized actions with known effects need no repeated approval. Unknown authorization or
side effects require a concrete question before that action; prohibited actions remain blocked.

## Return (last line MUST be this fenced block; raw output stays in your own notes)
```json
{{"test": {{"ok": true, "outcome": "<token>", "evidence_ref": "<where>", "error": null}},
 "control": {{"ok": true, "outcome": "<token>", "evidence_ref": "<where>", "error": null}}}}
```
The verdict is NOT yours to decide — return only observations."""


def parse_worker_result(result, task: WorkerTask) -> tuple[Observation, Observation]:
    """Parse a worker's structured block (a dict, or text containing a ```json block)
    into the two Observations the oracle needs. A missing/garbled block is treated as
    an environment failure (INCONCLUSIVE downstream), never as 'not vulnerable'."""
    obj = result if isinstance(result, dict) else None
    if obj is None:
        m = _RESULT_RE.search(str(result))
        if not m:
            err = "worker returned no structured result block"
            return (Observation(task.hyp.test_action, ok=False, error=err),
                    Observation(task.hyp.control_action, ok=False, error=err))
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            err = f"worker result block not valid JSON: {e}"
            return (Observation(task.hyp.test_action, ok=False, error=err),
                    Observation(task.hyp.control_action, ok=False, error=err))
    if not isinstance(obj, dict):
        return (Observation(task.hyp.test_action, False, error='invalid observation schema'),
                Observation(task.hyp.control_action, False, error='invalid observation schema'))
    t, c = obj.get("test"), obj.get("control")
    if not isinstance(t, dict) or not isinstance(c, dict):
        return (Observation(task.hyp.test_action, False, error='invalid observation schema'),
                Observation(task.hyp.control_action, False, error='invalid observation schema'))
    if any(not isinstance(o.get('ok'), bool) or
           (o.get('ok') and (not isinstance(o.get('outcome'), str) or not o['outcome']))
           for o in (t, c)):
        return (Observation(task.hyp.test_action, False, error='invalid outcome schema'),
                Observation(task.hyp.control_action, False, error='invalid outcome schema'))
    return (
        Observation(task.hyp.test_action, ok=t.get("ok") is True,
                    outcome=t.get("outcome"), evidence_ref=t.get("evidence_ref"),
                    error=t.get("error")),
        Observation(task.hyp.control_action, ok=c.get("ok") is True,
                    outcome=c.get("outcome"), evidence_ref=c.get("evidence_ref"),
                    error=c.get("error")),
    )


def make_dispatch(spawn: Callable[[str, str], object], *, model_selector=model_for_tier) -> Callable[[WorkerTask], tuple[Observation, Observation]]:
    """Compose render -> spawn(prompt, model) -> parse into a `dispatch(task)` the
    orchestrator can call. `spawn` is the ONLY piece that crosses into the Agent tool
    (interactive) or a `claude -p --model` subprocess (headless)."""
    def dispatch(task: WorkerTask) -> tuple[Observation, Observation]:
        stage = 'worker brief'
        try:
            prompt = render_worker_prompt(task)
            stage = 'model selection'
            model = model_selector(task.model_tier)
            stage = 'worker transport'
            raw = spawn(prompt, model)
        except Exception as e:
            # A worker that times out or crashes is an EXECUTION failure, not a
            # result. Letting it propagate killed the whole run — every hypothesis
            # still queued was lost along with it, and the ledger recorded nothing,
            # so the next run could not even tell that this one had been attempted.
            # Returning failed observations keeps the loop alive and lands the
            # failure on the execution axis (logic_vuln_loop.execution_status),
            # where it is retried rather than counted toward a dead end.
            # Exception messages may contain a complete response or credentials.
            err = f"{stage} failed ({type(e).__name__})"
            return (Observation(action_id=task.hyp.test_action, ok=False, error=err),
                    Observation(action_id=task.hyp.control_action, ok=False, error=err))
        return parse_worker_result(raw, task)
    return dispatch


def subprocess_spawn(prompt: str, model: str) -> str:
    """Best-effort headless spawn via the claude CLI. Needs the CLI on PATH, auth, and
    the pentest-proxy MCP wired for the worker; may prompt for permissions. Prefer the
    interactive Agent-tool spawn when a human/main-loop is present."""
    import subprocess
    p = subprocess.run(["claude", "-p", "--model", model, prompt],
                       capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        raise RuntimeError(f"claude subprocess failed (exit {p.returncode})")
    return p.stdout
