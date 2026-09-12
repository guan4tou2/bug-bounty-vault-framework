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
    the exact GET-only test+control actions} and REQUIRES a structured result block —
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
import re
from typing import Callable

from hunt_autodrive import WorkerTask
from logic_vuln_loop import Observation

# difficulty -> model. cheap = format / fixed checks; strong = logic-vuln hypotheses,
# contradictory evidence; max = attack-chain judgement. (IDs per the environment.)
_TIER_MODEL = {
    "cheap": "claude-haiku-4-5-20251001",
    "strong": "claude-sonnet-5",
    "max": "claude-opus-5",
}


def model_for_tier(tier: str) -> str:
    return _TIER_MODEL.get(tier, _TIER_MODEL["strong"])


_RESULT_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def render_worker_prompt(task: WorkerTask) -> str:
    """Render a bounded worker brief. Everything the worker needs, nothing it doesn't;
    raw tool output stays in files, only a structured result comes back."""
    h = task.hyp
    failed = "\n".join(f"  - {p}" for p in task.failed_paths) or "  - (none recorded)"
    stops = ", ".join(task.stop_conditions) or "patient PII, service impact, auth boundary"
    ev = ", ".join(task.evidence_refs) or "(none)"
    know = "\n".join(f"  - {k}" for k in task.knowledge) or "  - (none retrieved)"
    return f"""You are an isolated hunt worker. Do EXACTLY the one comparison below and return a structured result. Do not explore beyond it.

## Goal (invariant under test)
{task.goal}

## Applicable prior knowledge (methods / failure conditions — apply, don't re-derive)
{know}

## The two GET-only actions (use ONLY mcp__pentest-proxy__curl_probe — routes via VPS, GET/HEAD only)
- TEST    : {h.test_action}
- CONTROL : {h.control_action}
Classify each response OUTCOME honestly as one of: "200" (protected resource body returned),
"200_public"/"200_empty" (public/empty body), or the HTTP status for a denial ("301".."308"/"401"/"403").
The CONTROL must be a validated known-good denial; if it is not, say so (control ok=false).

## Environment this result is valid for
version={h.applies_env.version} role={h.applies_env.role} host={h.applies_env.host}

## Prior capabilities you may build on
{ev}

## Already-failed paths — DO NOT re-tread these
{failed}

## HARD STOP (stop immediately, return ok=false, and report) if any of:
{stops}. Never fabricate patient/episode identifiers. GET/HEAD only.

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
    t, c = obj.get("test", {}), obj.get("control", {})
    return (
        Observation(task.hyp.test_action, ok=bool(t.get("ok", False)),
                    outcome=t.get("outcome"), evidence_ref=t.get("evidence_ref"),
                    error=t.get("error")),
        Observation(task.hyp.control_action, ok=bool(c.get("ok", False)),
                    outcome=c.get("outcome"), evidence_ref=c.get("evidence_ref"),
                    error=c.get("error")),
    )


def make_dispatch(spawn: Callable[[str, str], object]) -> Callable[[WorkerTask], tuple[Observation, Observation]]:
    """Compose render -> spawn(prompt, model) -> parse into a `dispatch(task)` the
    orchestrator can call. `spawn` is the ONLY piece that crosses into the Agent tool
    (interactive) or a `claude -p --model` subprocess (headless)."""
    def dispatch(task: WorkerTask) -> tuple[Observation, Observation]:
        prompt = render_worker_prompt(task)
        model = model_for_tier(task.model_tier)
        return parse_worker_result(spawn(prompt, model), task)
    return dispatch


def subprocess_spawn(prompt: str, model: str) -> str:
    """Best-effort headless spawn via the claude CLI. Needs the CLI on PATH, auth, and
    the pentest-proxy MCP wired for the worker; may prompt for permissions. Prefer the
    interactive Agent-tool spawn when a human/main-loop is present."""
    import subprocess
    p = subprocess.run(["claude", "-p", "--model", model, prompt],
                       capture_output=True, text=True, timeout=600)
    return p.stdout
