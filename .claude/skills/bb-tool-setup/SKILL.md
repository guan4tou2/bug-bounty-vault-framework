---
name: bb-tool-setup
description: Use when the zero-LLM tool layer (Ring 2) is not yet established or needs configuring — before the first hunter/scanner run on a machine, when the bbflow CLI or your scanner is not found, or when no candidates.jsonl is being produced. Triggers include set up scanner, establish tool layer, configure bbflow, run hunters (first time), no candidates.
---

# Bug Bounty — Tool Layer Setup (establish Ring 2 and wire it into the loop)

The tool layer is **bring-your-own and not bundled** with this framework. Before any automated hunting can feed the loop, Ring 2 must be established and verified. This skill makes that an explicit, do-it-now step instead of a passive "bring your own tools" note — so the candidate generator actually exists and its output reaches the candidate lifecycle.

Full procedure: [`bbflow/setup.md`](../../../bbflow/setup.md). This skill is the trigger and the verification gate.

## Trigger

Run this when:

- starting hunter/scanner automation on a machine for the first time
- the `bbflow` CLI (or your chosen scanner) is not found / not configured
- a target has no `candidates.jsonl` and you are about to "run hunters"
- "set up scanner", "establish tool layer", "configure bbflow", "wire my scanner"

## Procedure

1. **Detect** whether a tool layer already exists:
   ```bash
   command -v bbflow >/dev/null && bbflow list || echo "no bbflow CLI"
   ls workspace/workshop/<target>/candidates.jsonl 2>/dev/null || echo "no candidates yet"
   ```
2. **If absent, establish one** (see `bbflow/setup.md`):
   - **Option A** — clone + install the bbflow tool (`guan4tou2/bbflow`) as a sibling repo; set `BBFLOW_WORKSPACE` to this vault's `workspace/`; verify `bbflow list`.
   - **Option B** — wire any scanner (Nuclei / own scripts) with a small private adapter that emits `candidates.jsonl` per [`bbflow/output-contract.md`](../../../bbflow/output-contract.md).
3. **Scope first.** Copy `bbflow/scope.example.yaml` to `workspace/workshop/<target>/scope.yaml` and fill in authorized scope. The tool must refuse to run without valid scope.
4. **Run in the ignored workspace.** Raw output and `candidates.jsonl` / `run_manifest.json` land in `workspace/workshop/<target>/` — never in the vault.
5. **Verify it feeds the loop** (the part that is easy to skip):
   ```bash
   test -f workspace/workshop/<target>/candidates.jsonl && echo "Ring 2 producing candidates"
   ```

## Hard Rules

- **Separate repo/process.** Never copy hunters, payloads, templates, or evasion logic into this framework repo or the vault — that boundary is enforced by the public-safety tests and the repo-boundary table in `docs/architecture-closed-loop.md`.
- **Candidates are leads, not findings.** A scanner hit does **not** become a Finding directly. It enters Ring 3 through `bb-surface-mapping` (cross-checked against the surface map) and the candidate gate pipeline.
- **Scope + safety still apply.** Noisy/active runs go through `bb-scope-safety-check` and run on an isolated runner / VPS.

## Wiring into the loop (do not stop at "installed")

Establishing the tool is only half the job. Confirm the hand-off:

```text
bb-tool-setup → tool emits candidates.jsonl → bb-surface-mapping (FRONT gate, cross-check)
              → bb-web-vuln-scan → dedup → scope-safety → chain-review → evidence → Finding
```

Each candidate's `suggested_skill` field routes it to the next gate. Once `candidates.jsonl` exists and `bb-surface-mapping` is consuming it, Ring 2 is part of the loop.

## Cross-References

- `bbflow/setup.md` (the full step-by-step)
- `bbflow/output-contract.md`, `bbflow/flow.md`, `bbflow/scope.example.yaml`, `bbflow/safety-boundary.md`
- `.claude/agents/bbflow-runner.md` (runs a configured Option-A tool)
- `bb-surface-mapping` (consumes candidates), `bb-scope-safety-check` (gate before noisy runs)
- `docs/architecture-closed-loop.md` (Ring 2 in the four-ring loop)
