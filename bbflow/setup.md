# Setup — Establishing the Tool Layer (Ring 2)

> **Read this before running any hunter/scanner automation.** The tool layer is **not bundled** with this framework — `bbflow/` here is a spec, not a runnable tool. An AI agent (or a human) must establish Ring 2 once per machine before the loop can consume candidates. This guide is written to be followed step by step by an automated agent.

Ring 2 is the **zero-LLM candidate generator** in the [closed loop](../docs/architecture-closed-loop.md). It runs scanners, enforces scope, and emits machine-readable candidates that the hunting ring (Ring 3) reviews. It owns *runtime*; it does not own vault notes or report prose.

---

## Decision: which tool layer?

Pick one. Both satisfy the same [output contract](output-contract.md), so the rest of the loop does not care which you chose.

| Option | When | What you get |
|---|---|---|
| **A — the bbflow tool** | You want a ready-made zero-LLM CLI (recon + pattern hunters + Nuclei templates) | Clone and install [`guan4tou2/bbflow`](https://github.com/guan4tou2/bbflow) |
| **B — bring your own** | You already run Nuclei / your own scripts, or have policy constraints | Wire any scanner to emit `candidates.jsonl` per the output contract |

Either way the tool layer stays a **separate repo/process** — never copy hunters, payloads, or templates into this framework repo or the vault (that boundary is enforced by the public-safety tests).

---

## Option A — install the bbflow tool

```bash
# 1. Clone the tool repo OUTSIDE this framework repo (it is a sibling, not a subdir)
git clone https://github.com/guan4tou2/bbflow.git ../bbflow

# 2. Make the CLI reachable (adjust to your shell)
export BBFLOW_HOME="$(cd ../bbflow && pwd)"
alias bbflow="$BBFLOW_HOME/bbflow.sh"

# 3. Point its output at this vault's gitignored workspace
export BBFLOW_WORKSPACE="$(pwd)/workspace"   # candidates land in workspace/workshop/<target>/

# 4. Verify the CLI responds
bbflow list        # should print available hunters
```

Persist the `export`/`alias` lines in your shell profile so future sessions and the `bbflow-runner` agent find the CLI.

> Noisy/active operations (`recon`, `hunt`, `flow`) should run on an isolated runner / VPS, not your main host. See [safety-boundary.md](safety-boundary.md) and the `bb-scope-safety-check` skill.

---

## Option B — wire your own scanner

You do not need the bbflow tool. Any scanner works if its output conforms to the contract.

1. Run your scanner against an **in-scope** target only (load scope first — see below).
2. Write raw output into `workspace/workshop/<target>/` (gitignored — never into the vault).
3. Emit two handoff artifacts per the [output contract](output-contract.md):
   - `run_manifest.json` — run id, scope file, safety level, summary counts.
   - `candidates.jsonl` — one review-oriented candidate per line, with `candidate_type`, `evidence_hint`, `chain_potential`, and `suggested_skill` so the loop can route each item.
4. A tiny adapter script that converts `nuclei -json` (or your tool's output) into `candidates.jsonl` is all that is required. Keep that adapter in your **private** tooling, not here.

---

## Scope is mandatory (both options)

```bash
# Copy the example and fill in YOUR authorized scope before any run
cp bbflow/scope.example.yaml workspace/workshop/<target>/scope.yaml
```

The tool layer must **refuse to run** when scope is missing, unclear, expired, or incompatible with the requested action (`flow.md` Gate 1). Out-of-scope assets are never scanned.

---

## Verify Ring 2 is established

```bash
bbflow list                                             # Option A only — CLI reachable
test -f workspace/workshop/<target>/scope.yaml          # scope present
# after a run:
test -f workspace/workshop/<target>/candidates.jsonl    # candidates produced
test -f workspace/workshop/<target>/run_manifest.json   # manifest produced
```

If `candidates.jsonl` exists and validates against the contract, Ring 2 is live.

---

## How candidates enter the loop (this is the wiring)

Establishing the tool is not enough — its output must be **consumed**. The flow:

```text
Ring 2 (tool)  ──run──▶  workspace/workshop/<target>/candidates.jsonl
                                      │  (raw leads, not findings)
                                      ▼
Ring 3 starts:  bb-surface-mapping  ──┤ cross-check candidates against the
                (FRONT gate)          │ vuln-agnostic surface map — a scanner
                                      │ hit is a lead, NOT a confirmed finding
                                      ▼
                bb-web-vuln-scan  →  candidate gate pipeline (dedup → scope-safety
                                     → chain-review → evidence → Finding)
```

Routing is driven by each candidate's `suggested_skill` field (output contract). A scanner hit **never** becomes a Finding directly — it is a lead that the front gate and the gate pipeline must still validate. This keeps Ring 2 honest (cheap detection) and Ring 3 in control (judgement).

The `bb-tool-setup` skill triggers this whole procedure; the `bbflow-runner` agent runs a configured Option-A tool and writes candidates into the workshop.

---

## See also

- [output-contract.md](output-contract.md) — the candidates.jsonl / run_manifest.json schema
- [flow.md](flow.md) — Gate 0–5 run lifecycle
- [scope.example.yaml](scope.example.yaml) — scope file shape
- [safety-boundary.md](safety-boundary.md) — what the tool layer must never do
- [../docs/architecture-closed-loop.md](../docs/architecture-closed-loop.md) — where Ring 2 sits in the loop
- `.claude/skills/bb-tool-setup` — the skill that drives this setup
- `.claude/agents/bbflow-runner.md` — the agent that runs a configured tool
