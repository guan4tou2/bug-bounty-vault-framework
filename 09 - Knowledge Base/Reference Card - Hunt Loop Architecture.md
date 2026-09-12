---
fileClass: ReferenceCard
type: reference-card
title: Hunt Loop Architecture
category: methodology
tags: [reference-card, hunt-loop, cgt, dag, priority-scoring, workflow]
added: 2026-08-29
---

# Reference Card — Hunt Loop Architecture

> Formalizes a full hunt-loop: surface-map through KB capture, with priority scoring and exit conditions.
> Each stage maps to an existing skill/script. The loop is the spine.

> **⚠️ Status reconcile (2026-09-12).** This card describes a **CGT-centric, opt-in DEEP variant** of the loop.
> The canonical, load-bearing loop is now narrower and lives elsewhere — do not read this as the mandatory
> per-round protocol:
> - **Canonical orchestrator**: `automation/hunt_autodrive.py` — one ASG ledger (`.state/asg-events.jsonl`)
>   → select valuable+ready hypothesis → dispatch worker → **control-comparison oracle** → update → auto-replan.
>   Reference implementation: the `automation/hunt_autodrive.py` + `automation/hunt_live.py` modules in this seed.
> - **Load-bearing parts only**: **autogen** (rank anomalous surfaces) + **oracle** (control comparison blocks
>   fake 200s). Everything else (CGT pin/traverse, ledger-resume, bbflow ingest) is **opt-in**, not per-round.
> - **CGT is opt-in, not "the nervous system"**: mandatory P/R tagging was retired; CG→DAG auto-reachability
>   (`dag-suggest`) is parked/dead (0 triggers). A deliberate deep chain pass (capability pin + traverse) is opt-in — do it when a confirmed
>   capability-granting finding makes chaining worthwhile, not as a per-round gate.
> The priority formula and exit-condition tables below remain good general references.

---

## Hunt Loop Stages

```
  [1] Surface Map ──→ [2] CGT Pin ──→ [3] Capability Traverse
         │                                      │
         ▼                                      ▼
  [8] KB Capture ◄── [7] Submit ◄── [6] Chain ◄── [5] Test ◄── [4] Prioritize
```

| # | Stage | Skill / Script | Input | Output |
|---|-------|---------------|-------|--------|
| 1 | **Surface Map** | `bb-surface-mapping` + `pre-recon` agent | Target scope | Attack Surface Graph (nodes, edges, capability_state) |
| 2 | **CGT Pin** | capability pin (opt-in; helper not shipped in this seed) | Graph yaml | Session-start capability_state pin |
| 3 | **Traverse** | capability traverse (opt-in; helper not shipped in this seed) | capability_state + findings P/R | Unlocked vs blocked partition |
| 4 | **Prioritize** | Priority formula (below) + `automation/dag_gaps.sh` | Unlocked set + DAG gaps | Ranked work queue |
| 5 | **Test** | `bb-web-vuln-scan` / `web-hunter` agent / manual | Top-priority candidate | Verified finding or recorded attempt |
| 6 | **Chain** | `bb-exploit-chain` (Q1-Q8) | Verified finding | P/R tags, capability_state update, chain extensions |
| 7 | **Submit** | `bb-dedup-finding` → `bb-evidence-readiness` → `bb-submission-readiness` → `bb-form-writer` | Chained finding | FORM / Submission |
| 8 | **KB Capture** | `bb-knowledge-capture` | Session learnings | Pattern / Lesson / Checklist / bbflow update |

**Loop re-entry**: After Stage 6 (Chain), new capabilities feed back to Stage 3 (Traverse) -- newly unlocked nodes re-enter at Stage 4.

---

## Priority Scoring Formula

Each candidate node receives a composite score. Higher = work first.

```
score(f) = tier_weight(f) + severity_weight(f) + unlock_bonus(f) + gate_opener_bonus(f)
```

| Component | Values | Rationale |
|-----------|--------|-----------|
| `tier_weight` | T1=3, T2=2, T3=1 | T1 = LLM-addressable (highest ROI); T3 = needs manual/specialized tooling |
| `severity_weight` | P1=5, P2=4, P3=3, P4=2, P5=1 | Higher severity = higher program payout |
| `unlock_bonus` | +2 if all R: tags satisfied | Ready to test now -- no blockers |
| `gate_opener_bonus` | +1 per downstream finding this node's P: tags would unlock | Findings that open paths for others are force multipliers |

**Example**: T1 finding, P2 severity, unlocked, opens 3 downstream nodes:
`score = 3 + 4 + 2 + 3 = 12`

**Tie-breaking** (same score):
1. Prefer findings whose P: tags satisfy the most blocked nodes (maximize unblock fan-out)
2. Prefer findings on surfaces not yet tested (coverage diversity)
3. Prefer findings with existing PoC sketch (lower effort to verify)

**Parallel edge identification**: `dag_gaps.sh` already detects independent edges (no dependency between TO/FROM). Run candidates at the same priority level concurrently via subagents.

---

## Hunt Loop Exit Conditions

Stop hunting a target when ANY of these hold:

| Condition | Signal | Action |
|-----------|--------|--------|
| **Surface exhausted** | All Graph nodes tested (no pending DAG edges) | `dag_gaps.sh --count` returns 0 |
| **Capability ceiling** | All blocked nodes require capabilities that are out-of-scope or infeasible to acquire | the (opt-in) capability traverse shows only blocked nodes with unacquirable R: tags |
| **Diminishing returns** | Last 3+ test cycles produced only attempts, no new findings | Check Attempts/ count vs Findings/ count ratio |
| **Budget exhausted** | Session token budget or calendar time exceeded | Handoff via `bb-context-handoff` |
| **Program blocked** | Needs account/KYC/hardware/VPN not available | Park target, record blocker in HANDOFF.md |
| **Scope risk** | Further testing would require dangerous/out-of-scope operations | `bb-scope-safety-check` flags red |

**Partial exit**: Park blocked branches (mark DAG edges as blocked with reason), continue on unlocked branches. A target is fully parked only when ALL branches hit an exit condition.

---

## Stage Details

### Stage 1: Surface Map (anti-streetlight)

The gate that prevents pattern tunnel vision. Must produce an Attack Surface Graph with nodes before any hunter/pattern scan runs. `surface_map_gate.sh` enforces this at scan time.

### Stage 4: Prioritize (work queue construction)

```bash
# 1. Get unlocked/blocked partition
# (opt-in) capability traverse: partition unlocked vs blocked
# 2. Get pending DAG edges with tier distribution
bash automation/dag_gaps.sh <target>
# 3. Score and rank (manual or future automation)
# Pick top 1-3 candidates per session cycle
```

### Stage 6: Chain (the multiplier)

Q8 of `bb-exploit-chain` feeds back into the loop:
1. Tag P/R on the new finding
2. Update capability_state in the Attack Surface Graph
3. Re-run the (opt-in) capability traverse -- newly unlocked nodes enter the priority queue
4. Q7 clue-correlation re-scans blocked attempts for retest triggers

This creates a positive feedback loop: each finding potentially unlocks the next.

---

## Invariants

1. **No testing before mapping** -- Stage 5 never precedes Stage 1 (enforced by `surface_map_gate.sh`)
2. **No submission before chaining** -- Stage 7 never precedes Stage 6 (enforced by `bb-submission-readiness`)
3. ~~**Every finding gets P/R tags** -- Q8 mandatory~~ **RETIRED (2026-09-12)**: mandatory CGT P/R tagging was
   retired (adoption ≈0). P/R tagging is now opt-in for a deliberate chain pass; the loop no longer gates on it.
4. **Every session ends with KB capture** -- Stage 8 runs at session close (enforced by `vault-sync` agent)
5. **Capability_state is monotonic (when used)** -- in the ASG ledger the capability layer is a projection over
   an append-only event log; a capability can be withdrawn when its supporting verdict is refuted/revoked
   (least-fixed-point), so "only added, never removed" holds for events, not for the derived capability set.

---

## Cross-References

- [[Reference Card - Attack Surface Graph Schema]] -- capability_state / P/R / tier schema
