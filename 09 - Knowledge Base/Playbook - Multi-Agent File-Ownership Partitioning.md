---
fileClass: Playbook
type: playbook
category: playbook
title: Multi-Agent File-Ownership Partitioning
tags:
  - subagent
  - orchestration
  - parallelism
  - file-ownership
  - clobber-avoidance
  - coordinator
last_updated: 2026-07-08
status: active
source: internal
origin: session method — parallel skill authoring + governance-file wave without clobbering
---

# Playbook — Multi-Agent File-Ownership Partitioning

## The clobber problem
When a task needs many edits across many files, the reflex is to fan out parallel subagents to go faster.
But two agents editing the **same file** concurrently overwrite each other: each holds a stale copy, the
last writer wins, and the other agent's work silently vanishes. Parallelism is only safe when no two
agents' write-sets intersect. This playbook makes that safety explicit.

## The method (5 points)

1. **Partition by exclusive file-ownership.** Each parallel authoring agent OWNS a disjoint set of files;
   no two agents touch the same file. The cleanest ownership boundaries are **independent NEW files**
   (new skill dirs, new KB docs) and **separate repos** — a brand-new file has no other writer by
   construction, so contention is zero.

2. **Coordinator (main thread) owns the shared-file + serialized steps.** Registration into shared tables
   (CLAUDE.md skill/agent table, README), mirror regen (`sync_codex` / `sync_gemini`), running gates
   (leak-test, `check_harness_invariants.sh`), commit grouping, and push all touch shared files and/or
   need global judgment → **NOT parallelized**. The commander integrates; it does not fan these out.

3. **Two-wave shape.**
   - **Wave 1 — parallel authoring:** agents write only NEW / isolated files → zero shared-file contention.
   - **Wave 2 — coordinator integrates:** register + mirror + gate + commit, serialized in the main thread.
   If a governance file (CLAUDE.md, AGENTS.md) would be touched by 2+ concerns, assign it to exactly ONE
   agent that owns it end-to-end, or defer that edit to the coordinator.

4. **Contention check before dispatch.** List each agent's file set; confirm the sets are **pairwise
   disjoint**. If two agents must touch the same hot file (e.g. CLAUDE.md), either serialize them or give
   ONE agent sole ownership of that file for BOTH concerns.

5. **Defer the cross-file-coupled risky item.** Anything with wide coupling (e.g. splitting a monolith that
   14 pointers reference) gets its own careful **single-owner** pass — never parallelize it. The blast
   radius of a bad merge there is larger than the time parallelism would save.

## Worked example (this session)

**Wave 1 — 3 new skills authored in parallel.** Three agents each got a distinct, brand-new skill
directory (`.claude/skills/<skill-a|b|c>/`). Write-sets were disjoint by construction (separate new dirs),
so all three ran concurrently with no clobber risk.

**Wave 2 — coordinator integrated.** Main thread then, serialized: registered the 3 skills into the
shared CLAUDE.md skill table + README, regenerated the codex/gemini mirrors, ran the leak-test and
`check_harness_invariants.sh` gates, grouped the commit, and pushed.

**Governance wave — 3 disjoint agents.** A separate batch of governance edits was split so each of the 3
agents owned a distinct file; the shared hot file (CLAUDE.md) was handed to exactly one owner. Pairwise-
disjoint confirmed before dispatch → no overwrites.

## When NOT to parallelize
Partitioning assumes you can enumerate the write-set **up front**. For **adaptive / discover-then-decide**
work — where the next file to touch depends on what the last step found — you cannot pre-declare disjoint
sets, so fan-out will race. Run that as a single **interactive Agent** in the main thread instead. See
[[01 - Model Dispatch Doctrine]] §1a (commander context-isolation vs. when to keep work inline).

## See also
- [[01 - Model Dispatch Doctrine]] §1a — commander doesn't go on the field / when to keep it inline
- [[03 - Delegation Templates]] — fill-in dispatch templates (goal / acceptance / report + model/effort)
- [[Reference Card - Promotion Ladder]] — when a repeatable multi-agent orchestration graduates to a Saved Workflow
