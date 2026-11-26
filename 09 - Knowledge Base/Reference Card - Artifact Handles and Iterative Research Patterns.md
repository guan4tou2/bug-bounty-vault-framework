---
type: reference-card
title: "Reference Card - Artifact Handles and Iterative Research Patterns"
tags: [meta, context-engineering, workflow, handoff, research]
status: draft
last_updated: 2026-10-17
---

# Reference Card - Artifact Handles and Iterative Research Patterns

> **TL;DR**: Two harness engineering patterns borrowed from bytedance/deer-flow 2.0 and adapted to this vault: (1) **artifact handles** — big tool outputs live on disk, context keeps 1-line pointers that survive compaction; (2) **iterative deep research** — a plan → fan-out → critique → fill-gap loop that runs inside a single agent with zero external dependencies. This card records the design rationale; the operational rules live in the skills/agents themselves.

## Where each pattern is operationalized

| Pattern | Canonical rules | Template support |
|---------|----------------|------------------|
| Artifact handles | `.claude/skills/bb-context-handoff/SKILL.md` → "Artifact Handle Discipline" + In-Progress block `### Artifact Handles` | `automation/templates/HANDOFF_template.md` → "Artifact Handles" section |
| Iterative pre-hunt research | `.claude/agents/disclosed-report-researcher.md` → "Step 5.5 — Deep-research loop" | — |

## Pattern 1 — Artifact handles (why, in one screen)

The conversation context is lossy (compaction truncates mid-session); the filesystem is not. Sessions that summarize tool output into conversation lose the ability to re-derive details after compaction, and takeover sessions re-run expensive scans because the summary was compressed away.

Handle = `path — size — fingerprint (line/hit count, timestamp, first bytes)`. Three consequences of this design, worth remembering when extending it:

1. **Persist-then-summarize ordering.** Write the file the moment the tool returns; the summary is derived from the file, never the other way round. Mirrors the persist-before-verify rule in docs/context-engineering.md §1.
2. **Fingerprint verification on recovery.** A takeover verifies the fingerprint before trusting the file — this catches the crash-mid-write case and routes it to the degraded-input path instead of silently trusting truncated data (context-engineering.md §2).
3. **Handles never go inline.** HANDOFF.md is read at every session start; pasting 200 lines into it defeats the token-light brief.

## Pattern 2 — Iterative deep research (why, in one screen)

A single pass of searches leaves answered-only-the-easy-questions briefings. The DeerFlow-style loop fixes this with an explicit budget:

```
plan (3-5 open questions from evidence so far)
  → fan-out (parallel WebSearch/WebFetch, category table from bb-multi-search)
  → critique (what got answered? what contradicts? what NEW question surfaced?)
  → fill-gap (next iteration plans only the gaps) — max 3 iterations, stop on no-new-answers
```

Two invariants: contradictions are resolved by targeted follow-up searches, never by keeping the more exciting claim; and "unanswered ≠ dead end" — only vendor-patched items go to Dead Ends, the rest stay as an unresolved-questions footnote (anti-exaggeration).

## What was evaluated and NOT adopted (from deer-flow 2.0)

| DeerFlow capability | Verdict | Reason |
|---|---|---|
| Whole framework as harness replacement | rejected | ~80% overlap with vault (sub-agents ≈ Agent tool, skills ≈ .claude/skills, memory ≈ HANDOFF/RECON_DB, sandbox ≈ sandbox-replay); heavy infra (Python 3.12 + Node 22 + Postgres/Redis + Docker) for negative net value |
| MCP-mode deep research engine (1.x branch) | rejected | Operator decision: pre-hunt research automation must not depend on MCP; the agent-internal loop (Pattern 2) achieves the goal with zero added infra |
| Lease-based run ownership (vs claim.sh file locks) | deferred | Current single-operator usage doesn't hit the concurrency cases leases solve; revisit if multi-VPS parallel hunting becomes routine |
| Server-owned sandbox references | deferred | Revisit if sandbox-replay grows a shared/replayable artifact store |

## Cross-reference

- docs/context-engineering.md — the persist-before-verify and degraded-input principles these patterns implement
- bb-context-handoff skill — operational rules for handles
- bb-multi-search skill — the source-category table the fan-out step reuses
- disclosed-report-researcher agent — the loop's canonical implementation
