---
fileClass: ReferenceCard
type: reference-card
title: Promotion Ladder — Rule → KB → CLAUDE.md → Skill → Agent → Workflow
last_updated: 2026-07-09
tags: [reference-card, governance, taxonomy, skill, agent, claude-md, workflow, bb-referencecard]
source: vault-distilled
added: 2026-07-09
---

# Reference Card — Promotion Ladder

> **Where should each thing live?** This card is the single source of truth for that question.
> A seven-layer ladder. Each layer has an explicit "trigger to promote up", a "signal to demote down", and a load cost.

---

## 0. The seven-layer ladder at a glance

```
   HIGH: always-loaded / always-applies / broad impact
   ┌─────────────────────────────────────────────────────────┐
T1 │ Governance docs (AGENTS.md / STRUCTURE.md / *_QUICK.md)  │ ← read by every agent
T2 │ KB Reference / Pattern / Playbook / Checklist           │ ← queried on demand; LLM invokes actively
T3 │ CLAUDE.md / CODEX.md                                    │ ← read every session by that agent
T4 │ Skill (.claude/skills/<name>/SKILL.md)                  │ ← loads only on trigger; enforcing
T5 │ Agent (.claude/agents/<name>.md)                        │ ← spawned subagent, isolated context
T6 │ Saved Workflow (.claude/workflows/<name>.json)          │ ← re-runnable orchestration of many agents
T7 │ One-off inline orchestration (ad-hoc Workflow use)      │ ← disposable
   └─────────────────────────────────────────────────────────┘
   LOW: on-demand / one-shot / narrow impact
```

---

## 1. "Load cost vs. blast radius" per layer

| Layer | Loaded when | Token cost | Blast radius | Enforcement |
|---|---|---|---|---|
| T1 Governance docs | Every session (read on start) | High (20-100KB) | Every agent | Rule-level; violating it = wrong |
| T2 KB | LLM queries it / dataview | 0 (on demand) | Only when the LLM sees it | Soft reference |
| T3 CLAUDE.md | Every session (that agent) | Medium (5-15KB) | That agent, whole session | Rule-level |
| T4 Skill | Trigger matches + Skill tool | Low (only on hit) | That session, that trigger | Strong (procedure inside must run) |
| T5 Agent | When a subagent is spawned | Medium (per spawn) | Isolated context | Strong (subagent does not inherit CLAUDE.md; it must carry its own) |
| T6 Saved Workflow | Called via the Workflow tool | Medium-high | Orchestrates many agents | Strong |
| T7 Inline Workflow | Written ad hoc | Medium-high | One-off | Weak (discarded) |

---

## 2. Promote / demote decision trees

### Note → KB (T2)

```
[Is the note] ── reproduced on >= 2 targets?
  yes → write it up as a Pattern / Playbook / Checklist in 09 - Knowledge Base/
  no  → keep it in the target's recon note or an individual Lesson
```

### KB → CLAUDE.md (T3)

```
[Should the KB item] ── be read every single session? (and should everyone know it?)
  yes → do NOT paste the whole thing into CLAUDE.md; rewrite it as a one-line "pointer + trigger"
        e.g. "external skills are opt-in installs → see the External Skills Catalog"
  no  → leave it in the KB; the LLM queries it via its trigger
```

> **CLAUDE.md is a collection of pointers, not a content dump.** Keep it tight (a few hundred lines, not thousands).

### Rule → Skill (T4)

**Four conditions to promote to a Skill (all must hold):**

1. **A clear trigger word exists** (something the user says, or a keyword that shows up in the LLM's context).
2. **Content is > 50 lines** (short things stay in CLAUDE.md / a KB Reference).
3. **It is a procedure, not just a fact** (has steps / gates / an ordering requirement).
4. **It should NOT be visible when its trigger is absent** (avoids polluting the context of unrelated sessions).

Examples:
- ✅ `bb-form-writer` — triggered by "write a report / build a submission form", a long procedure, should not load otherwise.
- ✅ `bb-surface-mapping` — triggered by "start hunting X", has a multi-phase gate, enforces anti-streetlight-effect mapping.
- ❌ "no internal IDs in reports" — a one-line principle, write it straight into CLAUDE.md.
- ❌ "prefer GET-first probing" — a one-line principle, write it straight into CLAUDE.md.

### Skill → Agent (T5)

**Three conditions to promote to an Agent (any one is enough):**

1. **Needs an isolated context** (the main thread is already polluted, or you want to keep it clean).
2. **Needs to run in parallel** (the same task against many targets at once).
3. **Needs a different model** (e.g. a batch extraction step pinned to a cheaper model while the main thread runs a stronger one).

Examples:
- ✅ `bbflow-runner` — runs the hunter series and returns structured results to the main session.
- ✅ `report-writer` — platform formats differ; an isolated context keeps the main session clean.
- ✅ `attack-chain-deep-dive` — multi-hop analysis that benefits from a fresh, dedicated context.
- ❌ `bb-dedup-finding` — it is a procedure; the main thread can just follow it → a Skill is enough.
- ❌ "check RECON_DB" — a single action, just do it, no spawn needed.

> **An Agent is a spawned subagent and does NOT inherit CLAUDE.md** — when writing an Agent you must inject the relevant conventions into its prompt.

### Agent → Saved Workflow (T6)

**Conditions to promote to a Workflow (any one is enough):**

1. **You need >= 2 agents to run in parallel and then converge** (fan-out / barrier / pipeline).
2. **The same prompt + same schema must be re-run >= 2 times** (so you stop rewriting it).
3. **There is a dependency between agents** (stage 1's output feeds stage 2).

Examples:
- ✅ A fan-out that deep-reads N external write-ups in parallel, then converges the results into one collection.
- ✅ Several curator agents each owning one category, running in parallel.
- ✅ A chunked semantic-extraction pass (many chunks extracted in parallel, then merged).
- ❌ Reviewing a single PR once → an inline workflow (T7) is enough.

---

## 3. Demotion signals (move it down)

| What you notice | Demote to |
|---|---|
| A Skill's trigger has not matched for >= 90 days | KB (keep it as reference, no longer always-resident) |
| An Agent has not been spawned in >= 60 days and is stale | Mark archive, move to `.claude/agents/_archive/` |
| A CLAUDE.md section is never referenced | Delete it or condense to a one-line pointer |
| A Workflow ran once and never again | Delete `.claude/workflows/<name>.json`, keep a Playbook note |
| A KB Pattern with 0 references + 0 backlinks for >= 180 days | Evaluate deleting it or merging it into a related Pattern |

---

## 4. Anti-patterns (do NOT do this)

❌ **Making a Skill out of every tiny rule** — a Skill is not a rule; a Skill is a trigger-gated procedure.
❌ **Stuffing a long procedure into CLAUDE.md** — it loads once per session and burns tokens.
❌ **Flattening Skill content into the KB** — the KB is dataview-friendly knowledge; a procedure needs the enforcement of a Skill.
❌ **Writing an Agent without convention injection** — subagents do not inherit, so they will violate rules like "no internal IDs in reports" and "no exaggeration".
❌ **Discarding a Workflow after one run** — a production-validated workflow should be saved under `.claude/workflows/` so it is re-runnable; one-off things stay purely inline.

---

## 5. Taking stock of your own ladder

Periodically inventory each layer so nothing drifts. A quick census:

| Layer | How to count | Health check |
|---|---|---|
| T1 Governance docs | `ls *.md` at repo root (AGENTS / STRUCTURE / *_QUICK) | All present and read on start |
| T2 KB | Count of Pattern / Playbook / Checklist / Reference Card / Lessons | Each has a distinct purpose; no orphans |
| T3 CLAUDE.md / CODEX.md | 1-2 files | Kept tight, pointers not dumps |
| T4 Skill | `ls -d .claude/skills/*/ \| wc -l` | Each trigger distinct; none silently unused |
| T5 Agent | `ls .claude/agents/*.md \| wc -l` (minus README) | None stale past the demotion window |
| T6 Saved Workflow | `ls .claude/workflows/*.json` | Each was production-validated |
| T7 Inline | (n/a) | — |

---

## 6. Worked promotion examples (the learning path)

### Example 1: OTP appears in the response → Information Disclosure (not Auth Bypass)

- First time you hit it → write it into the individual target's recon note.
- Reproduced a second time → promote to a Lesson.
- Across many targets / the classification rule generalizes → promote to a Reference Card ([[Reference Card - Vulnerability Type Classification]]).
- A report-writing mistake keeps recurring → add a one-line principle to CLAUDE.md ("no internal IDs in reports").

### Example 2: A platform submission-form format

- First time → jotted into a recon note.
- After it reproduces → a Reference Card (field definitions).
- After repeated user corrections → a Skill (`bb-form-writer`, an enforcing procedure).
- The platform-type mapping table → folded into the Skill (no separate Agent, since no spawned context is needed).

### Example 3: Deep-reading many external write-ups

- First time, done by hand → a one-off inline workflow (T7).
- Ran fine and is repeatable → promote to a Saved Workflow (T6).
- Write it up in a Playbook alongside any quota / rate-limit caveats you learned.

---

## Related

- [[Reference Card - External Skills Catalog]] — where opt-in third-party skills sit on this ladder
- [[Reference Card - Finding Lifecycle State Machine]] — the state model that findings move through
- [[Reference Card - Vulnerability Type Classification]] — promotion Example 1's destination card
- [[Playbook - Trigger Chain Dry-Run]] — the paper dry-run whose by-products (new patterns / lessons) feed this ladder
- `automation/CONVENTIONS.md` — automation/ vs _automation/ split (the same "where does it live" problem at the script layer)
- CLAUDE.md skill/agent trigger table — the bb-* skill + agent trigger list (count it with `ls -d .claude/skills/*/`)
