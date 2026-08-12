---
type: playbook
title: "Reusable Workflows"
tags: [playbook, workflow, automation, orchestration, bb-playbook]
category: maintenance
status: draft
last_updated: 2026-08-12
---

# Playbook - Reusable Workflows

> **TL;DR**: This playbook captures verified, rerunnable multi-agent orchestration patterns for batch knowledge-base maintenance tasks (bulk writeup summarization, session-learning triage, semantic graph extraction), along with the pitfalls hit while building them. A workflow orchestration tool is not worth rewriting from scratch each time — the three patterns below were built and validated during a knowledge-base maintenance session and produced real output.

---

## Scope / When to use

Use this playbook when you need to fan out many subagents against a batch of similar inputs — for example: deep-reading a stack of external writeups, triaging a large pile of raw session-learning notes into categories, or re-running semantic extraction across an entire knowledge base. It is not meant for one-off single-agent tasks; the orchestration overhead only pays off once you're coordinating multiple parallel agents against a shared schema.

---

## Phases

### Phase 0: Shared pitfalls (read first)

These were the actual failure modes hit while building the patterns below — check them before designing a new fan-out workflow.

| Pitfall | Symptom | Fix |
|---|---|---|
| **Agent fan-out too large, hits quota** | Launching 50+ agents at once triggers a "session limit" response, and the harness reports the subagent completed without producing structured output | Batch in groups of **≤10 parallel agents**, run the next batch after the current one finishes; or scale the fleet dynamically against remaining budget |
| **Schema too heavy for the agent to fill in** | A schema with 4+ required arrays and deep nesting causes the agent to fall back to free-form natural language instead of structured output | Split the schema by phase — e.g. phase 1 only needs lessons, phase 2 adds techniques; keep `required` fields minimal |
| **Subagents don't inherit the parent's project conventions** | Rules get dropped, and the resulting report violates house style | Append a short conventions block directly into the agent prompt (see the `CONV` string in the example below) |
| **Retrying failed structured-output calls wastes budget** | The harness gives up after 2 retries, and the whole fleet stalls partway through | Wrap the call in try/catch; on failure, fall back to an unstructured natural-language response instead of retrying indefinitely |

### Phase 1: Bulk writeup deep-read and summarize

**Purpose**: Batch deep-read external writeups and produce house-format summaries (TL;DR / core techniques / workflow / cross-references to internal knowledge base).
**Input**: An array of `{url, topic, xref}` objects.
**Output**: One Markdown section per article, ready to append to a writeups index file.
**Verification status**: Verified in production — one batch of 11 articles processed successfully end-to-end.
**Scale guidance**: 11 articles in one batch is fine; batch anything above ~20 to avoid quota issues.

```javascript
// pseudocode illustrating the orchestration pattern —
// one agent per writeup, run in parallel, each doing WebFetch + structured summary

export const meta = {
  name: 'deepread-writeups',
  description: 'Deep-read external writeups and produce house-format summaries',
  phases: [{ title: 'DeepRead', detail: 'one agent per writeup: WebFetch + structured summary' }],
}

const CONV = `Conventions: no overclaiming (only state what the article actually demonstrates); techniques must be actionable (include payloads/commands/steps); cross-references must point to real existing files — if unsure, mark as "suggest creating".`

phase('DeepRead')
const results = await parallel(args.articles.map(a => () =>
  agent(`WebFetch ${a.url} and deep-read it. Topic: ${a.topic}.

Output Markdown, with heading "## N. ${a.topic}", and sub-headings:
### TL;DR (2-3 sentences)
### Core techniques (bulleted, with payloads/commands)
### Reusable workflow (repeatable steps)
### Cross-references (${a.xref})

${CONV}`)))
return results.filter(Boolean).join('\n\n')
```

**Usage example**: invoke the workflow with an `args.articles` array as shown above; each element produces one summary section.

### Phase 2: Session-learning batch triage

**Purpose**: Take the raw, unsorted recommendations produced by a mining/extraction pass and classify them per-category into a digest that a human can review and decide whether to promote, merge, or drop.
**Input**: Raw items grouped by category (e.g. lessons / patterns / playbooks / checklists / wiki / tooling-workflow), one input file per category.
**Output**: One digest file per category.
**Verification status**: Verified in production — one run processed roughly 170 raw items into 6 category digests.
**Scale guidance**: One curator agent per category, run in parallel, is safe (6-way parallelism in the verified run).

```javascript
// pseudocode illustrating the orchestration pattern

const CATEGORIES = [
  { name: 'lessons', count: 72 }, { name: 'patterns', count: 18 },
  { name: 'playbooks', count: 15 }, { name: 'checklists', count: 28 },
  { name: 'wiki', count: 25 }, { name: 'tooling-workflow', count: 10 },
]

phase('Consolidate')
const out = await parallel(CATEGORIES.map(c => () =>
  agent(`You are the ${c.name} curator. Read the raw input for this category (${c.count} raw items).
Sort into four groups:
- NEW (no corresponding entry in the knowledge base — suggest creating one)
- MERGE (corresponds to an existing entry — should be folded in)
- FOLD (duplicate/weak signal — fold into another NEW or MERGE item)
- DROP (noise/overclaiming/already known — do not adopt)

Write a digest file listing each group's items with a brief rationale for each.`)))
```

### Phase 3: Full-corpus semantic graph extraction (rerun when needed)

**Purpose**: Extract entities and relationships from the entire knowledge base and produce an incremental update to the semantic graph.
**Verification status**: Heavier operation — parallelizing ~19 chunks across the whole corpus carries real quota risk; prefer running during off-peak hours. The extraction model must be a mid-tier model per the graph-extraction tool's own requirement.
**Scale guidance**: ~19 chunks is close to the safe upper bound; consider splitting into two rounds (e.g. 10 + 9) to avoid a mid-run failure taking out the whole batch.

```javascript
// pseudocode illustrating the orchestration pattern

phase('Extract')
const chunks = chunkFiles(KB_FILES, 19)
const fragments = await parallel(chunks.map((files, i) => () =>
  agent(EXTRACT_PROMPT(i, 19, files), {
    model: 'sonnet',  // required by the graph-extraction tool
    schema: KG_FRAGMENT_SCHEMA,
  })))
mergeIntoGraph(fragments.filter(Boolean))
```

**Rerun trigger**: when the knowledge base has grown by ≥30 documents, or as part of monthly maintenance.

---

## Decision Points

- **Anti-pattern — monolithic mining in one giant fan-out**: A single run that tried to fan out 50+ agents at once (mining dozens of batches, plus several research themes, plus gap analysis, plus synthesis, all in one shot) hit a quota wall — every parallel agent returned a natural-language "session limit" response, and the harness treated this as a structured-output failure across the board.

  **The fix is not a smaller schema — it's a different orchestration**:
  1. Split into separate workflows (mine / gap-analysis / synthesize), chained manually with a checkpoint between each stage.
  2. Run the mining stage in multiple rounds of ~9 agents each, rather than one round of 50+.
  3. When an agent fails structured output, automatically fall back to an unstructured natural-language response rather than retrying.

- **When to batch vs. run all at once**: if the fleet size is at or below ~10 agents, one round is usually safe; above that, split into rounds and treat each round as an independent checkpoint so a mid-run failure doesn't take down the whole batch.

- **When to fall back to schema-less mode**: if an agent fails structured output twice, stop retrying with the same schema — either simplify the schema or accept a natural-language response and post-process it.

---

## Expected Outputs

- Phase 1: one Markdown summary section per input article, ready to append to a writeups index.
- Phase 2: one per-category digest file, grouped into NEW / MERGE / FOLD / DROP with rationale.
- Phase 3: an incremental update merged into the semantic knowledge graph.
- In all cases: a short pitfalls/lessons note if the run hit any of the failure modes in Phase 0 or the Decision Points anti-pattern, so the next run doesn't repeat them.

---

## Related

- [[Playbook - Improved End-to-End Hunting Workflow]] — the 4-loop hunting cycle; the workflows in this playbook feed its learning loop
- [[Lessons Learned]] MOC — the "schema too heavy" pitfall in Phase 0 shares a root cause with lessons about LLM secondary-review design flaws
