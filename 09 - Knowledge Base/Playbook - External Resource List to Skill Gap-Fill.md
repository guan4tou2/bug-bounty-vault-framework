---
type: reference
category: playbook
tags: [playbook, knowledge-capture, gap-analysis, graph, skill-maintenance]
added: 2026-06-27
---

# Playbook — External Resource List → Skill Gap-Fill

> **When to use:** you have a curated external list (an Awesome list, a tool catalog, a domain
> cheatsheet, a conference resource page) and want to *absorb it into the vault* instead of
> skimming it once and forgetting it. Turn the list into a knowledge graph → use the graph to
> find the blind spots in your own skills → backfill.
>
> **Core insight:** a graph's **AMBIGUOUS / surprising edges are the blind-spot signal**. A
> relationship the extractor cannot classify with its existing vocabulary is often an
> *adversarial* or *cross-domain* pairing — exactly what a single-skill viewpoint misses.
> (Worked example: a "detector vs. detected" pair surfaced only as a low-confidence edge; it
> became a new anti-detection section in a dynamic-testing skill.)

## Flow (6 steps)

### 1. Ingest — normalize into a corpus directory
- Fetch the **raw** markdown (e.g. `raw.githubusercontent.com/.../README.md`), not the rendered
  summary — you want the full links and descriptions.
- Save it as a single `.md` inside a **dedicated directory**.
- Gotcha: many graph extractors detect files by scanning a **directory, not a single file** —
  point the tool at the folder, not the `.md`.

### 2. Build the graph → isolated output (never clobber an existing graph)
- If you already keep a vault-wide knowledge graph, a fresh small graph **must not overwrite it**.
  A good graph tool refuses to shrink an existing `graph.json` — treat that refusal as a safety
  feature, not an error.
- Write all outputs (`graph.json` / `graph.html` / report) to a **separate directory**; clean up
  any temp files left in the vault root.
- Use a cheaper model for extraction subagents and keep fan-out small; a short list is usually one chunk.

### 3. Read the graph for blind spots (the value is here, not in building it)
- **God nodes** = core abstractions. If a *concrete tool* breaks into the top few, it is the
  centre of that domain's ecosystem.
- **Surprising connections + AMBIGUOUS edges** = highest value. Ask of each: "why was this tagged
  uncertain?" → usually an adversarial pair (detector ↔ target), a cross-cluster bridge
  (static ↔ dynamic tooling), or a missing relation type.
- **Hyperedges** = workflow groups (e.g. a tool *family*, an *arms race*) → each maps to a whole
  skill section.

### 4. Gap analysis vs. existing skills
- Map each community / tool against the relevant skill and tag it **✅ covered / 🟡 partial /
  ❌ gap**.
- Produce a `Reference Card - <domain> Toolchain Gap Map`: a covered table + a gap table (ranked
  by ROI) + recommended actions.

### 5. Backfill (follow the promotion ladder)
- One-line rule → `CLAUDE.md` / a KB reference; a ≥50-line procedure with a trigger → a new skill
  section; needs spawned/parallel context → an agent.
- **Map onto the existing taxonomy; do not fork a parallel one.** Translate external concepts into
  the skill's existing dimensions (e.g. an APK's `exported="true"` component → the existing "trust
  boundary / internet-facing entry point" dimension) rather than starting a separate mobile-only
  checklist. Lower cognitive load, no duplication.
- Derived surfaces are not the end: a backend API host found inside an app gets extracted and fed
  back into the web recon floor.

### 6. Verify + record
- After every skill edit, run the harness checks (skills lint + harness-invariants).
- Add an "applied / landed" log entry to the gap-map card: which gaps you closed, which remain, and
  the gap-count delta (e.g. 4 → 0). The loop stays auditable.

## Anti-patterns (do not)
- ❌ Paste the whole list into a skill — no filtering, no blind-spot cross-check, token bloat.
- ❌ Build the graph in a directory that holds another graph and force-overwrite it.
- ❌ Invent a new taxonomy that fights the skill's existing dimensions.
- ❌ Promote domain-specific or competition-specific rules into the KB — only the abstracted
  methodology belongs there (KB purity).

## Cross-References
- `Reference Card - External Skills Catalog` (where domain tool-skills are registered)
- `Reference Card - Knowledge Capture Quality Rubric`
- `bb-knowledge-capture` (the gate that routes a learning to its destination)
