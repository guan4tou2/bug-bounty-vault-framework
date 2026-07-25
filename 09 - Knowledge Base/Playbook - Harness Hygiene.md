---
type: reference
category: playbook
tags: [playbook, maintenance, context-engineering, harness]
added: 2026-07-25
---

# Playbook — Harness Hygiene

> Keep the guidance layers (CLAUDE.md, skills, tool descriptions) lean and calibrated to your model as the vault ages — periodic upkeep, not a one-time setup.

---

## When

Run periodically (e.g. monthly), or whenever the harness feels bloated: the skill listing is large, a CLAUDE.md file has sprawled, or sessions are slow to start and spend context before doing useful work.

## 1. Prune unused extensions

- If you drive this framework with **Claude Code**, run `/doctor` (interactive) to surface unused plugins, a stale version, and redundant CLAUDE.md content. Disable zero-use plugins (reversible via settings), and update if you are behind.
- Note: `claude doctor` (CLI) is an **installation** health check only — it does not analyze prompt/skill redundancy. Redundancy is a manual cross-file review.
- Other harnesses have no equivalent command — do the review by hand: list what loads every session and cut what nothing uses.

## 2. Keep CLAUDE.md lean

Follow [docs/context-engineering.md](../docs/context-engineering.md):

- Always-loaded files hold only **gotchas and non-obvious patterns**. Cut anything a session can reconstruct from the file tree or manifest.
- Collapse repeated rules to a **single pointer** — state a rule once, link to it elsewhere. The same instruction should not appear in the system prompt, a skill, and CLAUDE.md.
- Prefer auto-memory (where your harness supports it) over hand-copying learnings into CLAUDE.md.
- Keep safety-critical prohibitions (scope guard, stop conditions, GET-first) **explicit** — never trade those for brevity.

## 3. Calibrate to your model

This framework is **model-agnostic**. When editing any guidance layer, match the constraint level to the model's capability:

- **Strong frontier models** — fewer constraints, trust judgment; hand them goals, not scripts.
- **Small / weaker / non-Claude models** — more explicit scaffolding, worked examples, and guardrails. Do **not** strip constraints; that degrades them and risks skipped safety gates.

Mark universal principles separately from capability-dependent ones (see the `[universal]` tags in the context-engineering doc). Full rationale: [docs/context-engineering.md](../docs/context-engineering.md).

---

## Related

- [docs/context-engineering.md](../docs/context-engineering.md) — the rules this playbook applies
- [CLAUDE.md](../CLAUDE.md) — the primary always-loaded guidance file
