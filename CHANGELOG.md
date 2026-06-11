# Changelog

## v0.1.3 — 2026-06-11

### Explore-first front gate + closed-loop architecture doc

Backports the private vault's most-emphasized discipline — map the attack surface vuln-agnostically *before* pattern-matching, then enforce full OWASP coverage — which the public seed had been missing. Also documents the four-ring closed loop explicitly to prevent recurring "is this a loop?" and "which repo does X go in?" confusion.

**Added:**
- `.claude/skills/bb-surface-mapping` — vuln-agnostic attack-surface mapping, the FRONT gate of the hunting ring (counters the streetlight effect)
- `.claude/skills/bb-web-vuln-scan` — OWASP Top 10 coverage + injection matrix + version→CVE + WAF-bypass discipline (runs after surface mapping)
- `.claude/skills/bb-exploit-chain` — the 6-question chaining gate run on any finding before moving to the next system (escalate exposures instead of stopping at first finding); closes the last methodology gap vs the private vault
- `.claude/skills/bb-tool-setup` — establishes the Ring 2 tool layer (clone the bbflow tool or wire your own scanner) and verifies its `candidates.jsonl` actually feeds the loop; makes "bring your own tools" an AI-actionable, do-it-now step instead of a passive note
- `bbflow/setup.md` — step-by-step, agent-followable guide for establishing the tool layer and wiring its output into the candidate lifecycle
- `docs/architecture-closed-loop.md` — the four-ring loop (wiki ⇄ hunters ⇄ hunting ⇄ learning), the explore-first rationale, the framework-vs-tool-vs-private-vault repo boundary, and the public←private migration direction

**Changed:**
- `docs/workflow.md` — candidate lifecycle now shows the surface-map front gate + coverage gate between Recon and Candidate; gate list and lifecycle steps updated
- `docs/architecture.md` — added the "explore-first hunting (anti-streetlight)" design principle
- `README.md` — architecture diagram shows the hunter ring (bring-your-own, e.g. bbflow) and the front gates; skill count 13 → 16; tool-layer setup pointer
- `docs/workflow.md` — added a "Tool Layer (Ring 2)" section + tool-layer gate so candidates are actually generated before hunting
- `.claude/agents/bbflow-runner.md` — Step 0 checks the tool layer exists and routes to `bb-tool-setup` instead of blindly failing on a fresh machine
- `tests/test_public_skeleton.py` — guards the new skills
- **Repositioned as LLM-agent-operated by design** — README intro + LLM Integration section now present agent operation as the primary mode (manual Obsidian = fallback), since the skills/gates are the operating interface
- Added a rendered **mermaid four-ring loop diagram** to README and `docs/architecture-closed-loop.md` (closing ④→① edge highlighted); the ASCII version is kept as a collapsible plain-text fallback
- **Documentation sync pass** — propagated the front gate + tool layer + exploit-chain + LLM-first framing through every spec/walkthrough that had drifted: `AGENTS.md` §3e.1/§0b, `AGENTS_QUICK.md`, `docs/session-lifecycle.md`, `docs/getting-started.md`, `docs/post-clone-checklist.md`, `docs/sop.md`, `docs/fresh-start.md`, and `templates/candidate-review.md` (added the 6-question exploit-chain block). Updated the post-clone positioning test to match.
- Regenerated `.codex` / `.gemini` mirrors via `automation/sync_codex_skills.py`

## v0.1.2 — 2026-06-02

### Seed content + onboarding

Adds usable starter content so a fresh clone has something to look at and learn from.

**Added:**
- `docs/getting-started.md` — full clone → recon → Finding → Submission walkthrough
- `01 - Targets/_example/` — a filled-in sample Finding + Submission (ACME-001 IDOR) so the dashboards render on first open
- `00 - Dashboard/Kanban Board.md` — master workflow board (Kanban plugin)
- KB seeds: `Pattern - SSRF`, `Pattern - Subdomain Takeover`, `Playbook - Recon`, `Checklist - Pre-Submission Validation`

**Changed:**
- `00 - Dashboard/Dashboard.md` — Dataview queries reconciled to the real frontmatter schema (P1-P5 severity, `discovered_date`) + added open-findings and severity-count views
- README Knowledge Base section updated for the expanded seed set

## v0.1.1 — 2026-05-23

### Candidate Lifecycle Skills

Added 6 lifecycle gate skills and 1 agent to formalize the candidate-to-submission pipeline.

**Added:**
- `.claude/skills/` — 6 new lifecycle skills:
  - `bb-scope-safety-check` — scope + safety gate before live verification
  - `bb-attack-chain-review` — chain potential assessment
  - `bb-evidence-readiness` — evidence completeness gate
  - `bb-attempt-recorder` — negative result preservation
  - `bb-submission-readiness` — final gate before report
  - `bb-knowledge-capture` — reusable learning capture
- `.claude/agents/attack-chain-deep-dive.md` — deep analysis agent for complex chains
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md` — safety quick reference
- `09 - Knowledge Base/Reference Card - Knowledge Capture Quality Rubric.md` — KB quality rubric
- `AGENTS.md §3e.1` — candidate lifecycle gates specification
- Codex + Gemini skill mirrors auto-synced

**Changed:**
- Skill count: 7 → 13; agent count: 5 → 6
- `CLAUDE.md` — skill trigger table expanded with 6 new entries
- `AGENTS_QUICK.md` — candidate lifecycle pipeline diagram added
- Private data safety test strengthened (case-insensitive + expanded forbidden list)

## v0.1.0 — 2026-05-22

### Public Seed Release

Initial public seed for an Obsidian vault-as-top-level bug bounty workflow framework.

This release contains architecture, workflow, SOP, templates, optional LLM entrypoints, and seed scanner configuration. It intentionally excludes private targets, findings, report drafts, screenshots, scan output, credentials, and personal knowledge-base content.

**Added:**
- Obsidian numbered folders: `00 - Dashboard/`, `01 - Targets/`, `01 - Dorks/`, `07 - Templates/`, `09 - Knowledge Base/`, `10 - Meta/`
- `.claude/agents/` — specialized agents (bbflow-runner, cvss-auto-scorer, pre-recon, report-writer, vault-sync)
- `.claude/skills/` — workflow skills (version-cve-precheck, dedup-finding, cve-citation, form-writer, context-handoff, triage-response, incident-response)
- `.codex/skills/` + `.gemini/skills/` — mirrored from Claude (source of truth)
- `automation/` — session lifecycle scripts (init_target.sh, start_session.py, end_session.py, check_vault.py, claim.sh, release.sh)
- `tools/` — scanner seed configs (Nuclei templates, Osmedeus profiles, BBOT presets)
- `_automation/lint_frontmatter.py` — pre-commit frontmatter validation
- `07 - Templates/` — 14 Obsidian templates (Finding, Submission, Target, Pattern, Kanban, etc.)
- `09 - Knowledge Base/` — 3 seed Patterns (IDOR, CORS, OAuth) + Lessons Learned + Wiki Schema
- `01 - Targets/_example/` — full target subfolder tree
- `STRUCTURE.md` — directory tree + naming conventions + frontmatter schema
- `VAULT_QUICK.md` — vault-level quick reference
- `docs/post-clone-checklist.md` — optional setup checklist after cloning

**Positioning:**
- Obsidian is the primary vault interface.
- LLM use is optional; Claude Code, Codex, and Gemini entrypoints are included for users who want them.
- VPS or another isolated runner is recommended for aggressive scanning, but not required for note-taking, templates, or low-risk local validation.
- Users are expected to grow their own private vault from this public seed.
