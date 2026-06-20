# Golden Rules — harness invariants (single source of truth)

> Harness-engineering pillar: *encode the golden rules in the repo, enforce them mechanically.*
> These invariants must always hold for the public framework. Each is checked by
> `bash automation/check_harness_invariants.sh` (run before any structural change /
> at session end). Edit a rule here → update its enforcer in the same change.

## Skills
- **S1** Every canonical skill is `.claude/skills/bb-*/SKILL.md` with frontmatter of exactly `name` + `description`, `description` starting with `Use when`. → `tests/test_public_skeleton.py`
- **S2** Every expected skill exists and is listed in `.claude/skills/README.md` + the `CLAUDE.md` skill table. → `tests/test_public_skeleton.py::test_claude_skills_exist`
- **S3** `.codex/` and `.gemini/` are generated mirrors — supersets (+ the `bb-agent-prompts` router), never hand-edited; regenerate with `automation/sync_codex_skills.py`. → `test_codex_skills_mirror_claude` + `sync_codex_skills.py --check`
- **S4** Counts agree: `# bb-* skill dirs` == `# rows in skills/README` == `# rows in CLAUDE.md skill table`. → `check_harness_invariants.sh`

## Agents
- **A1** Every expected agent exists; CVSS scoring is the `bb-cvss-score` skill, not an agent; `submit-form` is not in the public seed (use `report-writer`). → `tests/test_public_skeleton.py::test_claude_agents_exist`
- **A2** No agent carries a `model:` pin unless a specific tier is required (deep reasoning inherits the strong default). → review

## Flow / gates
- **F1** Surface-map before scan: `bbflow hunt <t>` / `hunt-*.sh <t>` blocked when the target RECON_DB has Discovered Paths but an empty Attack Surface Map. → `automation/surface_map_gate.sh` (PreToolUse); override `BB_SKIP_SURFACE_GATE=1`
- **F2** Lifecycle hooks present: Stop (close-out reminder) + SessionStart (claim/dedup). → `.claude/settings.json`
- **F4** Static-only mode: when `automation/.static_only` exists (or `BB_STATIC_ONLY=1`), live/network Bash actions (scanners, hunt/flow/recon, outbound curl/wget) are blocked — for source/static audits where no live traffic is wanted. Per-command override `BB_ALLOW_LIVE=1`. → `automation/static_only_gate.sh` (PreToolUse Bash) + `check_harness_invariants.sh` (F4)

## Public-seed boundary (the framework's reason to exist)
- **R1** `tools/nuclei/templates/` are shape-only examples — NO live payloads (real paths, secrets, exploit variants). Real templates live in `guan4tou2/bbflow`. → `tests/test_public_skeleton.py::test_nuclei_templates_are_shape_only_no_live_payloads`
- **R2** Platform-neutral only: no named-bounty/CVD-platform-specific report content or field mappings anywhere in the repo; generic `bb-form-writer` + `report-writer` only. → `test_public_framework_uses_platform_neutral_report_writing` (it greps the whole repo for forbidden platform tokens — including this file, so do not name platforms here)
- **R3** Public/private boundary documented; generic methodology flows private→public after sanitization, never operational data. → `docs/public-vs-private.md`

## Loop-health checks (capability — advisory, run at the right moment)
Heuristic reports that strengthen the three core loops (LLM judges; not hard gates):
- **Hunting** — `automation/check_pattern_coverage.sh`: KB Patterns lacking a bbflow hunter/template → expansion backlog (skips gracefully if bbflow isn't installed).
- **Templating** — `automation/check_report_quality.sh <FORM>`: anti-exaggeration + no-internal-IDs (hard) + impact/PoC/severity (warn). Run before every submission (also via `bb-submission-readiness`).
- **Knowledge** — `automation/check_kb_health.sh`: lessons-index completeness, orphan patterns, near-duplicate titles, Pattern-Index membership → merge/cleanup backlog.
- **Tooling** — `automation/check_orphan_scripts.sh`: skills/agents have invariants forcing them wired; the `automation/` layer doesn't, so this flags scripts with zero references from any real consumer (corpus excludes the README index; manual utils allowlisted).
- **Learning-capture** — `automation/check_learning_capture.sh`: correlates Finding/Attempt/Submission activity vs KB capture (Lesson/Pattern/Playbook) over a commit window; activity>0 & capture==0 → flags forgotten backfill, proportional to activity.
- **Hunter quality** — `automation/check_hunter_quality.sh`: aggregates the hunter-report corpus into per-hunter hit-rate + yield; flags dead-weight (≥N runs, 0 hits) and noisy (mass FP-prone output) hunters for tuning/retirement in the standalone tool repo (advisory; a miss may be environmental).

## How to use
- Before a structural change / at session end: `bash automation/check_harness_invariants.sh`
- A failure prints the exact fix. Fix, re-run, then commit.
- New rule? Add it here AND its enforcer (a `test_public_skeleton.py` test or a check in `check_harness_invariants.sh`) in the same commit — a rule with no enforcer is decoration.
