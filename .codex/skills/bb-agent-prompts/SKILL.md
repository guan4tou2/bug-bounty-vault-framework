---
name: bb-agent-prompts
description: Use when asked to use project Claude agents, agent-team-orchestrator, attack-chain-deep-dive, auto-poc-gen, bbflow-runner, chain-tracker, cve-monitor, cve-pattern-cross-gen, debug-leak-scanner, disclosed-report-researcher, endpoint-interest-scorer, js-sourcemap-miner, lessons-miner, nuclei-template-gen, pre-recon, recon-diff, regression-tester, report-writer, sandbox-replay, skill-synthesizer, submit-form, triage-classifier, vault-sync, web-hunter, or to mirror bug bounty agent behavior in Codex.
---

# Bug Bounty Agent Prompt Router

Codex does not run Claude Code workspace agents natively. This skill makes their prompts discoverable and tells Codex how to use them as canonical role instructions.

## Agent Prompt Map

| Agent | Canonical prompt |
|---|---|
| `agent-team-orchestrator` | `.claude/agents/agent-team-orchestrator.md` |
| `attack-chain-deep-dive` | `.claude/agents/attack-chain-deep-dive.md` |
| `auto-poc-gen` | `.claude/agents/auto-poc-gen.md` |
| `bbflow-runner` | `.claude/agents/bbflow-runner.md` |
| `chain-tracker` | `.claude/agents/chain-tracker.md` |
| `cve-monitor` | `.claude/agents/cve-monitor.md` |
| `cve-pattern-cross-gen` | `.claude/agents/cve-pattern-cross-gen.md` |
| `debug-leak-scanner` | `.claude/agents/debug-leak-scanner.md` |
| `disclosed-report-researcher` | `.claude/agents/disclosed-report-researcher.md` |
| `endpoint-interest-scorer` | `.claude/agents/endpoint-interest-scorer.md` |
| `js-sourcemap-miner` | `.claude/agents/js-sourcemap-miner.md` |
| `lessons-miner` | `.claude/agents/lessons-miner.md` |
| `nuclei-template-gen` | `.claude/agents/nuclei-template-gen.md` |
| `pre-recon` | `.claude/agents/pre-recon.md` |
| `recon-diff` | `.claude/agents/recon-diff.md` |
| `regression-tester` | `.claude/agents/regression-tester.md` |
| `report-writer` | `.claude/agents/report-writer.md` |
| `sandbox-replay` | `.claude/agents/sandbox-replay.md` |
| `skill-synthesizer` | `.claude/agents/skill-synthesizer.md` |
| `submit-form` | `.claude/agents/submit-form.md` |
| `triage-classifier` | `.claude/agents/triage-classifier.md` |
| `vault-sync` | `.claude/agents/vault-sync.md` |
| `web-hunter` | `.claude/agents/web-hunter.md` |

## Required Workflow

1. Match the task to the closest canonical agent prompt.
2. Read the corresponding `.claude/agents/*.md` file.
3. Follow its workflow locally in this Codex session.
4. If the prompt asks for Claude-specific subagents, continue locally unless the user explicitly asks for Codex subagents.
5. Preserve Vault rules from `AGENTS_QUICK.md`, `AGENTS.md`, `CODEX.md`, and `STRUCTURE.md`.

## Trigger Mapping

| User intent | Read |
|---|---|
| run hunters / bbflow / automated scan | `.claude/agents/bbflow-runner.md` |
| start recon / what do we know / pre-recon | `.claude/agents/pre-recon.md` |
| generate form / write report / disclosure draft | `.claude/agents/report-writer.md` |
| session end / sync vault / checklist | `.claude/agents/vault-sync.md` |
| CVSS / severity scoring / vector calculation | `.claude/skills/bb-cvss-score/SKILL.md` (skill, not agent) |
| deep-dive attack chain / chain analysis | `.claude/agents/attack-chain-deep-dive.md` |
