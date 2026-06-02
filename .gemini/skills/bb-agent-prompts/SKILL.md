---
name: bb-agent-prompts
description: Use when asked to use project Claude agents, attack-chain-deep-dive, bbflow-runner, cvss-auto-scorer, pre-recon, report-writer, vault-sync, or to mirror bug bounty agent behavior in Gemini CLI.
---

# Bug Bounty Agent Prompt Router

Gemini CLI does not run Claude Code workspace agents natively. This skill makes their prompts discoverable and tells Gemini how to use them as canonical role instructions.

## Agent Prompt Map

| Agent | Canonical prompt |
|---|---|
| `attack-chain-deep-dive` | `.claude/agents/attack-chain-deep-dive.md` |
| `bbflow-runner` | `.claude/agents/bbflow-runner.md` |
| `cvss-auto-scorer` | `.claude/agents/cvss-auto-scorer.md` |
| `pre-recon` | `.claude/agents/pre-recon.md` |
| `report-writer` | `.claude/agents/report-writer.md` |
| `vault-sync` | `.claude/agents/vault-sync.md` |

## Required Workflow

1. Match the task to the closest canonical agent prompt.
2. Read the corresponding `.claude/agents/*.md` file.
3. Follow its workflow locally in this Gemini session.
4. If the prompt asks for Claude-specific subagents, continue locally unless the user explicitly asks for separate agents.
5. Preserve Vault rules from `AGENTS_QUICK.md`, `AGENTS.md`, `GEMINI.md`, and `STRUCTURE.md`.

## Trigger Mapping

| User intent | Read |
|---|---|
| run hunters / bbflow / automated scan | `.claude/agents/bbflow-runner.md` |
| start recon / what do we know / pre-recon | `.claude/agents/pre-recon.md` |
| generate form / write report / disclosure draft | `.claude/agents/report-writer.md` |
| session end / sync vault / checklist | `.claude/agents/vault-sync.md` |
| CVSS / severity scoring / vector calculation | `.claude/agents/cvss-auto-scorer.md` |
| deep-dive attack chain / chain analysis | `.claude/agents/attack-chain-deep-dive.md` |
