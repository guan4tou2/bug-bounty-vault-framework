---
name: bb-ai-audit
description: Use when auditing an AI / LLM / agentic / MCP product — prompt injection (direct and indirect), system-prompt extraction, AI memory / skills / history endpoints, MCP server security, insecure output handling, tool-calling over-agency. This is the AI-SPECIFIC audit PROCEDURE (platform layer before model layer → 3-layer Impact Gate → OWASP LLM Top 10 mapping), distinct from generic bb-exploit-chain / bb-attack-chain-review. Triggers: AI / LLM / prompt injection / jailbreak / MCP / agent / RAG / AI SaaS / system prompt.
---

# Bug Bounty — AI / LLM / Agentic Audit (AI-product-specific procedure)

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
.claude/skills/bb-ai-audit/SKILL.md
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `.claude/skills/bb-ai-audit/SKILL.md` before acting.
3. Follow the canonical skill exactly, adapting Claude-specific tool names to Gemini tools:
   - Claude `Skill` call -> use `activate_skill` to load the referenced skill, or read the `SKILL.md` directly.
   - Claude subagent instruction -> do the work locally in this Gemini session.
   - `Read` / `Edit` / `Bash` -> Gemini file I/O and shell tools.
4. If the canonical file is unavailable, stop and report that the repo skill mirror is incomplete.

## Maintenance

Do not edit this wrapper by hand. Run:

```bash
python3 automation/sync_codex_skills.py
```
