#!/usr/bin/env python3
"""Generate Codex and Gemini skill wrappers from canonical Claude workspace skills."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLAUDE_SKILLS = ROOT / ".claude" / "skills"
CLAUDE_AGENTS = ROOT / ".claude" / "agents"
CODEX_SKILLS = ROOT / ".codex" / "skills"
GEMINI_SKILLS = ROOT / ".gemini" / "skills"


def parse_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError(f"{path} missing YAML frontmatter")
    end = lines.index("---", 1)
    data: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip():
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"')
    return data, "\n".join(lines[end + 1 :]).strip()


def claude_skill_dirs() -> list[Path]:
    return sorted(path for path in CLAUDE_SKILLS.iterdir() if (path / "SKILL.md").exists())


def claude_agent_files() -> list[Path]:
    return sorted(CLAUDE_AGENTS.glob("*.md"))


def skill_wrapper(name: str, description: str, title: str) -> str:
    canonical = f".claude/skills/{name}/SKILL.md"
    return f"""---
name: {name}
description: {description}
---

# {title or name}

This is a Codex compatibility wrapper. The canonical workspace skill remains:

```text
{canonical}
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `CODEX.md`, and `.claude/skills/`.
2. Read `{canonical}` before acting.
3. Follow the canonical skill exactly, adapting Claude-specific tool names to Codex tools:
   - Claude `Skill` call -> read the referenced `SKILL.md`.
   - Claude subagent instruction -> do the work locally unless the user explicitly requests Codex subagents.
   - `Read` / `Edit` / `Bash` -> Codex file tools and shell.
4. If the canonical file is unavailable, stop and report that the repo skill mirror is incomplete.

## Maintenance

Do not edit this wrapper by hand. Run:

```bash
python3 automation/sync_codex_skills.py
```
"""


def gemini_skill_wrapper(name: str, description: str, title: str) -> str:
    canonical = f".claude/skills/{name}/SKILL.md"
    return f"""---
name: {name}
description: {description}
---

# {title or name}

This is a Gemini CLI compatibility wrapper. The canonical workspace skill remains:

```text
{canonical}
```

## Required Workflow

1. Locate the Vault root: current working directory should contain `AGENTS.md`, `GEMINI.md`, and `.claude/skills/`.
2. Read `{canonical}` before acting.
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
"""


def gemini_agent_router() -> str:
    rows = []
    for agent in claude_agent_files():
        name = agent.stem
        rows.append(f"| `{name}` | `.claude/agents/{agent.name}` |")
    table = "\n".join(rows)
    agent_names = [a.stem for a in claude_agent_files()]
    agent_list = ", ".join(agent_names)
    return f"""---
name: bb-agent-prompts
description: Use when asked to use project Claude agents, {agent_list}, or to mirror bug bounty agent behavior in Gemini CLI.
---

# Bug Bounty Agent Prompt Router

Gemini CLI does not run Claude Code workspace agents natively. This skill makes their prompts discoverable and tells Gemini how to use them as canonical role instructions.

## Agent Prompt Map

| Agent | Canonical prompt |
|---|---|
{table}

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
| CVSS / severity scoring / vector calculation | `.claude/skills/bb-cvss-score/SKILL.md` (skill, not agent) |
| deep-dive attack chain / chain analysis | `.claude/agents/attack-chain-deep-dive.md` |
"""


def gemini_readme(skill_names: list[str]) -> str:
    rows = "\n".join(f"| `{name}` | `.gemini/skills/{name}/SKILL.md` |" for name in skill_names)
    return f"""# Gemini CLI Skills Mirror

These are Gemini CLI-compatible wrappers for the canonical Claude workspace skills and agent prompts.

Canonical sources:

- `.claude/skills/*/SKILL.md`
- `.claude/agents/*.md`

Generated wrappers:

| Skill | Path |
|---|---|
{rows}

## Install for Gemini CLI

Gemini CLI loads user skills from `~/.gemini/skills`. To link these repo wrappers into the local Gemini skill directory:

```bash
bash automation/install_gemini_skills.sh
```

To verify without writing:

```bash
python3 automation/sync_codex_skills.py --check
bash automation/install_gemini_skills.sh --check
```

Do not edit generated wrappers by hand. Update `.claude/skills` or `.claude/agents`, then run:

```bash
python3 automation/sync_codex_skills.py
```
"""


def agent_router() -> str:
    rows = []
    for agent in claude_agent_files():
        name = agent.stem
        rows.append(f"| `{name}` | `.claude/agents/{agent.name}` |")
    table = "\n".join(rows)
    agent_list = ", ".join(a.stem for a in claude_agent_files())
    return f"""---
name: bb-agent-prompts
description: Use when asked to use project Claude agents, {agent_list}, or to mirror bug bounty agent behavior in Codex.
---

# Bug Bounty Agent Prompt Router

Codex does not run Claude Code workspace agents natively. This skill makes their prompts discoverable and tells Codex how to use them as canonical role instructions.

## Agent Prompt Map

| Agent | Canonical prompt |
|---|---|
{table}

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
"""


def readme(skill_names: list[str]) -> str:
    rows = "\n".join(f"| `{name}` | `.codex/skills/{name}/SKILL.md` |" for name in skill_names)
    return f"""# Codex Skills Mirror

These are Codex-compatible wrappers for the canonical Claude workspace skills and agent prompts.

Canonical sources:

- `.claude/skills/*/SKILL.md`
- `.claude/agents/*.md`

Generated wrappers:

| Skill | Path |
|---|---|
{rows}

## Install for Codex

Codex loads user skills from `~/.codex/skills`. To link these repo wrappers into the local Codex skill directory:

```bash
bash automation/install_codex_skills.sh
```

To verify without writing:

```bash
python3 automation/sync_codex_skills.py --check
bash automation/install_codex_skills.sh --check
```

Do not edit generated wrappers by hand. Update `.claude/skills` or `.claude/agents`, then run:

```bash
python3 automation/sync_codex_skills.py
```
"""


def generated_files() -> dict[Path, str]:
    files: dict[Path, str] = {}
    codex_names: list[str] = []
    gemini_names: list[str] = []
    for skill_dir in claude_skill_dirs():
        meta, body = parse_frontmatter(skill_dir / "SKILL.md")
        name = meta["name"]
        description = meta["description"]
        title = ""
        for line in body.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        codex_names.append(name)
        gemini_names.append(name)
        files[CODEX_SKILLS / name / "SKILL.md"] = skill_wrapper(name, description, title)
        files[GEMINI_SKILLS / name / "SKILL.md"] = gemini_skill_wrapper(name, description, title)

    codex_names.append("bb-agent-prompts")
    gemini_names.append("bb-agent-prompts")
    files[CODEX_SKILLS / "bb-agent-prompts" / "SKILL.md"] = agent_router()
    files[CODEX_SKILLS / "README.md"] = readme(sorted(codex_names))
    files[GEMINI_SKILLS / "bb-agent-prompts" / "SKILL.md"] = gemini_agent_router()
    files[GEMINI_SKILLS / "README.md"] = gemini_readme(sorted(gemini_names))
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="exit non-zero when generated files are stale")
    args = parser.parse_args()

    files = generated_files()
    if args.check:
        stale = []
        for path, content in files.items():
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != content:
                stale.append(path.relative_to(ROOT))
        if stale:
            for path in stale:
                print(f"[stale] {path}")
            return 1
        print("[ok] codex skill wrappers are up to date")
        return 0

    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"[ok] wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
