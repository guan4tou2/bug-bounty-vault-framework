# Bug Bounty Vault Framework

An Obsidian-based vault system for organizing authorized security research — from recon through disclosure.

Clone, open in Obsidian, and start hunting. No target data, no findings, no secrets included.

This repository is a **public seed** for building your own private vault: start from the framework, collect your own target notes and lessons, and let it become a **self-updating private vault** over time.

## What This Is

- An **Obsidian vault as the top-level control plane** — not a flat file tree
- A complete **Finding → Submission → FORM** pipeline with templates and frontmatter schema
- **Session lifecycle management** with claim/release concurrency control
- **LLM agent integration** for Claude Code, Codex CLI, and Gemini CLI
- **Scanner config seeds** for Nuclei, Osmedeus, and BBOT (bring your own tools)
- A **Knowledge Base** framework for cross-target pattern capture
- A **workspace scaffold** for local-only operational data (.gitignored)

## What This Is Not

- Not a vulnerability database or scan toolkit
- Not a collection of private bug bounty reports
- Not a runtime workspace — real data stays local and .gitignored

## Repository Layout

```
bug-bounty-vault/                     ← Obsidian Vault root + Git repo
│
├── 00 - Dashboard/                   ← Dataview dashboards, Kanban boards
├── 01 - Targets/                     ← One subfolder per target
│   └── _example/                     ← Example target structure
├── 01 - Dorks/                       ← Google dork collections
├── 05 - Tools/                       ← Vault-level tool notes, not runtime tooling
├── 07 - Templates/                   ← Obsidian templates (Templater)
├── 09 - Knowledge Base/              ← Patterns, Playbooks, Lessons Learned
├── 10 - Meta/                        ← Workspace meta notes
│
├── .claude/agents/                   ← Specialized Claude Code agents
├── .claude/skills/                   ← Claude Code skills (source of truth)
├── .codex/skills/                    ← Codex CLI skill mirrors
├── .gemini/skills/                   ← Gemini CLI skill mirrors
│
├── automation/                       ← Session lifecycle scripts
├── _automation/                      ← Pre-commit hooks
├── tools/                            ← Scanner configs (Nuclei, Osmedeus, BBOT)
├── bbflow/                           ← Automation framework contract
├── docs/                             ← Workflow documentation
├── templates/                        ← Non-Obsidian templates (handoff, op-log)
│
├── workspace/                        ← .gitignored local scratch
│   ├── workshop/<target>/            ← Per-target: SCOPE, RECON_DB, HANDOFF, poc/
│   ├── reports/<platform>/           ← Platform submission copies
│   ├── firmware_analysis/            ← Firmware unpacking workspace
│   └── logs/                         ← Audit logs
│
├── AGENTS.md                         ← Full workflow specification
├── AGENTS_QUICK.md                   ← Token-light quick reference
├── STRUCTURE.md                      ← Directory tree + naming + frontmatter schema
├── CLAUDE.md                         ← Claude Code entrypoint
├── CODEX.md                          ← Codex CLI entrypoint
└── GEMINI.md                         ← Gemini CLI entrypoint
```

## Quick Start

```bash
# 1. Clone
git clone https://github.com/guan4tou2/bug-bounty-vault-framework.git
cd bug-bounty-vault-framework

# 2. Set up workspace (creates .gitignored local dirs)
bash automation/setup_workspace.sh

# 3. Initialize a target
bash automation/init_target.sh my-target

# 4. Open in Obsidian — point Obsidian at the repo root
```

For optional setup choices after cloning, see [docs/post-clone-checklist.md](docs/post-clone-checklist.md).

## Session Lifecycle

```bash
# Start session — claim scope to prevent parallel conflicts
python3 automation/start_session.py my-target

# ... do your work ...

# End session — checklist + release
python3 automation/end_session.py my-target
```

See [docs/session-lifecycle.md](docs/session-lifecycle.md) for the full protocol.

## Finding Pipeline

Every confirmed vulnerability follows:

```
Finding → Submission → FORM
```

All three share the same `finding_id`. Templates in `07 - Templates/` provide the frontmatter schema. See AGENTS.md §3 for the full specification.

## LLM Integration

LLM use is optional. The vault works as plain Markdown + Obsidian, and also includes optional entrypoints for three LLM CLI tools:

| Tool | Entrypoint | Skills |
|------|-----------|--------|
| **Claude Code** | `CLAUDE.md` → `.claude/skills/` + `.claude/agents/` | 7 skills + 5 agents |
| **Codex CLI** | `CODEX.md` → `.codex/skills/` | Mirrored from Claude |
| **Gemini CLI** | `GEMINI.md` → `.gemini/skills/` | Mirrored from Claude |

Choose Claude Code, Codex, Gemini, another assistant, or no LLM. The workflow documents are written so the vault can still be operated manually.

Skills: version-cve-precheck, dedup-finding, cve-citation, hitcon-form, context-handoff, triage-response, incident-response.

Agents: bbflow-runner, cvss-auto-scorer, pre-recon, submit-form, vault-sync.

## Knowledge Base

The `09 - Knowledge Base/` folder holds cross-target reusable knowledge:

- **Pattern** — Attack techniques (IDOR, CORS, OAuth, etc.)
- **Playbook** — Step-by-step workflows
- **Checklist** — Verification checklists
- **Lessons Learned** — What worked, what didn't

Three seed patterns are included. Add your own as you learn.

## Scanner Configs

Basic configurations in `tools/`:

- `tools/nuclei/templates/` — Custom Nuclei templates
- `tools/osmedeus/profiles/` — Osmedeus scan profiles
- `tools/bbot/presets/` — BBOT presets

These are starting points — customize for your workflow.

## Core Principles

| Principle | Summary |
|-----------|---------|
| **GET-first** | Never send POST/PUT/DELETE without understanding consequences |
| **Anti-exaggeration** | Theoretical chains must not be written as accomplished facts |
| **Dedup gate** | Read FINDINGS_QUICK_REF before creating any new Finding |
| **Isolated runner** | VPS or another isolated runner is recommended for aggressive or long-running scans |
| **KB capture** | Promote reusable lessons after every session |

## License

MIT — see [LICENSE](LICENSE).
