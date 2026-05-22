# Bug Bounty Vault Framework

An architecture-only public starter kit for organizing authorized security research work.

No target data, no findings, no private knowledge base, no raw scan output, and no operational secrets are included.

## Purpose

This repository is a seed framework. It provides a clean starting structure for teams or individuals who want a repeatable workflow around:

- Vault: canonical notes, decisions, review-ready summaries, and learning loops.
- Workspace: external scratch space for raw artifacts.
- Automation: lightweight checks that keep the structure clean.
- LLM Wiki: reusable process knowledge, not private target intelligence.
- bbflow: a simple framework layer for optional automation, not a scanner bundle.

## What This Is

- A public architecture and process skeleton.
- A starter kit for creating a separate private vault.
- A documentation-first operating model.
- A set of empty templates for targets, recon notes, findings, and review notes.
- A safety contract for keeping raw operational data out of git.
- Public-safe prompt, agent, and skill skeletons for authorized workflows.
- A self-learning knowledge workflow that users fill with their own sanitized lessons.

## What This Is Not

- It is not a vulnerability database.
- It is not a scan toolkit.
- It is not a collection of private bug bounty reports.
- It is not a knowledge base with target-specific techniques or evidence.
- It is not an external disclosure workflow template.
- It is not a runtime workspace.

## Repository Layout

```text
docs/       Architecture, workflow, SOP, public safety, and fresh-start notes
AGENTS.md   Public-safe LLM entrypoint shared by Claude, Codex, Gemini, and other agents
templates/  Empty placeholder templates for a new private vault
prompts/    Public-safe role prompts for authorized workflow steps
agents/     Tool-neutral agent cards derived from the prompt model
skills/     Generic skill skeletons for workflow adapters
hooks/      Public-safe hook skeletons for private runtime guardrails
bbflow/     Framework-only automation flow, scope guard, and output contract
scripts/    Generic bootstrap, note generation, scope validation, and public-safety verifier
workspace/  Vault-root runtime scaffold; contents stay ignored after adoption
tests/      Contract tests for the skeleton
```

## Quick Start

```bash
python3 scripts/verify_public_skeleton.py
python3 scripts/validate_scope_file.py bbflow/scope.example.yaml
python3 scripts/start_session.py --target sample-target --program sample-program --scope-file bbflow/scope.example.yaml
python3 scripts/end_session.py --target sample-target --summary "framework dry run" --knowledge-capture "none"
python3 scripts/check_vault.py
python3 -m pytest tests/test_public_skeleton.py -q
```

Then bootstrap a private vault, or use this repository as a template:

```bash
python3 scripts/bootstrap_private_vault.py ../my-private-vault
python3 scripts/new_note.py --type target --target sample-target --program sample-program
```

The private vault is an Obsidian vault root. Its `workspace/` folder is the ignored runtime workspace where bbflow, logs, reports, and temporary artifacts can live.

## How to Use This Framework

1. Clone this repository as a clean reference skeleton.
2. Read `docs/fresh-start.md` to create a private working vault from the templates or run `scripts/bootstrap_private_vault.py`.
3. Read `docs/adoption-model.md` to understand where this public repo ends and your private runtime begins.
4. Read `docs/architecture.md` and `docs/workflow.md` before adding real program notes.
5. Read `docs/session-lifecycle.md` before using `start_session.py` and `end_session.py`.
6. Read `docs/prompting-model.md` before copying prompt, agent, or skill skeletons into a private runtime.
7. Keep real target data, evidence, logs, screenshots, credentials, and scan output outside this public repository.
8. Run `python3 scripts/verify_public_skeleton.py` before publishing any fork or derivative skeleton.

## Obsidian Setup

Open the private vault folder in Obsidian after you copy the templates. This repository includes a generic `.obsidian/` preset with core plugin settings and community plugin IDs. Recommended core and community plugins are listed in `docs/obsidian-setup.md`.

## Core Principle

Keep this repository public and generic. It is a starter kit, not a runtime workspace. Put all real program data, target data, evidence, credentials, scan output, and private knowledge in a separate private environment.
