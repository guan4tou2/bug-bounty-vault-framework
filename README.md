# Bug Bounty Vault Framework

An architecture-only public framework for organizing authorized security research work.

No target data, no findings, no private knowledge base, no raw scan output, and no operational secrets are included.

## Purpose

This repository provides a clean starting structure for teams or individuals who want a repeatable workflow around:

- Vault: canonical notes, decisions, review-ready summaries, and learning loops.
- Workspace: external scratch space for raw artifacts.
- Automation: lightweight checks that keep the structure clean.
- LLM Wiki: reusable process knowledge, not private target intelligence.
- bbflow: a simple framework layer for optional automation, not a scanner bundle.

## What This Is

- A public architecture and process skeleton.
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

## Repository Layout

```text
docs/       Architecture, workflow, SOP, public safety, and fresh-start notes
templates/  Empty placeholder templates for a new private vault
prompts/    Public-safe role prompts for authorized workflow steps
agents/     Tool-neutral agent cards derived from the prompt model
skills/     Generic skill skeletons for workflow adapters
bbflow/     Framework-only automation flow, scope guard, and output contract
scripts/    Public-safety verifier
tests/      Contract tests for the skeleton
```

## Quick Start

```bash
python3 scripts/verify_public_skeleton.py
python3 -m pytest tests/test_public_skeleton.py -q
```

Then copy the templates into a private vault and keep operational data in a separate ignored workspace.

## How to Use This Framework

1. Clone this repository as a clean reference skeleton.
2. Read `docs/fresh-start.md` to create a private working vault from the templates.
3. Read `docs/architecture.md` and `docs/workflow.md` before adding real program notes.
4. Read `docs/prompting-model.md` before copying prompt, agent, or skill skeletons into a private runtime.
5. Keep real target data, evidence, logs, screenshots, credentials, and scan output outside this public repository.
6. Run `python3 scripts/verify_public_skeleton.py` before publishing any fork or derivative skeleton.

## Obsidian Setup

Open the private vault folder in Obsidian after you copy the templates. This repository includes a generic `.obsidian/` preset with core plugin settings and community plugin IDs. Recommended core and community plugins are listed in `docs/obsidian-setup.md`.

## Core Principle

Keep this repository public and generic. Put all real program data, target data, evidence, credentials, scan output, and private knowledge in a separate private environment.
