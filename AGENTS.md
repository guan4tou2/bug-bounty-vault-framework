# Agent Rules

This file is the public-safe shared instruction entrypoint for LLM agents working in this seed framework.

Read AGENTS_QUICK.md first. Then read only the docs needed for the current task.

## Purpose

This repository is an architecture-only Obsidian vault framework for authorized security research workflows.

It provides:

- public-safe workflow rules
- empty templates
- prompt, agent, skill, and hook skeletons
- a `workspace/` runtime scaffold
- a `bbflow/` automation contract

It does not provide target data, private findings, operational logs, scanner output, payloads, evasion guidance, or platform-specific disclosure templates.

## Authorized Scope

Authorized scope is mandatory before any research workflow, automation planning, finding review, report writing, or Knowledge Capture.

Stop if scope is absent, expired, ambiguous, or incompatible with the requested action.

Do not run active automation without a scope file.

## Public-Safe Workflow

1. Confirm the task is framework, documentation, template, or bootstrap work.
2. If the task involves security research workflow, confirm Authorized scope.
3. Use `docs/workflow.md` for the main Target -> Recon -> Finding -> Review -> Knowledge Capture flow.
4. Use templates through scripts/new_note.py instead of inventing new note shapes.
5. Validate scope files with `scripts/validate_scope_file.py`.
6. Keep raw data in `workspace/` and keep runtime contents uncommitted.
7. Run `scripts/verify_public_skeleton.py` before publishing public changes.

## Workspace

`workspace/` is intentionally present under the Obsidian vault root. It is the private runtime scratch area after adoption.

Allowed public contents are only scaffold files. Do not copy private runtime data into this public repository.

## bbflow

`bbflow/` defines a framework-only automation boundary:

- scope guard
- output contract
- Knowledge Capture hook
- example config shapes

It is not a scanner bundle and must not grow hunters, payloads, evasion guidance, or target-specific rules in this public seed.

## Knowledge Capture

Knowledge Capture means promoting reusable, sanitized process knowledge into the LLM Wiki:

- Pattern
- Playbook
- Checklist
- Reference Card

Do not promote raw output, private target names, credentials, account details, or copied report material.

## Verification

Use:

```bash
python3 scripts/verify_public_skeleton.py
python3 -m pytest tests/test_public_skeleton.py -q
```

If a change weakens scope, safety, evidence, public boundary, or Knowledge Capture gates, stop and revise the framework instead of proceeding.

