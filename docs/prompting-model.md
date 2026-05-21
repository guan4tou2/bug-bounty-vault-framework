# Prompting Model

This repository includes public-safe prompt, agent, and skill skeletons. They are designed for authorized security research workflow management, not for unrestricted offensive automation.

## Public vs Private Boundary

Public files may include:

- Role responsibilities.
- Authorized scope checks.
- Workflow gates.
- Evidence quality rules.
- Report structure.
- Knowledge capture prompts.
- Stop conditions.

Private implementation prompts may include:

- Local directory names.
- Private automation command names.
- Organization-specific report formats.
- Program-specific policy notes.
- Private memory, lessons, and workflow preferences.

In short: public files define reusable role behavior; private implementation prompts bind that behavior to local tools, local repositories, and private program rules.

Private prompts must still avoid credentials, raw evidence, tokens, personal session state, and copied platform content that should not be redistributed.

## Public Safety Contract

- No exploit payloads.
- No target-specific hostnames or accounts.
- No evasion cookbook.
- No private vulnerability knowledge base.
- No direct instructions to exceed authorization.
- Every active role starts with a scope guard.
- Every role has Stop conditions.

## Layers

| Layer | Purpose |
|---|---|
| `prompts/` | Source role prompts that are model-agnostic. |
| `agents/` | Tool-neutral agent cards that can be adapted into a runtime. |
| `skills/` | Skill skeletons for workflow adapters. |
| Private runtime | The place where tool-specific commands and local paths are added. |

## Adaptation Rule

Copy from public to private, then add local details in the private repository only. Do not copy private prompts back into this public skeleton without sanitizing them first.
