# Architecture

This project describes a reusable, private-by-default operating model for authorized security research.

## Layers

```text
Obsidian Vault Root
  Canonical notes, decisions, review-ready summaries, and reusable process knowledge.

workspace/
  Ignored runtime workspace for raw artifacts, tool output, logs, proof-of-concept files, and temporary analysis.
  This replaces the older External workspace wording while keeping runtime data outside public git.
  In workflow language this is the Workspace layer.

bbflow/
  Framework contract for connecting automation output back into the vault. The public repo includes design and example configs, not scanners.

Automation
  Local checks, initialization helpers, linting, and lifecycle validation.

Optional tooling runtime
  Recon or automation tools that can run independently from the vault.
```

## Architecture Map

```mermaid
flowchart LR
  A["Public Seed"] -->|"clone or use template"| B["Private Vault"]
  B -->|"opens as"| C["Obsidian Vault Root"]
  C -->|"stores canonical notes"| D["Private Knowledge Base"]
  C -->|"contains ignored runtime area"| E["workspace/"]
  C -->|"defines automation contract"| F["bbflow/"]
  G["Optional Automation Runtime"] -->|"writes raw output"| E
  E -->|"reviewed candidates only"| C
  C -->|"Knowledge Capture"| D
  D -->|"improves prompts, templates, checklists"| C
```

## Design Principles

### Vault as canonical source

The Vault stores durable, curated, review-ready information. It should contain enough context to understand what happened and why, without storing raw operational material.

### workspace/

Raw artifacts belong in the ignored `workspace/` scaffold under the Obsidian vault root. The directory exists so the private workflow has one predictable place for runtime state, but its contents are not synced back to the public seed.

### Automation as control plane

Automation should verify structure, session discipline, template shape, and public-safety boundaries. It should not require private target data.

### bbflow as framework contract

The `bbflow/` directory describes how scope, automation output, and knowledge capture connect. Public examples for Nuclei, Osmedeus, and BBOT are configuration shapes only. They provide baseline design language, not operational playbooks.

### Tooling as optional runtime

Tooling can produce machine-readable output, but the framework does not depend on any specific scanner or automation stack. Tools should be optional, replaceable, and filled in by the user after adoption.

## Source of Truth

| Need | Source |
|---|---|
| Canonical target summary | Private target note |
| Raw evidence | `workspace/` runtime directory |
| Review-ready evidence | Finding note |
| Reusable generic process knowledge | LLM Wiki |
| Current queue status | Private dashboard or board |

## Public Boundary

This public repository ends at architecture and workflow. A real deployment should keep private data in a separate private repository or local vault.
