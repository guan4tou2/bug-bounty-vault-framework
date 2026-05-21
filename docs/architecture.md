# Architecture

This project describes a reusable, private-by-default operating model for authorized security research.

## Layers

```text
Vault
  Canonical notes, decisions, report-ready summaries, and reusable process knowledge.

External workspace
  Raw artifacts, scan output, proof-of-concept files, logs, and temporary analysis.

Automation
  Local checks, initialization helpers, linting, and lifecycle validation.

Optional tooling runtime
  Scanner or recon tools that can run independently from the vault.
```

## Design Principles

### Vault as canonical source

The Vault stores durable, curated, report-ready information. It should contain enough context to understand what happened and why, without storing raw operational material.

### External workspace

Raw artifacts belong outside the Vault and outside git. The workspace can be deleted, rotated, encrypted, or rebuilt without corrupting the Vault.

### Automation as control plane

Automation should verify structure, session discipline, template shape, and public-safety boundaries. It should not require private target data.

### Tooling as optional runtime

Tooling can produce machine-readable output, but the framework does not depend on any specific scanner. Tools should be optional and replaceable.

## Source of Truth

| Need | Source |
|---|---|
| Canonical target summary | Private target note |
| Raw evidence | External workspace |
| Report-ready evidence | Finding note |
| Reusable generic process knowledge | LLM Wiki |
| Current queue status | Private dashboard or board |

## Public Boundary

This public repository ends at architecture and workflow. A real deployment should keep private data in a separate private repository or local vault.
