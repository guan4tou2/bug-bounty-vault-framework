# Adoption Model

This repository is a seed framework and starter kit. It is not a runtime workspace.

## Boundary

The fork-or-copy boundary is the moment an adopter creates their private vault or private operational repository.

After that point:

- Runtime notes are owned by the adopter.
- Private knowledge is owned by the adopter.
- Automation implementations are owned by the adopter.
- Tool output is owned by the adopter.
- Evidence, reports, logs, and queue state are owned by the adopter.

Those artifacts do not need to sync back to this public repository.

## Public Repository Responsibilities

This public repository maintains:

- Generic architecture.
- Empty templates.
- Public-safe prompts, agents, and skill skeletons.
- Obsidian preset defaults.
- A framework-only automation contract.
- Verifiers for this public skeleton.

## Private Runtime Responsibilities

The private runtime maintains:

- Real scope.
- Real target notes.
- Real review notes.
- Private knowledge base updates.
- Tooling decisions.
- Any downstream disclosure or case-management workflow.

## Do Not Sync Back

Rule of thumb: do not sync back anything created during private runtime use.

Do not sync back runtime data, private lessons, tool output, evidence, screenshots, platform-specific templates, or program-specific workflow changes.

If a private workflow improvement is broadly useful, first abstract it into a generic checklist, prompt, template, or documentation update. Then review it with the public safety verifier before proposing it here.
