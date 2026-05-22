# LLM Wiki Framework

The LLM Wiki stores reusable process knowledge in the Obsidian Vault's Knowledge Base layer. The LLM Wiki is not the whole Obsidian vault — it covers only the generic, reusable knowledge portion.

## Allowed Note Types

| Type | Purpose |
|---|---|
| Pattern | Generic recurring behavior or testing shape |
| Playbook | Multi-step process for a class of work |
| Reference Card | Short operational rule or decision aid |
| Checklist | Repeatable verification list |
| Tool | Generic tool usage guidance |
| Resource | Public reference list |

## Relationship to the Obsidian Vault

The full vault has these layers:

| Folder | Layer | LLM Wiki? |
|--------|-------|-----------|
| `00 - Dashboard` | Dashboards, Kanban, status views | No — Current state, not reusable knowledge |
| `01 - Targets` | Per-target findings, submissions, recon | No — target-specific |
| `05 - Tools` | Vault-level tool notes and configuration rationale | Shared — Tool-specific learning, not runtime output |
| `07 - Templates` | Templates for Findings, Submissions, and frontmatter scaffolds | Shared — Templates implement note creation |
| `09 - Knowledge Base` | Patterns, Playbooks, Checklists, Lessons | **Yes — this is the LLM Wiki** |
| `10 - Meta` | Meta notes, fileClasses, plans, snapshots | No — operational structure |

## Source of Truth

The LLM Wiki is a source of truth for generic process knowledge, not for target counts, live queue status, or raw evidence.

Use `00 - Dashboard/` or generated indexes for current state, `01 - Targets/` for entity records, `05 - Tools/` for durable tool notes, `07 - Templates/` for creation shape, and `10 - Meta/` for structural state. Runtime scanner output stays in ignored workspace paths. Treat historical status notes as a historical status log.

## Update Rules

1. Add a new note under an approved type.
2. Link it from the index.
3. Add related notes.
4. Remove private details before publishing.
5. Rebuild or refresh any search index if your private implementation has one.

## Sanitization Rules

- Replace real domains with `example.com`.
- Replace target names with `<target>`.
- Replace platform names with `<program>`.
- Remove credentials, tokens, cookies, internal paths, and screenshots.
- Convert raw evidence into generic reproduction shape.
