# LLM Wiki Framework

The LLM Wiki stores reusable process knowledge. It is not a private intelligence database.

## Allowed Note Types

| Type | Purpose |
|---|---|
| Pattern | Generic recurring behavior or testing shape |
| Playbook | Multi-step process for a class of work |
| Reference Card | Short operational rule or decision aid |
| Checklist | Repeatable verification list |
| Tool | Generic tool usage guidance |
| Resource | Public reference list |

## Source of Truth

The LLM Wiki is a source of truth for generic process knowledge, not for target counts, live queue status, or raw evidence.

Use a private dashboard or generated index for current state. Treat historical status notes as a historical status log.

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
