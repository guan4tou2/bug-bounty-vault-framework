---
type: reference-card
tags:
  - knowledge-base
  - quality
  - workflow
created: 2026-05-23
---

# Reference Card - Knowledge Capture Quality Rubric

Use this rubric to decide what goes into the Knowledge Base and at what quality bar.

## Capture Criteria

A finding, attempt, or observation is worth capturing when:

| Criterion | Question |
|-----------|----------|
| Reusability | Could another researcher apply this to a different target? |
| Non-obvious | Would a competent researcher miss this without the note? |
| Decision value | Does it change what you'd do next time? |
| Negative value | Does the failure prevent repeating wasted effort? |

If **any** criterion is met, capture it.

## Destination Routing

| Destination | Use when |
|-------------|----------|
| `Pattern - *.md` | Reusable attack technique or detection logic |
| `Lessons Learned.md` | Decision, pitfall, false positive, triage lesson, stop condition |
| `Checklist - *.md` | Repeatable verification gate |
| `Playbook - *.md` | Multi-step workflow |
| Tool note | Durable tool usage note or configuration rationale |
| bbflow template | Automation can detect or triage the pattern later |
| Attempt note | Main value is a negative result for one target |

## Quality Bar

### Minimum (Lesson entry)

- One sentence describing the insight
- Context: what target class or situation triggers this
- Source: which session or finding produced it

### Standard (Pattern or Checklist)

- Frontmatter with `type:` field
- Description section explaining the technique or check
- At least one concrete example (sanitized)
- Cross-references to related Patterns/Lessons

### High (Playbook)

- Step-by-step procedure
- Decision points with branch conditions
- Tool commands (sanitized)
- Expected outputs at each step
- Known failure modes

## Sanitization Rules

Before promoting to KB:

- Replace real domains with `example.com`
- Replace target names with `<target>`
- Remove credentials, tokens, cookies, internal paths
- Remove screenshots containing PII
- Convert raw evidence into generic reproduction shape

## Anti-Patterns

- Storing reusable learning only in HANDOFF (lost on session end)
- Writing a Pattern that only applies to one target
- Copying raw curl output without explaining the insight
- Skipping capture because "it's obvious" (it won't be in 3 months)

## Cross-References

- `bb-knowledge-capture` skill
- `bb-attempt-recorder` skill
- `AGENTS.md Knowledge Capture Gate`
- `09 - Knowledge Base/Wiki Schema.md`
