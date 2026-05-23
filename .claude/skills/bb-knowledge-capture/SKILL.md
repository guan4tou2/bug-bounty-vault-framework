---
name: bb-knowledge-capture
description: Use when a session, finding candidate, failed attempt, attack chain review, tool result, triage reply, or new observation teaches something reusable that should update Pattern, Lessons Learned, Checklist, Tool notes, or bbflow templates.
---

# Bug Bounty — Knowledge Capture

Use this gate as soon as reusable learning appears. Do not wait for session close or context compaction.

## Trigger

Run this when:

- a new technique, bypass, failure mode, chain idea, triage lesson, or tool behavior appears
- `bb-attack-chain-review` identifies a reusable pivot
- `bb-attempt-recorder` records a useful negative result
- a Recon note's Knowledge Capture Gate needs content
- a bbflow / hunter / Nuclei / BBOT / Osmedeus idea should be generalized

## Classification

| Destination | Use when |
|---|---|
| `Pattern - *.md` | Reusable attack technique or detection logic |
| `Lessons Learned.md` | Decision, pitfall, false positive, triage lesson, stop condition |
| `Checklist - *.md` | Repeatable review gate |
| `Playbook - *.md` | Multi-step workflow |
| `05 - Tools/` | Durable tool usage note or configuration rationale |
| bbflow template / hunter idea | Automation can detect or triage the pattern later |
| Attempt note | The main value is a negative result for one target |

## Output Format

```markdown
## Knowledge Capture
- Reusable learning:
- Existing KB coverage:
- Destination:
- New note needed: yes/no
- Pattern / Lesson / Checklist update:
- bbflow update idea:
- Recon note link:
- Done:
```

## Existing Coverage Check

Before saying no new Lesson is needed:

1. Read the closest Pattern / Lesson.
2. Ask whether another agent could reproduce this insight from the existing text.
3. If not, create a new Lesson or update the Pattern.

## Hard Rules

- New concept must become a new Lesson or an explicit Pattern update.
- HANDOFF is not KB; do not store reusable learning only in HANDOFF.
- If context is getting long, write the Recon note and KB delta now.
- Sanitize target-specific secrets, tokens, customer names, and private endpoints before promoting to KB or bbflow.
- Do not update bbflow with target-specific or sensitive data.

## Cross-References

- `AGENTS.md Knowledge Capture Gate`
- `09 - Knowledge Base/Reference Card - Knowledge Capture Quality Rubric.md`
- `09 - Knowledge Base/Wiki Schema.md`
- `bb-attempt-recorder`

