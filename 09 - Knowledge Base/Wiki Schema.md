# Knowledge Base Operating Model

The Knowledge Base (KB) stores reusable learnings extracted from bug bounty sessions. Every artifact follows a naming convention and has clear creation criteria.

---

## Artifact Types

| Prefix | Type | When to Create |
|--------|------|----------------|
| `Pattern -` | Attack pattern | When you discover a reusable technique that works across targets |
| `Playbook -` | Step-by-step procedure | When a vuln class needs a documented hunting workflow |
| `Checklist -` | Validation checklist | For pre-flight checks, submission reviews, or recurring audits |
| `Tool -` | Tool notes | When a tool needs config notes, custom flags, or integration docs |
| `Resource -` | External references | Curated links to writeups, advisories, or research papers |
| `Reference Card -` | Quick-reference card | Platform form fields, API schemas, protocol cheat sheets |
| `Skill -` | Agent workflow skill | When a repeatable Claude agent workflow should be formalized |

### Naming Examples

```
Pattern - IDOR via Predictable Object References.md
Playbook - OAuth Misconfiguration Hunting.md
Checklist - Firmware Analysis Pre-flight.md
Tool - Nuclei Custom Templates.md
Resource - SSRF Bypass Techniques.md
Reference Card - HITCON ZeroDay Form.md
Skill - Version CVE Precheck.md
```

## Creation Criteria

Create a new KB artifact when:

1. **Attack technique**: You discover a pattern that would apply to other targets
2. **Decision tree**: A non-obvious triage or analysis decision needs documenting
3. **Attack chain**: A multi-step exploit path is worth preserving as a template
4. **Stop-loss rule**: You learn when to abandon a line of investigation
5. **Gotcha/pitfall**: A mistake or false positive that others should avoid
6. **Checklist**: A recurring verification process needs standardizing

## Graphify Integration

The knowledge graph indexes all KB artifacts and maps relationships between patterns, targets, and findings.

**Three query points:**

1. **Before researching** -- Check if a Pattern or Playbook already exists for your topic
2. **During hunting** -- Look up related attack chains or known pitfalls
3. **Before writing reports** -- Reference existing KB entries for severity justification

**After adding new KB entries:**

- Run graphify to update the knowledge graph
- Use the `sonnet` model for all graphify subagents
- Keep parallel chunk count at 4-5 maximum

## Knowledge Capture Gate

At the end of every session, review your work against the six artifact types above. If any new learnings emerged, create the appropriate KB entry before closing the session.

Questions to ask:

- Did I use a technique that is not yet documented?
- Did I hit a dead end that others should know about?
- Did I chain vulnerabilities in a novel way?
- Did I waste time on something that a checklist could prevent?
- Did a vendor response teach me something about triage?
- Did I configure a tool in a non-obvious way?

If the answer to any question is yes, create the corresponding KB artifact.
