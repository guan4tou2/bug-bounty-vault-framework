# Vault Quick Reference

Quick path reference for the Bug Bounty Vault. Use this to find where things go.

---

## File Locations

| What | Path |
|------|------|
| Target hub | `01 - Targets/<target>/Target - <target>.md` |
| Findings | `01 - Targets/<target>/Findings/Finding - <target> - <ID>.md` |
| Submissions | `01 - Targets/<target>/Submissions/Submission - <target> - <ID>.md` |
| Forms | `01 - Targets/<target>/Submissions/Forms/FORM - <platform> - <ID>.md` |
| Attempts | `01 - Targets/<target>/Attempts/Attempt - <target> - <slug>.md` |
| Recon notes | `01 - Targets/<target>/Recon/Recon - <target> - <topic>.md` |
| Attack chains | `01 - Targets/<target>/Attack Chains/` |
| Services | `01 - Targets/<target>/Services/` |
| Screenshots | `01 - Targets/<target>/Screenshots/` |

## Knowledge Base Prefixes

Files in `09 - Knowledge Base/` use these naming prefixes:

| Prefix | Purpose |
|--------|---------|
| `Pattern -` | Reusable attack patterns and techniques |
| `Playbook -` | Step-by-step procedures for specific vuln classes |
| `Checklist -` | Pre-flight and validation checklists |
| `Tool -` | Tool configuration and usage notes |
| `Resource -` | External references, curated link collections |
| `Reference Card -` | Quick-reference cards for platforms, APIs, protocols |
| `Skill -` | Workflow skills (Claude agent integration) |

## Frontmatter Requirements

### Finding (required fields)

```yaml
---
fileClass: Finding
finding_id: "<TARGET>-<NNN>"
target: "<target>"
host: "affected.host.com"
severity: "Critical | High | Medium | Low | Informational"
status: "draft | verified | submitted | accepted | duplicate | n-a | fixed"
verified_evidence: "live | source_code | static | theoretical"
created: "YYYY-MM-DD"
---
```

### Submission (required fields)

```yaml
---
fileClass: Submission
finding_id: "<TARGET>-<NNN>"
platform: "hitcon | h1 | bugcrowd | intigriti | twcert"
status: "draft | ready | submitted | triaged | resolved | duplicate | n-a"
submitted_date: "YYYY-MM-DD"
---
```

### FORM (required fields)

```yaml
---
fileClass: Form
finding_id: "<TARGET>-<NNN>"
platform: "hitcon | h1 | bugcrowd | intigriti | twcert"
case_id: ""
status: "draft | ready | submitted"
---
```

## Finding Pipeline

Every vulnerability follows a three-document pipeline with a shared `finding_id`:

1. **Finding** -- Technical analysis, root cause, impact, PoC
2. **Submission** -- Platform-formatted report ready for submission
3. **FORM** -- Final form fields matching the target platform

The `finding_id` (e.g., `ACME-001`) links all three documents together.

## Graphify Integration

The knowledge graph (`graphify`) indexes KB artifacts and finding relationships.

- **Query before creating**: check if a Pattern or Playbook already covers your topic
- **Update after adding**: run graphify after adding new KB entries to keep the graph current
- **Use `sonnet` model**: all graphify subagents must use the sonnet model

## Templates

Starter templates are in `07 - Templates/` and `templates/`. Copy a template when creating a new Finding, Submission, or FORM to ensure correct frontmatter and section structure.
