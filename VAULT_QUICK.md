# Vault Quick Reference

Quick path reference for the Bug Bounty Vault. Use this to find where things go.

---

## File Locations

| What | Path |
|------|------|
| Target hub | `01 - Targets/<target>/Target - <target>.md` |
| Findings | `01 - Targets/<target>/Findings/Finding - <target> - <ID>.md` |
| Submissions | `01 - Targets/<target>/Submissions/Submission - <target> - <ID>.md` |
| Forms | `01 - Targets/<target>/Submissions/Forms/FORM - <channel> - <ID>.md` |
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

> These mirror the enforced schema in `_automation/lint_frontmatter.py` and `07 - Templates/`. If they ever diverge, the linter and templates win — they are the single source of truth.

### Finding (required fields)

```yaml
---
fileClass: Finding
finding_id: "<TARGET>-<NNN>"
target: "[[Target - <target>]]"
severity: "P1 | P2 | P3 | P4 | P5"
verification_level: "A | B | C | D"
verified_evidence: "live | source_code | static | theoretical"
status: "discovered | verified | ready | submitted | duplicate | na | accepted | fixed | on_hold | killed | withdrawn"
discovered_date: "YYYY-MM-DD"
discovered_time: "HH:MM"
---
```

### Submission (required fields)

```yaml
---
fileClass: Submission
type: submission
finding_id: "<TARGET>-<NNN>"
target: "[[Target - <target>]]"
platform: "<platform>"
severity: "P1 | P2 | P3 | P4 | P5"
status: "ready | submitted | triaged | duplicate | na | accepted | fixed | withdrawn | needs_revalidation | superseded"
---
```

### FORM (required fields)

```yaml
---
fileClass: Form
type: submission
finding_id: "<TARGET>-<NNN>"
target: "[[Target - <target>]]"
platform: "<platform>"
case_id: ""
status: "ready | submitted | withdrawn | duplicate | na | needs_revalidation | superseded"
---
```

## Finding Pipeline

Every vulnerability follows a three-document pipeline with a shared `finding_id`:

1. **Finding** -- Technical analysis, root cause, impact, PoC
2. **Submission** -- Canonical report draft
3. **FORM** -- Platform-neutral form fields for private downstream adaptation

The `finding_id` (e.g., `ACME-001`) links all three documents together.

## Knowledge-Graph Indexing (optional)

If you wire up a knowledge-graph indexer over `09 - Knowledge Base/`, it can map KB artifacts and finding relationships. This is optional and tool-agnostic — the framework does not require any specific indexer.

- **Query before creating**: check if a Pattern or Playbook already covers your topic
- **Update after adding**: re-run your indexer after adding new KB entries to keep it current

## Templates

Starter templates are in `07 - Templates/` and `templates/`. Copy a template when creating a new Finding, Submission, or FORM to ensure correct frontmatter and section structure.
