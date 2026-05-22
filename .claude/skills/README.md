# Workspace Skills Registry

This registry keeps Claude workspace skills discoverable and reviewable. Each skill lives in `.claude/skills/<name>/SKILL.md`, uses search-optimized frontmatter, and is referenced from `CLAUDE.md`.

| Skill | Trigger | Path |
|---|---|---|
| `bb-version-cve-precheck` | Software / firmware / SaaS analysis before hands-on work; latest version and CVE/advisory pre-checks | `.claude/skills/bb-version-cve-precheck/SKILL.md` |
| `bb-dedup-finding` | Opening a new Finding/FORM or deciding whether evidence is a duplicate | `.claude/skills/bb-dedup-finding/SKILL.md` |
| `bb-cve-citation` | Writing CVE, NVD, GHSA, vendor advisory, disclosed report, or prior disclosure references | `.claude/skills/bb-cve-citation/SKILL.md` |
| `bb-hitcon-form` | Creating or editing HITCON ZeroDay FORM files and field formatting | `.claude/skills/bb-hitcon-form/SKILL.md` |
| `bb-context-handoff` | Context-low checkpoint, handoff, takeover, or long-session continuation | `.claude/skills/bb-context-handoff/SKILL.md` |
| `bb-triage-response` | Accepted / Duplicate / N/A / Informative / Triaged / Resolved platform replies | `.claude/skills/bb-triage-response/SKILL.md` |
| `bb-incident-response` | Sustained 5xx, service impact, vendor downtime notice, or unintended impact | `.claude/skills/bb-incident-response/SKILL.md` |

## Maintenance

- Keep frontmatter to exactly `name` and `description`.
- Make `description` start with `Use when` and describe triggers only.
- Add the skill to this registry and `CLAUDE.md` in the same change.
- Verify with `pytest tests/test_workspace_skills.py -q`.
