---
name: bb-form-writer
description: Use when creating or editing a platform-neutral disclosure form, submission bundle, report package, or FORM draft from an existing Finding and Submission.
---

# Bug Bounty — Platform-Neutral Form Writer

This public framework intentionally avoids platform-specific form templates. Use this skill to create a generic disclosure-ready FORM draft that a private vault can later adapt to its own downstream channel.

## Preconditions

- A parent Finding exists.
- `bb-dedup-finding` has passed or the duplicate risk is documented.
- `bb-evidence-readiness` says the evidence is ready, or the draft is clearly marked `needs_evidence`.
- `bb-submission-readiness` has run before any final submission package is marked ready.

Do not generate a ready-to-send form directly from an informal user description.

## Output Path

Save generic form drafts under:

```text
01 - Targets/<target>/Submissions/Forms/FORM - Generic - <finding_id>.md
```

If the adopter prefers another platform, they can copy this generic draft into their private platform-specific format.

## Required Sections

```markdown
# Generic Disclosure Form — <finding_id>

## Source
- Finding:
- Submission:
- Evidence folder:

## Routing
- Intended channel:
- Program / policy URL:
- Scope status:
- Contact:

## Title
<One-line vulnerability title>

## Summary
<Plain-language summary>

## Affected Asset
<URL, product, version, or component>

## Vulnerability Type
<Generic class / CWE if known>

## Severity
- Rating:
- CVSS vector:
- Rationale:

## Steps to Reproduce
1.
2.
3.

## Evidence
- Command / request:
- Response summary:
- Screenshot references:
- Artifact references:

## Impact
<Verified impact only. Keep theoretical chains separate.>

## Remediation
<Concrete fix guidance>

## Safety / Scope Notes
- Authorization:
- Rate limits / write effects:
- Data handling:

## Final Checklist
- [ ] No internal tracking IDs in external-facing text
- [ ] No secrets, cookies, tokens, or third-party PII
- [ ] Evidence is reproducible
- [ ] Scope and authorization are documented
- [ ] Submission readiness gate passed
```

## Rules

- Keep the draft platform-neutral.
- Do not include platform-only field names, platform case numbers, or platform vulnerability taxonomies.
- Do not create platform-specific templates in this public seed.
- If a private vault needs a platform integration, keep that adapter private.
- If screenshots are required by the eventual destination, list them as evidence requirements instead of assuming a specific upload flow.

## Cross-References

- `bb-submission-readiness`
- `bb-evidence-readiness`
- `bb-cve-citation`
- `templates/form.md`
- `templates/submission.md`
