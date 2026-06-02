---
type: reference
category: checklist
tags: [checklist, submission, validation]
added: 2026-01-01
---

# Checklist — Pre-Submission Validation

> **Guiding principle:** Prove impact, never claim it. Every severity assertion must be traceable to a specific, reproducible evidence step — not to a theoretical attack chain.

---

## Strategy

Work through the sections below in order. A single unchecked item is a reason to pause and fix before submitting. Triage teams notice the same gaps you skipped. A rejected or downgraded report costs more time than the check that would have caught it.

---

## Dedup Check

- [ ] Read `FINDINGS_QUICK_REF.md` for the target — confirm no existing finding shares the same root cause.
- [ ] Search the program's public disclosure list and Hacktivity for similar vulnerability classes on this endpoint.
- [ ] If a near-duplicate exists, verify the root cause is distinct (different parameter, different auth context, different component) before proceeding.

---

## Scope Confirmation

- [ ] The affected host/endpoint appears on the program's explicit in-scope list.
- [ ] Wildcard scope (`*.example.com`) has been cross-checked against any explicit exclusions (e.g., `corp.example.com` excluded).
- [ ] The vulnerability class is not excluded by the program policy (e.g., "self-XSS", "rate limiting without impact", "missing headers on static assets").

---

## Evidence Completeness

- [ ] At least one full HTTP request (method, path, headers, body) and the corresponding response are captured.
- [ ] Steps to reproduce are written out sequentially — a stranger following them cold should hit the same result.
- [ ] The PoC can be reproduced end-to-end in under 5 minutes from a fresh session.
- [ ] If multiple accounts are required (e.g., IDOR), credentials for both accounts are noted in the private workspace (never in the report body).
- [ ] Screenshots or screen recordings cover the critical moment of impact (e.g., data rendered in the attacker's browser, unauthorized action confirmed).
- [ ] Any time-sensitive state (e.g., a token that expires) is documented with its validity window.

---

## Anti-Exaggeration

- [ ] Every impact statement references a concrete, demonstrated step — not a logical extension.
- [ ] Phrases like "an attacker could," "this may allow," or "in theory" are either removed or accompanied by a verified PoC that demonstrates the path.
- [ ] The worst-case scenario written in the report has been at least partially validated (e.g., PII read, not just "PII could be read").
- [ ] No impact has been elevated based on chaining with unverified or out-of-scope primitives.

---

## Severity Sanity

- [ ] The assigned severity (P-rating or CVSS score) matches the demonstrated impact, not the theoretical maximum.
- [ ] CVSS vector string has been double-checked: Attack Vector, Privileges Required, and User Interaction are realistic for the confirmed exploit path.
- [ ] If the program uses its own severity taxonomy, the chosen tier aligns with their published criteria (re-read the policy page if uncertain).
- [ ] A second opinion has been sought (or a personal sanity check against the [[Lessons Learned]] note) for any Critical/P1 rating.

---

## Report Quality

- [ ] No internal tracking IDs (e.g., PROJ-001, XX-042) appear anywhere in the report body.
- [ ] Vulnerability title is descriptive and accurate: `Unauthenticated IDOR on /api/v2/users/{id} returns full PII` — not `IDOR vulnerability`.
- [ ] The report distinguishes clearly between what was confirmed versus what was inferred.
- [ ] Generic example hostnames (example.com) are not used in place of real target endpoints in the reproduction steps.
- [ ] Sensitive data captured during testing (credentials, PII, tokens) is redacted in screenshots and replaced with `[REDACTED]` in text.

---

## Platform Fit

- [ ] The platform chosen for submission matches the program that owns the affected asset.
- [ ] Submission format (markdown, form fields, attachments) meets the platform's requirements.
- [ ] Any mandatory fields (asset, weakness type, severity, bounty program) are filled out completely.

---

## Final Gate

- [ ] Re-read the full draft report from the perspective of a skeptical triager seeing it cold.
- [ ] Run `python3 automation/check_vault.py` (or equivalent workspace audit) to confirm no linked artifacts are missing.
- [ ] The finding's status in the Kanban board is updated to `Submitted` immediately after sending.

---

## Related

- [[Playbook - Recon]]
- [[Lessons Learned]]
