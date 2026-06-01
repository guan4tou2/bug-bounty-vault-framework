# Private Adapter Pattern

This public seed ships a platform-neutral workflow. It gives you a generic Finding, Submission, and generic FORM pipeline, but it does not include downstream-channel field mappings, private program rules, account notes, target names, or organization-specific disclosure templates.

As your public seed becomes a private vault, keep any channel-specific automation in your private vault as a private adapter.

## What An Adapter Is

A private adapter is a thin layer that converts the public framework's generic FORM into a downstream channel's required shape.

Typical adapter files:

- `.claude/skills/<private-form-adapter>/SKILL.md`
- `07 - Templates/Template - FORM <Channel>.md`
- `automation/lint_<channel>_form.py`
- `docs/<channel>-submission-notes.md`

The public seed remains the reusable base. The private vault owns target-specific and channel-specific behavior.

## Flow

1. Start from a verified Finding in `01 - Targets/<target>/Findings/`.
2. Run the submission readiness workflow.
3. Generate a generic FORM with `bb-form-writer` and `templates/form.md`.
4. Let the private adapter reshape that generic FORM for the downstream channel.
5. Keep raw screenshots, logs, exports, and drafts in `workspace/`.
6. Promote only reusable, sanitized lessons back into the LLM Wiki.

The adapter should be downstream-only. It should not change the core Finding schema, target folder layout, session lifecycle, or Knowledge Capture gate.

## Do Not Upstream

The rule is simple: do not upstream private adapter content into this public seed.

- target names, hosts, accounts, cookies, screenshots, logs, or payload traces
- private downstream channel field names when they identify a specific program or process
- channel-specific vulnerability type tables
- private rate limits, triage notes, response examples, or account setup steps
- report text copied from real findings
- scanner output, workspace files, or exploit artifacts

Public changes should be generic and reusable: schema improvements, workflow guardrails, safety checks, note generators, and documentation that does not identify a target or downstream channel.

## Adapter Checklist

Before committing a private adapter:

- The public generic FORM still works without the adapter.
- The adapter reads from Finding/Submission data instead of duplicating source-of-truth fields.
- Raw evidence stays in `workspace/`; canonical evidence summaries stay in Vault notes.
- The adapter can be removed without breaking the public seed workflow.
- Any lesson promoted back to the public seed is sanitized and channel-neutral.
