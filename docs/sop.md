# Standard Operating Procedures

## New Target

1. Create a target note from `templates/target.md`.
2. Create a private workspace folder outside git.
3. Add scope and authorization references.
4. Run the safety and dedupe gates.
5. Start a recon note before storing raw outputs.

## New Recon Note

1. Create a note from `templates/recon-note.md`.
2. Record purpose, scope, tools, and key decisions.
3. Link any produced findings or stopped attempts.
4. Capture reusable lessons.

## New Finding

1. Create a finding from `templates/finding.md`.
2. Include reproduction steps and a minimal evidence summary.
3. Link raw artifacts by path and hash if needed.
4. Keep sensitive material out of the Vault.
5. Run a dedupe review before submission.

## Submission

1. Create a submission from `templates/submission.md`.
2. Keep platform-specific wording separate from the technical finding.
3. Store the final platform form from `templates/form.md` if needed.
4. Update triage status when a response arrives.

## Knowledge Capture

Only promote generic, sanitized lessons:

- repeatable decision trees
- false-positive filters
- safe workflow improvements
- template improvements

Do not promote private hostnames, customer data, credentials, or raw evidence.
