# Standard Operating Procedures

## New Target

1. Create a target note from `templates/target.md`.
2. Create a private workspace folder outside git.
3. Add scope and authorization references.
4. Establish the tool layer once if not already done (`bb-tool-setup` — install bbflow or a contract-conforming scanner).
5. **Map the attack surface vuln-agnostically first** (`bb-surface-mapping`, the front gate) — do not start from a scanner/pattern library.
6. Test with full OWASP coverage (`bb-web-vuln-scan`); chain any finding (`bb-exploit-chain`) before the next system.
7. Run the safety and dedupe gates, and start a recon note before storing raw outputs.

See [architecture-closed-loop.md](architecture-closed-loop.md) for why the front gate comes first.

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
5. Run a dedupe and evidence review before any downstream use.

## Review Note

1. Create a review note from `templates/review-note.md`.
2. Record scope status, duplicate risk, evidence quality, and open questions.
3. Keep external disclosure or case-management details in a private extension.
4. Feed general lessons back into the LLM Wiki.

## Generic Submission and Form

1. Create a neutral handoff note from `templates/submission.md` only after review.
2. Create a generic field bundle from `templates/form.md` only when a private workflow needs one.
3. Keep destination-specific fields, case IDs, contacts, and screenshots in a private extension.
4. Do not add destination-specific templates to this public framework.

## Knowledge Capture

Only promote generic, sanitized lessons:

- repeatable decision trees
- false-positive filters
- safe workflow improvements
- template improvements

Do not promote private hostnames, customer data, credentials, or raw evidence.
