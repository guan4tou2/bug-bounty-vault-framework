---
name: bb-scope-safety-check
description: Use when scans, fuzzing, payloads, POST/PUT/PATCH/DELETE, bbflow hunt/flow, Osmedeus, Nuclei, BBOT, or live verification may write data or create service impact.
---

# Bug Bounty — Scope Safety Check

Use this gate before risky live actions. It keeps scan scale, scope, GET-first discipline, and Operation Log requirements explicit.

## Trigger

Run before:

- bbflow `hunt` / `flow`, Osmedeus, Nuclei, BBOT, fuzzing, crawler expansion, or active scan
- POST / PUT / PATCH / DELETE
- payload upload, webhook, callback, SSRF, parser, import, or stored effect
- high-rate requests or actions that may affect service state
- user asks "可以掃嗎", "跑 nuclei", "osmedeus", "bbot", "payload", or "驗證"

## Required Checks

| Gate | Question |
|---|---|
| Scope source | Which `SCOPE.md`, program page, or written authorization allows this? |
| Asset match | Is every host / path / account in scope? |
| GET-first | Has a safe read-only check established behavior before writes? |
| Method safety | What changes if this request succeeds? |
| Rate / scale | Is the scan rate appropriate for the target and program? |
| Runtime location | Should this run on VPS rather than local? |
| Operation Log | Has the action been recorded in `RECON_DB.md ## Operation Log`? |
| Stop condition | What response, error, or impact signal stops the action immediately? |

## Output Format

```markdown
## Scope Safety Check
- Status: allowed / blocked / needs-human-confirmation
- Scope source:
- Asset match:
- GET-first status:
- Runtime: local / VPS
- Operation Log status:
- Rate / scale:
- Stop condition:
- Allowed command class:
```

## Runtime Decision

- Local: single read-only confirmation, file inspection, report writing, dedupe, status checks.
- VPS: scan, fuzz, payload, high-rate recon, bbflow hunt/flow, Osmedeus, Nuclei, BBOT, anything noisy.
- Blocked: unclear scope, write side effects unknown, missing Operation Log, or unsafe impact risk.

## Hard Rules

- GET-first is required before writes unless the program explicitly defines the action and impact.
- Use VPS for noisy or potentially dangerous operations.
- Do not bypass WAF, firewall, rate limits, or program controls unless explicitly authorized by scope.
- Do not proceed if Operation Log is required but missing.
- If service impact appears, stop and run `bb-incident-response`.

## Cross-References

- `bb-incident-response`
- `AGENTS.md §6`
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md`
- `$WORKSHOP_ROOT/<target>/SCOPE.md`
