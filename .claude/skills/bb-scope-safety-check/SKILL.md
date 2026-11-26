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
- user asks "can I scan", "run nuclei", "osmedeus", "bbot", "payload", or "verify"

## Layer 1: Programmatic Validation (new)

Before the prompt-level checks below, run the machine-readable scope validator:

```bash
python3 -I automation/scope_check.py --target <host_or_ip> --scope "$WORKSHOP_ROOT/<target>/SCOPE.md"
```

The script validates:
- **Target authorization**: host/IP/CIDR/domain-glob matching against SCOPE.md
- **Forbidden destinations** (default-deny): cloud metadata endpoints (169.254.169.254, fd00:ec2::254, metadata.google.internal, metadata.azure.com, 100.100.100.200)
- **Sensitive TLDs** (default-deny): `.gov`, `.mil`, `.edu`, `.int` — requires explicit `allow_sensitive_tlds: true` in SCOPE.md frontmatter
- **Command patterns**: regex-based rejection of forbidden commands
- **Time windows**: authorized and blackout windows from SCOPE.md frontmatter
- **Fail-closed**: missing or malformed SCOPE.md → refuse

If the script returns `"allow": false`, **stop**. Do not proceed to Layer 2.

For command validation:
```bash
python3 -I automation/scope_check.py --command "<shell_command>" --scope "$WORKSHOP_ROOT/<target>/SCOPE.md"
```

## Layer 2: Prompt-Level Checks (existing)

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
- Programmatic verdict: <allow/refuse — reason_code>
- Scope source:
- Asset match:
- GET-first status:
- Runtime: local / VPS
- Operation Log status:
- Rate / scale:
- Cost gate: <smoke-test result / not applicable>
- Stop condition:
- Allowed command class:
```

## Cost-Aware Gate (from Decepticon ExploitBench)

Before expensive operations, estimate cost and apply a smoke-test go/no-go gate:

| Operation | Smoke Test | Go/No-Go |
|---|---|---|
| Full Nuclei scan (all templates) | Run 10 high-signal templates first | Full scan only if smoke finds results |
| Password spray (AD) | Read lockout policy; try top-10 passwords on 3 accounts | Full spray only if smoke succeeds AND lockout policy allows |
| Hash cracking (Kerberoast) | Try top-1000 wordlist first (~5 min) | Full wordlist only if top-1000 cracks at least 1 hash |
| Full port scan (all ports) | Scan top-1000 ports first | Full scan only if top-1000 reveals unusual services |
| Fuzzing (parameter/path) | 100 payloads per parameter first | Extend only if 100-payload run shows anomalies |
| bbflow full hunt | Single pattern run first | Full hunt only if single pattern generates candidates |

Record the smoke-test result and go/no-go decision in the Operation Log.

## Runtime Decision

- Local: single read-only confirmation, file inspection, report writing, dedupe, status checks.
- VPS: scan, fuzz, payload, high-rate recon, bbflow hunt/flow, Osmedeus, Nuclei, BBOT, anything noisy.
- Blocked: unclear scope, write side effects unknown, missing Operation Log, or unsafe impact risk.

## Default-Denied Destinations

These are blocked unless the SCOPE.md frontmatter explicitly opts in:

| Destination | Reason | Opt-in |
|---|---|---|
| 169.254.169.254, fd00:ec2::254 | AWS IMDS | `allow_cloud_metadata: true` |
| metadata.google.internal | GCP metadata | `allow_cloud_metadata: true` |
| metadata.azure.com | Azure IMDS | `allow_cloud_metadata: true` |
| 100.100.100.200 | Alibaba Cloud metadata | `allow_cloud_metadata: true` |
| *.gov, *.mil, *.edu, *.int | High-collateral TLDs | `allow_sensitive_tlds: true` |

## SCOPE.md Frontmatter Extensions

The programmatic validator reads these optional frontmatter fields:

```yaml
---
# Existing fields
target_name: "example-corp"
program_url: "https://..."
status: active
# New fields for programmatic validation
in_scope:
  - "*.example.com"
  - "10.0.0.0/24"
  - "api.example.com"
out_of_scope:
  - "staging.example.com"
  - "*.internal.example.com"
forbidden_commands:
  - "rm -rf"
  - "DROP TABLE"
allow_cloud_metadata: false
allow_sensitive_tlds: false
authorized_windows:
  - { start: "2026-11-01T00:00:00", end: "2026-12-01T00:00:00" }
blackout_windows:
  - { start: "2026-11-28T00:00:00", end: "2026-11-29T00:00:00" }
# Blue-team deconfliction (from Decepticon engagement middleware)
deconfliction:
  user_agent: "BugBounty-Authorized/1.0 (Ticket: ENG-1234)"
  source_ip_tag: "203.0.113.42"
  ticket_id: "ENG-1234"
---
```

When frontmatter is absent, the validator falls back to parsing `## In Scope` / `## Out of Scope` sections as plain-text target lists.

## Deconfliction (from Decepticon engagement middleware)

If `SCOPE.md` frontmatter contains a `deconfliction` block, inject the coordination identifiers into active requests:

- **User-Agent**: set `User-Agent` header to `deconfliction.user_agent` value in all HTTP requests
- **Source IP tag**: record `deconfliction.source_ip_tag` in Operation Log header so SOC can filter
- **Ticket ID**: include `deconfliction.ticket_id` in Operation Log entries

If no `deconfliction` block exists, note "no deconfliction ID" in the first Operation Log entry. This prevents SOC from mistaking authorized testing for a real attack.

## Hard Rules

- GET-first is required before writes unless the program explicitly defines the action and impact.
- Use VPS for noisy or potentially dangerous operations.
- Do not bypass WAF, firewall, rate limits, or program controls unless explicitly authorized by scope.
- Do not proceed if Operation Log is required but missing.
- If service impact appears, stop and run `bb-incident-response`.
- Cloud metadata endpoints are ALWAYS out-of-scope unless `allow_cloud_metadata: true`.
- Government/military/education domains are ALWAYS out-of-scope unless `allow_sensitive_tlds: true`.
- Programmatic refusal cannot be overridden by prompt-level reasoning.

## Cross-References

- `bb-incident-response`
- `AGENTS.md §6`
- `09 - Knowledge Base/Reference Card - Testing Safety Rules.md`
- `$WORKSHOP_ROOT/<target>/SCOPE.md`
- `automation/scope_check.py` (programmatic validator)
- `automation/injection_detector.py` (tool output injection detection)
