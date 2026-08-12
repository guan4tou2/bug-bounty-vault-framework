---
type: pattern
title: Pattern - Unauth Security Dashboard Enumeration
cwe: "CWE-306, CWE-200, CWE-862"
description: "Detect, verify, and chain unauthenticated security/admin dashboards (/admin /dashboard /grafana /kibana /actuator /metrics) into a high-impact pivot via leaked tokens / webhooks / tenant IDs."
tags: [bb-pattern, info-disclosure, dashboard, unauth, enumeration, chain, escalation]
status: active
last_updated: 2026-06-05
source: "distilled from internal notes + a public $1895 bounty writeup (merged 2026-06-05)"
---

# Pattern - Unauth Security Dashboard Enumeration

> **2026-06-05 merge**: this pattern absorbed an earlier "Unauthenticated Security Dashboard Chain" pattern (~85% overlap, sourced from a public Medium bounty writeup) — folding in its unique content: the bb_log schema, escalation tiers, payload ideas, and source attribution. The earlier chain-only pattern is now deprecated.

## Source

- Original writeup: "From Recon to Critical Finding: An Unauthenticated Security Dashboard" — a $1895 bug bounty writeup published on Medium (author: codewithvamp).

## When To Use

- Recon finds a service/security/admin dashboard exposed on the internet.
- The panel UI or API endpoint is reachable without login.
- The dashboard exposes environment / alerting / integration / host-or-cluster metadata.

## Discovery Signals

- **Path / keyword signals**: `/admin`, `/dashboard`, `/grafana`, `/kibana`, `/actuator`, `/metrics`, `/debug`, `/internal`, `/security`, `/monitor`, `status`
- **HTTP signals**: unauthenticated request returns `200` directly, no login redirect, front-end bundle exposes back-end API paths
- **Content signals**: tenant/project IDs, webhook config, internal host/IP, integration config, token/session-like strings, debug/test actions, cloud metadata

## Verification Flow (Exploitation Flow)

1. First prove unauthorized access is possible (compare an anonymous request against an authenticated one).
2. Enumerate panel functionality: settings, integrations, logs, alerts, test/debug endpoints.
3. Verify the server-side permission boundary (**do not rely on UI visibility alone**).
4. Extract leverage points: tokens / webhooks / internal endpoints / org or user identifiers.
5. Attempt a privilege pivot:
   - Config / API token reuse
   - Integration abuse (webhook / test connector)
   - Internal endpoint traversal using leaked topology
6. Establish chain impact (not just panel exposure): unauthorized data access / account impact / control-plane action.

## Attack Chain (canonical template)

```
public endpoint → panel exposure → sensitive config leak → token/session abuse → account impact
```

Every step needs evidence: request + response + the link that advances to the next step.

## bb_log Mandatory Schema (absorbed from the deprecated chain pattern)

Every chain step must record:

```yaml
chain_from:    # initial unauth dashboard exposure
chain_to:      # derived impact node (e.g. token abuse / privileged API action)
precondition:  # concrete conditions required
blocked_by:    # exact blocker if chain cannot progress
next_steps:    # precise follow-up probes
```

## Escalation Heuristics (severity judgment)

| Tier | Condition |
|---|---|
| **Medium** | Unauthenticated visibility + limited operational metadata |
| **High** | Sensitive config / token / tenant mapping exposed |
| **Critical** | Demonstrated control-plane action OR broad unauthorized data access via the chain |

## Privilege Escalation / Lateral Movement

- **Permission boundary testing**: compare anonymous / low-priv / alternate-role responses
- **Secret exploitability**: replay tokens/sessions/config, try alternate identities, attempt cross-tenant access
- **Same-surface expansion**: search the same domain and subdomains for the same path/API family (endpoint pattern expansion)

## Reusable Payload Ideas

- **Endpoint family diff**: same action endpoint with/without an auth cookie
- **ID pivot**: iterate over tenant / project / user IDs leaked by the dashboard
- **Connector abuse**: test endpoints that trigger outbound or internal calls

## False Positive Filters

| Anti-pattern | Why it doesn't count |
|---|---|
| Judging "dashboard visible" alone as high risk without proving impact | Unauthenticated visibility ≠ exploit; see Escalation Heuristics |
| Only client-side controls are visible, server-side authorization was never checked | A feature gate may still be enforced server-side |
| Reporting a plain status page (no sensitive data, no actionable action) as critical | Read-only telemetry with no actionable pivot is not reportable |
| Finding a token-like string but never validating it | Must replay it and prove the token actually works |
| Never expanded to the same domain / subdomains | Under- or over-estimates the true blast radius |
| A status dashboard the vendor intentionally exposed publicly | Deliberately public status pages are not findings |

## Evidence Requirements

- Request/response proving unauthorized access
- Artifact proving sensitive exposure OR a successful pivot (redacted where needed)
- Evidence for every chain step, from entry point to impact

## Related

- `bb-attack-chain-review` skill — the 6-question gate a chain must pass before escalating
- `bb-exploit-chain` skill — the mandatory 6 questions for chain impact
- [[Pattern - Spring Boot Actuator Unauth RCE]] — deeper pattern for `/actuator` hits
- [[Pattern - Blind SSRF Error Code Differential Oracle]] — next step when a dashboard reveals K8s services
- [[Pattern - AI Memory API Unauth IDOR]] — dashboard IDOR-style pivot
