---
name: bb-cvss-score
description: Use when creating or reviewing a Finding and you need a CVSS 3.1 vector + base score. Stateless desc→vector transform for common BB vuln classes (IDOR, SSRF, XSS, SQLi, RCE, auth bypass, file upload, business logic, OAuth, GraphQL). Triggers include 算 CVSS, CVSS 評分, severity 多少.
---

# Bug Bounty — CVSS 3.1 Scoring

Given a vuln class, description, PoC/attack steps, and affected component + auth context, output a precise CVSS 3.1 vector and base score. Pure transform — no network, no state, no file writes; do it inline.

## Step 1 — determine each metric

**Attack Vector (AV)**: `N` network (remote) · `A` adjacent · `L` local · `P` physical
**Attack Complexity (AC)**: `L` no special conditions · `H` needs specific config / race / user-controlled prerequisite
**Privileges Required (PR)**: `N` none · `L` regular user · `H` admin/root
**User Interaction (UI)**: `N` none · `R` victim must act (click/visit)
**Scope (S)** — most commonly wrong, reason carefully: `U` only the vulnerable component · `C` other components affected (stored XSS in admin context, SSRF reaching internal services, SQLi on a shared DB host)
**Confidentiality / Integrity / Availability (C/I/A)**: `N` none · `L` limited · `H` full disclosure / full modification / complete DoS

## Step 2 — common vuln-class defaults (adjust to concrete target)

| Vuln Class | Typical Vector | Notes |
|---|---|---|
| RCE (unauth) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | S:C if code runs in container/shared host |
| RCE (auth) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | |
| SQLi (unauth, data leak) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | add I:H if write possible |
| IDOR (read other user) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | |
| IDOR (modify other user) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | |
| SSRF (internal reach) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N | S:C due to pivot |
| Stored XSS (admin panel) | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | raise C/I if ATO |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | |
| Auth Bypass | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | |
| Unauth File Upload (webshell) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | |
| Business Logic (payment bypass) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | |
| OAuth token theft | AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N | AC:H due to redirect chain |

## Step 3 — base score ranges

9.0–10.0 Critical (AV:N, no auth, high C/I/A + S:C) · 7.0–8.9 High · 4.0–6.9 Medium (auth/limited) · 0.1–3.9 Low (local/minimal).

## Output

```text
CVSS 3.1 Vector: AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Base Score: X.X (Critical/High/Medium/Low)
Metric Reasoning:
- AV:_ — ...   (one line per metric)
```

Always flag Scope decisions and any low-confidence metric for human review — Scope is the most error-prone.
