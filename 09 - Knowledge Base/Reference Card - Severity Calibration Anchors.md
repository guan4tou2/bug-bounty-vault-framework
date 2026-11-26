# Reference Card — Severity Calibration Anchors

> Concrete examples that anchor severity ratings. Use these as comparison points when scoring findings. Adapted from Decepticon's severity calibration methodology.

## Purpose

Severity inflation is the most common quality issue in bug bounty reports. These anchors provide real-world examples at each severity level so reviewers can compare "is my finding more or less impactful than this anchor?"

## Critical (CVSS 9.0-10.0)

Requires: remote, unauthenticated, no user interaction, wide blast radius.

| Anchor | CVSS Vector | Score | Why Critical |
|--------|-------------|-------|-------------|
| Unauthenticated RCE via deserialization | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 | Full server compromise, no auth needed |
| Pre-auth SQL injection with data exfil | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Full database access without authentication |
| Auth bypass to admin → all tenant data | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N | 9.3 | Cross-tenant data breach, no interaction |
| SSRF to cloud metadata → IAM creds → S3 full access | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N | 9.3 | Chain: SSRF→creds→data (all verified) |

**Anti-pattern**: "Theoretical RCE" without working PoC is NOT Critical.

## High (CVSS 7.0-8.9)

Requires: significant impact, but with some limiting factor (auth required, user interaction, limited scope).

| Anchor | CVSS Vector | Score | Why High |
|--------|-------------|-------|---------|
| Authenticated IDOR → read any user's PII | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5→7.5 with chain | Needs auth, but mass PII exposure |
| Stored XSS in admin panel → session hijack | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N | 8.7 | Needs victim click, but admin takeover |
| Password reset token leak → account takeover | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | One user at a time, but full ATO |
| JWT secret leak → forge any user's session | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Key disclosure enables impersonation |

**Anti-pattern**: IDOR that reads only your own data is NOT High.

## Medium (CVSS 4.0-6.9)

Requires: real impact but limited blast radius, requires interaction, or information disclosure that enables further attacks.

| Anchor | CVSS Vector | Score | Why Medium |
|--------|-------------|-------|-----------|
| Reflected XSS (no cookie access, CSP present) | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Needs victim click, CSP limits impact |
| CSRF on non-critical action (profile change) | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 | Needs victim click, low impact action |
| Information disclosure: internal IPs, stack traces | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Useful for chaining, not directly exploitable |
| Rate limit bypass on login (brute force possible) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Enables attack but doesn't guarantee success |
| Open redirect (no token in URL) | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Phishing aid, needs social engineering |

**Anti-pattern**: "Internal IP disclosure = High because attacker learns network topology" — no, it's Medium without a chain.

## Low (CVSS 0.1-3.9)

Requires: minimal direct impact, information useful only in combination with other findings.

| Anchor | CVSS Vector | Score | Why Low |
|--------|-------------|-------|--------|
| Username enumeration via timing | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | 3.7 | Difficult to exploit, weak signal |
| Verbose error messages (framework version) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3→2.0 adjusted | Information only, common, low impact |
| Missing security headers (no exploitable vector) | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N | 0.0 | Defense-in-depth only, no direct impact |
| Cookie without Secure flag (HTTPS-only site) | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 | Requires MitM + victim on HTTP |
| CORS misconfiguration (no credentials reflected) | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N | 4.3→2.0 adjusted | No actual cross-origin data access |

**Anti-pattern**: Missing headers without a demonstrated exploit path is Informational, not Low.

## Informational (CVSS 0.0 / no score)

Not a vulnerability. Useful for defense-in-depth recommendations.

| Anchor | Why Informational |
|--------|------------------|
| TLS 1.0 enabled (no downgrade attack demonstrated) | Configuration weakness, no exploit |
| Server banner disclosure | Public information, no impact |
| Directory listing (empty or public content only) | No sensitive data exposed |
| SPF/DMARC missing (no demonstrated spoofing impact) | Email config, not application vuln |

## Chain Severity Rules

1. **Score the chain's final impact, not the sum of individual scores** — severity stacking is prohibited
2. **A chain is as reliable as its weakest link** — one theoretical edge caps the chain's confidence
3. **Preconditions matter** — "admin ATO" that requires physical access to victim's unlocked laptop is not Critical
4. **User interaction downgrades** — each required click or action lowers exploitability
5. **Blast radius matters** — "affects 1 test account" vs "affects all users" is a severity tier difference

## Common Inflation Patterns

| Inflation | Reality | Correct Rating |
|-----------|---------|---------------|
| "Full account takeover" via self-XSS | Requires victim to paste attacker's payload into own console | Low / N/A |
| "RCE" via admin-only feature | Admin already has server access; this is by design | Medium at best |
| "Sensitive data exposure" of public profile fields | Name, avatar, bio are intentionally public | Informational |
| "Authentication bypass" that is actually a public endpoint | No auth was intended on this endpoint | Informational |
| "SSRF" that can only reach localhost:80 (the app itself) | No cross-boundary access, no metadata | Low |
| "SQL injection" that is actually a search feature | Parameterized query, no actual injection | N/A |
| Chain of 3 vulns, scoring each separately and summing | Severity stacking: score final impact only | Varies |

## Usage

- Before scoring: find the closest anchor and adjust from there
- During counterevidence (bb-counterevidence): use anchors to challenge "is this really High?"
- During submission: cite the anchor your finding most resembles
- Cross-reference: bb-cvss-score skill, cvss-adversary agent
