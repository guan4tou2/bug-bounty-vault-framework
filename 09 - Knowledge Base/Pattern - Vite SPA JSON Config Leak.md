---
type: pattern
title: Pattern - Vite SPA JSON Config Leak
tags: [pattern, cwe-200, info-disclosure, spa, vite, config-leak, bb-pattern]
status: verified
first_seen: 2026-04-23
last_updated: 2026-04-24
severity: P4 (single-tenant) → P3 (systemic across tenants)
---

# Pattern - Vite SPA JSON Config Leak

## TL;DR

Multi-tenant SaaS web apps built on **Vite + Vue / React + env-config pattern** often place environment configuration JSON files at public static paths like `/json/*.json`, `/config/*.json`, `/env/*.json`. These are fetched at runtime by the SPA and reveal:

- Full environment map (dev / test / uat / production API URLs)
- Tenant URL-slug naming pattern (enabling tenant enumeration)
- Business constants (token lifetime, rate limits, pricing)
- Sometimes: hardcoded API keys, JWT secrets, admin endpoints

**CWE-200 / Information Exposure**. P4 on single tenant. **P3 aggregate** if same build template ships to ≥5 customers.

## Root cause

Vite's default build places imported JSON (via `import '@/assets/json/env.json'`) or statically-copied assets (via `public/json/`) into the final `dist/` at publicly-accessible paths. Many vendors don't move them to an authenticated `/api/v1/config` endpoint after they migrate from static SPA config to runtime-fetched config.

Typical build pattern that creates this leak:

```javascript
// src/main.ts or bootstrap.ts
const env = import.meta.env.VITE_ENV;           // "production"
const config = await fetch(`/json/${env}.json`); // <-- PUBLIC PATH
// or
const config = await fetch('/json/version_pmo.json'); // env map dispatcher
```

## Detection

### Static probes

```bash
# Core env-config endpoints
for p in version_pmo uat-company test develop production uat portal config env; do
    curl -sk -o /dev/null -w "%{http_code} %{size_download} $p\n" "https://TARGET/json/$p.json"
done

# Or in one line
curl -sk "https://TARGET/json/version_pmo.json"
```

### Indicators the target uses this pattern

- Vite build signature: `<script type="module" crossorigin src="/assets/index-<8charhash>.js">`
- `index.html` has minimal `<div id="app"></div>` or `<div id="root"></div>` body
- Response headers: `Server: Apache` + Vue/React on client (vendor serves from PHP/nginx backend)
- Static paths: `/assets/`, `/json/`, `/config/` (not `/api/`)

### Vite-specific signatures that make this leak likely

- Fat-Free Framework (F3) PHP backend — common with Vite SPA in Taiwan
- Vue 3 + Pinia + `secure-ls` (localStorage wrapper — doesn't matter if env is public)
- Element Plus UI library

## Exploitation

**Passive only — information disclosure. No active exploit needed.** The value is in what the JSON leaks:

### Typical yields

1. **Environment map** (`/json/version_pmo.json`):
   ```json
   {
     "uat": "uat-portalite.vendor-api.example.com",
     "uat-company": "api.vendor-api.example.com",
     "production": "hs.vendor-api.example.com"
   }
   ```
   → leaks production + staging hostnames that may be otherwise unlisted.

2. **Tenant URL slug** (`/json/<env>.json`):
   ```json
   {
     "ENV": "production",
     "BASE_API": "https://hs.vendor-api.example.com/<tenantSlug>/api/capi/",
     ...
   }
   ```
   → confirms tenant identifier + reveals routing pattern for multi-tenant probing.

3. **Business constants** that hint at abuse primitives:
   - `TOKEN_VALIDTIME: 30` (30-second JWT) → timing-attack tolerance
   - `BATCHSENDCOUNT_MAX: 20000` (SMS send limit) → abuse ceiling
   - `SMS_CHARGE: 1` (per-unit pricing) → financial impact math

## Case studies

### Example Vendor / Vendor-SMS / Enterprise Customer (generic)

- **`customer-test.vendor-api.example.com/json/version_pmo.json`** (enterprise customer test tenant) → env map
- **`hs.vendor-api.example.com/json/production.json`** (production) → `BASE_API: https://hs.vendor-api.example.com/customerSlug/api/capi/`
- **New apex domain discovered** via leaked test/dev URLs: `test-portalite.vendor-alt.example.com`, `dev-portalite.vendor-alt.example.com`
- Tested 32 other vendor-sms tenants — **only these 2 leaked** (Vite-specific, not systemic across IIS/ASP.NET tenants)
- Filing: CERT + private enterprise customer CSO notification

Finding: [[Target - Example Vendor]] ACME-003.

## Remediation (vendor-side)

1. Move environment configuration out of `/public/` (static served) to `/src/` (bundled + obfuscated)
2. Even better: fetch config from authenticated `/api/v1/config` requiring session cookie / bearer token
3. Audit all `/json/`, `/config/`, `/env/` paths across SPA deployments
4. Add CSP `connect-src` allow-list to constrain what config is reachable

## Severity calibration

| Scope | CVSS | Triage likely outcome |
|-------|------|----------------------|
| Leaks only public hostnames | 3.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) | P5 / Informational |
| Leaks tenant slug pattern + API routes | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) | P4 |
| Leaks production API + tenant slug + regulated customer | 6.5 | **P3** |
| Leaks hardcoded API keys / JWT secrets / admin endpoint tokens | 8.1+ | **P2-P1** |
| Systemic across ≥5 tenants | Severity + 1 | P2 aggregate likely |

**Don't overclaim**: this is CWE-200 info disclosure, not direct exploit. Chain with a tenant-IDOR / auth-bypass bug to get to P1/P2.

## Pre-submit checklist

- [ ] Confirmed ≥1 live endpoint returns 200 with valid JSON
- [ ] Captured the actual leaked URL + redacted credentials
- [ ] Verified not behind authentication (not a session-required path)
- [ ] Checked for similar leak across multiple tenants (single → P4, systemic → P3+)
- [ ] Explicit mention of regulated-customer impact if any (FSC / banking / hospital)

## Related

- [[Pattern - Source Map Exposure]] — similar but different source (source maps reveal source code; /json/ reveals runtime config)
- [[Pattern - Hardcoded Credentials]] — if the config contains real secrets
- [[Pattern - User Enumeration]] — tenant-URL-slug leak enables next-stage enumeration
- [[Tool - Source Map Reverse Engineering]] — companion attack for SPA bundles
- [[Target - Example Vendor]] — ACME-003 primary case study
