---
name: bb-graphql-audit
description: "Structured GraphQL endpoint deep testing. Triggers: GraphQL endpoint discovered, introspection response, 'graphql audit', 'schema analysis', 'test graphql', 'batch query', 'alias abuse', 'nested query', 'depth attack'."
---

# Bug Bounty — GraphQL Audit

Structured methodology for testing GraphQL endpoints beyond basic introspection. Covers schema extraction, authorization, abuse patterns, and injection.

## Trigger

- GraphQL endpoint discovered during recon or surface mapping
- Introspection response returned during probing
- User says "test graphql", "graphql audit", "schema analysis"
- `/graphql`, `/gql`, `/api/graphql`, or similar path found

## Phase 1: Discovery & Introspection

Send the `__schema` introspection query via both GET and POST:

```graphql
{ __schema { types { name fields { name type { name } } } queryType { name } mutationType { name } subscriptionType { name } } }
```

If introspection is disabled:

| Fallback | Technique |
|----------|-----------|
| Field suggestion | Send partial field names, observe "did you mean" errors |
| Error-based leak | Send malformed queries, check for type names in errors |
| Apollo Sandbox | Check `/graphql/sandbox`, `/graphiql`, `/playground`, `/altair` |
| Voyager | Check if GraphQL Voyager is exposed |
| `.well-known` | Check `/.well-known/apollo/server-health` |

Extract and record:
- Types (count, names, relationships)
- Queries (name, arguments, return types)
- Mutations (name, arguments, return types)
- Subscriptions (if any)
- Custom scalars (DateTime, JSON, URL, Upload)
- Deprecated fields (often less maintained)

## Phase 2: Vulnerability Testing

| Category | Test | Signal | Severity Anchor |
|----------|------|--------|----------------|
| Introspection enabled | `__schema` returns full schema | Info disclosure | Low-Medium |
| Verbose errors | Malformed query → stack trace / path leak | Info disclosure | Low-Medium |
| Batching abuse | Send array `[{query:...},{query:...}]` | Rate limit bypass, brute-force | Medium |
| Alias-based batching | `{ a1: user(id:1) a2: user(id:2) ... }` | IDOR enumeration, rate limit bypass | Medium-High |
| Depth attack | 10+ levels of nested related objects | DoS / resource exhaustion | Medium |
| Circular fragments | Fragment A spreads B, B spreads A | DoS | Medium |
| Field duplication | Repeat same field 100+ times in one query | DoS | Medium |
| Directive overload | Complex `@skip`/`@include` boolean chains | DoS | Low-Medium |
| Subscription abuse | Subscribe to sensitive event streams | Info disclosure | Medium-High |
| Custom scalar injection | Inject into DateTime, JSON, URL scalars | Type confusion, injection | Medium |
| Mutation without auth | Call state-changing mutations unauthenticated | Broken access control | High-Critical |
| IDOR via arguments | Enumerate `id`/`uuid` arguments on queries | IDOR | High |
| Nested object traversal | Follow relational edges to access other users' data | Broken access control | High |
| SQL injection via arguments | `'` `"` `OR 1=1` in string arguments | SQLi | Critical |
| NoSQL injection | `{"$gt":""}` in JSON scalar arguments | NoSQLi | Critical |

## Phase 3: Authorization Matrix (mini)

For each mutation and sensitive query, test with:

| Query/Mutation | No Auth | User A (owner) | User B (other) | Admin | Expected |
|---------------|---------|----------------|----------------|-------|----------|
| `createUser` | | | | | |
| `updateUser(id:A)` | | | | | |
| `deleteUser(id:A)` | | | | | |
| `adminSettings` | | | | | |

Record HTTP status + data presence in each cell. Deviations are findings. For comprehensive auth testing, hand off to `bb-auth-matrix`.

## Phase 4: Reporting

```markdown
## GraphQL Audit — <target>
- Endpoint: <URL>
- Introspection: enabled / disabled / partial
- Schema summary: <N> types, <N> queries, <N> mutations, <N> subscriptions
- Custom scalars: <list>

### Vulnerabilities

| # | Category | Finding | Severity | Evidence | Kill Chain Stage |
|---|----------|---------|----------|----------|-----------------|
| 1 | ... | ... | ... | ... | ... |

### Authorization Matrix (excerpt)
<mini matrix from Phase 3>

### Chain Extensions
- <recommendations from bb-exploit-chain Q1-Q6>
```

## Safety Rules

- Run `bb-scope-safety-check` before active testing
- Depth/batch limits for initial probes: depth 10, batch 20, field duplication 100
- Increase only if target handles initial probes without degradation
- GET-first: probe read operations before mutations
- Record all mutations in Operation Log before execution
- If rate limited or error rate spikes above 10%: stop, reduce rate, record
- Do not send queries designed to crash the server — test for limits, do not exploit DoS

## Cross-References

- `bb-scope-safety-check` — before active testing
- `bb-web-vuln-scan` — standard vuln testing
- `bb-auth-matrix` — full authorization matrix
- `bb-exploit-chain` — chain opportunities
- `bb-evidence-readiness` — evidence quality
- `bb-api-schema-diff` — compare schema vs actual surface
