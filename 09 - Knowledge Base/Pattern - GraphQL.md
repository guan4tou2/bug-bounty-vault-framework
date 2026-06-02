---
fileClass: KB
type: pattern
tags: [pattern, graphql, api, idor, introspection, dos]
added: 2026-01-01
---

# Pattern — GraphQL

## Summary

GraphQL endpoints expose a wide attack surface due to introspection, flexible query composition, and object-level authorization that must be manually implemented per resolver. Common issues include schema disclosure via introspection, IDOR through node IDs, rate-limit bypass via query batching and aliasing, denial of service via deeply nested queries, and missing object-level authorization in resolvers.

## Detection Signals

- Endpoint paths: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`
- `Content-Type: application/json` with `{"query": ...}` body
- Introspection query (`__schema`, `__type`) returns schema data
- Field suggestions in error responses when introspection is disabled (`Did you mean ...?`)
- Array-wrapped query body accepted (batching enabled)
- Deeply nested queries accepted without timeout or depth limit
- Node IDs in responses (`id: "VXNlcjox"` — often base64-encoded type+ID)

## Grep Signatures

```bash
# GraphQL endpoint definitions in source
grep -rn 'graphql\|GraphQL\|graphene\|apollo-server\|strawberry\|ariadne' \
  --include='*.js' --include='*.py' --include='*.rb' --include='*.ts'

# Resolver functions without explicit auth check
grep -rn 'resolve\|resolver\|@strawberry\.' --include='*.py' --include='*.js' --include='*.ts' | \
  grep -v 'auth\|permission\|login_required\|require_auth\|IsAuthenticated'

# Introspection enabled check (schema/type queries present in tests)
grep -rn '__schema\|__type\|IntrospectionQuery' \
  --include='*.js' --include='*.py' --include='*.ts' --include='*.graphql'

# Batching-related config (disable flag)
grep -rn 'allowBatchedRequests\|batching\|batch.*true' \
  --include='*.js' --include='*.ts' --include='*.json'

# Depth/complexity limit settings
grep -rn 'depthLimit\|maxDepth\|complexity\|queryComplexity\|maxAliasCount' \
  --include='*.js' --include='*.ts' --include='*.py'
```

## Test Methodology

1. Discover the GraphQL endpoint; probe `/graphql`, `/api/graphql`, and look for `application/graphql` content type in browser traffic.
2. Run an introspection query to retrieve the full schema:
   ```
   { __schema { queryType { name } types { name fields { name type { name } } } } }
   ```
3. If introspection is disabled, probe for field suggestions by querying a plausible-but-wrong field name (e.g., `{ user { emai } }`) and check if the error message suggests the correct field name.
4. Test batching by wrapping multiple queries in a JSON array and observing whether all execute; use aliasing to send many operations in one request (brute-force / rate-limit bypass).
5. Test nested query DoS: construct a query with 10+ levels of nested relationships and measure response time; confirm server lacks depth limiting.
6. Test IDOR via node IDs: decode base64 node IDs, modify the embedded numeric ID or type prefix, and re-query; check if another user's object is returned.
7. Test missing object-level auth: query an object belonging to another user using only that object's ID while authenticated as a different user.
8. Review mutations for missing authorization — especially `delete`, `update`, `addMember`, `changeRole` mutations.
9. Check for subscription endpoints that lack authentication.

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Introspection disabled | Use field suggestion errors to enumerate types/fields incrementally |
| Rate limiting per IP | Query batching — send 100 aliased queries in one HTTP request |
| Rate limiting per query | Aliasing within a single query body (`a1: login(...) a2: login(...)`) |
| Depth limit present | Widen instead of deepen — many parallel fields rather than deep nesting |
| Opaque node IDs (base64) | Decode (`echo "VXNlcjox" | base64 -d`), increment integer, re-encode |
| Object hidden from list query | Query by direct node ID even if not visible in list |
| Field-level auth on top-level query | Access same field via a nested resolver that lacks the same check |
| Query complexity limit | Split into multiple cheap queries; bypass may reset across requests |

## Severity Guide

| Scenario | Severity |
|----------|----------|
| Authentication bypass via GraphQL mutation (login as arbitrary user) | P1 |
| IDOR exposing another user's sensitive PII or financial data | P2 |
| Missing object-level auth allowing modification/deletion of arbitrary records | P2 |
| Batching / aliasing enables brute-force of credentials or OTPs at scale | P2-P3 |
| Deep nesting DoS causes measurable service degradation | P3 |
| Introspection exposes schema on a public, non-sensitive API | P4-P5 |
| Field suggestions disclose internal field names only | P5 |

## Related

- [[Pattern - IDOR]]
- [[Pattern - SSRF]]
- [[Lessons Learned]]
- [[Playbook - Recon]]
