---
fileClass: KB
type: pattern
tags: [pattern, idor, auth, api]
added: 2026-01-01
---

# Pattern — IDOR (Insecure Direct Object Reference)

## Summary

User-controlled identifiers (IDs, UUIDs, filenames) are used to access resources without verifying the requesting user's authorization.

## Detection Signals

- Sequential numeric IDs in API paths (`/api/users/123`)
- UUID parameters that change response content when modified
- File download endpoints with path parameters
- GraphQL queries with ID arguments lacking auth checks

## Grep Signatures

```bash
# API routes with numeric IDs
grep -rn '/api/.*/:id\|/api/.*/{id}' --include='*.js' --include='*.py' --include='*.rb'

# Direct database lookups without auth check
grep -rn 'findById\|get_object_or_404\|Model.find(' --include='*.js' --include='*.py' --include='*.rb'
```

## Test Methodology

1. Authenticate as User A, capture a request with an object ID
2. Authenticate as User B (or unauthenticated), replay with User A's object ID
3. Compare responses — if User B gets User A's data, IDOR confirmed
4. Test both read (GET) and write (PUT/PATCH/DELETE) operations

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| UUID instead of int | UUIDs may be predictable or leaked elsewhere |
| API gateway auth | Check if backend validates independently |
| Frontend hiding | API still returns data even if UI hides it |
| Rate limiting | Doesn't prevent targeted single-request IDOR |

## Severity Guide

| Impact | Severity |
|--------|----------|
| Read other user's PII | P2-P3 |
| Modify other user's data | P2 |
| Delete other user's data | P1-P2 |
| Read non-sensitive data | P4 |

## Related

- [[Pattern - User Enumeration]]
- [[Lessons Learned]]
