---
fileClass: KB
type: pattern
tags: [pattern, broken-access-control, auth, privilege-escalation, authorization]
added: 2026-01-01
---

# Pattern — Broken Access Control

## Summary

The server does not enforce authorization at the function or object level, allowing a lower-privileged user to access resources or perform actions reserved for higher-privileged roles (vertical escalation) or to access another user's data within the same privilege tier (horizontal escalation). Covers forced browsing to admin endpoints, HTTP verb tampering, and missing server-side checks on role-sensitive parameters.

## Detection Signals

- Admin or management endpoints reachable without elevated session (`/admin/`, `/manage/`, `/console/`)
- Role-determining parameters in requests (`is_admin=true`, `role=admin`, `privilege=1`)
- API responses that differ based only on client-supplied role claims
- Endpoints that respond 200 when accessed with a regular-user token after mapping with an admin account
- Same endpoint accessible via an alternate HTTP verb (e.g., `POST` blocked but `PUT` allowed)
- Missing function-level authorization checks in middleware or route guards

## Grep Signatures

```bash
# Role/privilege parameters in source
grep -rn 'is_admin\|isAdmin\|role=\|privilege\|user_type\|user_role' \
  --include='*.js' --include='*.py' --include='*.rb' --include='*.php'

# Admin route definitions
grep -rn '"/admin\|/manage\|/console\|/internal\|/superuser' \
  --include='*.js' --include='*.py' --include='*.rb' --include='*.php'

# Authorization middleware absence — routes without auth decorator
grep -rn '@app.route\|router\.(get\|post\|put\|delete)' --include='*.py' --include='*.js' | \
  grep -v 'require_auth\|@login_required\|auth\.verify\|authenticate'

# Missing role checks in Java/Spring
grep -rn '@RequestMapping\|@GetMapping\|@PostMapping' --include='*.java' | \
  grep -v '@PreAuthorize\|@Secured\|hasRole\|hasAuthority'
```

## Test Methodology

1. Map all endpoints as an unauthenticated user using a spider/crawler; note any 302/401/403 responses.
2. Authenticate as a low-privileged (standard) user and replay admin-only requests with the standard-user session token.
3. Compare responses: if an admin function returns 200 (or executes the action) for the low-privileged user, vertical BAC is confirmed.
4. For horizontal BAC: authenticate as User A, capture a request that references User A's resource ID, then replay with User B's session; if User B's session retrieves User A's data, horizontal BAC is confirmed.
5. Test HTTP verb substitution: if `POST /admin/users/delete` is blocked, try `DELETE /admin/users/delete`, `PUT`, `PATCH`, `HEAD`, `OPTIONS`.
6. Inject role parameters into request body, query string, and cookies (`role=admin`, `is_admin=1`, `group=superadmin`) and observe whether the server trusts the client-supplied value.
7. Attempt forced browsing to unlisted paths discovered via JS files, documentation, or error messages.
8. Verify that authorization is enforced server-side (not just hidden in the UI).

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| UI hides admin links | Direct URL access (forced browsing) still works |
| Role enforced by frontend JS | Replay raw HTTP request; server-side check absent |
| RBAC on `POST` only | Switch to `PUT`, `PATCH`, or `DELETE` for same endpoint |
| Check on path prefix `/admin/` | Try `/Admin/`, `/ADMIN/`, `/admin;/`, URL encoding (`%2fadmin`) |
| Role claim in JWT | Modify `role` claim if JWT is not properly verified or uses `alg: none` |
| Admin parameter blocked in body | Move parameter to query string or cookie |
| Feature flag check | Guess or enumerate flag names; toggle via a request parameter |

## Severity Guide

| Scenario | Severity |
|----------|----------|
| Admin takeover / account takeover (vertical escalation to superuser) | P1 |
| Access to sensitive administrative functions (user management, billing, config) | P2 |
| Horizontal access to another user's sensitive PII or financial data | P2 |
| Horizontal access to non-sensitive data of another user | P3 |
| Read-only access to low-sensitivity admin info (e.g., user count) | P4 |
| No material impact, theoretical only | P5 |

## Related

- [[Pattern - IDOR]]
- [[Pattern - OAuth Misconfiguration]]
- [[Lessons Learned]]
- [[Playbook - Recon]]
