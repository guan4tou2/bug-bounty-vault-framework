---
name: bb-auth-matrix
description: "Structured authorization testing with Role x Endpoint x Operation matrix. Triggers: 'auth matrix', 'test auth', 'role testing', 'privilege escalation testing', 'access control audit', multiple roles identified, IDOR hunting, permission matrix."
---

# Bug Bounty — Authorization Matrix

Systematic role-based access control testing. Build a matrix of roles x endpoints x operations, execute it, and flag deviations.

## Trigger

- Multiple user roles identified during recon
- IDOR candidate found — need systematic role coverage
- API endpoints discovered with varying auth requirements
- User says "test auth", "auth matrix", "privilege escalation", "role testing"

## Phase 1: Enumerate Roles

List all discovered roles:

| Role | How to Obtain | Priority |
|------|--------------|----------|
| Unauthenticated | No session | Always test |
| User A (owner) | Registration / given credentials | Always test |
| User B (non-owner, same privilege) | Separate registration | Always test (horizontal) |
| Low-privilege role | Limited account / free tier | Test if exists |
| Moderator / manager | Invitation / escalation | Test if exists |
| Admin | Admin panel / escalation | Test if accessible |
| Service account / API key | API key management | Test if discovered |

Minimum viable matrix: unauthenticated + User A (owner) + User B (non-owner) + highest available privilege.

## Phase 2: Enumerate Operations

Group by resource:

| Resource | Endpoints | Methods | Sensitivity |
|----------|-----------|---------|-------------|
| Users | `/api/users`, `/api/users/:id` | GET, PUT, DELETE | PII |
| Billing | `/api/billing`, `/api/invoices` | GET, POST | Financial |
| Admin | `/api/admin/*` | GET, POST, PUT | Administrative |
| Content | `/api/posts`, `/api/comments` | GET, POST, PUT, DELETE | Standard |
| Settings | `/api/settings`, `/api/config` | GET, PUT | Configuration |

Prioritize:
1. State-changing endpoints (POST/PUT/PATCH/DELETE)
2. Sensitive read endpoints (PII, billing, admin, internal)
3. Meta operations (password reset, role change, invitation, export)

## Phase 3: Build & Execute Matrix

| Endpoint | Method | Operation | Unauth | User A | User B | Admin | Expected |
|----------|--------|-----------|--------|--------|--------|-------|----------|
| `/api/users/A` | GET | Read own profile | | | | | A:200, B:403 |
| `/api/users/A` | PUT | Edit own profile | | | | | A:200, B:403 |
| `/api/admin/config` | GET | Read admin config | | | | | Admin:200, others:403 |

Cell notation:
- `200✓` — 200 with data returned
- `200✗` — 200 with empty/filtered response (soft denial)
- `401` — authentication required
- `403` — forbidden
- `404` — not found (may be access-dependent)
- `500` — server error

Testing order:
1. Admin token → establish the baseline of what SHOULD work
2. Unauthenticated → find public leaks
3. User A (owner) → establish owner access
4. User B (non-owner, same role) → horizontal privilege (IDOR)
5. Low-privilege role → vertical privilege escalation

## Phase 4: Deviation Analysis

| Pattern | Classification | Severity |
|---------|---------------|----------|
| Unauth gets `200✓` on sensitive endpoint | Broken authentication | Critical |
| User B accesses User A's data | Horizontal privilege escalation (IDOR) | High |
| Low priv accesses admin-only data | Vertical privilege escalation | High-Critical |
| `200✗` instead of `403` | Soft denial — may leak metadata or be bypassable | Medium |
| `404` for some roles, `403` for others | Inconsistent error — role oracle | Low-Medium |
| Admin-only action accessible to regular user | Broken function-level authorization | High |
| Response time differs by role (slow 403) | Timing oracle for resource existence | Low |

## Phase 5: Output Format

```markdown
## Authorization Matrix — <target>
- Roles tested: <list>
- Endpoints tested: <count>
- Matrix cells: <count>
- Deviations found: <count>

### Matrix
| Endpoint | Method | Unauth | User A | User B | Admin | Expected | Deviation? |
<rows>

### Deviations
| # | Endpoint | Expected | Actual | Role | Classification | Severity |
<rows>

### Horizontal IDOR Summary
<User A vs User B differences>

### Vertical Escalation Summary
<Low priv vs Admin differences>

### Chain Opportunities
<recommendations via bb-exploit-chain>
```

## Efficiency Rules

- Cap the matrix at 200 cells — prioritize state-changing and sensitive-read endpoints
- One session/token per role, stored in variables — do not re-authenticate per request
- Record raw HTTP status codes AND response body indicators — `403` is not always "secure"
- A `200` with empty array is NOT the same as `403` — record separately
- If the API uses cursor-based pagination, test whether User B can paginate through User A's resources

## Safety Rules

- Run `bb-scope-safety-check` before active testing
- GET-first for each endpoint before state-changing methods
- Record all state-changing requests in Operation Log
- If a mutation succeeds unexpectedly (privilege escalation): screenshot/record immediately, do NOT repeat
- Do not create/delete real user accounts unless explicitly authorized
- Rate limit: max 2 req/sec per role rotation
- If a successful escalation modifies real data: note it in the finding and stop testing that path

## Cross-References

- `bb-scope-safety-check` — before active testing
- `bb-idor-coverage` — IDOR-specific deep dive
- `bb-graphql-audit` — GraphQL authorization testing
- `bb-exploit-chain` — chain deviations into higher impact
- `bb-evidence-readiness` — evidence quality
- `Reference Card - Severity Calibration Anchors` — severity assessment
