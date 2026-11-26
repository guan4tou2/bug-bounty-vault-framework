---
name: bb-auth-matrix
description: "Use when testing authorization, IDOR, privilege escalation, role confusion, multi-tenant isolation, JWT/session scope, or any access control boundary. Builds a Role × Endpoint × Operation matrix and tests every cell systematically."
---

# Bug Bounty — Auth Matrix

Structured authorization testing. Builds a complete Role × Endpoint × Operation matrix, tests every cell, and flags anomalies where actual behavior diverges from expected access control.

## Trigger

- Testing authorization or access control on any target
- IDOR hunting, privilege escalation, role confusion
- Multi-tenant isolation verification
- JWT/session scope analysis
- User says "auth test", "check permissions", "role testing", "who can access what"
- After `bb-surface-mapping` identifies multiple roles or auth-gated endpoints

## Protocol

### Step 1: Enumerate Roles

Extract all roles from recon data, surface map, and RECON_DB:

| Role | Auth Mechanism | How Obtained | Notes |
|------|---------------|-------------|-------|
| Unauthenticated | None | — | Default starting point |
| Regular user | Session cookie / JWT | Registration | |
| Admin | Session cookie / JWT | Invite / escalation | |
| API key (read) | Bearer token | Developer portal | |
| Service account | OAuth2 client credentials | Internal | |

Include: unauthenticated, every named role, API key tiers, service accounts, cross-tenant users.

### Step 2: Enumerate Endpoints and Operations

From surface map and RECON_DB, list every endpoint with its operations:

| Endpoint | Method | Operation | Auth documented? | Sensitive? |
|----------|--------|-----------|-------------------|------------|
| /api/users | GET | List users | Yes (admin) | PII |
| /api/users/{id} | GET | Get user | Yes (self or admin) | PII |
| /api/users/{id} | PUT | Update user | Yes (self or admin) | Write |
| /api/admin/config | GET | Read config | Yes (admin) | Config |

Prioritize: write operations, PII endpoints, admin functions, payment/billing, cross-tenant data.

### Step 3: Build the Matrix

For every Role × Endpoint × Method combination:

| Endpoint | Method | Role | Expected | Actual | Status |
|----------|--------|------|----------|--------|--------|
| /api/users | GET | unauth | deny | | ⏳ untested |
| /api/users | GET | user | allow (self) | | ⏳ untested |
| /api/users | GET | admin | allow (all) | | ⏳ untested |
| /api/users/{id} | PUT | user (other) | deny | | ⏳ untested |

Status values: `⏳ untested`, `✅ pass` (matches expected), `❌ fail` (anomaly), `⚠️ partial` (inconsistent).

### Step 4: Test Systematically

Order of testing:

1. **Horizontal first** — same role across all endpoints (reveals missing auth on specific routes)
2. **Vertical second** — same endpoint across all roles (reveals privilege escalation)
3. **Cross-tenant** — same role, different tenant's resources (reveals isolation failures)
4. **Parameter manipulation** — swap IDs, GUIDs, emails between roles (reveals IDOR)

For each test:
- Send the request with the role's credentials
- Record exact status code and response body hash
- Compare against expected behavior
- Mark status in the matrix

### Step 5: Classify Anomalies

| Anomaly Type | Pattern | Severity Signal |
|-------------|---------|----------------|
| Missing auth | Deny expected → 200 OK | High: unauth access |
| Privilege escalation | User gets admin response | High: vertical escalation |
| IDOR | User A reads User B data | Medium–High: depends on data |
| Role confusion | Mixed response (partial data) | Medium: broken access control |
| Tenant isolation | Tenant A accesses Tenant B | Critical: multi-tenant bypass |
| Mass assignment | Extra fields accepted in write | Medium–High: depends on fields |

### Step 6: Chain Assessment

For each anomaly, evaluate chain potential with `bb-exploit-chain`:
- Does this access enable further escalation?
- Can leaked data (IDs, tokens, config) chain into other findings?
- Does privilege escalation reach admin/system level?

## Output Format

```markdown
## Auth Matrix — <target>

### Summary
- Roles tested: <N>
- Endpoints tested: <N>
- Matrix cells: <total> (tested: <N>, pass: <N>, fail: <N>, untested: <N>)
- Anomalies found: <N>

### Matrix (anomalies only)
| Endpoint | Method | Role | Expected | Actual | Type | Severity |
|----------|--------|------|----------|--------|------|----------|

### Recommended Findings
1. <anomaly → finding recommendation with evidence pointer>
```

## Anti-Patterns

| Anti-Pattern | Why It Fails | Matrix Fix |
|-------------|-------------|------------|
| Testing only admin endpoints | Misses auth bypass on "public" routes | Matrix covers ALL endpoints × ALL roles |
| Testing only own role | Misses cross-role escalation | Vertical testing is mandatory |
| Swapping only numeric IDs | Misses GUID/email/slug IDOR | Test all identifier types per parameter |
| Ignoring 403 vs 401 | Different bypass strategies | Record exact status codes |
| Skipping unauthenticated | Misses missing-auth bugs entirely | Unauth is always the first role tested |

## Hard Rules

- GET-first: read operations before writes
- Lowest-privilege first: test unauthenticated → user → admin order
- Do not modify or delete real user data during testing
- Record every test in Operation Log
- Run `bb-scope-safety-check` before any write operation testing
- Do not brute-force IDs — use known IDs from authorized recon

## Cross-References

- `bb-scope-safety-check` — before write-operation testing
- `bb-idor-coverage` — IDOR-specific deep testing
- `bb-exploit-chain` — chain anomalies into higher impact
- `bb-evidence-readiness` — prepare anomalies as findings
- `bb-counterevidence` — challenge anomaly severity
- `bb-surface-mapping` — source of endpoints and roles
