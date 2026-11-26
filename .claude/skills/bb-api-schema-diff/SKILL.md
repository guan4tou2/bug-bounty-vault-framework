---
name: bb-api-schema-diff
description: "Use when target has OpenAPI/Swagger spec or API documentation. Compares documented API spec vs actual behavior to find undocumented endpoints, shadow APIs, parameter discrepancies, and auth mismatches."
---

# Bug Bounty — API Schema Diff

Compare documented API specification against actual API behavior. Finds shadow APIs, undocumented endpoints, parameter discrepancies, and auth requirement mismatches.

## Trigger

- Target has OpenAPI/Swagger spec (`/swagger.json`, `/openapi.yaml`, `/api-docs`)
- Public API documentation found in recon
- JS bundles contain route definitions or API client code
- User says "hidden endpoints", "undocumented API", "API diff", "shadow API"
- After `bb-surface-mapping` when API surface is partially documented

## Protocol

### Step 1: Collect Documented Spec

Sources in priority order:

| Source | Location | Method |
|--------|----------|--------|
| OpenAPI/Swagger | `/swagger.json`, `/openapi.yaml`, `/v2/api-docs` | Direct download |
| API docs page | `/docs`, `/api`, `/developer` | Parse HTML structure |
| JS bundles | `*.js` in page source | Extract route definitions, fetch calls, API client code |
| SDK/client library | npm/pip packages, GitHub repos | Reverse-engineer endpoints |
| Postman collection | Public or leaked | Import and extract |

Record: spec version, endpoint count, last-modified date if available.

### Step 2: Collect Actual Endpoints

From recon and runtime observation:

| Source | Method |
|--------|--------|
| Directory bruteforce results | From RECON_DB or prior recon |
| JS static analysis | Route strings, fetch/axios calls, API base URLs |
| Wayback Machine | Historical endpoints that may still respond |
| CT subdomain logs | API-specific subdomains (api.*, v2.*, internal.*) |
| Traffic analysis | Proxy logs if authorized |
| Error responses | 404 messages that leak valid paths |
| Mobile app | Decompile APK/IPA for API calls |

### Step 3: Build Comparison Matrix

| Endpoint | Method | In Spec? | Observed? | Params (spec) | Params (actual) | Auth (spec) | Auth (actual) |
|----------|--------|----------|-----------|---------------|----------------|-------------|---------------|
| /api/v1/users | GET | ✅ | ✅ | page, limit | page, limit, **debug** | Bearer | Bearer |
| /api/v1/users/export | GET | ❌ | ✅ | — | format, all | — | **None** |
| /api/v2/users | GET | ✅ | ❌ (404) | page | — | Bearer | — |
| /api/internal/health | GET | ❌ | ✅ | — | verbose | — | **None** |

### Step 4: Identify Discrepancies

| Discrepancy Type | Pattern | Priority | Why It Matters |
|-----------------|---------|----------|----------------|
| Shadow API | Not in spec, responds | **High** | Undocumented = likely untested security |
| Auth mismatch | Spec says auth, works without | **High** | Broken access control |
| Extra parameters | Accepts params not in spec | **Medium** | Hidden functionality, debug flags, injection surface |
| Deprecated alive | Spec removed, still responds | **Medium** | Old code = old vulnerabilities |
| Version drift | v1 and v2 both respond | **Medium** | Older version may lack security patches |
| Missing endpoint | In spec, 404 | **Low** | May indicate incomplete deployment |
| Response mismatch | Different fields than documented | **Low** | Information disclosure via extra fields |

### Step 5: Test Discrepancies

For each discrepancy, test in priority order:

1. **Shadow APIs**: test auth requirements (unauthenticated, user, admin), enumerate parameters, check for sensitive data
2. **Auth mismatches**: verify bypass is real (not cached response), test with expired/invalid tokens
3. **Extra parameters**: test for injection, test debug/admin flags (`debug=1`, `admin=true`, `internal=1`)
4. **Deprecated endpoints**: test for known CVEs in older API versions, check if old auth mechanisms still work

### Step 6: Prioritize Findings

Severity ranking:
1. Shadow API with no auth returning sensitive data → Critical/High
2. Auth bypass on documented endpoint → High
3. Extra parameters enabling injection → Medium–High (depends on impact)
4. Deprecated endpoint with known vulnerability → Medium–High
5. Version drift with security regression → Medium
6. Information disclosure via undocumented response fields → Low–Medium

## Output Format

```markdown
## API Schema Diff — <target>

### Spec Source
- Type: <OpenAPI 3.0 / Swagger 2.0 / HTML docs / JS extraction>
- Endpoints documented: <N>
- Endpoints observed: <N>
- Overlap: <N> | Undocumented: <N> | Missing: <N>

### Discrepancy Table
| Endpoint | Method | Type | Priority | Detail |
|----------|--------|------|----------|--------|

### Recommended Findings
1. <finding with evidence pointer>
```

## Anti-Patterns

| Anti-Pattern | Why It Fails | Fix |
|-------------|-------------|-----|
| Trusting spec is complete | Most specs miss internal/debug endpoints | Always collect actual endpoints independently |
| Ignoring JS bundles | Frontend often references endpoints not in spec | Extract routes from all JS sources |
| Ignoring mobile API | Mobile apps often use different/older API | Decompile and diff if in scope |
| Testing only documented endpoints | Shadow APIs are where bugs hide | Full actual-endpoint enumeration first |
| Skipping deprecated endpoints | "It's old" ≠ "it's turned off" | Test every responding endpoint |

## Hard Rules

- GET-first on all discovered endpoints
- Run `bb-scope-safety-check` before testing undocumented endpoints with writes
- Do not fuzz undocumented endpoints without confirming they are in scope
- Record all discovered endpoints in Operation Log
- Do not assume an undocumented endpoint is unauthorized — verify auth requirements

## Cross-References

- `bb-scope-safety-check` — before testing undocumented endpoints
- `bb-surface-mapping` — source of observed endpoints
- `bb-auth-matrix` — integrate API auth findings into the full matrix
- `bb-web-vuln-scan` — API endpoints are part of OWASP coverage
- `bb-exploit-chain` — chain shadow API access into deeper exploitation
