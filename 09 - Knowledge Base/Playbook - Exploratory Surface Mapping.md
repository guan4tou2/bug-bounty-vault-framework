---
type: reference
category: playbook
tags: [playbook, exploration, surface-mapping, anti-pattern-bias]
last_updated: 2026-06-03
---

# Playbook -- Exploratory Surface Mapping (Exploration First, Anti-Streetlight Effect)

> **Core question**: Your hunter library all ran clean -- does that mean there are no vulnerabilities?
> No. It means you found "vulnerabilities that known techniques can find." **New attack surfaces are not under the streetlight.**

---

## 1. Why (Core Principles)

### Pattern = recall; Exploration = discovery

| Mode | Question Asked | What You Find |
|------|---------------|---------------|
| **Pattern / Hunter Scanning** | "Is there XSS here?" "Is there SSRF?" | Known vuln types -> known defenses -> high false negative rate |
| **Exploratory Surface Mapping** | "What can this component do? What happens if it breaks?" | New attack surfaces, target-specific primitive combos, business logic vulns |

**Rule (mandatory)**: Map the complete attack surface, ask "how could this break?" for each element, THEN run pattern checks. Never reverse this order.

### Why Hunters Clean Does Not Mean Done

- Hunters can only find vuln types that the pattern author thought of.
- High-bounty findings mostly come from **target-specific primitive combinations** (e.g., API multipart boundary + unexpected content-type + authorization logic = IDOR; no single hunter can find this).
- Running only hunters means letting your blind spots determine your testing scope.

---

## 2. 8 Vuln-Agnostic Surface Dimensions (Must Exhaustively Enumerate, No Gaps Allowed)

> Each dimension must list **specific elements**, not just checkmarks.

### D1: Every Input / Parameter (Every Input Point)

All user-controllable data: URL path, query string, POST body (JSON / form / multipart), HTTP headers (`X-*`, `Referer`, `Origin`, `Cookie`, `Authorization`), GraphQL variables, WebSocket frame, file upload content, metadata fields.

Note: **Hidden / auto-populated parameters** are more commonly vulnerable than obvious fields (e.g., `_method`, `format`, `locale`, `debug`).

### D2: Every Role (Auth Matrix)

List all roles (unauthenticated / free / paid / admin / internal service) x every function (CRUD + special actions) with their expected permissions.

Attack perspective: **horizontal privilege escalation** (role A -> role B resources), **vertical privilege escalation** (user -> admin functions), **unauthenticated paths** (bypass login entirely).

### D3: Every State Transition (Multi-Step Flows)

Shopping cart -> payment -> confirmation, email verification flow, password reset flow, OAuth authorization flow, multi-step onboarding, data state machine (draft -> published -> archived).

Attack perspective: **step skipping**, **replay**, **concurrent race conditions**, **mid-flow parameter modification**.

### D4: Every Trust Boundary

Frontend -> backend, backend -> third-party, frontend -> CDN -> backend, mobile app -> API, webhook receiver -> internal system, microservice A -> microservice B.

Attack perspective: every boundary is a **"who trusts whose data?"** question. More boundaries = more assumptions = more vulnerabilities.

### D5: Every Integration / Third-Party

Payment gateway, SSO provider (OAuth/SAML), storage (S3/GCS), CDN, push notification service, webhook outbound, email provider, map/geolocation API.

Attack perspective: **misconfiguration** (bucket public, callback missing state validation), **dependency confusion**, **third-party callback forgery**.

### D6: Every Dependency / Framework

Framework version, known CVEs, non-default debug endpoints (`/actuator`, `/clockwork`, `/_ignition`), framework-specific magic parameters (Laravel `_method`, Rails `format`).

Attack perspective: first run **bb-version-cve-precheck**, then consider framework-specific gadgets.

### D7: Every File / Upload (File Upload Surface)

File type whitelist, MIME detection method (magic bytes vs content-type header), storage path (stored directly in webroot?), filename sanitization, how backend serves the file (static? dynamic? preview?).

Attack perspective: **RCE via webshell**, **stored XSS via SVG**, **path traversal via filename**, **SSRF via file:// or http:// in content**.

### D8: Every Business Flow (Business Logic Flows)

Refund flow, discount code application, subscription upgrade/downgrade, API rate / quota billing, referral rewards, multi-currency conversion, batch operations.

Attack perspective: **negative amounts**, **integer overflow**, **quota bypass**, **free tier -> paid feature**, **ordering exploits**.

---

### Anomaly Radar (Must-Check)

The following characteristics = custom logic / non-standard implementation = highest bug density areas, **mark as high-priority**:

| Anomaly Characteristic | Why It Matters |
|----------------------|---------------|
| Custom auth token (not JWT/session cookie) | Custom = high probability of forgery |
| Non-standard headers (`X-Internal-Token`, `X-Admin-Bypass`) | May be residual dev shortcuts |
| Homegrown framework (framework name not Googleable) | No public CVEs but usually full of vulnerabilities |
| Duplicate endpoints (`/v1/` + `/legacy/` doing the same thing) | Legacy versions usually have fewer security updates |
| Mixed authentication methods (some use JWT, some use session) | Boundary inconsistency = IDOR breeding ground |
| Both API gateway and direct service ports exposed externally | May bypass gateway authorization logic |

---

## 3. Method -- Five-Step Operating Procedure

### Step 1: Build Attack Surface Map Table (Write to RECON_DB)

In the `## Attack Surface Map` section of `RECON_DB.md`, build the table:

```markdown
| Element | Dimension | Sub-type | Notes | Threat Hypothesis | Priority | Tested? |
|---------|-----------|----------|-------|-------------------|----------|---------|
| POST /api/order | D1 | JSON body | amount, currency, items[] | Negative amount -> refund attack? currency mismatch? | HIGH | [ ] |
| GET /admin/export | D2 | Role boundary | Docs say admin-only | Can a regular user access it? Does server verify JWT role claim? | HIGH | [ ] |
| OAuth callback /auth/callback | D3+D5 | State transition + Integration | Google SSO | Is state validated? CSRF possible? | HIGH | [ ] |
```

Rule: every endpoint / input / flow must have its own row; do not merge.

### Step 2: Write Threat Hypothesis for Each Element (Free text, Mandatory)

**Cannot be blank**, cannot just write "check for XSS". Must write a **specific breakage hypothesis**:

- Good example: "`filename` field does not strip `../`; path concatenation when serving the upload may enable path traversal; also, does inline preview of SVG with embedded JS trigger execution?"
- Bad example: "test XSS", "check auth", "fuzzing"

**This forced-thinking step is the core of exploration** -- replacing it with tick-boxes defeats the purpose.

### Step 3: Mark Anomalies (High Priority)

Cross-reference against the Anomaly Radar in section 2; mark homegrown, non-standard, legacy rows as `ANOMALY` + `HIGH`. **Start testing from these.**

### Step 4: Test Hypothesis Per Element

Execute corresponding tests for each row's Threat Hypothesis, record results.

- Productive -> candidate -> run [[bb-attack-chain-review]] -> [[bb-evidence-readiness]] -> Finding
- Unproductive -> mark `[x]` on the row, record testing methods used (for dedup + knowledge capture)

### Step 5: Run Pattern / Hunter Check (As Closing Backstop)

**Only after all hypotheses are tested**, run nuclei / bbflow hunter / pattern scan. The purpose is "confirm I haven't missed known vuln types," NOT to let them drive testing scope.

---

## 4. Session Gate (Mandatory -- Must Check Before Closing Session)

```
SURFACE MAP GATE (audit_workspace.sh will detect)
[ ] RECON_DB "## Attack Surface Map" exists
[ ] Every endpoint from Discovered Paths has a row in the Surface Map
[ ] Every row's Threat Hypothesis field is non-empty
[ ] Anomalies are marked and tested with priority
[ ] Sessions with Findings must not have an empty or fewer-than-5-rows Surface Map
```

If the Surface Map has gaps, the session must not be marked complete.

---

## 5. Anti-Gaming (Anti-Cheat Rules)

These behaviors violate the spirit of this playbook:

| Cheat Behavior | Why It Is Not Acceptable |
|----------------|-------------------------|
| 8 rows each corresponding to 8 dimensions, but no specific elements | You are checking off dimensions, not mapping surfaces |
| Threat Hypothesis only writes vuln type ("XSS") without mechanism | No thinking = no exploration |
| Surface Map built then immediately running nuclei | Violates "exploration first" principle |
| Copying previous target's Surface Map | Every target's elements are different |
| Waiting for hunters to finish before filling in Surface Map | Order must be: map -> hypothesis -> test -> hunter |

**Audit mechanism**: `audit_workspace.sh` checks the ratio of Surface Map row count vs Discovered Paths count; warns if the ratio is too low.

---

## 6. Position in Lifecycle

```
[Recon / Fingerprint]
       |
[Surface Mapping (this Playbook)]   <- vuln-agnostic, list all elements
       |
[Per-element Hypothesis Testing]    <- for each element ask "how could this break?"
       |
[Candidate Found]                   <- initial indicators present
       |
[bb-scope-safety-check]             <- must run before POST/PUT/DELETE
[bb-attack-chain-review]            <- can it chain?
[bb-evidence-readiness]             <- is evidence strong enough?
[bb-attempt-recorder]               <- cannot confirm -> record negative
       |
[Finding -> Submission -> FORM]     <- dedup happens here (not during mapping)
       |
[Pattern / Hunter Check (closing)]  <- confirm known types not missed
       |
[bb-knowledge-capture]              <- capture new techniques, failure lessons to KB
```

**Note**: Dedup (reading `FINDINGS_QUICK_REF.md`) happens at Finding-creation time, **not during the Surface Mapping phase**, to prevent KB content from framing your exploratory perspective.

---

## 7. RECON_DB Integration Example

Add the following section to `workshop/<target>/RECON_DB.md` (future versions of init_target.sh will auto-create the skeleton):

```markdown
## Attack Surface Map

> Surface Mapping completed: 2026-06-03 14:00
> Mapped by: Claude Code session XXX
> Endpoints covered: 23 / Discovered Paths count: 23 (100%)

| Element | Dim | Sub-type | Threat Hypothesis | Priority | Tested? |
|---------|-----|----------|-------------------|----------|---------|
| POST /api/v2/transfer | D1+D8 | JSON body / business flow | Negative amount? Same account for to/from? Currency conversion boundary? | HIGH ANOMALY | [ ] |
| GET /internal/health | D4 | Trust boundary | Internal endpoint exposed externally, leaks env vars? | HIGH | [ ] |
| multipart /api/upload | D7 | File upload | filename `../`? SVG XSS? content-type spoofing? | HIGH | [ ] |
| ... | ... | ... | ... | ... | ... |

### Anomaly List (ANOMALY)

- `POST /api/v2/transfer`: Custom HMAC signature (non-standard JWT), field order affects hash
- `GET /debug/vars`: Non-standard path, not appearing in documentation
```

---

## 8. Cross-Reference

- [[Checklist - Attack Surface Coverage]] -- per-dimension specific testing checklist
- [[Playbook - Recon Methodology]] -- Phase 1-8 subdomain/infrastructure recon; Surface Mapping executes after Phase 4 (web probing)
- [[Lessons Learned]] -- streetlight effect failure cases, past target-specific primitive combo high-bounty findings
- `bb-surface-mapping` skill (planned) -- auto-scan RECON_DB Discovered Paths to generate Surface Map skeleton
- [[Pattern - Business Logic Flaws]] -- D8 business logic vuln type classification
- [[Playbook - API Attack Surface]] -- D1/D5 API-specific expansion

---

> **Remember this playbook in one sentence**: Under the streetlight you find pennies; in the dark corners lie gold bars. Illuminate every corner first, then use hunters to confirm you haven't missed the pennies.
