---
name: bb-retest-gate
description: Use when retesting a target, verifying vendor patches, or running regression tests — six-phase structured methodology for remediation verification. Enforces variant/bypass testing on FIXED verdicts, regression checks, evidence standards, and cleanup tracking.
---

# Bug Bounty — Remediation Verification Gate (Retest)

## Trigger

Run this when:
- "retest X" / "verify fixes" / "check if patched"
- Vendor says they fixed something and you need to verify
- Periodic regression check on parked/submitted findings
- Any remediation verification session

## Phase 0: Pre-Retest Checklist (BLOCK if not met)

Before touching any endpoint:

- [ ] **Authorization confirmed**: written consent on file. If no written consent, mark "authorization status: verbal/unconfirmed" at the report header
- [ ] **Scope documented**: which hosts, which actions allowed, write-testing Y/N, validity period -> record in retest frontmatter
- [ ] **Vendor patch list**: request per-item declaration of "fixed / risk-accepted / will-not-fix". **If unavailable, document "not obtained"**
- [ ] **Fix analysis**: if commit/changelog is available, read it before testing; if not, document as "blind retest"
- [ ] **Original PoC inventory**: confirm each Finding's PoC commands are available and executable
- [ ] **Residual inventory**: catalog prior PoC artifacts left in production (test accounts, payload files, callback URLs)

## Phase 1: Direct Reproduction (Original PoC Replay)

Execute against each Finding one by one:

```
Finding ID | Original PoC Command | Time (UTC) | Status | Size | Key Response | vs Original Diff | Initial Verdict
```

Rules:
- **Exact same command** — no "close enough"
- GET-first: POST/PUT/DELETE requires understanding consequences first
- Log each test in the operation log
- Unreachable endpoints -> immediately differentiate using CT telemetry + DNS: HOST GONE vs BLOCKED AT EDGE
- **Persist before verifying further**: write each finding's Phase 1 verdict to the report table (and start its Phase 6 regression script) immediately after that finding's probe completes — do not wait until Phase 2/3 finish. Phase 2 (variant/bypass testing) is slower and more failure-prone (multiple payloads, WAF interaction, sibling-host enumeration); if it times out partway through, the already-durable Phase 1 verdicts are still usable instead of being lost with the rest of the session.

## Phase 2: Variant & Bypass Testing (Mandatory)

> **Every Finding initially judged FIXED must have at least one variant test. A FIXED verdict without variant testing = confidence level "preliminary" only — do not state it as definitive in external reports.**

Select variant directions based on vulnerability type:

| Vulnerability Type | Minimum Variant Test |
|---|---|
| SQLi | Encoding variants (URL/double/Unicode) + different injection points |
| XSS | Different contexts + WAF bypass payloads |
| IDOR | Same resource with different HTTP methods (GET fixed -> PUT/DELETE?) |
| Auth bypass / API key | Same key on different endpoints + key format variants + header name variants |
| File upload / path traversal | Different MIME types + different extensions + encoded paths |
| Info leak | Same endpoint with different params + sibling endpoints |

**Sibling Host Enumeration (Phase 2 starting move — mandatory)**:
1. Search RECON_DB for all known hosts under the same root domain
2. Check certificate transparency logs / `crt.sh` for recently issued sibling certificates
3. Newly deployed siblings (certificate date after Phase 1) get **priority testing**

**Narrow Patch Detection (mandatory)**:
1. Are ALL sibling endpoints/hosts with the same root cause patched? (Most common failure: main site fixed, subsite missed)
2. Did ALL endpoints on the same service get authz added? (Not just the one in the PoC)
3. Do other modules in the same codebase have the same pattern? (grep for the same function/middleware)
4. WAF/network-layer blocking does not equal code fix -> attempt encoding bypass

Record format:
```
Finding ID | Variant Type | Variant Payload | Result | Conclusion
```

## Phase 3: Regression Testing

For each FIXED Finding and its patch impact radius:

- [ ] Other endpoints using the modified middleware/sanitizer still function correctly
- [ ] Patch has not introduced new error paths (new 500s / debug output / stack traces)
- [ ] Patch has not accidentally exposed new attack surface (new endpoints / redirects / CORS changes)
- [ ] Previously FIXED findings have not reappeared after new deployment (code revert detection)

**Sanitization Side Effect Check (post-injection-fix — mandatory)**:
After SQLi/XSS/CMDi fixes, replay with sanitized input and check:
- [ ] Does the sanitized value embedded in a template trigger a syntax error -> stack trace leak?
- [ ] Does the error handler leak exception class / mapper path / SQL template?
- [ ] Do response headers leak service metadata (e.g., `X-Application-Context` with service name + environment + port)?

**Common Info Leak Header Check**:
- [ ] `X-Application-Context` (Spring Boot: service:environment:port)
- [ ] `Server` / `X-Powered-By` with version numbers
- [ ] `version` field in error responses (NestJS / Express)
- [ ] HTTP status code vs body status mismatch (e.g., 200 + body `code:401`)

## Phase 4: Final Verdict Assignment

Assign verdicts only after Phases 1-3 are ALL complete.

| Verdict | Criteria |
|---|---|
| **FIXED** | Original PoC fails **AND** at least one variant also fails **AND** root cause fixed (not just surface block) |
| **PARTIAL** | Original PoC fails but variant succeeds, or multi-host fix covers only some hosts |
| **STILL PRESENT** | Original PoC reproduces |
| **HOST GONE** | DNS does not resolve + CT certificate updates stopped + no siblings alive |
| **BLOCKED AT EDGE** | Endpoint alive but 403/reset; underlying state indeterminate |
| **NOT VERIFIABLE** | Read-only methods cannot verify the fix |
| **RISK ACCEPTED** | Vendor has documented acceptance of the risk in writing |

**Iron rules:**
1. Unreachable does not equal fixed
2. FIXED requires positive evidence ("cannot see it" is not enough; need "can see the fix working")
3. The same evidence cannot support contradictory conclusions

Stamp each Finding's frontmatter:
```yaml
retest_date: YYYY-MM-DD
retest_verdict: <verdict>
retest_variant_tested: true/false
retest_note: "..."  # for low-confidence or special situations
```

## Phase 5: Report Structure

Retest report must contain:

1. Authorization status + scope + methodology statement
2. Fixed findings (positive evidence + variant test results)
3. Still present findings (PoC reproduction)
4. Partially fixed findings (narrow patch details)
5. Not verifiable + unreachable findings
6. New discoveries
7. **Regression test results** (if not performed, state "not executed")
8. Residual cleanup checklist
9. Authoritative verdict table (one table covering all findings)
10. **Methodology gap self-assessment** (Phase 2/3 coverage rate)

## Phase 6: Regression Library

**Generate during Phase 1 testing (not retroactively)** — for each FIXED Finding, create a re-runnable regression script:

```bash
#!/bin/bash
# regression_<FINDING-ID>.sh — <one-line description>
# Expected: non-200 (vulnerability patched)
result=$(curl -sk -o /dev/null -w '%{http_code}' '<url>')
if [ "$result" = "200" ]; then echo "REGRESSION: <FINDING-ID> reappeared"; exit 1; fi
echo "<FINDING-ID>: still fixed ($result)"
```

Add a `run_all.sh` runner (exit 1 if any regression detected).

Storage: `workshop/<target>/regression/`
Trigger: monthly / vendor new deployment / before next retest

## Cleanup Tracking Checklist

> **PoC residuals have one canonical location**: the operation log's `[residual]` tag. Submissions and reports reference this list — they do not duplicate it. Re-running a PoC (e.g., for screenshots) creates new residuals that must be appended.

Before completing the retest:

- [ ] All test accounts created by PoCs are listed in the cleanup checklist (with account ID + identifying field values)
- [ ] **Residuals from re-running PoCs** (e.g., for screenshots or form evidence) are appended
- [ ] All uploaded payload files are listed (with path + host)
- [ ] All callback URL infrastructure status confirmed (is the IP still under your control?)
- [ ] Cleanup list is complete (cross-reference Finding / Submission / Form PoC sections — counts must match)

## Quality Gate

Minimum standard before the report can be sent externally:

- [ ] Phase 1 coverage = 100% (all Findings replayed)
- [ ] Phase 2 coverage > 0 (at least high-risk FIXED findings have variant testing)
- [ ] Verdict table count matches Finding frontmatter count (script-verifiable)
- [ ] No "same evidence, opposite conclusion" contradictions
- [ ] No severity inflation (CVSS changes require new supporting evidence)
- [ ] Residual cleanup checklist is complete
- [ ] Independent audit completed (adversarial agent review)
