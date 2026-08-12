---
type: reference-card
title: "Remediation Verification (Retest) Methodology"
tags: [methodology, retest, remediation, regression-testing, reporting]
status: draft
last_updated: 2026-08-12
---

# Reference Card - Remediation Verification Methodology

> **TL;DR**: A six-phase framework for verifying that a vendor's fix actually closes a reported vulnerability, rather than just closing the exact reported PoC. Sources include HackerOne's pentest retesting guidance, Halock/Amatas/NFLO retesting methodology writeups, Invicti's continuous-security-testing research, and academic work on incomplete-patch analysis (arXiv 2607.13206).

## Quick Reference

### Six-Phase Framework

| Phase | Purpose |
|---|---|
| 0 | Pre-Retest Gate — authorization, environment alignment, PoC availability, fix-analysis reading |
| 1 | Direct Reproduction — replay the original PoC exactly |
| 2 | Variant & Bypass Testing — the phase most often skipped |
| 3 | Regression Testing — did the fix break or newly expose something else |
| 4 | Verdict Assignment — FIXED / PARTIAL / STILL PRESENT / HOST GONE / BLOCKED AT EDGE / NOT VERIFIABLE / RISK ACCEPTED |
| 5 | Documentation & Vendor Communication |
| 6 | Continuous Regression Library — convert each FIXED finding into an automated regression check |

### Verdict Table (Phase 4)

| Verdict | Criteria | Minimum evidence |
|---|---|---|
| **FIXED** | Original PoC does not reproduce **and** at least one variant also fails **and** the fix is at the root-cause level (not just surface blocking) | Original PoC output + variant output + confirmation of the fix mechanism |
| **PARTIAL** | Original PoC fails but a variant succeeds, or only some of multiple affected hosts/endpoints were fixed | Output of the successful variant |
| **STILL PRESENT** | Original PoC still reproduces | PoC output |
| **HOST GONE** | DNS no longer resolves + CT certificate issuance has stopped + no sibling host is alive | `dig` output + certificate-transparency check + evidence distinguishing "service decommissioned" from "IP-level block" |
| **BLOCKED AT EDGE** | Endpoint is alive but returns 403/reset/timeout — **cannot determine whether the underlying code was fixed** | HTTP response + an explicit "not determinable" statement |
| **NOT VERIFIABLE** | A read-only method cannot verify this (would require a destructive/write action to prove) | Explanation of why it cannot be verified |
| **RISK ACCEPTED** | Vendor has stated in writing they accept the risk and do not intend to fix | Vendor statement excerpt/screenshot |

**Three hard rules:**
1. **Unreachable ≠ fixed** — NXDOMAIN / TLS reset / 403 must always be classified as HOST GONE or BLOCKED AT EDGE, never FIXED
2. **FIXED requires positive evidence** — "I can't see the vulnerability anymore" is not enough; you need "I can see the fix taking effect" (e.g., the same endpoint returns 401 both with and without the original credential, proving the credential itself was revoked)
3. **The same evidence cannot support two contradictory verdicts** — a single HTTP response cannot be cited as FIXED in one place and STILL PRESENT in another

## Details

### Phase 0: Pre-Retest Gate

- [ ] **Authorization confirmed**: written consent on file; scope defined (host list, permitted actions, write-testing allowed Y/N, validity window)
- [ ] **Environment alignment**: confirm the retest target matches the vendor's actual production deployment (not staging/dev)
- [ ] **Original PoC available**: every finding's PoC command can be copy-pasted and re-run
- [ ] **Vendor remediation statement**: distinguish "fixed" vs. "risk accepted" vs. "won't fix" — track each on a different verdict path
- [ ] **Fix analysis**: if a commit/changelog/release notes are available, read them first so testing can target what actually changed

### Phase 1: Direct Reproduction

Re-run every original PoC with **exactly the same command**. Record:

| Field | Required |
|---|---|
| Finding ID | ✓ |
| Original PoC command | ✓ |
| Execution time (UTC) | ✓ |
| HTTP status + response size | ✓ |
| Key response excerpt (truncated — never store full sensitive data) | ✓ |
| Difference from the original result | ✓ |

### Phase 2: Variant & Bypass Testing (most commonly skipped)

> "You cannot judge FIXED just by replaying the original payload — the fix may only have blocked the single path that was reported." — Invicti / arXiv 2607.13206

Every finding marked FIXED needs **at least one variant test**:

| Vulnerability class | Variant testing direction |
|---|---|
| SQLi | Encoding variants (URL-encode, double-encode, Unicode), different injection points on the same endpoint, different SQL dialects |
| XSS | Different contexts (attribute/JS/HTML), WAF-bypass payloads, DOM-based paths |
| IDOR | Same resource with a different HTTP method (GET fixed → try PUT/PATCH/DELETE?), sibling endpoints |
| Auth bypass | Same credentials against a different endpoint, token-format variants, header-name case variants |
| Hardcoded credential | Same key against a different endpoint, a shape-matched fake key as a negative control, verify key rotation actually happened |
| File upload | Different MIME type, different extension, path-traversal variants |

**Sibling host enumeration (the Phase 2 starting move)**:
- Enumerate every known host on the same root domain from prior recon data
- Query `certspotter` / `crt.sh` for recently issued sibling certificates
- **Prioritize newly deployed siblings** — a real case involved the main site being fixed while a sibling deployed just days earlier was completely unpatched

**Narrow-patch detection**:
- Were all sibling endpoints/hosts sharing the same root cause actually fixed? (measured real-world detection rate for narrow patches: ~25%)
- Did **every** endpoint of the same service get an auth check added, or only some of them? (a real case: 5 endpoints shared the vulnerable pattern, only 2 were fixed)
- Does the same pattern exist in other modules of the same codebase?
- Is the mitigation a WAF/network-layer block rather than a code fix? → attempt bypass (encoding, HTTP method, path normalization)

### Phase 3: Regression Testing

> "The fix touched a shared code path — you must test whether other consumers of that path broke, or gained a new vulnerability."

- [ ] Do other consumers of the modified auth middleware / input sanitizer / API gateway still work correctly?
- [ ] Did the fix introduce a new error path (a new 500, new debug output, new stack trace)?
- [ ] Did the fix unintentionally expand the attack surface (a new endpoint, a new redirect, a new CORS header)?
- [ ] Has a previously-FIXED finding reappeared in a **later deployment** (code revert / merge conflict)?

**Sanitization side-effect check** (do this after any injection fix):
Input sanitization changes the error path — a sanitized value embedded into the original template can trigger a syntax error that exposes the error handler:
- [ ] A sanitized SQL value → syntax error → stack trace (ORM exception class + mapper path + SQL template)
- [ ] Spring Boot `X-Application-Context` header → service name:environment:internal port
- [ ] Version / exception class name / internal path leaking in an error response
- [ ] HTTP status code inconsistent with the body's own status field (a common pattern in some frameworks: HTTP 200 with a body containing `code: 401`)

### Phase 4: Verdict Assignment

See Quick Reference above.

### Phase 5: Documentation & Vendor Communication

Minimum fields (per finding):

```
Finding ID | Original severity | PoC replay result | Variant test result | Verdict | Confidence | Notes
```

Overall report structure:
1. Authorization status + scope
2. Confirmed fixed (with positive evidence)
3. Still present (original PoC reproduces)
4. Partially fixed (narrow patch)
5. Not verifiable
6. Not reachable (HOST GONE / BLOCKED)
7. New findings discovered during retest
8. Cleanup checklist (test accounts, payload files, callback URLs)
9. Regression test results
10. Recommendations (including a suggested cadence for the next retest)

### Phase 6: Continuous Regression Library

Convert every FIXED finding into a re-runnable regression test:

```bash
# regression_FINDING-004.sh
# Expected: non-200 (SQLi patched)
result=$(ssh remote-vps "curl -sk -o /dev/null -w '%{http_code}' 'https://target.example.com/api/endpoint?id=1%27%20AND%201=1--'")
if [ "$result" = "200" ]; then echo "REGRESSION: FINDING-004 SQLi reappeared"; exit 1; fi
```

Storage location: a per-target `regression/` directory alongside the rest of the target's working files.
Trigger cadence: monthly automated run / whenever the vendor announces a new deployment / before the next scheduled retest.

## Anti-Patterns

1. ❌ Judging FIXED just from replaying the original payload (no variant testing)
2. ❌ Treating a WAF block as a fix (surface-level blocking ≠ root-cause fix)
3. ❌ Treating a disappeared endpoint as FIXED (HOST GONE ≠ FIXED)
4. ❌ Only testing the endpoint named in the report, ignoring siblings that share the same root cause
5. ❌ Not recording the exact retest command and output (impossible to verify after the fact)
6. ❌ Re-running an automated scanner and calling it done (ML/similarity-based tools score under 50% F1 on partial-fix detection)
7. ❌ Not checking whether the fix introduced a new vulnerability (missing regression testing)
8. ❌ Incomplete cleanup checklist (untracked test accounts, payload files, callback IPs)
9. ❌ PoC artifacts scattered across multiple locations with no single source of truth (a real case: re-running a PoC to produce a screenshot left additional artifacts that were never listed in the disclosure email)
10. ❌ Only testing the hosts listed in the original finding's `affected_hosts`, without enumerating siblings on the same root domain

## Related

- [[Reference Card - GET-first Dangerous Ops]]
- [[bb-retest-gate]]
- [[Checklist - IDOR Test Coverage Matrix]]
