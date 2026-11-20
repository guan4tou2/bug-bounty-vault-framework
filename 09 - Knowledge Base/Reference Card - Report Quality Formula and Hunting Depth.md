---
fileClass: ReferenceCard
title: "Report Quality Formula and Hunting Depth"
type: reference
trigger: "hunting depth, report quality, how to increase bounty, how deep should a chain go, how to write impact, pre-report self-assessment, review finding quality"
tags: [reporting, hunting, methodology, quality]
---

# Report Quality Formula and Hunting Depth

> Established 2026-11-20 based on HexBrain 15,244 disclosed report analysis of high-bounty patterns.
> This card covers both the **hunting phase** (how deep to go) and the **reporting phase** (how to write it up).
> Vulnerability bar (whether it qualifies): [[Reference Card - Vulnerability Bar and Report Bar]].
> Report writing: [[Reference Card - Report Writing Standard]] + [[Reference Card - Report House Style]].

## 1. Report Quality Formula

```
Report Value = Root Cause Depth × Chain Length × Impact Specificity × Defense Bypass
```

Four dimensions multiply. If any dimension is zero (e.g., impact is just the vulnerability class name), overall value drops sharply.

## 2. Four-Dimension Grading

| Dimension | Level 1 (passes bar) | Level 2 (good) | Level 3 (high bounty) |
|---|---|---|---|
| **Root Cause Depth** | Describes symptom ("not validated") | Component + parameter (`GraphQL deleteSnap missing owner_id check`) | Source code path file:line + fix at function level |
| **Chain Length** | Single vulnerability | 2-step chain (vuln → meaningful impact) | 3+ steps, each independently proven |
| **Impact Specificity** | States consequence sentence | Quantifies consequence (N records / N users / what scope) | Shows artifact (redacted token / shell / data screenshot) |
| **Defense Bypass** | N/A (no defense) | Bypasses one layer (CSP / WAF / rate limit) | Bypasses multiple layers + explains why |

**Grading criteria:**
- P1 target: root cause ≥ L2 + chain ≥ L2 + impact ≥ L2
- P2 target: each ≥ L1, with at least one ≥ L2
- Not reaching this depth ≠ do not report — but honestly state where you stopped and why

## 3. Hunting Phase: Depth Improvements

### 3.1 Five-Question Depth Checklist (after finding a vuln)

After V1–V3 pass (confirmed it is a vuln), **before moving to the next target**, ask yourself:

1. **Can I go one step further?** From "read data" → "obtain a token and use it." From "XSS fires" → "steal cookie and log in." Each additional step is a chain link.
2. **Does the target have defenses?** CSP, WAF, rate limit, CSRF token, auth middleware — record results for each tested, record methods for each bypassed. **No defenses = explicitly write "none observed".**
3. **How far did I trace the root cause?** OSS target: did I find the source code? Closed-source: did I do a response diff? Or did I stop at "it doesn't validate"?
4. **Can I quantify the impact?** Not "can read data" but "can read 10,432 user PII records." Not "can delete posts" but "can delete any user's Spotlight content (affecting 2.3M creators)."
5. **Did I run end-to-end?** The entire chain executed in one session? Step 1 output fed directly into Step 2?

### 3.2 Per-Vuln-Type Depth Targets

| Vuln Type | Stop at L1 (low bounty) | Reach at least L2 | L3 Target |
|---|---|---|---|
| **IDOR** | Change ID, see another user's data | Read+Write+Delete full verb coverage + cross-tenant | Quantify affected record count + chain to ATO/PII |
| **SSRF** | Out-of-band callback | Read internal services / cloud metadata | Obtain token → use token (read S3, open shell) |
| **XSS** | alert(1) fires | Steal cookie/token + demonstrate | CSP bypass + actual ATO (log in as victim) |
| **Auth Bypass** | Unauthenticated access to one endpoint | Multi-endpoint coverage + data volume | Chain to admin privileges / write / RCE |
| **Info Disclosure** | See internal paths / versions | Obtain usable token / key / PII | Use obtained token for next step (chain) |

### 3.3 Chain Thinking Framework

After finding a vulnerability, try extending in this order:

```
Current primitive → Can it escalate?
  Read → What was read? Any token/key? → Use it to log in / call API
  Write → What can be written? Can config be changed? → Privilege escalation / RCE
  Delete → What can be deleted? Can auth be deleted? → Password reset / takeover
  Enumerate → Any IDs? → Use in IDOR

Cannot extend → Honestly record where you stopped and why → Still report (but do not inflate impact)
```

### 3.4 Defense Bypass Probe Checklist

| Defense Type | What to Test |
|---|---|
| CSP | Has unsafe-inline? JSONP endpoint on allowlist? base-uri gap? |
| WAF | Encoding bypass (double URL encode, unicode)? Alternative payload? HTTP method switch? |
| Rate limit | IP rotation? Endpoint variants? Header forgery (X-Forwarded-For)? Concurrency race? |
| CSRF token | Remove token still works? Another session's token accepted? Cross-site token fixation? |
| Auth middleware | Path normalization bypass? HTTP method override? Case sensitivity? Trailing slash? |
| Cloud metadata | v1beta1 no header required? SSRF redirect? DNS rebinding? |

### 3.5 Root Cause Tracing Methods

| Target Type | Method | Trace To |
|---|---|---|
| **OSS** | Read source → find function handling your payload → trace data flow | file:line + what check is missing + where to fix |
| **Closed-source Web** | Response diff (normal vs abnormal request) → infer backend logic | Component + parameter + inferred logic (labeled `[inference]`) |
| **Firmware** | Reverse engineering → find handling function → trace data flow | function + offset + what boundary check is missing |
| **SaaS API** | API schema analysis + permission matrix → find missing authz check | endpoint + action + what role/resource check is missing |

## 4. Pre-Submit Self-Assessment

| Dimension | Your Level | P1 Target | P2 Target |
|---|---|---|---|
| Root Cause Depth | ___ / 3 | ≥ 2 | ≥ 1 |
| Chain Length | ___ / 3 | ≥ 2 | ≥ 1 |
| Impact Specificity | ___ / 3 | ≥ 2 | ≥ 2 |
| Defense Bypass | ___ / 3 | ≥ 1 when defense exists | ≥ 1 when defense exists |

## 5. High-Bounty Pattern Quick Reference (from HexBrain analysis)

| Pattern | Example | Effect |
|---|---|---|
| Source-code-level root cause | GitLab XSS $16K: 4 Ruby files, explaining string interpolation escape step by step | Triager can locate fix directly |
| Multi-step attack chain | Shopify SSRF $25K: SSRF → GCP metadata → kubelet → root shell (3 steps) | Severity jumps tiers |
| Concrete blast radius | HackerOne SSRF $25K: showed AWS temporary token's AccessKeyId + SecretAccessKey | Surpasses "theoretically possible" |
| Existing defense bypass | GitLab XSS $16K: CSP bypass using Google JSONP + setTimeout callback | Confirmed bounty uplift |
| Current vs Expected | GitLab SSRF $10K: "AttributeCleaner should remove remote_attachment_url" | Triager writes ticket directly |

## Related

- [[Reference Card - Vulnerability Bar and Report Bar]] — V1–V3 vulnerability bar and R1–R3 report bar
- [[Reference Card - Report Writing Standard]] — Report writing (sentence structure, structure, length)
- [[Reference Card - Report House Style]] — Style four rules
- `bb-exploit-chain` skill — On-the-spot chaining reflex + Post-Chain Depth Quality Gate (self-assessment entry)
- `bb-submission-readiness` skill — Final gate before submission
