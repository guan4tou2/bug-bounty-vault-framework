---
name: bb-surface-mapping
description: Use when starting work on any target — after recon, before any pattern/hunter/scan/dedup — to force vuln-agnostic full attack-surface mapping that counters the streetlight effect (pattern tunnel vision). Triggers include start recon, explore, map the attack surface.
---

# Bug Bounty — Surface Mapping (explore-first, anti-streetlight)

This is the **FIRST gate in the candidate lifecycle**. It exists because relying on a known pattern/hunter library biases hunting toward known vulnerability types and misses novel surface — the "streetlight effect" (searching only where the light is good).

**Map the full surface vuln-agnostically and ask "how could this break?" per element BEFORE running any pattern/hunter/scanner. Patterns are a post-mapping checklist, not the search starting point.**

## Trigger

Run this at the very start of working a target — after recon enumeration, before any pattern/hunter/scan/dedup:

- "start recon", "explore", "map the attack surface", "begin hunting"
- whenever you are about to run a scanner / hunter / grep-for-known-sinks → STOP, map first

## Hard Rule

A target that has discovered endpoints but an **empty Attack Surface Map is incomplete**. Do not proceed to pattern-matching, scanning, or close a session by skipping this. If your vault has an audit/lint step, it should fail this condition (the reference automation does — a target with Discovered Paths and an empty Surface Map is a hard violation).

**Scan-time block:** the reference automation ships `automation/surface_map_gate.sh`, a `PreToolUse(Bash)` hook that **blocks the scan in real time** — `bbflow hunt <target>` / `hunt-*.sh <target>` exits 2 when that target's RECON_DB has Discovered Paths but an empty Surface Map. Loud override: prefix with `BB_SKIP_SURFACE_GATE=1`.

## Context discipline (delegate the large reads)

Mapping means reading a lot of recon files / URL lists — a "bulk read" chore. When an endpoint list exceeds a few dozen rows, **dispatch an `Explore` or `endpoint-interest-scorer` subagent to read it and return only a Surface Map summary + top-N + reasons**; do not `Read` the raw recon files one by one on the main thread. The map body (nodes/edges) is written to the graph file, not pasted back into the main context.

## Pre-gates (run in this order, before Method)

### Gate -3 — Is your ranking criterion a *search* filter or a *submit* filter?

Before ranking candidates or deciding "what to hunt first", answer one sentence:

> **Is the criterion I'm about to rank by a *search* condition or a *submission* condition?**

They often look identical, but using one for the other prunes away the vein.

- A *submission* condition ("can this be reported? does it reach a shipping surface? is impact enough?") decides **reporting and resource allocation**.
- A *search* condition ("could there be something here?") decides **where to look**.

**A submission condition must never be used to prune the search tree.** Whether a bug is worth reporting is only knowable *after* you've found it and judged channel + impact — using it as a filter beforehand is deciding with information you don't have yet. (Real case: a class of findings was deemed low-value for *submission*; that reasoning was then wrongly used as a *search* filter, down-ranking a bucket — and the one real finding of the round was sitting in that bucket.) Same misuse to watch for: pruning by "this target's historical finding types" (you'll only ever find more of the same); pruning by "where source is available to run a sanitizer" (verifiability ≠ value).

### Gate -2 — Passive OSINT before any active request

**Mandatory before Gate -1** (needs no authorization, does not touch the target, zero risk). Active recon never surfaces these — they live in other people's repos, historical snapshots, and TLS-certificate SANs, not in the target's HTTP responses. (A target whose active recon is exhausted after many rounds routinely yields employee accounts, historical token patterns, and dozens of historical subdomains on the first passive-OSINT pass — see [[LL-336]].)

| # | Item | Tool (example) | Output |
|---|---|---|---|
| 1 | CT logs | `crt.sh` + `certspotter` | historical subdomains |
| 2 | Wayback | `waybackurls` / web.archive.org | historical endpoints / config paths |
| 3 | GitHub code search | `site:github.com "<domain>"` + `org:<org>` + employee `*-test/*-poc` repos | leaked config / token / endpoint / account |
| 4 | Gitee search | `site:gitee.com "<domain>"` (mandatory for CN-region targets, else `skipped:not-cn-target`) | same |
| 5 | Shodan / Censys | `shodan search hostname:<domain>` | IP / port / service / banner |
| 6 | Passive DNS | SecurityTrails / passive-DNS source | historical A/CNAME/NS |
| 7 | Disclosed reports | public hacktivity / advisory archives | known vuln types → avoid dupes, find regressions |
| 8 | DNS infra mapping | `dig` all names → group by IP → TLS SAN → default vhost | infrastructure topology |

Items 1–7 are pure passive; item 8's TLS-SAN / bare-IP requests are active, so split that tracking. **The seven items are a floor, not a ceiling** — above the floor, add target-specific OSINT (job-board tech-stack disclosures, FCC filings for IoT, app-store version history for mobile, regulatory filings for finance, …).

**Search-First principle (all phases, not just version/CVE):** any factual claim about the outside world → **search before claiming**, never from training data or memory. Test: if the fact "was A a year ago and might not be A now", search it; only principles fixed since an RFC/spec may be answered directly. This covers versions/CVEs/PoCs, default behaviors, WAF-bypass techniques, default creds, program scope/status, technique validity, API behavior, vendor patch status.

**Version → CVE instant trigger:** the moment any node's response carries a version string (`Server:` header, JSON `version`, `<meta generator>`) → **immediately** search `"<product> <version> CVE"` + `"… exploit"`. Do not wait for a dedicated CVE round.

**Three-tier verification ladder (version match ≠ exploitable):**

| Level | Evidence | Status | Reportable? |
|---|---|---|---|
| Version match | CVE affected range includes this version | `suspected` | ❌ |
| Static confirm | vulnerable code path found in source/binary; standalone sanitizer harness triggers | `suspected` | ❌ |
| Dynamic verify | **a full PoC achieves `expected_impact` on an authorized target or a proven-equivalent controlled environment** | `validated` | ✅ |
| Cannot dynamically verify | risk too high or environment-limited | `suspected` + `blocked:needs_auth` | ⚠️ ask for authorization or downgrade |

A matched version is `suspected`, not `validated`; a static/harness hit is still `suspected`; "a packet went out" ≠ impact. When a verification PoC would write data, disrupt service, or modify data, stop and ask for authorization first — the ceiling for acting without asking is pure reads (GET/HEAD/OPTIONS). Finding-creation rules: `expected_impact` is mandatory at creation (it is the success criterion); `suspected` requires a `verification_plan`; `validated` requires `verification_method` + `poc_ref`. Schema → [[Reference Card - Attack Surface Graph Schema]].

### Gate -1 — Disclosed pre-read evidence

Before Method step 0, confirm the disclosed-findings pre-read is complete (`automation/check_disclosed_preread.sh <target>`): an evidence file with `status: pre_read_complete` must exist. For a competition / prior-disclosure program this is mandatory — you may not skip it by claiming "no disclosed section". See [[Checklist - Disclosed Findings Pre-Read Gate]].

### Gate 0.5 — Find the system's own authorization model before testing authz

**Before testing any missing authorization, find out how the application itself defines who may do what.** That is the only evidence of "defect vs by-design" a vendor cannot overturn with "works as designed".

| Strength | Form | How to find |
|---|---|---|
| **Strongest** | a role × function matrix (RBAC policy table) | look for "permission"/"role"/"privilege" entities or pages; often a detail endpoint returning a wide table |
| Strong | the app enforces the same model elsewhere | e.g. one module overwrites a response field with the session's value → it knows the limit; another place not doing so = inconsistent enforcement |
| Medium | frontend gate bound to an operation code | map the endpoint to its UI gate |
| **Zero** | "this looks sensitive" | **not admissible as a basis** |

Getting this early makes every later authz judgment faster and more accurate: the matrix doubles as an authoritative coverage list (a `0/N` test account means anything it can do is a violation) and as the system's-own basis for "defect, not design" on each related finding.

> ⚠️ **When design intent is genuinely ambiguous, write it as a question to the client, not a Finding.** Reporting a by-design behavior as a defect damages the credibility of the genuinely-valid items in the same report.

## Method

0. **Run a recon floor first** (do not skip). Recon tool output is the raw material for the Surface Map; manual browsing alone does not count. At minimum: subdomain enumeration + live-host probing + historical URL mining (e.g. wayback/CDX) + crawl + a known-vuln scan pass + JS analysis. See `Playbook - Recon`. **APK / mobile target → use the static-SAST floor in the "Mobile / APK target branch" below instead of the web recon floor.**

   > **JS bundle / large static-file analysis = delegate to a desk subagent (default, not optional).** The main thread only fetches the bundle to disk (`curl … -o`, one request); extracting endpoints/secrets/sinks goes to a desk subagent (parsing a landed file, no packets — not restricted by subagent-scope). Two reasons: (1) the multi-MB raw content never enters the main context; (2) the large volume of intermediate parse output stays out of the main thread, which lowers the chance a long session trips a safety interruption. This is the highest-value subagent pattern here — main thread sends packets, subagent parses. To mine several bundles, give one agent the whole batch and get back one ranked list; don't grep them one by one on the main thread.
1. **Enumerate every surface element** into `RECON_DB.md ## Attack Surface Map`: one row per element. **Tag each row with its recon source** (crawler / historical / subdomain enum / scanner / manual…). Too many `manual` rows means the recon floor was not run to completion — treat that as a warning, not a result.
2. **Per element, write a free-text "how could this break?" hypothesis.** This forces thinking. Tick-boxes are forbidden; the column cannot be empty and cannot just name a vuln type.
3. **Mark anomalies first** (homegrown framework, non-standard header/auth scheme, unusual parameter naming). That is where pattern libraries are blind and where novel bugs hide.
4. **Test each hypothesis.**
5. **ONLY THEN** run pattern/hunter/scanner checks as a "did I miss a known type?" backstop — never as the starting point.

## The 8 vuln-agnostic dimensions (do not skip any)

Every input/parameter · every role (auth matrix) · every state transition (multi-step flow) · every trust boundary · every integration / third party · every dependency / framework · every file / upload path · every business flow — plus the **anomaly sweep** (anything homegrown or non-standard).

## Feature-abuse probe list (design-layer question bank)

After mapping the 8 dimensions, run each business-flow / integration / data-export element through this list. These are legitimate features used for unintended purposes — design bugs that pattern/hunter scanners cannot find, all black-box testable.

- **Export/Backup as exfil**: A low-privilege account triggers an export/snapshot/backup — does the output contain cross-tenant, deleted, draft, or revision-history data that should have been purged? → cross-user data leak (an IDOR variant)
- **Import/Restore as injection**: Does import/restore apply the same permission model as the UI? Can it overwrite existing data, create validation-bypassing records, or write into a collection you have no permission for? → access-control bypass / data tampering
- **Search/Filter/Sort as oracle**: Can search/filter confirm the existence of content you cannot access directly? Can sorting by a hidden field let you infer its value? → indirect information disclosure
- **Enumeration via side effects**: Do "does not exist" vs "no permission" differ in error message / response time / size / status code? Can reset / invite / register be used to enumerate users? → user/resource enumeration
- **Preview/Draft/Staging leakage**: Does a preview token unlock only one item or a wider scope? Can drafts be discovered via sitemap / RSS / API listing? Can cache headers make a CDN serve private content publicly? → unauthorized access / CDN cache leak
- **Notification/Webhook as SSRF**: Will the server fetch a user-controlled notification / webhook / callback URL? Does it block internal ranges? Does it **re-validate after a redirect** (blocking only the first hop = bypassable)? → SSRF (hand off to your installed SSRF skill — see `Reference Card - External Skills Catalog`)
- **API-not-frontend**: For every endpoint ask "the frontend would never call it this way, but does the API allow it?" — extra/missing params, changed method, undocumented param/header? → hidden functionality / broken access control

## Anti-gaming

- Map at the **element level, not the dimension level** — you cannot satisfy this by pasting 8 boilerplate lines.
- Every discovered endpoint must have a matching Surface Map row (cross-check it).
- The "how could this break?" column must contain a real hypothesis, not a vuln-type name.

## Mobile / APK target branch (static-SAST floor)

When the target is an APK / mobile app, the recon floor is **static SAST + manifest analysis**, not subdomain/host enumeration. Run this floor, then feed its output into the same 8 dimensions above.

### Mobile recon floor (run all, cross-check)

| Step | Tool (example) | Output → feeds |
|---|---|---|
| One-shot static report | a mobile static-analysis framework (e.g. MobSF) | permissions, exported components, secrets, certs, network-security-config, trackers → seeds most Surface Map rows |
| Vuln cross-scan | an APK vuln scanner (e.g. QARK / AndroBugs) | exported-component / WebView / insecure-storage findings → confirm the static report, fill gaps |
| Decompile to source | a DEX→Java decompiler (e.g. JADX) | read the logic behind each entry point; grep for secrets / endpoints |
| Static→dynamic bridge | an instrumentation generator (e.g. Dexcalibur) | auto-generate runtime hooks → hand off to dynamic testing |

### Map the manifest onto the 8 dimensions

- **Every input/param** → deep-link URIs (`<data android:scheme>`), Intent extras, IPC payloads
- **Every role / auth matrix** → which components require a permission vs `exported="true"` with none
- **Every trust boundary** → each `exported="true"` Activity / Service / Receiver / Provider is an entry point reachable by other apps (the mobile equivalent of an internet-facing endpoint)
- **Every integration / third party** → SDKs / trackers in the static report; backend API hosts in strings / decompiled code
- **Every dependency / framework** → Flutter / React Native / Xamarin / Cordova (changes the SSL-pinning + native approach); obfuscator presence (e.g. DexGuard)
- **Every file / upload** → FileProvider paths, `content://` providers
- **Every business flow** → multi-Activity flows, payment / login state
- **Anomaly sweep** → custom crypto, homegrown auth, a native `.so` doing the real work

> **Key:** a backend API host found inside the APK is **not the end** — extract it and run the standard web recon floor (Method step 0) against it. The APK is often just the map to the real server-side surface.

### Hand-off

Surface Map done → dynamic testing with your installed mobile skills: SSL-pinning bypass to intercept traffic, exported-component / WebView / intent-redirect abuse, root & anti-instrumentation bypass, de-obfuscation, native `.so` analysis (see `Reference Card - External Skills Catalog`). Then treat the intercepted backend API as a web target → `bb-web-vuln-scan`.

## Catch-all / false-200 filter (run before trusting any 200)

Before mapping a host's "live" endpoints, screen for SPA / framework catch-all behavior: if a host returns 200 on a random non-existent path, then **HTTP 200 ≠ endpoint exists** and the catch-all is immune to header/IP path tricks. Compare the homepage response against a random-path response; if they are effectively identical, do not enter path-guess 200s into the Surface Map as real endpoints.

## After: tag discovery mode

When a Surface Map hypothesis becomes a Finding, tag it `discovery_mode: exploration`. When a pattern/hunter/scanner finds it, tag `discovery_mode: pattern`. Track the exploration:pattern ratio — if pattern dominates, exploration is starved and the streetlight effect has won.

## Next step (mandatory hand-off — do not stop here)

A completed Surface Map **must** flow into a testing phase. "Mapped, therefore done" is not allowed:

```text
bb-surface-mapping → bb-web-vuln-scan → [finding]    → bb-exploit-chain → chain DAG
                                       → [no finding] → mark Exhausted
```

1. Load `bb-web-vuln-scan` — OWASP Top 10 coverage + injection matrix + version→CVE + WAF bypass.
   - **Mobile / APK target:** run dynamic testing via your installed mobile skills first (see the Mobile branch hand-off above), then feed the intercepted backend API into `bb-web-vuln-scan`.
2. On any finding → run `bb-exploit-chain` (the 6-question chain) before moving to the next system.
3. Persist chain results as an Exploit Chain DAG so every path is tracked to ✅ or ❌.

### Target Work DAG — XL targets only (do not build by default)

The `Template - Target Work DAG` is a **records** artifact, not a **decision-driver**. Build it **only for XL targets** — a target that is **multi-system OR has ≥2 chainable findings** and where you keep losing track of the next step across sessions.

**For single-finding or small targets, SKIP it.** The inline `bb-exploit-chain` gate (step 2 above) already covers the "what can this chain into?" reasoning, and a full Work DAG on a small target is overhead nobody maintains. ROI scales with target size: applying the DAG broadly turns it into low-adoption shelfware, so gate it to the XL cases where the cross-session tracking actually pays off. (The Exploit Chain DAG in step 3 is separate and stays mandatory once a chain exists.)

## Cross-References

- `09 - Knowledge Base/Playbook - Recon.md` (the recon floor that feeds this map)
- `docs/architecture-closed-loop.md` (where this gate sits in the 4-ring loop)
- `bb-web-vuln-scan` (the mandatory next gate)
- `bb-dedup-finding` (runs LATER, at Finding creation — not before mapping)
- `bb-scope-safety-check`, `bb-attack-chain-review`, `bb-evidence-readiness`
- `Reference Card - External Skills Catalog` (mobile dynamic-testing skills for the APK hand-off)
