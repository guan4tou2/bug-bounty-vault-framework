---
name: bb-web-vuln-scan
description: Use when testing a web target's endpoints/params for vulnerabilities — enforces OWASP Top 10 coverage, version→CVE lookup, the full injection matrix, WAF-bypass discipline, and dynamic (not hardcoded) parameter discovery. Triggers include scan, test, pentest, find vulns.
---

# Bug Bounty — Web Vulnerability Scan (OWASP coverage + version→CVE + injection matrix)

This skill enforces systematic testing **after** surface mapping (`bb-surface-mapping`). It prevents the common failure of testing only XSS + SQLi and missing LFI / SSRF / SSTI / CMDi / XXE / outdated-component exploits.

Payloads below are canonical, publicly-documented OWASP WSTG test strings — they are a **starting point, not the full set**. Keep target-specific payloads, evasion, and real scanner output in your private vault / tool repo, never here. When a technique needs more than the starting point (full payload sets, bypass matrices, PoC walkthroughs), go to `09 - Knowledge Base/wiki/README.md` — its FAQ table routes each vuln class in this checklist to a matching `wiki/NN-*.md` deep-dive.

## Context discipline (delegate execution)

The main line (commander) should hold only **decisions and conclusions**. Executing this matrix is the heavy work — many hosts, many parameters, batched payloads, spidering. **When the surface is non-trivial (>1 host or batch testing is needed), delegate execution to the `web-hunter` agent and keep only the matrix conclusions on the main line: which OWASP items were covered, what hit, and `file:line` evidence pointers.** Do not flush raw HTTP responses, full spider lists, or per-payload output into the main line's context. Only a single-endpoint quick check runs inline.

## Trigger

Run when actively testing a web target's endpoints/parameters:

- "scan", "test", "pentest", "find vulns"
- after `bb-surface-mapping` has populated the Attack Surface Map
- before declaring "no findings" on a target

## Hard Rules

1. **Search-First (applies throughout).** Before making any factual judgment — version→CVE, tech-stack defaults, WAF behavior, payload validity, default credentials, technique feasibility — search to confirm. Do not answer from training data on anything that "can change over time".
2. **Every version number → look up CVE immediately.** When you find a version, stop and search `"<product> <version> CVE exploit"` before continuing. Delegate the SOP to `bb-version-cve-precheck`.
3. **Hit a WAF → attempt bypass, do not give up.** Identify the WAF, find a documented bypass, test its coverage (different paths/params may have different rules).
4. **Cover every OWASP Top 10 category** — not just A03 + A05.
5. **Do not hardcode lists.** The paths / parameter names / payloads here are a starting point. For each target, expand dynamically from the tech stack and a real wordlist.
6. **Any finding → trigger `bb-exploit-chain`** (the 6-question chain) before moving to the next system.
7. **Finding lifecycle: suspected → validated.** An anomaly opens a `suspected` finding (with `expected_impact` + `verification_plan`) → you then write a full PoC → the PoC achieves the `expected_impact` against the authorized target or a proven-equivalent controlled environment → only then is it `validated`. **An ASAN-harness trigger, a short-term timing wobble, or "the request was sent" is only `suspected`, never `validated`.** Only a `validated` finding with a `poc_ref` may go into a report.

## Anti-patterns (forbidden)

- ❌ Testing only the paths listed here → you must crawl + research to expand.
- ❌ Skipping a parameter because its name does not match a known list → every parameter is in scope.
- ❌ "Did A03, injection is done" → every parameter × every injection type is the bar.
- ❌ Ticking the OWASP list and leaving → any anomaly must run the chain review.
- ❌ Marking an item ✅ that was not actually tested.

## Phase 0 — KB query gate (before you test)

Before testing a target's tech stack / vuln class, **query the KB first** to see whether an existing pattern can accelerate the work:

```bash
bash automation/surface_kb.sh "<tech-stack>"   # e.g. "laravel" / "spring boot" / "wordpress"
```

KB hit → load the pattern's checklist / known chain path, don't re-explore. KB miss → run full coverage as normal, then backfill the new pattern with `bb-knowledge-capture` afterward.

## Phase 1 — Version → CVE

For every version string in your recon DB, run the `bb-version-cve-precheck` SOP: search CVEs → confirm affected range → verify if a PoC exists → flag auth-required items → record the exclusion reason if not exploitable. Do not re-implement the search logic here.

## Phase 2 — OWASP Top 10 checklist (per item: ✅ tested / ❌ N/A / ⏳ needs auth)

### A01 Broken Access Control
- IDOR: crawl every URL with a numeric ID; test ±1/±10/±100/0/large; use full navigations (not cross-origin fetch) to avoid CORS blocking; diff response size + content. Leaked IDs → replay into other endpoints.
- Path traversal: every non-numeric parameter that could take a file path (do not rely on a fixed name list); inject `../../../etc/passwd` and `..\..\..\..\windows\win.ini`; also `..%c0%af`, `....//`, `..%5c`, `php://filter`; `root:` or `[boot loader]` in the response = success.
- Force browse: crawl first, then expand with a tech-stack-appropriate wordlist (search `"<CMS> admin path common endpoints"`); a 200 that is not a login redirect = unauthorized access.
- CORS: `Origin: https://evil.com` → is `Access-Control-Allow-Origin` reflected?
- HTTP verb tampering: send PUT/DELETE/PATCH to known GET endpoints.
- Download endpoints (`download`/`file`/`export`/`pdf`): unauthenticated? swap file ID/filename? `filename=../../../etc/passwd`?

### A02 Cryptographic Failures
- Every cookie: check Secure / HttpOnly / SameSite.
- Mixed content: `http://` src/href on an HTTPS page.
- Sensitive data in URL: `token=` / `key=` / `password=` / `secret=`.

### A03 Injection (full matrix — run per parameter)

| Technique | Canonical payload | Signal |
|---|---|---|
| Boolean SQLi | `' AND '1'='1` vs `' AND '1'='2` | response-size diff |
| Time SQLi | `' WAITFOR DELAY '0:0:3'--` / `SLEEP(3)` | response time > 3s |
| XSS | `"><img src=x onerror=alert(1)>` | dialog / reflection (WAF → Phase 3) |
| LFI | `../../../etc/passwd` + `php://filter` | `root:` or base64 blob |
| SSRF | `http://127.0.0.1` + `http://169.254.169.254` | internal content or delay (see A10) |
| CMDi | `;id` / `\|id` / `` `id` `` | `uid=`+`gid=` |
| SSTI | `${7*7}` / `{{7*7}}` / `<%= 7*7 %>` | `49` in response |
| XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | `root:` (only XML endpoints) |

### A04 Insecure Design
- Business logic: skip intermediate steps; tamper hidden flow fields (`step=2`→`3`).
- Race condition: fire N identical requests concurrently; check double-execution.
- Rate limit: burst the endpoint; is there a 429?

### A05 Security Misconfiguration
- Debug mode: trigger 404/500; stack trace / version / path leak?
- Default credentials: a short list (≤5) only on a real login page with non-production accounts.
- Headers: `Server` / `X-Powered-By` / `X-AspNet-Version` = version leak.
- `robots.txt` + `sitemap.xml`: visit every `Disallow` path.
- Sensitive files: `.env` / `.git/HEAD` / `web.config` / `*.bak` / `phpinfo.php`.

### A06 Vulnerable & Outdated Components
- Every version checked for CVE? (delegate to `bb-version-cve-precheck`).
- Flag EOL software (but only report with a real CVE).
- Confirm client-lib versions (e.g. jQuery).

### A07 Identification & Authentication Failures
- Cookie bypass: list every cookie; for each, is the value boolean-like / role-like / encoded? Flip `N`→`Y`, `user`→`admin`, `0`→`1`, `false`→`true`; replay against admin pages. Any cookie can be an auth flag, not just `session`.
- JWT: find `eyJ`; decode header; test `alg:none`; test weak secrets.
- Session fixation: does the session ID rotate on login?
- Weak passwords: ≤5 common pairs, no brute force.

### A08 Software & Data Integrity Failures
- Deserialization: find an app key / signing secret (`.env`, error page, JS); look for serialized cookies (`s:`-prefixed base64, Java `rO0AB`); check ViewState MAC.
- Unsigned updates: JS/CSS loaded over HTTP.

### A09 Logging & Monitoring Failures
- Error exposure: 404/500/405 with stack trace / version / path.
- Log injection: `\r\nAdmin logged in` in a user-controlled field.
- Verbose error: special chars → SQL/framework error reflected.

### A10 Server-Side Request Forgery
- SSRF: every parameter whose value looks like a URL/domain (do not rely on a fixed name list); inject `http://127.0.0.1`, `http://169.254.169.254/latest/meta-data/`; internal content = SSRF; large external-fetch delay = blind SSRF.
- `xmlrpc.php`: methods that fetch a URL (`pingback.ping`).
- DNS rebinding: only when SSRF is already indicated.

## Phase 3 — WAF Bypass (when blocked)

1. Identify the WAF (F5 / Cloudflare / AWS / ModSecurity).
2. Search documented bypasses for that WAF + technique.
3. Test bypass payloads.
4. Map WAF coverage — different paths/params may enforce different rules.

## When is a target "Exhausted"?

All of these must hold before claiming exhaustion:

1. Every OWASP A01–A10 item is ✅ / ❌ / ⏳ (no silent gaps).
2. Every crawled endpoint is in a terminal state (Dead End or Finding).
3. Every discovered version was CVE-checked.
4. Any WAF encountered had a bypass attempt.
5. Every finding ran `bb-exploit-chain` (the 6-question chain).
6. Every ⏳ is genuinely auth-blocked, not skipped.
7. **Every finding has an `expected_impact`** — a finding with no defined "what success looks like" is not done.
8. **Every `validated` finding has a `poc_ref`** — without a re-runnable PoC the finding is not verified.
9. **No finding is `validated` while missing a `verification_method`** — a transient trigger or "the request was sent" is `suspected`, not `validated`.

You **cannot** claim exhaustion while any non-auth ⏳ remains, any endpoint is still untested, any finding skipped the chain review, any WAF was left untried, any finding lacks an `expected_impact`, or any `validated` finding lacks a `poc_ref` / `verification_method`.

## Phase 4 — Output

Record each test result in `RECON_DB.md ## Operation Log`. Mark the OWASP checklist state: full A01–A10 coverage = you may declare "surface exhausted"; any untested item = you may not.

## Tooling (platform-neutral)

Use whatever browser-automation and request-interception tools your setup provides. Requirements, not products:

- Render JS before reading the DOM (SPA params live in rendered HTML).
- Auto-detect dialogs for XSS verification.
- Use full navigations (not cross-origin fetch) for IDOR/SQLi so CORS does not block reads.
- Be able to intercept and rewrite request body / cookies / headers, and reuse session tokens across requests.
- Use direct HTTP (curl/httpie) for fast API checks where JS rendering is not needed.

## Technique handoff (once the matrix hits, hand off — don't hand-roll payloads here)

This skill owns **coverage and ordering**; when a class is actually worth attacking, hand off to the matching technique skill for its payloads and bypasses:

| Hit | Hand off to |
|---|---|
| Parameter reaches SQL | `sqli-sql-injection` |
| Reflected / stored sink | `xss-cross-site-scripting` (CSP blocks → `csp-bypass-advanced`; no JS execution → `dangling-markup-injection`) |
| Server fetches a URL | `ssrf-server-side-request-forgery` (cloud metadata → `offensive-cloud`; k8s → `offensive-k8s-attacks`) |
| File path controllable | `path-traversal-lfi` |
| Blocked by a WAF | `waf-bypass-techniques` |
| Object ID swappable | `bb-idor-coverage` (coverage gate) + `idor-broken-object-authorization` (technique) |
| 401 / 403 | `401-403-bypass-techniques` |
| GraphQL | `graphql-and-hidden-parameters` |
| Upload point | `upload-insecure-files` |
| Template / expression echo | `ssti-server-side-template-injection` · `expression-language-injection` |
| XML parsing / SOAP / SVG upload | `xxe-xml-external-entity` (XSLT engine → `xslt-injection`) |
| JSON / document-DB query | `nosql-injection` |
| State change with no token / loose SameSite | `csrf-cross-site-request-forgery` (framable → `clickjacking`) |
| One-shot operation / quota / concurrency | `race-condition` |
| Host header reaches URL generation / routing | `http-host-header-attacks` (cache layer → `web-cache-deception`) |
| Same-name params parsed differently front vs back | `http-parameter-pollution` |
| Front/back proxy framing mismatch | `request-smuggling` (HTTP/2 → `http2-specific-attacks`) |
| Input reaches a response header / Location / Set-Cookie | `crlf-injection` |
| JS deep-merge / query parser | `prototype-pollution` → `prototype-pollution-advanced` |
| Serialized object reaches a deserializer | `deserialization-insecure` (Java JNDI lookup → `jndi-injection`) |
| Login / signup / reset / 2FA flow | `authbypass-authentication-flaws` |
| Price / flow / state machine / coupon | `business-logic-vulnerabilities` |
| REST / GraphQL API surface | `api-recon-and-docs` → `api-authorization-and-bola` → `api-auth-and-jwt-abuse` |
| SSO / SAML assertion | `saml-sso-assertion-attacks` |
| `.git` / `.env` / backup / source map | `insecure-source-code-management` |
| Redirect target controllable (`?next=` `?url=`) | `open-redirect` (chains into OAuth callback → `oauth-oidc-misconfiguration`) |

> Why spell this out: while a model executes **inside a procedural skill**, it does not re-scan the skill catalog — it follows the path you wrote. Leaving a technique off this table means those technique skills effectively do not exist at that step.

### If this is a red-team / pentest engagement (not bug bounty)

**The coverage this skill pursues is not the goal in a red-team context.** The client's question is "can you get in?", and a stack of low-severity findings answers it poorly — a pile of step-1 findings still sums to step-1 on the privilege ladder.

→ Run each finding through `bb-web-foothold` to place it on the privilege ladder, and throttle scanning to its noise budget. The engagement-level flow is `bb-redteam-engagement`.

## Cross-References

- `bb-surface-mapping` (prerequisite gate — map before you scan)
- `bb-scope-safety-check` (gate before any write/active operation)
- `bb-version-cve-precheck` (firmware/software pre-check SOP)
- `bb-exploit-chain` (the 6-question chain — run on every finding)
- `bb-attack-chain-review` (candidate-lifecycle chain-assessment gate)
- `09 - Knowledge Base/` Pattern notes (IDOR / SSRF / XSS / SQLi / SSTI / …)
- `09 - Knowledge Base/Reference Card - Vulnerability Type Classification.md`
- `09 - Knowledge Base/wiki/README.md` — per-class deep-dive playbooks (full payload sets, PoC walkthroughs, bypass matrices); use this, not just the checklist above, once a technique is worth pursuing
- `docs/architecture-closed-loop.md`
