---
name: bb-web-vuln-scan
description: Use when testing a web target's endpoints/params for vulnerabilities — enforces OWASP Top 10 coverage, version→CVE lookup, the full injection matrix, WAF-bypass discipline, and dynamic (not hardcoded) parameter discovery. Triggers include scan, test, pentest, find vulns.
---

# Bug Bounty — Web Vulnerability Scan (OWASP coverage + version→CVE + injection matrix)

This skill enforces systematic testing **after** surface mapping (`bb-surface-mapping`). It prevents the common failure of testing only XSS + SQLi and missing LFI / SSRF / SSTI / CMDi / XXE / outdated-component exploits.

Payloads below are canonical, publicly-documented OWASP WSTG test strings — they are a **starting point, not the full set**. Keep target-specific payloads, evasion, and real scanner output in your private vault / tool repo, never here.

## Trigger

Run when actively testing a web target's endpoints/parameters:

- "scan", "test", "pentest", "find vulns"
- after `bb-surface-mapping` has populated the Attack Surface Map
- before declaring "no findings" on a target

## Hard Rules

1. **Every version number → look up CVE immediately.** When you find a version, stop and search `"<product> <version> CVE exploit"` before continuing. Delegate the SOP to `bb-version-cve-precheck`.
2. **Hit a WAF → attempt bypass, do not give up.** Identify the WAF, find a documented bypass, test its coverage (different paths/params may have different rules).
3. **Cover every OWASP Top 10 category** — not just A03 + A05.
4. **Do not hardcode lists.** The paths / parameter names / payloads here are a starting point. For each target, expand dynamically from the tech stack and a real wordlist.
5. **Any finding → trigger `bb-attack-chain-review`** before moving to the next system.

## Anti-patterns (forbidden)

- ❌ Testing only the paths listed here → you must crawl + research to expand.
- ❌ Skipping a parameter because its name does not match a known list → every parameter is in scope.
- ❌ "Did A03, injection is done" → every parameter × every injection type is the bar.
- ❌ Ticking the OWASP list and leaving → any anomaly must run the chain review.
- ❌ Marking an item ✅ that was not actually tested.

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
5. Every finding ran `bb-attack-chain-review`.
6. Every ⏳ is genuinely auth-blocked, not skipped.

You **cannot** claim exhaustion while any non-auth ⏳ remains, any endpoint is still untested, any finding skipped the chain review, or any WAF was left untried.

## Phase 4 — Output

Record each test result in `RECON_DB.md ## Operation Log`. Mark the OWASP checklist state: full A01–A10 coverage = you may declare "surface exhausted"; any untested item = you may not.

## Tooling (platform-neutral)

Use whatever browser-automation and request-interception tools your setup provides. Requirements, not products:

- Render JS before reading the DOM (SPA params live in rendered HTML).
- Auto-detect dialogs for XSS verification.
- Use full navigations (not cross-origin fetch) for IDOR/SQLi so CORS does not block reads.
- Be able to intercept and rewrite request body / cookies / headers, and reuse session tokens across requests.
- Use direct HTTP (curl/httpie) for fast API checks where JS rendering is not needed.

## Cross-References

- `bb-surface-mapping` (prerequisite gate — map before you scan)
- `bb-scope-safety-check` (gate before any write/active operation)
- `bb-version-cve-precheck` (firmware/software pre-check SOP)
- `bb-attack-chain-review` (run on every finding)
- `09 - Knowledge Base/` Pattern notes (IDOR / SSRF / XSS / SQLi / SSTI / …)
- `09 - Knowledge Base/Reference Card - Vulnerability Type Classification.md`
- `docs/architecture-closed-loop.md`
