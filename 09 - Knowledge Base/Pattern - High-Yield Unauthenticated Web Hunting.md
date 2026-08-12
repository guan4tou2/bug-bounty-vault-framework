---
type: pattern
title: "Pattern - High-Yield Unauthenticated Web Hunting"
tags: [pattern, methodology, target-selection, recon, unauth, web, info-leak, bb-pattern]
status: verified
vuln_class: info-leak
severity_range: P2-P4
seen_in: [laravel-debug-mode, spring-actuator, vite-spa, wordpress, graphql-api]
prerequisites: []
last_updated: 2026-06-05
---

# Pattern - High-Yield Unauthenticated Web Hunting

> **TL;DR**: A field-distilled meta-pattern for unauthenticated, GET-only hunting: pick the right target, hit the right exposure surfaces, and don't burn cycles on things that are already known non-issues. This is a target-selection and triage doctrine, not a single vulnerability class.

## 1) Target Selection (highest leverage)

**Cold vendors outperform big vendors by roughly 10x.**

- Prioritize vendors with a sparse CVE history. Field example: a legacy IoT/device vendor with zero disclosed CVEs in several years yielded 20+ findings (a mix of critical/high/medium) on a single pass of unauthenticated recon.
- Large, heavily-tested vendor programs (major banks, telcos, video platforms, CDNs) mostly return duplicates or hit an auth wall on unauthenticated GET testing. **Don't grind through a target list alphabetically by brand recognition.**
- Before picking a new target, check NVD / cvedetails for its CVE history — a vendor with 0-2 CVEs in the last 3 years usually has more low-hanging fruit.
- Regional or niche IoT/SaaS vendors are particularly underexplored (fewer researchers looking).

**Batch auditing with a proven pattern is the highest-ROI activity.**

- The moment you have a working pattern, enumerate every target it could apply to and sweep them all.
- One root-cause grep can turn a single finding into dozens. Once you find the first instance of a pattern, don't stop — grep for every variant across the whole scope.

## 2) High-Yield Unauthenticated GET Surfaces

Hit these — impact is verifiable with unauthenticated GET alone — instead of getting stuck staring at login pages behind auth walls:

| Surface | Detection | Impact |
|---------|-----------|--------|
| **Laravel `APP_DEBUG=true`** | Clockwork (`/__clockwork`), Horizon (`/horizon`), Ignition | Can yield 3-4 separate findings: SQL/session disclosure, PII in job payloads, stack trace + env vars, potential RCE |
| **Large-response debug page** | HTTP 405/500 with a response body **>100 KB** | Almost certainly Ignition/Whoops/Symfony debug -> stack trace + env vars. Send GET to POST-only routes to trigger it |
| **Ignition RCE precondition check** | `/_ignition/health-check` -> `can_execute_commands:true` | Signals it's worth probing for RCE |
| **Exposed Git/.env/source maps** | `/.git/config`, `/.env`, `*.js.map` | Source code, credentials, internal structure |
| **Unauthenticated Actuator/metrics** | `/actuator/env`, `/actuator/heapdump` | Config/secret leak -> chainable |
| **Exposed config JSON** | Inline Vite/SPA config, `/config.json` | API keys, internal endpoints |

## 3) Known Non-Vulnerabilities (Stop-Loss List)

Don't log these, don't spend cycles on them:

| Observation | Why it's not a finding |
|-------------|------------------------|
| Admin/login page is reachable (`/admin`, `/login`, `/wp-admin`) | Every site has one. Only a bypass of the login itself is a finding |
| Panel exists but is blocked by auth / 302 / 403 / SSO / Cloudflare | Protection is working correctly — that's an observation, not a vulnerability |
| `/wp-json/` namespace enumeration | Default WordPress core behavior |
| `/wp-json/wc/store/v1/products` product listing | Public product catalog is expected in e-commerce |
| grep hits on an XSS payload | You must inspect the raw HTML — most are HTML-encoded (`&quot;`, `&lt;`) or stripped. Encoded output is not exploitable |
| SPA returns 200 + identical HTML for every path | Catch-all client-side routing — every scanner "hit" is a false positive. Compare the homepage against a random 404 path by size to rule it out |
| Monitoring shows a "priority changed" signal | That's just a change-detection signal, not a vulnerability. Advance to confirmed impact before it counts |

## 4) Pre-Submission Three-Question Filter (mandatory gate)

Every finding must pass all three before it's reported:

1. **What can an attacker actually obtain?** Nothing concrete -> don't report.
2. **Is this default framework/software behavior?** Yes -> don't report.
3. **What's left after removing every "theoretically possible" claim?** Nothing left -> don't report.

Panel exposure alone fails Q1/Q3 on its own — it's an observation, not a finding.

## 5) Per-Parameter Technique Coverage (GET-safe)

Field lesson: testing only XSS/SQLi on every parameter misses an entire class of bugs. **Spider every link, extract every GET parameter, and run the following read-oriented, non-destructive payload set against each one** (these are all read-only GET probes; command injection, XXE, and other write/disruptive classes are left to manual testing, not run autonomously):

| Technique | GET payload | Signal |
|-----------|-------------|--------|
| LFI / Path Traversal | `../../../etc/passwd`, `..%c0%af`, `....//`, `..%252f` | File contents reflected |
| PHP filter wrapper | `php://filter/convert.base64-encode/resource=index` | base64-encoded source returned |
| SSTI (arithmetic probe) | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` | `49` reflected |
| SSRF (read-only probe) | `http://127.0.0.1/`, `http://169.254.169.254/` | Internal response differential |
| `web.config` / sensitive files | Direct GET on `/web.config`, `/.git/config`, `/.env`, `*.js.map` | File content |
| 405/500 debug page | Send GET to a POST-only route | Response >100 KB = Ignition/Whoops |

**WAFs have blind spots**: being blocked on one technique doesn't mean the whole endpoint is protected (e.g. a WAF that blocks XSS but not SQLi). Switch technique/encoding and keep going instead of abandoning the whole parameter after one blocked attempt.

> Note: command injection (`;id`), XXE, and time-based SQLi (`SLEEP`) can have side effects or add load — do not run these autonomously; only test them when read-only safety can be confirmed. Never run write/destructive classes automatically.

## Field Pitfalls — Large Estate Hunting

Discipline for deep-diving a large microservices estate (hundreds of subdomains, Spring Boot / Kubernetes / cloud-hosted):

### Trap 1: "Exposed Actuator" is often an SPA catch-all false positive

- `api.*` subdomains returning 200 on `/actuator/env`, `/actuator/heapdump`, `/v3/api-docs` look like an instant critical.
- **But** if they all return the same response size with `content-type: text/html` (a real Actuator response is `application/json`), it's an SPA front-end catch-all.
- **Verify by**: (1) hitting a random nonsense path (`/zzznotreal`) and comparing size, (2) checking whether `content-type` is HTML, (3) checking whether the body starts with `<!doctype html>`. Any one of these being true means false positive — do not report as critical.

### Trap 2: NXDOMAIN is not a subdomain takeover

- A dead subdomain from a certificate-transparency log with no A record and no CNAME (NXDOMAIN via `dig`) means DNS has been fully removed — it **cannot** be taken over.
- Takeover requires a **dangling CNAME pointing at a claimable service** (S3, Fastly, Heroku, etc.) where that resource is unclaimed.
- Only "CNAME still resolves, points at a vulnerable service, and that service returns 404/unclaimed" is a real takeover candidate.

### Trap 3: `/health` is a signal, not a prize

- A Spring Boot `/health` endpoint leaking a build version is low severity on its own, but it signals there may be a broader Actuator surface worth checking (`/env`, `/heapdump` = real secrets). Check it, but validate with Trap 1 first.

### Tooling: single-source CT lookups are unreliable — use a multi-source union

- A single certificate-transparency source can time out intermittently or return non-JSON. Union multiple sources (certspotter, hackertarget, rapiddns, best-effort crt.sh, OTX) instead of relying on one.

### The ceiling on well-architected estates

- A well-architected large estate often locks down the unauthenticated surface completely: SPA front ends, internal-only infrastructure (unreachable, NXDOMAIN), SSO logins on the identity provider, and reverse proxies that only route specific paths to the backend.
- Real bugs (IDOR/BOLA/business logic) live behind the API, which usually requires a registered account — many SaaS/education platforms allow open self-registration, which is the practical way in.

## Stop-Loss: Public-Design Artifacts Are Not Vulnerabilities

A public certificate-authority issuance endpoint publishing its Root CA certificate + CRL is working as designed, not leaking anything — only a **private key** exposure is reportable. As a rule of thumb, a public certificate is roughly ~1.5 KB; a private key PEM file is ~3 KB+ and its filename typically contains `key`/`private`.

## References

- [[Pattern - Laravel Debug Chain]]
- [[Pattern - Vite SPA JSON Config Leak]]
- [[Pattern - Subdomain Takeover]]
- [[Checklist - Disclosed Findings Pre-Read Gate]]
