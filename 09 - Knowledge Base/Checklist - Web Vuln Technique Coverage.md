---
type: checklist
title: "Web Vuln Technique Coverage"
tags: [checklist, technique-coverage, injection, payload, methodology]
status: active
last_updated: 2026-06-03
source: a large-scale government web application assessment (unauthenticated)
---

# Checklist — Web Vuln Technique Coverage (technique / payload level)

> **Complementary document**: Checklist - Attack Surface Coverage covers "has the attack surface dimension been considered" (vuln-agnostic). This document covers "has every known web technique actually been injected against every param" (technique-level).
>
> **Core lesson**: don't assume you've fully scanned a target after testing only XSS + SQLi. Every param needs the full payload matrix run against it. Skipping LFI/SSRF/CMDi/SSTI/XXE means missing an entire vulnerability class.
>
> **Precondition**: spider every link → extract every param (GET query / POST body / JSON key / header / cookie) → run every technique in the table below against **each** param. Poking at the home page with `curl` does not count as testing.

---

## Methodology (previously overlooked)

1. **A real browser-automation tool is a real weapon, not a lightweight browser extension**: unrestricted JS execution, network interception, XSS alert/dialog detection, auto form-filling, batch scanning. A lightweight extension gets blocked by page JS and misses dialogs.
2. **Every param must actually be injected against**, not skipped just because "it's a form." Spider → extract params → inject each of `'`, `{{7*7}}`, `../etc/passwd`, `;id`, `php://filter` one by one.
3. **Don't give up when hitting a WAF**: fingerprint the WAF type → search for public bypass payloads → test coverage. WAF rules have blind spots — one real case showed a WAF blocking XSS but not SQLi — being blocked on one technique ≠ everything is blocked; switch techniques and keep going.
4. **Depth beats breadth**: scanning many systems across shallow passes is worse than fully exploiting one system. Don't stop once you find one bug on a system — chase a SQLi→RCE chain to the end; shallow scanning only surfaces surface-level info disclosure.
5. **No account = half the attack surface gone**: CAPTCHA-gated / post-login functionality / auth systems become untestable. **Registering an account is the single most direct way to expand the attack surface** — prioritize it.

---

## Technique coverage matrix (check off per param)

| Technique | Example payload | Verification signal |
|------|-------------|---------|
| **Reflected XSS** | `"><svg onload=alert(1)>`, event handlers, JS context break | alert fires (detect via browser automation), not HTML-encoded |
| **Stored XSS** | same as above, stored then reloaded | requires an account / comment/profile field |
| **Boolean SQLi** | `' AND 1=1--` vs `' AND 1=2--` | response diff |
| **Time-based SQLi** | `'; WAITFOR DELAY '0:0:5'--`, `' OR SLEEP(5)--` | delay difference |
| **LFI / Path Traversal** | `../../../etc/passwd`, `..%c0%af`, `....//`, `..%252f` | file content reflected |
| **PHP Wrapper** | `php://filter/convert.base64-encode/resource=index`, `data://`, `expect://` | base64 source / command output |
| **SSRF** | `http://127.0.0.1`, `http://169.254.169.254/`, DNS rebinding | internal response / OOB hit |
| **Command Injection** | `;id`, `\|id`, `` `id` ``, `$(id)`, `%0aid` | command output / delay (`;sleep 5`) |
| **SSTI (server)** | `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `{{config}}`, `#{7*7}` | `49` reflected / config dump |
| **CSTI (client)** | `{{7*7}}` in Angular/Vue context | client-side render of `49` |
| **XXE** | xmlrpc.php, SOAP, XML upload with an external entity | file read / OOB |
| **CRLF / Header Injection** | `%0d%0aSet-Cookie:x=1` | injected header |
| **Open Redirect** | `returnUrl=//evil`, `redirectURL=https://evil` | 302 to an external site |
| **CORS** | Origin: evil + credentials | ACAO reflection + ACAC:true |
| **IDOR** | sequential ID / UUID enumeration | cross-user data returned |

### ASP.NET / IIS specific (previously untested)

| Technique | Payload | Signal |
|------|---------|------|
| **web.config traversal** | direct access to `/web.config`, unicode traversal `..%c0%af` | config content leaked |
| **IIS 8.3 short name** | `/somedi~1/`, scanner enumeration | 404 vs 400 timing difference leaks filenames |
| **HTTP Verb Tampering** | PUT / DELETE / custom verb | non-405/403 response = possibly writable |
| **ViewState** | decode `__VIEWSTATE` / check MAC validation | unencrypted / weak key → RCE |

---

## Stop-loss point (confirmed ceiling)

- **Many systems × no login/registration = every known web technique tested with zero new findings.** XSS/SQLi/LFI/SSRF/CMDi/SSTI/XXE/CORS/CRLF/Open Redirect/IDOR/Path Traversal/PHP wrapper/WAF bypass all attempted.
- Conclusion: on this class of unauthenticated government web app, the surface had already been swept clean by prior assessment rounds. To break through, either **register an account to open up the authenticated attack surface**, or dig deeply into a single system's homegrown logic.

---

## Technique — extracting minified JS source (page-object introspection method)

To read the full definition of a function inside CDN-hosted minified JS:
1. Grab the whole minified blob from the rendered page's text content
2. Locate the section via `indexOf("functionName")`
3. Evaluate in-page to read out the complete function definition (bypasses view-source truncation)

Usable on any minified JS analysis task (finding a hidden endpoint / client-side secret / logic).

---

## Related
- Checklist - Attack Surface Coverage — dimension level (consider the attack surface first, then use this checklist to inject technique-by-technique)
- Lessons Learned log
- Exploratory Surface Mapping playbook

---

## Session-Mined Additions

**HTTP Verb Coverage**
- Every tested endpoint must be sent GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS individually — auth controls are often only implemented on GET, letting other verbs bypass them directly

**IDOR Section**
- Cross-role / cross-tenant IDOR: each access path needs independent server-side authorization confirmation; don't infer that "path B is equally restricted" just because "path A was confirmed restricted"

**Stop-Loss Gates**
- Stop-loss trigger conditions (same endpoint): 403 regardless of payload variation, 20+ payload variants already tried, 30+ minutes on the same endpoint, or requires 5+ simultaneous preconditions → stop immediately and pivot

**Blind SSRF Impact Gate**
- Blind SSRF with no response readback and no second-order target → do not report; requires at least one demonstrable impact path (OOB DNS/HTTP callback + internal network access, or an SSRF chain) before opening a Finding

**OTP/2FA**
- OTP session binding: the session token issued after OTP verification must (a) be bound to the original session, (b) be single-use; if `POST /otp/verify` issues a new session → CWE-613; if the old session remains valid → CWE-384

**Account Enumeration**
- Catch-all 200 response confirmation step: diff the response body (length, message, timing) for existing vs. non-existing accounts; if identical → the oracle doesn't hold, stop
- Enumeration impact upgrade: once confirmed, trace what downstream resources (permissions/data/actions) an enumerated account exposes, and use that as the basis for an impact upgrade

**Electron / macOS**
- Additional macOS Electron attack surface: (1) missing App Sandbox (`com.apple.security.app-sandbox` entitlement not enabled); (2) weakened Hardened Runtime (`com.apple.security.cs.disable-library-validation` → dylib injection); (3) ATS disabled (`NSAllowsArbitraryLoads: true` → cleartext HTTP); (4) custom URL scheme handlers (`app://`-style custom schemes) → cross-check against the Electron per-window contextIsolation variance pattern

**CVE Citation Gate**
- Before citing a CVE as prior art, confirm the issue pattern actually matches (not just that the CVE ID exists); this matters especially for shell.openExternal-class CVEs: the bypass method the CVE describes must match the bypass path used in your own PoC; see the CVE citation methodology for details

**Electron Dedup**
- Electron dedup must search across both the platform's disclosed-report list AND public GitHub mirrors of disclosed reports; keywords: `shell.openExternal`, `UNC path`, `search-ms`, `SMB`, `asar`, `protocol bypass`, plus the target app's name; searching only one source is not a complete dedup

**Spring Boot / Java — confirmed CAS SSO dead end**
- Spring Boot + CAS SSO dead end: (1) open redirect blocked by the CAS whitelist; (2) Actuator exposing only health/info → not directly exploitable; (3) a suspected internal endpoint returning 404 → not a feature in this version. If you hit all three of these results → stop and pivot, don't keep digging down the same path
