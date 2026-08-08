---
type: reference
category: checklist
tags: [checklist, methodology, xss, recon, bug-bounty, 2026]
source: https://thexssrat.medium.com/bug-bounty-web-application-security-hunting-checklist-2026-xss-rat-version-1886138a8200
author: thexssrat
published: 2026-04-06
added: 2026-04-06
---

# Bug Bounty Hunting Checklist 2026 (XSS Rat Edition)

> **Principle: PoC or GTFO -- before submitting, you must have a working proof of concept, and the report must clearly demonstrate impact**

---

## Strategy

- [ ] First use the target application as a normal user while running Burp Suite to build a site map
- [ ] Prioritize testing **XSS and SSTI**, try payloads on all input fields
- [ ] Build a **custom fuzzing wordlist** tailored to the target's tech stack
- [ ] Continuously update the checklist based on findings during testing
- [ ] Evaluate VDPs as an alternative -- less competition
- [ ] Each report must clearly demonstrate the **actual impact of the vulnerability**; bugs without impact will be ignored

---

## Recon & Hidden Endpoints

- [ ] Read all available documentation (API docs, changelog, help pages)
- [ ] Even if the app is not in scope, check the **mobile app's backend**
- [ ] Use GAU or waybackurls to find historical endpoints and JS files
- [ ] Check "disabled by default" modules in application settings
- [ ] Google Dorks:
  - `site:target.com filetype:js`
  - `site:target.com api docs`
  - `site:target.com inurl:api`
  - Look for `.bak`, `.old`, `.zip`, `.tar.gz` backup files
- [ ] Audit JS files for hardcoded endpoints, API keys, tokens
- [ ] Find admin panels: `/admin`, `/administrator`, `/manage`, `/dashboard`, `/cp`
- [ ] Directory bruteforce: gobuster, feroxbuster, ffuf (with quality wordlists)
- [ ] Find Swagger / OpenAPI: `/api-docs`, `/openapi.json`, `/swagger-ui.html`

---

## Session Management

- [ ] Create accounts for each role, confirm role-based access is enforced server-side
- [ ] After removing a role, confirm the server-side (not just client-side) truly restricts access
- [ ] After login, confirm the session token is rotated (prevent session fixation)
- [ ] After deleting an account, confirm active sessions are terminated server-side
- [ ] Session tokens should not appear in URLs, only in cookies
- [ ] Confirm tokens are invalidated server-side after logout (not just clearing browser)
- [ ] Session tokens must be sufficiently long, random, and unpredictable (avoid sequential or time-based)
- [ ] Idle timeout must be enforced

---

## Cookies

- [ ] Session cookie has `HttpOnly` flag (prevent XSS theft)
- [ ] Session cookie has `Secure` flag (prevent plaintext HTTP transmission)
- [ ] Cookie has `SameSite=Strict` or `Lax` (CSRF protection)
- [ ] Domain scope does not allow wildcard subdomain
- [ ] Path scope is properly configured
- [ ] Expiry is reasonable: persistent cookies should not be valid forever
- [ ] Sensitive values should not appear in URL GET parameters
- [ ] Test whether writing cookies to subpaths can bypass validation

---

## Authentication & Login

- [ ] Test username enumeration (response differences between valid vs invalid accounts)
- [ ] Assess brute force protection (whether lockout policy is weak)
- [ ] Test default credentials on admin / login pages
- [ ] Confirm credential transmission uses HTTPS
- [ ] Password reset flow testing:
  - Multiple email parameters
  - Whether token is transmitted over HTTP
  - Whether token is weak/predictable
  - Whether re-authentication is required
- [ ] Test whether alternative login methods (OAuth, magic link, mobile) have lower security
- [ ] JWT testing: `alg: none`, weak HMAC key, HMAC vs RSA confusion
- [ ] Confirm session token is rotated after successful login

---

## SQL Injection

- [ ] Test all inputs that reach the DB: URL parameters, POST fields, HTTP headers, cookies
- [ ] Start with a single quote `'`, observe error behavior
- [ ] Time-based blind SQLi: `' AND SLEEP(5)--`
- [ ] After confirming an injection point, automate with sqlmap
- [ ] Test second-order SQLi (stored in DB first, triggered in subsequent queries)
- [ ] NoSQL injection: inject `{"$gt":""}` and similar payloads in JSON body
- [ ] Focus on: search, login, sort, filter parameters

```bash
# Basic sqlmap usage
sqlmap -u "https://target.com/page?id=1" --dbs
sqlmap -u "https://target.com/page?id=1" -D dbname --tables
```

---

## Cross-Site Scripting (XSS)

### Stored XSS
- [ ] Inject basic HTML into every field: `<a href=#>test</a>`
- [ ] If HTML renders, escalate to script tag
- [ ] Use obfuscated variants to bypass filters
- [ ] Focus: profile, comments, reviews, filenames, any user-visible content

### Reflected XSS
- [ ] Test parameter reflection on error pages (404, 403, 500)
- [ ] Trigger 403 errors and test for reflection
- [ ] All URL parameters and search queries
- [ ] HTTP Referer header reflection

### DOM XSS
- [ ] DOM XSS occurs browser-side, server-side scanners will miss it
- [ ] Burp Suite Pro can auto-detect
- [ ] Dangerous sinks: `document.write()`, `innerHTML`, `eval()`, `location.href`, `setTimeout()` with user input
- [ ] Tool: ra2-dom-xss-scanner

### Blind XSS
- [ ] Use XSS Hunter for out-of-band callbacks (triggered in admin panel)
- [ ] Inject blind XSS payloads early, they may fire much later
- [ ] Copy XSS Hunter payload into every input field
- [ ] XSS Hunter provides CSP bypass attempts
- [ ] Generate payload variants (replace `<` with entities or different event handlers)

### XSS Filter Evasion
- [ ] HTML entities: `&lt;` `&gt;`
- [ ] XSS polyglot for cross-context attempts
- [ ] Case variants: `<ScRiPt>`
- [ ] Keyword splitting: `<scr<script>ipt>`
- [ ] Encoding: URL, double-URL, Unicode
- [ ] Escape HTML attribute: `" onmouseover="alert(1)`
- [ ] Escape JS string: `'; alert(1)//`

---

## Server-Side Template Injection (SSTI)

- [ ] Inject `{{7*7}}` in every field, return `49` confirms (Jinja2/Twig)
- [ ] Try escaping: `}}{{7*7}}`, `}}[[7*7]]`
- [ ] FreeMarker / Velocity / JS engine: `${7*7}`
- [ ] ERB template: `<%= 7*7 %>`
- [ ] Automate: tplmap
- [ ] SSTI can escalate to RCE -- test carefully

---

## Command Injection

- [ ] Build a command injection fuzzing list
- [ ] Blind injection payloads: `; sleep 5`, `| ping -c 5 attacker.com`
- [ ] Cover both Linux and Windows formats
- [ ] Focus on: file name, IP, hostname, shell option inputs
- [ ] Chaining: `;`, `&&`, `||`, `|`, `` ` `` ``, `$()`
- [ ] Out-of-band detection: Burp Collaborator, interactsh

---

## CSRF

- [ ] Do all state-changing requests have a CSRF token?
- [ ] Is the token rotated on each request? (a static token is as good as none)
- [ ] Test accepting wrong/random tokens
- [ ] Test whether removing the CSRF parameter still works
- [ ] Confirm `SameSite` cookie attribute (missing or None makes CSRF easier)
- [ ] Focus: authenticated sensitive actions; login/logout CSRF is usually out-of-scope

---

## IDOR / Broken Access Control

- [ ] Access other same-privilege users' objects (substitute numeric ID, GUID, username)
- [ ] Vertical privilege escalation: attempt to access higher-privilege objects
- [ ] Multi-tenant apps: test cross-tenant access
- [ ] Test APIs directly (UI may hide certain options)
- [ ] EU PII access involves GDPR, severity multiplier
- [ ] Indirect references: file path, email, order/invoice number

---

## LFI / RFI

- [ ] Test file/image parameters: `file=test.jpg`, `page=home`, `template=login`
- [ ] Basic payload: `../../../../etc/passwd` (repeat `../` to root)
- [ ] Windows: `..\..\..\windows\win.ini`
- [ ] Null byte: `../../../../etc/passwd%00` (older PHP)
- [ ] PHP wrapper: `php://filter/convert.base64-encode/resource=/etc/passwd`
- [ ] RFI requires `allow_url_include=On` (PHP, rare but testable)

---

## File Upload Vulnerabilities

- [ ] Upload dangerous extensions: `.php`, `.php5`, `.phtml`, `.asp`, `.aspx`, `.jsp`
- [ ] Bypass extension restrictions: change MIME type, double extension, null byte, alternative extensions
- [ ] Polyglot files (valid image + PHP/JS code)
- [ ] Confirm uploaded file path: must be in web-accessible directory to execute shell
- [ ] Upload SVG files with embedded JS or XXE
- [ ] Upload DOCX/XLSX with XXE payload (embedded XML)

---

## XXE (XML External Entity)

- [ ] Find all endpoints that accept XML input
- [ ] Basic payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```
- [ ] Blind XXE: OOB exfiltration via DNS/HTTP
- [ ] Test SVG upload, DOCX/XLSX parsing, SAML

---

## Pre-Submission Checklist

- [ ] Can the PoC be reproduced within 5 minutes?
- [ ] Does every claimed impact have corresponding PoC steps?
- [ ] Does the severity match platform's realistic standards? (not theoretical worst case)
- [ ] Have you searched disclosed reports to confirm no duplicates?
- [ ] Are complete curl commands or screenshots attached?
- [ ] Are you NOT writing "static analysis finding" as "confirmed vulnerability"?
- [ ] Assessed against [[Pattern - Triage Calibration]]

---

## Tool List

| Tool | Purpose | Installation |
|------|---------|-------------|
| Burp Suite | Intercept/replay/scan | https://portswigger.net |
| ffuf | Directory/param fuzz | `brew install ffuf` |
| subfinder | Subdomain enumeration | `brew install subfinder` |
| GAU / waybackurls | Historical URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| sqlmap | SQL injection | `brew install sqlmap` |
| tplmap | SSTI automation | `git clone https://github.com/epinna/tplmap` |
| XSS Hunter | Blind XSS callback | https://xsshunter.trufflesecurity.com |
| ra2-dom-xss-scanner | DOM XSS | https://github.com/ra2-dom-xss-scanner |
| interactsh | OOB detection | `brew install interactsh-client` |
| JS-Tap | XSS post-exploitation | `git clone https://github.com/trustedsec/js-tap` |

---

## Related Notes

- [[Tool - JS-Tap]]
- [[Pattern - User Enumeration]]
- [[Pattern - CORS Misconfiguration]]
- [[Pattern - Git Exposure]]
- [[Pattern - Source Map Exposure]]
- [[Pattern - Triage Calibration]]
- [[Skill - web2-recon]]
- [[Skill - web2-vuln-classes]]
