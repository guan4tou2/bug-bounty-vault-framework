---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# Nuclei Full Attack-Surface Coverage Guide

> Solves the "nuclei default templates run and find nothing" pain point: the default run only covers `cves/` plus a small slice of `vulnerabilities/`, but there are actually **100+ tags available**.
> Pair with `tools/hunters/hunt-nuclei-deep.sh` to cover every category in one command.

## Automation (recommended)

```bash
# Scan all categories (~5-15 min)
tools/hunters/hunt-nuclei-deep.sh https://target.com

# Only run XSS + SQLi + SSRF + LFI
CATEGORY=xss,sqli,ssrf,lfi tools/hunters/hunt-nuclei-deep.sh https://target.com

# Only run high/critical (saves time)
FAST=1 tools/hunters/hunt-nuclei-deep.sh https://target.com

# Enable DAST fuzz mode (payload-fuzzes URL parameters)
DAST=1 CATEGORY=xss,sqli URL_LIST=endpoints.txt tools/hunters/hunt-nuclei-deep.sh

# Low-noise variant (government / WAF-protected targets)
RATE=10 CONC=5 tools/hunters/hunt-nuclei-deep.sh https://target.com
```

## Manual scanning by category

### XSS

```bash
# Reflected / stored / DOM
nuclei -u https://target -tags xss,dom -silent

# DAST mode (fuzzes URL params)
nuclei -l endpoints.txt -tags xss -dast -silent
nuclei -u "https://target/search?q=FUZZ" -tags xss -dast -silent

# Only run the official exposure/xss/ set
nuclei -u https://target -t http/vulnerabilities/xss/ -silent
```

### SQL Injection

```bash
# Error-based
nuclei -u https://target -tags sqli -silent

# DAST (injects payloads into every param)
nuclei -l endpoints.txt -tags sqli -dast -silent

# Only run known-CVE SQLi templates
nuclei -u https://target -tags sqli,cve -silent
```

### SSRF

```bash
# Requires OAST (interact.sh)
nuclei -u https://target -tags ssrf -silent

# Blind SSRF needs -oast
nuclei -u https://target -tags ssrf,oast -silent

# Specify an interactsh server
nuclei -u https://target -tags ssrf -iserver oast.pro -silent
```

### LFI / Path Traversal

```bash
# LFI + file traversal
nuclei -u https://target -tags lfi,file,traversal -silent

# DAST
nuclei -l endpoints.txt -tags lfi,traversal -dast -silent

# Specific LFI targets: /etc/passwd, /proc/self/environ
# these live under http/vulnerabilities/generic/
```

### RCE (highest value)

```bash
# All RCE tags
nuclei -u https://target -tags rce,cmd -silent

# Specific frameworks
nuclei -u https://target -tags log4j,spring,struts,fastjson,shiro,thinkphp,weblogic,tomcat -silent

# OAST RCE (blind)
nuclei -u https://target -tags rce,oast -silent

# CVE-2021-44228 Log4j
nuclei -u https://target -t http/cves/2021/CVE-2021-44228.yaml -silent
```

### Auth / Access

```bash
# Default login (vendor default credentials)
nuclei -u https://target -tags default-login,default-logins -silent

# Weak credentials
nuclei -u https://target -tags weak-credential -silent

# Panel detection (then run default-login)
nuclei -u https://target -tags panel,exposed-panel -silent
```

### Information Disclosure

```bash
# Disclosure / exposure / token / key
nuclei -u https://target -tags exposure,exposed,disclosure,token,key -silent

# .git / .svn / .env only
nuclei -u https://target -t http/exposures/ -silent

# Secret / API key exposure
nuclei -u https://target -tags secret,apikey -silent
```

### Debug endpoints

```bash
# /debug /actuator /phpinfo /server-status /prometheus /jmx
nuclei -u https://target -tags debug,phpinfo,actuator,springboot,jmx,prometheus,trace -silent

# Deep-dive Spring Boot Actuator
nuclei -u https://target -t http/misconfiguration/springboot/ -silent
```

### CORS

```bash
# CORS misconfig
nuclei -u https://target -tags cors -silent

# Reflective CORS only
nuclei -u https://target -t http/misconfiguration/cors/ -silent
```

### Open Redirect

```bash
nuclei -u https://target -tags redirect,open-redirect -silent

# DAST
nuclei -l endpoints.txt -tags redirect -dast -silent
```

### SSTI (Server-Side Template Injection)

```bash
nuclei -u https://target -tags ssti -silent
nuclei -l endpoints.txt -tags ssti -dast -silent
```

### XXE

```bash
nuclei -u https://target -tags xxe -silent
```

### Subdomain Takeover

```bash
nuclei -l subdomains.txt -tags takeover -silent

# Verify individually
nuclei -u https://sub.target.com -t http/takeovers/ -silent
```

### Cloud Misconfig (AWS / Azure / GCP)

```bash
nuclei -u https://target -tags aws,azure,gcp,s3,cloud -silent

# S3 bucket
nuclei -u https://target -t http/cves/ -tags s3 -silent
```

## CVE by year / severity

```bash
# Recent-year CVEs (critical only)
nuclei -u https://target -tags cve,2024 -severity critical -silent
nuclei -u https://target -tags cve,2025 -severity critical -silent
nuclei -u https://target -tags cve,2026 -severity critical -silent

# High-value CVE quick scan
nuclei -u https://target \
  -tags log4j,spring4shell,shiro,fastjson,struts,weblogic,thinkphp,tomcat,ghost \
  -severity high,critical \
  -silent
```

## DAST mode explained

nuclei's `-dast` flag fuzzes the query parameters of a URL with payloads, similar to sqlmap.

```bash
# Against a single URL
nuclei -u "https://target/search?q=test&lang=en" -dast -silent

# Against a URL list (recommended: pair with gf-classified results)
nuclei -l gf_xss.txt -dast -tags xss -silent
nuclei -l gf_sqli.txt -dast -tags sqli -silent
nuclei -l gf_ssrf.txt -dast -tags ssrf -silent
nuclei -l gf_lfi.txt -dast -tags lfi -silent

# Feed in results from bbflow crawl-chain's 07_gf_* output
for pat in xss sqli ssrf lfi redirect ssti; do
  nuclei -l crawl_chain_out/target/07_gf_${pat}.txt \
    -tags $pat -dast -silent \
    -o nuclei_deep_out/dast_${pat}.txt
done
```

## Custom templates (bb-recon)

Custom templates live in `tools/nuclei-templates/bb-recon/`; `hunt-nuclei-deep.sh` picks them up automatically.

```yaml
# tools/nuclei-templates/bb-recon/custom-cms-config.yaml
id: custom-cms-config
info:
  name: CustomCMS config exposure
  author: bbflow
  severity: high
  tags: exposure,cms
http:
  - method: GET
    path:
      - "{{BaseURL}}/customcms/config.inc"
    matchers:
      - type: word
        words:
          - "db_password"
          - "db_user"
        condition: or
      - type: status
        status: [200]
```

## Template management

```bash
# Update official templates
nuclei -update-templates

# List all tags
nuclei -tl | head -100

# See which templates exist for a given tag
nuclei -tl -tags xss | head -20

# Only use recent templates (last 30 days)
nuclei -u target -tags cve -newer-than 30d
```

## Low-noise combo (WAF-friendly)

```bash
# High/critical only + slow rate + low concurrency
nuclei -u https://target \
  -severity high,critical \
  -rate-limit 5 \
  -c 5 \
  -timeout 15 \
  -retries 1 \
  -silent
```

## Recommended tag combo for government sites

```bash
# Government sites (low-risk findings still pay out)
nuclei -u https://target.gov \
  -tags exposure,disclosure,phpinfo,actuator,springboot,default-login,xxe,lfi,xss,redirect \
  -severity low,medium,high,critical \
  -rate-limit 10 \
  -silent \
  -o gov_findings.txt
```

## bbflow integration

```bash
# Add into bbflow
bbflow hunt target --only nuclei-deep

# CATEGORY can be passed through
CATEGORY=xss,sqli bbflow hunt target --only nuclei-deep
```

## Related files

- [24-tool-nuclei.md](24-tool-nuclei.md) — nuclei tool deep dive
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — crawl-chain produces gf_*.txt for DAST feeding
- [03-xray-rules-reference.md](03-xray-rules-reference.md)
