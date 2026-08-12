---
type: wiki
category: tool
tool: nuclei
status: active
last-updated: 2026-04-21
source: https://github.com/projectdiscovery/nuclei
---

# Tool: nuclei (YAML-based DAST scanner)

> **Purpose:** The most popular template-based vulnerability scanner. **4000+ official templates** covering CVE / exposure / misconfig / default-login / CORS / etc.
> For full coverage with `hunt-nuclei-deep.sh`, see [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md).

## Installation

```bash
# Recommended: Go install
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Homebrew
brew install nuclei

# Update templates after first install
nuclei -update-templates
nuclei -update

# Check version
nuclei -version
```

## Basic usage

```bash
# Single target
nuclei -u https://target.com -silent

# From a list
nuclei -l alive.txt -silent

# Specify template directory
nuclei -u https://target -t ~/nuclei-templates/http/cves/ -silent

# Specify tag
nuclei -u https://target -tags cve,rce -silent

# Specify severity
nuclei -u https://target -severity high,critical -silent

# Output
nuclei -u https://target -silent -o nuclei.txt
nuclei -u https://target -silent -json-export nuclei.json
```

## Essential flags

| Flag | Purpose |
|------|------|
| `-u URL` | Single target |
| `-l file` | Target list |
| `-t path` | Template path (can be repeated) |
| `-tags tag1,tag2` | Only run specified tags |
| `-etags tag` | Exclude tag |
| `-severity info,low,medium,high,critical` | Severity filter |
| `-c 25` | Concurrency |
| `-rate-limit 150` `-rl 150` | Rate limit |
| `-timeout 10` | Per-request timeout |
| `-retries 1` | Retry count |
| `-H 'Header: value'` | Add header |
| `-dast` | DAST mode (param fuzzing) |
| `-ni` | No interactsh (don't connect to OAST server) |
| `-iserver oast.pro` | Specify interactsh server |
| `-silent` | Only output findings |
| `-v` | Verbose |
| `-debug` | Debug |
| `-stats` | Show progress |
| `-nmhe` | No template hash verification (faster) |
| `-o file` | Text output |
| `-json-export file.json` | JSON export |
| `-jsonl-export file.jsonl` | JSONL |
| `-newer-than 7d` | Only use templates from the last 7 days |
| `-exclude-matchers matcher-name` | Exclude specific matcher |

## Important tag categories

### By vulnerability type

```
xss, dom                 → XSS
sqli, sql-injection      → SQL Injection
ssrf                     → SSRF
lfi, file, traversal     → LFI / Path Traversal
rce, cmd, command        → RCE
ssti                     → Template injection
xxe                      → XXE
redirect, open-redirect  → Open Redirect
cors                     → CORS misconfig
takeover                 → Subdomain Takeover
```

### By exposure type

```
exposure, exposed        → General exposure
disclosure               → Information disclosure
token, key               → API token / API key
secret, apikey           → Secret category
debug, trace             → Debug endpoint
phpinfo                  → PHP info
actuator, springboot     → Spring Boot Actuator
prometheus, jmx          → Monitoring dashboards
```

### By function

```
panel, exposed-panel     → Admin interface
default-login, default-logins, weak-credential  → Default credentials
misconfig, misconfiguration  → General misconfiguration
```

### By technology

```
wordpress, wp            → WordPress
joomla                   → Joomla
drupal                   → Drupal
jenkins                  → Jenkins
gitlab                   → GitLab
oracle                   → Oracle
log4j                    → Log4Shell
spring                   → Spring
fastjson                 → Fastjson
shiro                    → Apache Shiro
struts                   → Struts2
```

### By CVE year

```
cve,2023
cve,2024
cve,2025
cve,2026
```

## Recommended combinations

### Full scan (official templates)

```bash
nuclei -u https://target \
  -severity low,medium,high,critical \
  -silent \
  -o nuclei_all.txt
```

### High-value quick scan

```bash
nuclei -u https://target \
  -tags cve,rce,sqli,xss,ssrf,lfi,default-login,exposure \
  -severity high,critical \
  -silent \
  -o nuclei_hit.txt
```

### Low-noise scan for government targets

```bash
nuclei -u https://target.gov.tw \
  -tags exposure,disclosure,phpinfo,actuator,springboot,default-login \
  -severity medium,high,critical \
  -rate-limit 10 \
  -c 5 \
  -timeout 15 \
  -silent \
  -o nuclei_gov.txt
```

### DAST mode (fuzz URL params)

```bash
nuclei -l endpoints_with_params.txt \
  -dast \
  -tags xss,sqli,ssrf,lfi,redirect \
  -silent \
  -o nuclei_dast.txt
```

### CVE-focused (last two years)

```bash
nuclei -u https://target \
  -tags cve,2025,2026 \
  -severity high,critical \
  -silent
```

### WordPress-focused (~200 known plugin vulns)

```bash
nuclei -u https://target/wp \
  -tags wordpress,wp \
  -silent
```

### Custom template (bb-recon)

```bash
nuclei -u https://target \
  -t tools/nuclei-templates/bb-recon/ \
  -silent
```

## Template development

### Simplest template

```yaml
# http/custom/my-vuln.yaml
id: my-vuln-check
info:
  name: My Vulnerability Check
  author: yourself
  severity: high
  tags: exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/config.inc"

    matchers:
      - type: word
        words:
          - "db_password"
          - "secret_key"
        condition: or
      - type: status
        status:
          - 200
    matchers-condition: and
```

### DAST template

```yaml
id: custom-xss-dast
info:
  name: Reflected XSS
  severity: high
  tags: xss,dast

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'

    payloads:
      reflection:
        - "'\"><svg onload=alert(1)>"
        - "<script>alert(1)</script>"

    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"
```

## Template management

```bash
# Update official templates
nuclei -update-templates

# List all tags
nuclei -tl | awk '{print $NF}' | tr ',' '\n' | sort -u

# See which templates exist for a tag
nuclei -tl -tags xss

# Only run templates added in the last 30 days
nuclei -u target -tags cve -newer-than 30d

# Validate custom template syntax
nuclei -t my-template.yaml -validate

# View template details
nuclei -tl -silent | grep "log4j"
nuclei -t http/cves/2021/CVE-2021-44228.yaml -silent -verbose
```

## Speed-up tips

### 1. Increase parallelism

```bash
nuclei -u target -c 50 -rl 500 -silent
```

### 2. Skip template hash verification

```bash
nuclei -u target -nmhe -silent
```

### 3. Only run the severities you care about

```bash
# Other severities won't even be loaded
nuclei -u target -severity critical -silent
```

### 4. Only load the templates you need

```bash
nuclei -u target -t http/cves/2025/ -silent
```

### 5. -no-store-response to save memory

```bash
nuclei -u target -nsr -silent
```

## FAQ

### Q: -dast mode isn't triggering
A: The URL must **contain a param with `=`**. Example: `https://target/search?q=test` (OK) vs `https://target/` (won't trigger).

### Q: Too many templates, scan never finishes
A:
- Filter with `-tags`
- Narrow with `-severity`
- Use `-exclude-tags dos,intrusive`

### Q: Can't connect to OAST
A:
- Add `-ni` to skip OAST (but you'll miss blind vulns)
- Or self-host an interactsh server (`interactsh-server`)

### Q: Getting banned by WAF
A:
- `-rate-limit 5 -c 5`
- Add header: `-H "X-Forwarded-For: 127.0.0.1"`
- Change User-Agent: `-H "User-Agent: Mozilla/5.0 ..."`

### Q: Broke after a template update
A: `nuclei -update-templates` occasionally has breaking changes. Rollback:
```bash
cd ~/nuclei-templates
git log --oneline
git checkout <previous-commit>
```

## bbflow integration

```bash
# Default tag set (hunt-nuclei)
bbflow hunt target --only nuclei

# Deep expansion (all categories)
bbflow hunt target --only nuclei-deep

# Only run a specific CATEGORY
CATEGORY=xss,sqli bbflow hunt target --only nuclei-deep
```

## Companion tools

### interactsh (self-hosted OAST)

```bash
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# Self-host (requires a public domain)
interactsh-server -domain oast.yourdomain.com

# Client only receives payloads
interactsh-client -server oast.yourdomain.com
```

### notify (push results to Slack / Telegram)

```bash
go install github.com/projectdiscovery/notify/cmd/notify@latest

nuclei -u target -silent | notify -bulk -id telegram
```

## Related files

- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — Full attack surface coverage
- [03-xray-rules-reference.md](03-xray-rules-reference.md) — xray → nuclei template conversion
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) §Stage 9
