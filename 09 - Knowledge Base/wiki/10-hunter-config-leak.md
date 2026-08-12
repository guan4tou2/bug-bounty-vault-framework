---
type: wiki
category: hunter
hunter: config-leak
status: active
last-updated: 2026-04-21
---

# Hunter: `config-leak`

> **Purpose:** For sites behind a WAF / firewall, detect 100+ commonly exposed sensitive files with **minimal noise** (1 GET per path).
> **Inspiration:** [chaitin/xray](https://github.com/chaitin/xray) `config-leak` + `dirscan`-style rules + Nuclei `exposures/configs`.

## Why it's worth using

1. **1 GET per path** — almost never trips a WAF (compared to ffuf/feroxbuster firing hundreds of requests at once)
2. **Content-match verification** — an HTTP 200 alone doesn't count; the body must match the corresponding regex
3. **Tiered labeling** — four severity tiers: `P1-CRIT` / `P2-HIGH` / `P3-MED` / `P4-INFO`
4. **FAST=1 mode** — only runs the 24 highest-confidence paths (completes in under 30 seconds)
5. **zero LLM** — pure bash + curl, no dependency on external services

## Usage

```bash
# Full scan (100+ paths)
tools/hunters/hunt-config-leak.sh https://target.gov.tw

# Fast mode (P1/P2 only, < 30 seconds)
FAST=1 tools/hunters/hunt-config-leak.sh https://target.gov.tw

# Via bbflow
bbflow hunt target --only config-leak
```

### Output

```
./config_leak_out/https_target.gov.tw.txt
```

Format:
```
[12:34:56] === Config leak hunt: https://target.gov.tw (FAST=0) ===
🔴 [P1-CRIT] .git/config: https://target.gov.tw/.git/config [200]
     evidence: [core] repositoryformatversion = 0 filemode = true ...
🔴 [P2-HIGH] swagger-ui.html: https://target.gov.tw/swagger-ui.html [200]
     evidence: <!DOCTYPE html><html><head><title>Swagger UI</title>
🟡 [P3-MED]  composer.json: https://target.gov.tw/composer.json [200]
```

## Categories covered (full list)

### P1 Critical (also runs under FAST=1)

| Category | Path | Detection regex |
|------|------|-----------|
| **SCM** | `/.git/config` `/.git/HEAD` `/.git/index` `/.git/logs/HEAD` | `\[core\]`, `ref: refs/heads/`, `DIRC` magic |
| | `/.svn/entries` `/.svn/wc.db` | dir/file, SQLite magic |
| | `/.hg/hgrc` | `\[paths\]` |
| **Environment variables** | `/.env` `/.env.local` `/.env.production` `/.env.backup` | `DB_PASSWORD\|APP_KEY\|SECRET_KEY\|AWS_\|_TOKEN` |
| | `/appsettings.json` `/appsettings.Development.json` | `ConnectionStrings`, `Jwt`, `Secret` |
| **IDE** | `/.idea/workspace.xml` | `<project\|<component` |
| **Spring Boot** | `/actuator` `/actuator/env` `/actuator/heapdump` `/env` `/heapdump` | `"activeProfiles"`, `"propertySources"`, `JAVA PROFILE` |
| **WEB-INF** | `/WEB-INF/web.xml` | `<web-app\|<servlet\|<filter` |
| **phpinfo** | `/phpinfo.php` `/info.php` | `phpinfo\(\)\|PHP Version` |
| **Druid** | `/druid/index.html` | `Druid Monitor` |

### P2 High

| Category | Path | Detection |
|------|------|------|
| **Config JS** | `/env.js` `/config.js` `/config.json` | `window\.`, `apiKey`, `"apiKey` |
| **IDE** | `/.idea/modules.xml` `/.vscode/settings.json` `/.DS_Store` | XML/JSON start, `Bud1` magic |
| **Swagger** | `/swagger-ui.html` `/v2/api-docs` `/v3/api-docs` `/openapi.json` | `Swagger UI`, `"swagger"`, `"openapi"` |
| **PHPMyAdmin** | `/phpmyadmin/` `/pma/` | `phpMyAdmin` |
| **Nacos** | `/nacos/` | `Nacos\|nacos-server` |
| **Druid login** | `/druid/login.html` | `Druid Monitor` |
| **Apache** | `/.htaccess` `/server-status` `/server-info` | `RewriteEngine`, `Apache Server Status` |
| **Backup** (effectively P1) | `/backup.zip` `/backup.sql` `/db.sql` `/dump.sql` `/www.zip` | `PK\x03\x04`, `CREATE TABLE`, `INSERT INTO` |
| **SVN wc.db** | `/.svn/wc.db` | `SQLite format` |
| **CI/CD** | `/.gitlab-ci.yml` `/.travis.yml` `/.circleci/config.yml` | `stages:`, `language:` |
| **web.config** | `/web.config` | `<configuration\|<system\.web` |
| **.htpasswd** | `/.htpasswd` | `^[a-zA-Z0-9]+:\$` |

### P3 Medium

| Category | Path |
|------|------|
| Dependency management | `/composer.json` `/package.json` `/Gemfile` `/requirements.txt` `/pom.xml` `/build.gradle` `/go.mod` |
| Docker | `/Dockerfile` `/docker-compose.yml` `/Jenkinsfile` |
| crossdomain | `/crossdomain.xml` `/clientaccesspolicy.xml` |
| PHP ini | `/.user.ini` |

### P4 Info

| Category | Path |
|------|------|
| Machine-readable | `/sitemap.xml` `/robots.txt` `/.well-known/security.txt` |
| Project docs | `/README.md` `/CHANGELOG.md` `/TODO` `/.gitignore` |

## False-positive filtering

The built-in content-match in config-leak already filters out most fake SPA 200s. If you're still seeing false positives:

- **SPA returns index.html for every path**: you can exclude by `Content-Type: text/html` in bash, but `hunt-config-leak.sh` already excludes HTML bodies for binary-type files.
- **CDN cache miss returns 200 on first hit**: manually re-run with `curl -I` to confirm.
- **Honeypot**: some government sites return fake content for `/.git/config`. Follow up with `git-dumper`; if the retrieved repo has empty commits, it's a honeypot.

## Advanced: custom paths

Edit `hunt-config-leak.sh` and add new rules in the `!FAST` block:

```bash
# Custom path format:
probe "label"  "/path"  'content regex'  severity

# Example: an internal CMS leak path
probe "MyCMS config"  "/admin/config.inc"  'db_pass|db_user'  critical
```

## Relationship to other hunters

```
config-leak  → finds .git/config → git-exposure restores the repo → trufflehog scans history
config-leak  → finds /actuator   → actuator-deep probes deeper into /env /heapdump
config-leak  → finds swagger     → crawl-chain consumes swagger endpoints for DAST
config-leak  → finds /admin      → weak-login tries default credentials
```

## Report writing (example)

Example for a HITCON ZeroDay submission:

```markdown
## Vulnerability Summary
Found that https://target.gov.tw/.env can be downloaded directly, containing DB_PASSWORD, APP_KEY, and AWS credentials.

## Reproduction Steps
```bash
curl -sI https://target.gov.tw/.env
# HTTP/1.1 200 OK
# Content-Type: text/plain

curl -s https://target.gov.tw/.env | head -5
# APP_KEY=base64:xxxxxxxxxxxxx==
# DB_PASSWORD=XXXX
# AWS_ACCESS_KEY_ID=AKIAxxxxx
```

## Impact
- DB credential leak → if the DB is publicly reachable, direct connection is possible
- AWS credential leak → needs further verification of whether the key is active

## Classification
Sensitive Data Exposure > Sensitive Application Data
```

**Notes:**
- Don't overstate this as RCE (unless you actually logged in)
- Pick a precise classification; don't select "Disclosure of Secrets For Publicly Accessible Asset" (it auto-suggests P1)

## Related documents

- [03-xray-rules-reference.md](03-xray-rules-reference.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [28-tool-git-dumper.md](28-tool-git-dumper.md)
