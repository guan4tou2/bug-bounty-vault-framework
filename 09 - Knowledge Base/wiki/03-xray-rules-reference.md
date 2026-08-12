---
type: wiki
category: reference
status: active
last-updated: 2026-04-21
source: https://github.com/chaitin/xray
---

# xray Rules Localization Reference

> The [ChaitinTech/xray](https://github.com/chaitin/xray) community edition's rules themselves are open source (phantasm YAML rules); the commercial edition's PoCs are closed source. This document classifies xray's **stable and usable** rules and maps them to bbflow hunters or nuclei templates, so you can get the same coverage without installing xray.

## xray Rule Categories

xray rules are grouped into:
- **`baseline`** — basic security checks (CORS, CSP, CRLF, cookie flags, X-Frame-Options)
- **`config-leak`** — sensitive config file exposure
- **`dirscan`** — directory scanning (backups, SCM, IDE)
- **`jsonp`** — JSONP leaks
- **`redirect`** — open redirect
- **`ssrf`** — SSRF detection
- **`crlf`** — CRLF injection
- **`sql-injection`** — SQL injection (error-based only)
- **`xss`** — reflected XSS
- **`xxe`** — XXE
- **`path-traversal`** — path traversal
- **`struts2`** — OGNL/Struts2
- **`shiro`** — Shiro rememberMe
- **`fastjson`** — Fastjson deserialization
- **`brute-force`** — weak passwords
- **`phantasm`** — PoC-based (CVE / known vulnerabilities)

## 1. xray → bbflow hunter Mapping

| xray rule category | bbflow hunter | Notes |
|-----------|--------------|------|
| `config-leak` + `dirscan` | `hunt-config-leak.sh` | 100+ paths, content-match verification |
| `brute-force` | `hunt-weak-login.sh` | vendor panel detection + default creds |
| `dirscan` backup | `hunt-backup-files.sh` | 41 static + dynamic candidates |
| `baseline` CORS | `hunt-cors-reflect.sh` | 4-layer reflection + credentials:true |
| `redirect` | `hunt-open-redirect.sh` | redirect param variants |
| `shiro` | `hunt-weak-login.sh` | rememberMe cookie detection |
| `xss` | `hunt-dalfox-xss.sh` + `hunt-crawl-chain.sh` | nuclei DAST + dalfox |
| `sql-injection` | `hunt-crawl-chain.sh` | gf sqli + nuclei DAST |
| `ssrf` | `hunt-crawl-chain.sh` | gf ssrf + nuclei DAST |
| `path-traversal` | `hunt-crawl-chain.sh` | gf lfi + nuclei DAST |
| `phantasm` (CVE) | `hunt-nuclei` + `hunt-nuclei-wp` | official templates + Wordfence |

## 2. xray `config-leak` / `dirscan` Full Path List

This is xray's most reliable category. Below is the complete path list extracted from the open-source edition (all baked into `hunt-config-leak.sh`):

### SCM exposure

```
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.git/refs/heads/master
/.git/packed-refs
/.svn/entries
/.svn/wc.db
/.svn/all-wcprops
/.hg/hgrc
/.hg/store/00manifest.i
/.bzr/branch-format
/CVS/Root
/CVS/Entries
```

### IDE / editor leftovers

```
/.idea/workspace.xml
/.idea/modules.xml
/.idea/misc.xml
/.idea/vcs.xml
/.vscode/settings.json
/.vscode/launch.json
/.DS_Store
/.ftpconfig
/.phpintel
/.project
/.classpath
/.settings/
```

### Environment variables / config files

```
/.env
/.env.local
/.env.production
/.env.development
/.env.backup
/.env.bak
/.env.example
/.env.sample
/.env.test
/.env.stage
/env.js
/config.js
/config.json
/config.php
/config.yaml
/config.yml
/appsettings.json
/appsettings.Development.json
/application.properties
/application.yml
/application-dev.yml
/application-prod.yml
```

### Dependencies / build

```
/composer.json
/composer.lock
/package.json
/package-lock.json
/yarn.lock
/Gemfile
/Gemfile.lock
/requirements.txt
/Pipfile
/Pipfile.lock
/pom.xml
/build.gradle
/go.mod
/go.sum
/.gitignore
/Dockerfile
/docker-compose.yml
/Jenkinsfile
/.gitlab-ci.yml
/.travis.yml
/.circleci/config.yml
/buildspec.yml
```

### Backup / dump

```
/backup.zip, /backup.tar.gz, /backup.tar, /backup.rar, /backup.7z, /backup.sql
/bak.zip, /bak.tar.gz
/www.zip, /www.tar.gz, /www.rar, /www.7z
/web.zip, /wwwroot.zip, /website.zip, /site.zip
/db.sql, /db.zip, /dump.sql, /dump.zip
/database.sql, /data.sql
/admin.zip, /src.zip, /app.zip
/{hostname}.zip, /{hostname}.tar.gz, /{hostname}.sql
```

### WEB-INF / J2EE

```
/WEB-INF/web.xml
/WEB-INF/classes/
/WEB-INF/lib/
/WEB-INF/classes/config.properties
/WEB-INF/classes/db.properties
/WEB-INF/classes/application.xml
/META-INF/MANIFEST.MF
```

### Debug / info endpoints

```
/phpinfo.php, /info.php, /test.php, /debug.php
/server-status, /server-info
/status
/.user.ini
/php_info.php
```

### Apache / Nginx / IIS

```
/.htaccess
/.htpasswd
/web.config
/nginx.conf
/httpd.conf
/crossdomain.xml
/clientaccesspolicy.xml
```

### Spring Boot Actuator

```
/actuator
/actuator/env
/actuator/heapdump
/actuator/mappings
/actuator/configprops
/actuator/beans
/actuator/loggers
/actuator/httptrace
/actuator/threaddump
/actuator/jolokia
/actuator/caches
/actuator/metrics
/env
/heapdump
/mappings
/beans
/configprops
```

### Swagger / API docs

```
/swagger-ui.html
/swagger/index.html
/swagger/ui/index
/swagger-ui/index.html
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/v2/api-docs
/v3/api-docs
/api-docs
/docs
/documentation
```

### Other high-value

```
/phpmyadmin/
/pma/
/druid/index.html
/druid/login.html
/nacos/
/solr/
/kibana/
/grafana/
/jenkins/
/elasticsearch/_cat/indices
/manager/html
```

## 3. xray `baseline` Category (add to your hunt flow)

Always run these — low noise, high ROI:

| Check | Tool | Notes |
|-------|------|------|
| CORS misconfig | `hunt-cors-reflect.sh` | origin reflect / null origin / regex bypass |
| Missing CSP | `nuclei -t misconfiguration/missing-csp.yaml` | standalone P5, escalates when paired with XSS |
| CRLF injection | `nuclei -t vulnerabilities/crlf-injection` | most modern WAFs block this now |
| Cookie missing HttpOnly/Secure | manual `curl -I` | P5 Info |
| Missing X-Frame-Options | manual `curl -I` | Clickjacking, P5 |
| Reflected email (user enum) | `hunt-user-enum.sh` | standalone P5, chains to P3 |
| Excessive HTTP methods | manual `curl -X OPTIONS` | TRACE / PUT / DELETE |

## 4. xray `phantasm` Category (CVE/PoC)

The commercial xray edition's PoCs are closed source, but the community edition's `phantasm` set has dozens. bbflow's alternative:

```bash
# Use official nuclei templates to cover the phantasm category
bbflow hunt target --only nuclei,nuclei-wp

# Fast check for specific high-value CVEs
nuclei -u https://target \
  -tags cve,oast,struts,fastjson,shiro,thinkphp,weblogic,tomcat \
  -severity high,critical \
  -silent
```

## 5. xray Rule Implementation Example (reference)

An xray YAML rule looks like this:

```yaml
name: poc-yaml-git-source-code
rules:
  - method: GET
    path: /.git/config
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"[core]") &&
      response.body.bcontains(b"repositoryformatversion")
```

The equivalent in bbflow:

```bash
# hunt-config-leak.sh, line 55
probe ".git/config" "/.git/config" 'repositoryformatversion|\[core\]|\[remote ' critical
```

Same logic: `HTTP 200 + body match content regex`.

## 6. Converting an xray Rule to a nuclei Template (advanced)

If you want to convert an xray YAML rule to nuclei:

**xray:**
```yaml
rules:
  - method: GET
    path: /actuator/env
    expression: response.status==200 && response.body.bcontains(b"activeProfiles")
```

**nuclei equivalent:**
```yaml
id: actuator-env-exposure
info:
  name: Spring Boot Actuator env
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
    matchers:
      - type: word
        words:
          - "activeProfiles"
          - "propertySources"
        part: body
        condition: or
      - type: status
        status:
          - 200
```

Drop this kind of template into `tools/nuclei-templates/bb-recon/` and bbflow's `nuclei` hunter will automatically run it.

## 7. Running xray (if you really need the commercial edition)

```bash
# Docker edition (community-edition phantasm rules)
docker run --rm -it -v $PWD:/data chaitin/xray webscan \
  --basic-crawler https://target.gov.tw \
  --html-output result.html

# Important: the community edition can webscan, but phantasm coverage is limited
# Commercial licensing must be requested from Chaitin Tech
```

## Related Documents

- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [11-hunter-weak-login.md](11-hunter-weak-login.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [24-tool-nuclei.md](24-tool-nuclei.md)
