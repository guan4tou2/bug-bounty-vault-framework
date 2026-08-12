---
type: wiki
category: flow
tool: semgrep,grep,ripgrep,ast-grep
status: active
last-updated: 2026-04-21
---

# Source Code Review Flow (2026 Edition)

> **Purpose:** After finding a .git / source map / GitHub repo / decompiled APK / ghidra binary, how do you "find 3 high-value vulnerabilities within 2 hours"? This doc lists sinks, regexes, and quick tools by language.

## 0. Flow Skeleton

```
1. Identify language / framework
2. Find entrypoints (router / controller)
3. Trace user input flow (taint tracking)
4. Find dangerous sinks
5. Check sanitization / validation
6. Write a PoC
```

## 1. Generic Regex (Any Language)

### 1.1 Credentials

```bash
rg -i 'api[_-]?key|secret|password|token|auth' --type-add 'all:*' -t all
rg '(aws_access_key|aws_secret|sk_live_|pk_live_|AKIA[0-9A-Z]{16})'
rg '(-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)'
```

Tools: `trufflehog`, `gitleaks`, `detect-secrets`.

```bash
trufflehog filesystem ./source --json
gitleaks detect --source ./source --report-format json
```

### 1.2 URLs / Internal hosts

```bash
rg 'https?://' | grep -v 'github.com\|google.com\|w3.org'
rg '(internal|admin|staging|dev)\.[a-z-]+\.'
rg '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.'
```

### 1.3 SQL

```bash
rg -i 'select\s+.*from|insert\s+into|update\s+.*set|delete\s+from'
rg 'execute\(|executequery\(|rawQuery\('
```

### 1.4 Command execution

```bash
rg 'exec\(|system\(|popen\(|spawn\(|Runtime\.getRuntime'
```

## 2. PHP

### 2.1 File inclusion

```bash
rg 'include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\('
rg 'file_get_contents\s*\(|fopen\s*\(|readfile\s*\('
```

A sink combined with `$_GET`/`$_POST`/`$_REQUEST` in the same function = LFI / RFI.

### 2.2 SQL

```bash
rg 'mysql_query\(|mysqli_query\(|pg_query\('
rg '\$(pdo|db|conn)->query\('
rg '->raw\('       # Laravel raw query
```

### 2.3 Command

```bash
rg 'shell_exec\(|exec\(|system\(|passthru\(|popen\(|proc_open\(|backtick'
```

### 2.4 Deserialization

```bash
rg 'unserialize\('
```

### 2.5 XXE

```bash
rg 'simplexml_load_string|DOMDocument|SoapClient'
rg 'LIBXML_NOENT'  # if set → entity expansion is enabled
```

### 2.6 Key Laravel / Symfony files

```
.env
config/database.php
routes/web.php / routes/api.php
app/Http/Controllers/
app/Http/Middleware/
```

## 3. Node.js / JavaScript

### 3.1 Command

```bash
rg 'child_process\.(exec|execSync|spawn|execFile)'
rg 'require\([\'"]child_process'
```

### 3.2 SQL

```bash
rg 'raw\(|\.query\([\'"][^?]*\+'
rg 'sequelize\.(query|literal)'
rg 'knex\.raw'
```

### 3.3 Template injection (SSTI)

```bash
rg 'ejs\.render|pug\.render|handlebars|dust\.render'
rg 'new Function\('
rg 'eval\('
```

### 3.4 Deserialization

```bash
rg 'node-serialize|unserialize'
```

### 3.5 Prototype pollution

```bash
rg '__proto__|constructor\.prototype|Object\.assign'
rg 'lodash\.(merge|defaultsDeep|set)'
```

### 3.6 Express routes

```bash
rg 'app\.(get|post|put|delete|patch)\('
rg 'router\.(get|post|put|delete|patch)\('
```

### 3.7 Key files

```
package.json          # dependencies / scripts
.env.local
config/*.json
next.config.js        # sometimes leaks env vars
```

## 4. Python

### 4.1 Command

```bash
rg 'os\.system|subprocess\.(run|Popen|call|check_output)'
rg 'shell=True'
```

### 4.2 Eval

```bash
rg '\beval\(|\bexec\('
rg 'pickle\.(loads|load)'
rg 'yaml\.load\('     # without SafeLoader
```

### 4.3 SQL

```bash
rg 'cursor\.execute\(|cursor\.executemany\('
rg '\.raw\(|\.extra\('       # Django
rg '(text|sqlalchemy\.text)\('
```

### 4.4 SSTI (Flask/Django)

```bash
rg 'render_template_string|Template\('
rg 'Mark(Safe|safe)'
```

### 4.5 Deserialization

```bash
rg 'pickle\.|cPickle|marshal\.'
rg 'yaml\.load\b'             # dangerous if no Loader=SafeLoader
```

### 4.6 Django / Flask entrypoints

```
urls.py / views.py
app.py / main.py
requirements.txt / pyproject.toml
settings.py           # SECRET_KEY, DB
```

## 5. Java

### 5.1 Command

```bash
rg 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder'
```

### 5.2 SQL

```bash
rg 'createQuery|createNativeQuery|createStatement'
rg 'prepareStatement\(' -A 5 | rg '\+ '     # concat inside prepare
```

### 5.3 Deserialization

```bash
rg 'ObjectInputStream|readObject|XMLDecoder|JsonMapper.*DefaultTyping'
rg 'ysoserial'
```

### 5.4 XXE

```bash
rg 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory'
rg 'setFeature.*disallow-doctype'   # if missing → XXE
```

### 5.5 Log4Shell

```bash
rg 'log4j' --no-ignore
cat pom.xml | grep -i log4j
```

### 5.6 Spring

```bash
rg '@RequestMapping|@GetMapping|@PostMapping|@RequestBody'
rg '@PreAuthorize|@Secured'
```

### 5.7 Key files

```
pom.xml / build.gradle
application.properties / application.yml
src/main/resources/
```

## 6. Go

### 6.1 Command

```bash
rg 'exec\.Command\(|exec\.CommandContext\('
```

### 6.2 SQL

```bash
rg 'db\.Exec\(|db\.Query\(|db\.QueryRow\('
rg 'fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT'  # concat
```

### 6.3 SSRF

```bash
rg 'http\.Get\(|http\.Post\('
rg 'net\.Dial\('
```

### 6.4 Template

```bash
rg 'text/template|html/template'
# html/template auto-escapes, text/template does not
```

## 7. Ruby / Rails

### 7.1 Command

```bash
rg '\bsystem\(|\bexec\(|%x\(|\bbacktick|Kernel\.open'
```

### 7.2 SQL

```bash
rg 'find_by_sql|execute\(|exec_query'
rg 'where\([\'"][^?]*#{'       # interpolation → SQLi
```

### 7.3 Deserialization

```bash
rg 'Marshal\.load|YAML\.load'  # not safe_load
```

### 7.4 Mass assignment

```bash
rg 'params\.permit'            # check the permit list
rg 'params\[.*\]\.permit!'     # allows everything
```

### 7.5 Rails routes

```
config/routes.rb
app/controllers/
app/models/
```

## 8. C / C++

### 8.1 Buffer overflow

```bash
rg '\b(strcpy|strcat|sprintf|gets|scanf)\b'
```

### 8.2 Format string

```bash
rg 'printf\s*\([^,]*\);|fprintf[^,]*,\s*[^"]*\);'
```

### 8.3 Integer overflow

```bash
rg 'malloc\(.*\*|alloca\('
```

### 8.4 Use after free

ASan / Valgrind runtime runs are more reliable here.

## 9. Semgrep (Automation)

```bash
# install
pip install semgrep
# or
brew install semgrep

# Registry rules (useful)
semgrep --config=p/security-audit ./source
semgrep --config=p/owasp-top-ten ./source
semgrep --config=p/javascript ./source
semgrep --config=p/php ./source

# JSON output for post-processing
semgrep --config=p/security-audit --json ./source > findings.json
```

## 10. ast-grep (Structural Search)

```bash
brew install ast-grep

# find all eval calls that take user input directly
ast-grep run -l js -p 'eval($_)'

# more complex pattern
ast-grep run -l python -p 'subprocess.$FN($CMD, shell=True)'
```

## 11. Priority Order (Highest ROI Within 2 Hours)

```
1. Credentials (run trufflehog across the whole repo)
2. Hardcoded API keys (AWS/GCP/Stripe)
3. .env / config files → find connection strings
4. Router / route files → find endpoints with no auth
5. Exec / system calls → trace user input
6. String concatenation in SQL queries
7. File include / read → trace user input
8. Deserialize → trace the data source
9. XML / YAML parser configuration
10. Version check: does the dependency have a known CVE
```

## 12. Tool Overview

| Tool | Purpose | URL |
|------|------|-----|
| trufflehog | Credentials scan | https://github.com/trufflesecurity/trufflehog |
| gitleaks | Git secret scan | https://github.com/gitleaks/gitleaks |
| detect-secrets | Yelp secret scanner | https://github.com/Yelp/detect-secrets |
| semgrep | Static analysis with rule sets | https://semgrep.dev/ |
| ast-grep | Structural search | https://github.com/ast-grep/ast-grep |
| ripgrep | Fast grep | https://github.com/BurntSushi/ripgrep |
| bandit | Python SAST | https://github.com/PyCQA/bandit |
| brakeman | Rails SAST | https://brakemanscanner.org/ |
| njsscan | Node.js SAST | https://github.com/ajinabraham/njsscan |
| sonarqube | Enterprise SAST | https://www.sonarsource.com/ |
| SAST-scan (Shiftleft) | Multi-lang | https://github.com/ShiftLeftSecurity/sast-scan |
| CodeQL | GitHub advanced | https://codeql.github.com/ |

## 13. Quick-Play Checklist

```
[ ] Run trufflehog + gitleaks once
[ ] Search .env / config/*.{json,yml,properties}
[ ] Search hardcoded hosts / internal.*
[ ] List routes → flag the no-auth ones
[ ] Run the regexes from sections 1-8 of this doc
[ ] Run semgrep p/security-audit
[ ] Cross-check package.json / pom.xml / requirements for CVEs (snyk db)
[ ] Readme / CI config → may leak CI secrets
[ ] Test fixtures → often contain real data
```

## Related Documents

- [27-tool-trufflehog.md](27-tool-trufflehog.md) — secret scanning
- [28-tool-git-dumper.md](28-tool-git-dumper.md) — git exposure tools
- [73-ssti-deep.md](73-ssti-deep.md) — template injection sinks
- [72-sqli-deep.md](72-sqli-deep.md) — SQL sink patterns
- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/
- Semgrep rules registry: https://semgrep.dev/explore
