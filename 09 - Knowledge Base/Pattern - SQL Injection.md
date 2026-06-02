---
fileClass: KB
type: pattern
tags: [pattern, sqli, injection, database]
added: 2026-01-01
---

# Pattern — SQL Injection

## Summary

Unsanitized user input is concatenated directly into a SQL query string, allowing an attacker to alter query logic. Variants include error-based (verbose DB errors expose data), UNION-based (append a SELECT to return attacker-chosen columns), boolean-based blind (infer data from true/false response differences), and time-based blind (infer data from response delays via `SLEEP`/`WAITFOR`).

## Detection Signals

- Single quote (`'`) causes a 500 error, syntax error, or changed response
- Boolean pair test: `param=1 AND 1=1` vs `param=1 AND 1=2` produces different content or HTTP status
- Time delay: `param=1; SELECT SLEEP(5)--` causes a measurable response delay
- Verbose database error messages (ORA-, MySQL syntax error, MSSQL near ...) in responses
- ORM raw-query methods used with user input (`raw()`, `execute()`, `query()`, string-format patterns)
- Search, filter, sort-column, and order-direction parameters are common injection points

## Grep Signatures

```bash
# String concatenation into SQL — Python
grep -rn 'execute(\s*["\x27].*%s\|execute(\s*f["\x27]\|\.format(.*query\|% .*WHERE' --include='*.py'

# Raw query calls — Django / SQLAlchemy
grep -rn '\.raw(\|\.execute(\|text(' --include='*.py'

# Node.js string template queries
grep -rn 'query(`\|query("[^?]*\${' --include='*.js' --include='*.ts'

# PHP string concatenation
grep -rn 'mysql_query\s*(\s*\$\|mysqli_query\s*(\|PDO.*query\s*(\s*"\s*\.' --include='*.php'

# Ruby on Rails find_by_sql / ActiveRecord string interpolation
grep -rn 'find_by_sql\s*(\s*"\|where(\s*"\s*#{' --include='*.rb'

# Java JDBC string concatenation
grep -rn 'createStatement\(\)\|executeQuery\s*(\s*".*\+' --include='*.java'

# Order-by injection (user-controlled column name)
grep -rn 'ORDER BY.*params\[\|order_by.*request\.' --include='*.py' --include='*.rb' --include='*.php'
```

## Test Methodology

1. Identify all parameters that influence a database query: URL path segments, query parameters, POST body fields, cookie values, HTTP headers (X-Forwarded-For, User-Agent)
2. Inject a single quote (`'`) and observe the response for errors, truncation, or behavior change
3. Run a boolean pair: append `AND 1=1--` (should behave normally) then `AND 1=2--` (should return empty/different); difference confirms injection
4. For numeric parameters: test `param=1-1` (should behave like `param=0`) vs `param=1-0` (behaves like `param=1`)
5. If no visible error, test time-based: `'; SELECT SLEEP(5)--` (MySQL) / `'; WAITFOR DELAY '0:0:5'--` (MSSQL) / `'; SELECT pg_sleep(5)--` (Postgres)
6. For UNION injection: determine column count with `ORDER BY N--` until error, then use `UNION SELECT NULL,NULL,...--`; identify string columns by substituting string literals
7. Confirm impact by extracting `@@version` (MSSQL/MySQL) or `version()` (Postgres) — stop at proof of concept; do not dump production data
8. Document exact payload, endpoint, parameter name, HTTP method, and observed response difference

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Single-quote escaping (`\'`) | Use numeric context (no quotes needed), or second-order injection |
| Keyword filtering (`SELECT`, `UNION`) | Case variation (`SeLeCt`), inline comments (`SEL/**/ECT`), URL encoding |
| WAF signature matching | Chunked encoding, parameter pollution, alternate syntax (`||` instead of `OR`) |
| Parameterized queries (properly used) | Second-order SQLi: input stored then later inserted unsafely |
| Error messages suppressed | Switch to boolean-blind or time-based techniques |
| Rate limiting | Slow the payload to stay under threshold; use binary search to minimize requests |

## Severity Guide

| Impact | Severity |
|--------|----------|
| Authentication bypass (login as any user or admin) | P1 |
| Extraction of credentials, PII, or payment data from production DB | P1-P2 |
| Full DB read access (multiple tables) | P1-P2 |
| Blind SQLi with confirmed data exfiltration path | P2-P3 |
| Blind SQLi with no demonstrated exfiltration (time-based proof only) | P3 |
| Read-only access to non-sensitive data | P4 |

## Related

- [[Pattern - IDOR]]
- [[Pattern - SSRF]]
- [[Lessons Learned]]
- [[Checklist - Pre-Submission Validation]]
- [[Playbook - Recon]]
