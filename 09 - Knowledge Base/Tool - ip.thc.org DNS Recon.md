---
type: tool
title: "Tool - ip.thc.org DNS Recon"
tags: [tool, recon, subdomain, rdns, dns, passive, thc, cname]
status: active
last_updated: 2026-06-06
---

# Tool -- ip.thc.org DNS Recon (Subdomain / RDNS / CNAME)

A free passive DNS database by THC, containing **5.90 Billion** DNS records (as of May 2026). No account or API key required; supports CLI (curl) and JSON REST API.

**Use cases**: Quick passive subdomain enumeration, IP-to-domain reverse lookup, CNAME target lookup. Supplements crt.sh / Amass coverage gaps.

---

## 1. CLI Usage (curl -- fastest)

### 1.1 Subdomain Enumeration

```bash
# Basic (list all known subdomains)
curl https://ip.thc.org/<domain>
curl https://ip.thc.org/example-vendor.com

# With options (for scripting)
curl "https://ip.thc.org/example-vendor.com?l=100&nocolor=1&noheader=1"

# Pure subdomain list (filter out comment lines)
curl -s "https://ip.thc.org/example-vendor.com?nocolor=1&noheader=1" | grep -v '^;'
```

**CLI options:**

| Option | Description |
|--------|-------------|
| `l=N` | Number of results to return (max 100) |
| `nocolor=1` | Disable ANSI colors (required for piped output) |
| `raw=1` | Do not decode IDN/punycode |
| `noheader=1` | Suppress `;;` summary lines |

**Short path aliases:**
- Subdomain: `https://ip.thc.org/<domain>` or `https://ip.thc.org/sb/<domain>`
- CNAME reverse lookup: `https://ip.thc.org/cn/<domain>`

### 1.2 Reverse DNS (IP to domains)

```bash
# Basic (find domains hosted on an IP)
curl https://ip.thc.org/203.0.113.75

# Filter by apex domain (only show example-vendor.com)
curl "https://ip.thc.org/203.0.113.75?f=example-vendor.com&l=50&nocolor=1&noheader=1"
```

**Additional options:**

| Option | Description |
|--------|-------------|
| `f=<apex>` | Only return records belonging to a specific apex domain |

Output includes ASN, Org, City, Country, GPS (useful for infrastructure fingerprinting).

### 1.3 CNAME Reverse Lookup (who CNAMEs to this domain)

```bash
# Find who CNAMEs to target (subdomain takeover exploration)
curl "https://ip.thc.org/cn/google.com?nocolor=1&noheader=1"
```

---

## 2. REST API (JSON, no auth required)

**Base URL:** `https://ip.thc.org/api/v1`

**Rate limit:** Approximately 250 initial request credits, 0.5/sec replenishment (about 30/min).

### 2.1 Subdomain Lookup

```bash
curl -s -X POST https://ip.thc.org/api/v1/lookup/subdomains \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example-vendor.com", "page_state": "", "limit": 100}' | jq .
```

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Apex domain to query |
| `page_state` | string | Pagination token (empty for first request, use `next_page_state` from response for subsequent pages) |
| `limit` | integer | Results per page |

**Response:**
```json
{
  "subdomains": [ ... ],
  "next_page_state": "eyJuZXh0X3BhZ2UiOjJ9"
}
```

### 2.2 Reverse DNS Lookup

```bash
curl -s -X POST https://ip.thc.org/api/v1/lookup \
  -H 'Content-Type: application/json' \
  -d '{"ip_address": "203.0.113.75", "tld": [], "apex_domain": "example-vendor.com", "page_state": "", "limit": 50}' | jq .
```

**Request body:**

| Field | Type | Description |
|-------|------|-------------|
| `ip_address` | string (required) | Single IP or IP block |
| `tld` | string[] | TLD filter (e.g. `["com","net"]`); not supported for IP blocks |
| `apex_domain` | string | Apex domain filter; not supported for IP blocks |
| `page_state` | string | Pagination token |
| `limit` | integer | Results per page |

**Response:**
```json
{
  "domains": [ ... ],
  "next_page_state": "eyJuZXh0X3BhZ2UiOjJ9"
}
```

### 2.3 CNAME Lookup

```bash
curl -s -X POST https://ip.thc.org/api/v1/lookup/cnames \
  -H 'Content-Type: application/json' \
  -d '{"target_domain": "example-vendor.com", "page_state": "", "limit": 50}' | jq .
```

**Response:**
```json
{
  "domains": [ ... ],
  "next_page_state": "eyJuZXh0X3BhZ2UiOjJ9"
}
```

### 2.4 Full Pagination Example (Python)

```python
import requests, json

def fetch_all_subdomains(domain):
    url = "https://ip.thc.org/api/v1/lookup/subdomains"
    subs, page = [], ""
    while True:
        r = requests.post(url, json={"domain": domain, "page_state": page, "limit": 100})
        data = r.json()
        subs.extend(data.get("subdomains", []))
        page = data.get("next_page_state", "")
        if not page:
            break
    return subs
```

---

## 3. Bulk Data (Monthly Full Database)

Released at the end of each month. Latest: **May 2026** (released 2026-06-04, 5.90 Billion records)

| Format | Compressed | Uncompressed | URL |
|--------|------------|--------------|-----|
| Parquet | 47 GB | 72 GB | `https://dns.team-teso.net/2026/rdns-may.parquet.gz` |
| CSV | 32 GB | 234 GB | `https://dns.team-teso.net/2026/rdns-may.csv.gz` |

**Daily CT Log dumps (Certificate Transparency):** `https://cs2.ip.thc.org/`

---

## 4. Practical Usage Templates

### Quick Subdomain List (pipe to httpx)

```bash
curl -s "https://ip.thc.org/example-vendor.com?l=100&nocolor=1&noheader=1" \
  | grep -v '^;' \
  | httpx -silent -status-code -title
```

### Compare Against RECON_DB for New Discoveries

```bash
KNOWN=$(cat workshop/<target>/RECON_DB.md | grep -oE '[a-z0-9._-]+\.example-vendor\.(com|net)' | sort -u)
FRESH=$(curl -s "https://ip.thc.org/example-vendor.com?l=100&nocolor=1&noheader=1" | grep -v '^;' | sort -u)
comm -13 <(echo "$KNOWN") <(echo "$FRESH")
```

### IP Reverse Lookup (confirm what domains are on a given IP)

```bash
# After finding an IP, reverse lookup to confirm service scope
curl -s "https://ip.thc.org/203.0.113.75?nocolor=1&noheader=1" | grep -v '^;'
```

### CNAME Takeover Exploration

```bash
# Find who CNAMEs to an abandoned service
curl -s "https://ip.thc.org/cn/s3.amazonaws.com?l=100&nocolor=1&noheader=1" | grep -v '^;'
```

---

## 5. Comparison With Other Tools

### 5.1 Empirical Comparison (example-vendor.com + example-vendor.net)

| Tool | example-vendor.com results | example-vendor.net results | Unique discoveries | Status |
|------|----------------------------|----------------------------|--------------------|--------|
| **ip.thc.org** | 10 | 34 | sip/02.sip (SIP/TLS server) | Stable |
| **subfinder** | 11 | 54 | jabber01 (XMPP loopback), auth-meet (Jitsi 200), docs/guest/giphy-proxy/recorder/stream/wiki/prod/v2/beta | Stable |
| **findomain** | 25 | 6 | dev/UAT environment historical records (all NXDOMAIN); redis.dev name exposure | Stable |
| **crt.sh** | 0 | 0 | -- | Down (502) |
| amass passive | (not tested) | -- | -- | -- |

### 5.2 Tool Characteristics Analysis

| Tool | Data Source | Strengths | Weaknesses | Best Use Case |
|------|------------|-----------|------------|---------------|
| **ip.thc.org** | Passive DNS observation (5.9B records) | No auth, ultra-fast (one curl command), RDNS + CNAME three-in-one, "currently resolving" records | No cert history, no brute force, some records filtered | Quick live DNS confirmation; IP-to-domain reverse lookup; CNAME takeover exploration |
| **subfinder** | Multi-source aggregation (Chaos/Shodan/VirusTotal/SecurityTrails/HackerTarget and 50+ others) | Broadest passive source coverage; discovers the most live subdomains | Requires installation; some sources need API keys for full coverage | Primary passive enumeration; found 20+ more results than ip.thc.org for .net domain |
| **findomain** | Primarily Certificate Transparency | Discovers "historically existed" cert records (dev/UAT environments); NXDOMAIN but valuable naming intelligence | Many NXDOMAIN results; .net had only 6 results, far fewer than other tools | Architecture reconnaissance (discover dev/UAT naming patterns); find deleted endpoints with useful name intelligence |
| **crt.sh** | Certificate Transparency (crt.sh database) | Most complete historical cert data; wildcard cert expansion; no installation | Frequently 502/timeout; no RDNS; rate limited | Backup tool; cert history; wildcard `*.example.com` expansion |
| **amass passive** | 100+ source fusion (including WHOIS/ASN) | Most complete passive aggregation | Slow (may take 10-30 minutes); requires configuration | Deep enumeration; ASN range tracking |

### 5.3 Per-Tool Coverage Matrix (Empirical Results for example-vendor.com)

| Subdomain | ip.thc | subfinder | findomain | Notes |
|-----------|--------|-----------|-----------|-------|
| example-vendor.com | Yes | -- | Yes | apex |
| api.example-vendor.com | Yes | Yes | Yes | loopback SSRF |
| download.example-vendor.com | Yes | Yes | -- | S3/CloudFront |
| im.example-vendor.com | Yes | Yes | Yes | TCP 000 |
| mgm.example-vendor.com | Yes | Yes | Yes | wildcard DNS |
| portal.example-vendor.com | Yes | Yes | Yes | CodeIgniter 503 |
| sip.example-vendor.com | Yes | Yes | -- | **SIP/TLS server** |
| 02.sip.example-vendor.com | Yes | Yes | -- | SIP/TLS target |
| track.example-vendor.com | Yes | Yes | Yes | IP live, port no response |
| www.example-vendor.com | Yes | Yes | Yes | main site |
| **jabber01.example-vendor.com** | No | Yes | -- | loopback XMPP |
| **cpapi.uat.example-vendor.com** | No | Yes | Yes | NXDOMAIN |
| **dev/UAT series** | No | No | Yes | NXDOMAIN cert history |

### 5.4 Recommended Strategy (Suggested Order)

```bash
# Step 1: ip.thc.org -- fastest "currently live" subdomain confirmation (30 seconds)
curl -s "https://ip.thc.org/$DOMAIN?l=100&nocolor=1&noheader=1" | grep -v '^;' > /tmp/thc.txt

# Step 2: subfinder -- broadest passive sources, find live + more (2-5 minutes)
subfinder -d $DOMAIN -silent > /tmp/sf.txt

# Step 3: findomain -- cert history for architecture intelligence (30 seconds, NXDOMAIN still valuable)
findomain -t $DOMAIN -q > /tmp/fd.txt

# Step 4: crt.sh -- backup, check cert when stable (may 502)
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" | jq -r '.[].name_value' | \
  tr ',' '\n' | sed 's/^\*\.//' | sort -u > /tmp/crt.txt 2>/dev/null || true

# Step 5: Merge + DNS resolution liveness check
cat /tmp/thc.txt /tmp/sf.txt /tmp/fd.txt /tmp/crt.txt | sort -u | \
  while read sub; do
    ip=$(dig +short "$sub" 2>/dev/null | head -1)
    [[ -n "$ip" ]] && echo "LIVE $sub -> $ip" || echo "DEAD $sub"
  done | tee /tmp/all_subs_status.txt
```

**Conclusion**:
- **Primary combo**: ip.thc.org (fast confirmation) + subfinder (broadest coverage)
- **Architecture recon bonus**: + findomain (cert history naming intelligence)
- **crt.sh**: Unreliable, use as backup
