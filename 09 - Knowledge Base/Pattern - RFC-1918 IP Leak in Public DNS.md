---
type: pattern
title: Pattern - RFC-1918 IP Leak in Public DNS
tags: [pattern, cwe-200, dns, internal-ip, recon, info-disclosure, network-topology, bb-pattern]
status: verified
first_seen: 2026-04-25
severity: P5 Informational (standalone) / recon ingredient for SSRF chains
---

# Pattern - RFC-1918 IP Leak in Public DNS

## TL;DR

Public DNS A/CNAME records that resolve to RFC-1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), link-local (169.254.0.0/16), or loopback (127.0.0.0/8) leak internal network topology to unauthenticated internet users. Each leaked record reveals subnet boundaries, host naming conventions, and service roles — information that directly feeds SSRF target selection, phishing pretext design, and internal pivot planning. The bug is **information disclosure, not access**: knowing `192.168.57.171` exists does not grant connectivity to it. Honest severity cap is P5 Informational unless the records enable a concrete follow-on attack.

## Root-cause ingredients

- **Split-horizon DNS misconfiguration** — internal zone records accidentally published to the public-facing authoritative nameserver instead of (or in addition to) the private resolver
- **Dev/staging records mistakenly published** — CI/CD pipelines or manual DNS updates add hostnames like `dev.*`, `uat.*`, `dbackend.*` pointing to internal IPs and never clean them up
- **CNAME chain resolving to internal A record** — a CNAME that looks external eventually resolves to a private-IP A record in the same zone, leaking through the chain
- **Cloud-managed DNS auto-export** — Route53 split-horizon or Google Cloud DNS where a "private" zone record is accidentally added to the public hosted zone as well; terraform/pulumi state drift is a common cause

## Detection methodology

### Step 1 — Subdomain enumeration

```bash
# Passive enum: CT logs + passive DNS
subfinder -d target.com -all -o subs.txt

# CT log direct query
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | jq -r '.[].name_value' | sort -u >> subs.txt

# Deduplicate
sort -u subs.txt -o subs.txt
```

### Step 2 — Bulk DNS resolution

```bash
# Resolve all subdomains, capture A + AAAA + CNAME
dnsx -l subs.txt -resp -a -aaaa -cname -o resolved.txt

# Example output lines of interest:
# dev.target.example [192.168.57.171] [A]
# dbackend.target.example [192.168.57.171] [A]
# uat-portal.target.example [192.168.110.147] [A]
```

### Step 3 — Filter for private / non-routable IPs

```bash
# RFC-1918 + link-local + loopback
grep -E '\b(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|127\.)' resolved.txt \
  > rfc1918_hits.txt

# Also catch 0.0.0.0 (misconfigured wildcard)
grep '0\.0\.0\.0' resolved.txt >> rfc1918_hits.txt
```

### Step 4 — Identify repeated IPs (same internal host, multiple roles)

```bash
# Extract just the IP column and count occurrences
grep -oE '\b(10|172|192|169|127)\.[0-9.]+\b' rfc1918_hits.txt \
  | sort | uniq -c | sort -rn

# High count = one internal IP serving many service roles
# Multiple distinct IPs = multiple internal subnets exposed
```

### Step 5 — Multiple subnets = stronger topology leak

If you see two or more distinct RFC-1918 /24 prefixes, you have confirmed that the internal network is segmented — **each unique subnet prefix is a separate intelligence finding** (case study below: `192.168.57.x` + `192.168.110.x` confirmed two distinct internal segments).

## Live verification SOP

```bash
# 1. Confirm public resolution (not just local DNS)
dig @8.8.8.8 +short dev.target.example
# 192.168.57.171   <-- confirmed Google DNS returns RFC-1918

# 2. Cross-check with authoritative NS
dig +short dev.target.example NS
dig @<authNS> +short dev.target.example

# 3. whois the IP block (RFC-1918 has no public whois — confirms private)
whois 192.168.57.171
# "No match found" or IANA reserved block → confirms non-routable
```

**Note**: never try to HTTP-connect or port-scan the private IP from the internet — it will not route and is out-of-scope for most programs. The finding is the DNS leak itself.

## Variants

| Variant | Description | Confidence |
|---------|-------------|------------|
| **A** | Direct A record → RFC-1918 IP | High — unambiguous misconfiguration |
| **B** | CNAME chain → internal hostname → RFC-1918 A | Medium — may be intentional AWS internal DNS |
| **C** | AAAA record → ULA fc00::/7 (IPv6 equivalent) | High — same issue, IPv6 space |
| **D** | TXT/SPF record disclosing internal hostname or IP | Medium — sometimes leaks mail relay IPs |
| **E** | SRV record for internal services (e.g. `_kerberos._tcp`, `_ldap._tcp`) pointing to internal DC | High — reveals Active Directory topology |

Variant A is the most clear-cut and most common. Variant E is rarest but highest-impact as it reveals AD/Kerberos infrastructure names directly.

## Real-world examples

### [Vendor] multi-brand messaging platform — VENDOR-001 + VENDOR-002 + VENDOR-003 (2026-04-25)

All verified via `dig @8.8.8.8`.

**Subnet 1: `192.168.57.171`** — 10 subdomains point to the same internal host:

| Subdomain | Record |
|-----------|--------|
| `app1.target.example` | A → 192.168.57.171 |
| `app1-alt.target.example` | A → 192.168.57.171 |
| `dev.target.example` | A → 192.168.57.171 |
| `adminapi.target.example` | A → 192.168.57.171 |
| `dcapi.target.example` | A → 192.168.57.171 |
| `dbackend.target.example` | A → 192.168.57.171 |
| `dsticker.target.example` | A → 192.168.57.171 |
| `dfls.target.example` | A → 192.168.57.171 |
| `dmfa.target.example` | A → 192.168.57.171 |
| `dmfaapi.target.example` | A → 192.168.57.171 |
| `dchatapi.target.example` | A → 192.168.57.171 |

Naming convention (`d` prefix = dev, `adminapi`/`dcapi`/`dbackend` = service roles) reveals internal microservice architecture.

**Subnet 2: `192.168.110.147`** — second internal segment (VENDOR-003):

| Subdomain | Record |
|-----------|--------|
| `uat-portal.target.example` | A → 192.168.110.147 |
| `portal-c-uat.target.example` | A → 192.168.110.147 |

The `192.168.57.0/24` vs `192.168.110.0/24` split confirms two distinct internal subnets — not a single flat /16.

### HackerOne comparable disclosures

- **HackerOne report #1062708** (Shopify): subdomain `buildkite.shopify.io` resolved to `10.20.x.x` — submitted as info disclosure, triaged P4 Informational, used by reporter to narrow SSRF target range in follow-up report
- **HackerOne report #792891** (various): multiple `uat.*` and `dev.*` records across a payment processor resolved to `172.16.x.x`; triaged P5 standalone, credited as recon assist for separate P2 SSRF chain

**Pattern**: in all known cases, platforms reward the SSRF chain, not the DNS leak itself. The DNS leak is the enabler.

## Defense

1. **Strict split-horizon DNS**: internal zone served by a completely separate authoritative server with no public delegation; public NS servers have no visibility into the internal zone file
2. **Audit DNS publishing pipeline**: review all automated zone-push scripts and terraform DNS modules for conditions where internal records may reach the public zone
3. **Scrub before push**: add a pre-publish lint step that rejects any A/AAAA record resolving to RFC-1918, link-local, or loopback ranges
4. **Lifecycle hygiene**: decommission dev/uat/staging DNS records when environments are torn down; use short TTLs on non-production records so stale entries expire faster

## Filing & severity

| Scenario | Appropriate severity |
|----------|---------------------|
| RFC-1918 A record in public DNS, standalone | **P5 Informational** — disclosure only |
| 10+ subdomains mapping to same internal IP (topology inference) | **P4 Low** — systemic misconfiguration |
| Dev/uat hostnames exposed (not intended to be public) | **P4 Low** — separate disclosure from the topology leak |
| RFC-1918 leak used as ingredient in verified SSRF | **Follow SSRF's own severity** (typically P2–P3) |

**Do not claim "internal network compromise"** — knowing a private IP exists is not access. Triagers will immediately downgrade or reject reports that conflate IP knowledge with network access. File the finding as what it is: information disclosure that narrows an attacker's SSRF target space.

## Chains

```
DNS RFC-1918 leak
  → narrows SSRF target IP range (192.168.57.0/24 has services, try :8080, :3000, :8443)
  → combine with TURN/STUN relay (e.g. default-credential Coturn deployment): TURN relay to RFC-1918 IP = blind internal probe
  → combine with HTTP-fetch SSRF or URL-fetch API parameter: targeted internal host scan
  → combine with zone walking or NSEC walking: reconstruct full internal hostname list
  → combine with subdomain takeover of dead CNAME: impersonate internal service name to phish internal users
```

## Related

- Pattern - Coturn Default TURN Credentials — TURN relay can be abused to reach RFC-1918 IPs identified via DNS leak
- Pattern - SSRF Filter Bypass — DNS leak provides concrete internal IPs for SSRF payloads
- Primary case study: multi-brand messaging platform, 13 affected subdomains across 2 internal subnets
