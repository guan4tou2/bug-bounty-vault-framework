---
type: pattern
title: Pattern - CDN Origin Discovery via Subnet Scan
tags: [pattern, cwe-284, cdn, origin-ip, waf-bypass, recon, tls, bb-pattern]
status: active
vuln_class: access-control
severity_range: P4-P2 (P4 bare origin exposure; higher when the origin serves an admin surface or bypasses a protective control)
seen_in: []
last_updated: 2026-10-12
precedents: general CDN origin-exposure technique (origin reachable without an edge allowlist)
---

# Pattern - CDN Origin Discovery via Subnet Scan

## TL;DR

The target sits behind a CDN and the CDN hostname does not help (no response, generic edge page, aggressive WAF). If at least one related subdomain resolves to a concrete IP, the origin is often in the same small network block. Scan that block for web ports, identify the origin by its TLS certificate and Host-header behaviour, then check whether it answers directly — bypassing every control the CDN enforces.

## Preconditions

- Several subdomains of the target point at the same CDN or the same network block.
- At least one subdomain resolves to a specific A record (not CNAME-only to the CDN).
- **Scope confirmed for every IP you will touch.** A neighbouring IP in the same /24 can belong to a hosting provider's other customers. Run `bb-scope-safety-check` before any active scan; if ownership of the block is unclear, stay passive (CT logs, historical DNS, passive DNS) — see [[Reference Card - Passive Recon is Always In-Scope]].

## Steps

### 1. Collect IPs

```bash
for d in sub1.example.com sub2.example.com; do
  dig +short A "$d"
done
```

Supplement passively with historical DNS and certificate transparency results before touching any host.

### 2. Determine the network block

Note which block the IPs fall into (/24, or narrower such as /26 or /27). Confirm ownership with RDAP/WHOIS for the block — the result decides whether active scanning is in scope.

### 3. Scan the block (in-scope addresses only)

```bash
nmap -sS -Pn -p 80,443,8080,8443 --open <in-scope-block>/26
```

Run automated scanning from an isolated runner (AGENTS.md §6c) and log it in the Operation Log (AGENTS.md §6d).

### 4. Identify candidates by TLS certificate

```bash
echo | openssl s_client -connect <IP>:443 -servername <target-host> 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

### 5. Host header test

```bash
curl -sk "https://<IP>/" -H "Host: <target-host>" \
  -w "HTTP %{http_code}, %{size_download} bytes\n" -o /dev/null
```

## Signs that you found the origin

- The certificate matches the target hostname or its wildcard (`*.example.com`).
- The target Host header returns the full application (200 with substantial HTML), while unrelated Host values return a default vhost (403/404).
- The `Server` header and response headers differ from the CDN edge.
- Content matches the CDN-served page byte-for-byte (or nearly) — compare a stable asset hash.

## Impact

- An origin with no edge allowlist bypasses everything the CDN enforces: WAF rules, rate limits, geo-blocking, bot protection.
- An exposed origin for an admin panel or internal tool is usually more severe than for a public marketing site.
- Origin exposure alone is often low severity; demonstrate the bypass of a specific control (e.g. a payload blocked at the edge but accepted at the origin) before claiming more (AGENTS.md §5).

## Related

- [[Checklist - Enterprise Subnet Recon]]
- [[Pattern - SSL Certificate Intelligence Extraction]]
- [[Pattern - Internal IP Disclosure via Gateway]]
- [[Reference Card - Testing Safety Rules]]
