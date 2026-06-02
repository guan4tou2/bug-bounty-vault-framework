---
fileClass: KB
type: pattern
tags: [pattern, ssrf, cloud, metadata, network]
added: 2026-01-01
---

# Pattern — SSRF (Server-Side Request Forgery)

## Summary

The server fetches a user-supplied URL (or hostname) on behalf of the requester. An attacker abuses this to reach cloud metadata services, internal network hosts, or back-end services that are not directly reachable from the internet.

## Detection Signals

- Parameters named `url`, `uri`, `src`, `dest`, `redirect`, `callback`, `webhook`, `feed`, `endpoint`, `proxy`, `image_url`, `avatar_url`
- PDF/screenshot/preview generation features that accept a URL
- Import-from-URL or "fetch remote resource" functionality
- Webhook configuration screens where the attacker supplies the destination
- DNS-based callbacks observable via out-of-band interaction (e.g., Burp Collaborator)
- Error messages leaking internal hostnames or RFC-1918 IP ranges

## Grep Signatures

```bash
# URL/URI parameter sinks in Python
grep -rn 'requests\.get\|requests\.post\|urllib\.request\|httpx\.get' \
  --include='*.py' | grep -v '#'

# URL sinks in JavaScript / Node
grep -rn 'fetch(\|axios\.get\|http\.get\|https\.get\|node-fetch' \
  --include='*.js' --include='*.ts'

# curl usage in PHP
grep -rn 'curl_setopt\|CURLOPT_URL\|file_get_contents\s*(\\$_' \
  --include='*.php'

# Ruby Net::HTTP / open-uri
grep -rn 'Net::HTTP\|open-uri\|URI\.open' \
  --include='*.rb'

# Generic parameter names suggestive of SSRF
grep -rn '"url"\|"uri"\|"endpoint"\|"webhook"\|"callback"\|"src"' \
  --include='*.json' --include='*.yaml' --include='*.yml'
```

## Test Methodology

1. Identify every parameter that accepts a URL or hostname; map them to features (webhook, preview, import, export).
2. Attempt the AWS/GCP/Azure metadata endpoint as a baseline:
   ```
   http://169.254.169.254/latest/meta-data/
   http://metadata.google.internal/computeMetadata/v1/
   http://169.254.169.254/metadata/instance?api-version=2021-02-01
   ```
3. If the metadata endpoint is blocked, probe internal RFC-1918 ranges via port-scanning payloads (`http://192.168.1.1:22`, `http://10.0.0.1:6379`).
4. If direct IP is filtered, attempt bypass payloads (see Common Bypass Techniques).
5. For blind SSRF, use an out-of-band DNS/HTTP callback collector; confirm DNS resolution or HTTP hit before escalating.
6. If credentials are returned from the metadata service, stop and document — do not use the credentials.
7. Document full request/response evidence including headers; note which bypasses were required.

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Blocklist on `127.0.0.1` | Decimal: `http://2130706433/`, octal: `http://0177.0.0.1/`, IPv6: `http://[::1]/` |
| Blocklist on `169.254.169.254` | Decimal: `http://2852039166/`, DNS alias pointing to the IP, URL shortener |
| Hostname allowlist | DNS rebinding: first resolution returns allowed IP, second returns 169.254.169.254 |
| Scheme filter (`http://` only allowed) | `dict://`, `gopher://`, `file://` if not separately blocked |
| `@` trick | `http://allowed.example.com@169.254.169.254/` (credential-in-URL) |
| Redirect following | Host a redirect at allowed domain: `Location: http://169.254.169.254/` |
| AWS IMDSv2 requirement | Still attempt IMDSv1 — many deployments have not disabled it |
| Request validation on input | Server-side validation may differ from fetch library parsing; try URL-encoded or mixed-case schemes |

## Severity Guide

| Impact | Severity |
|--------|----------|
| Cloud metadata credential theft (AWS keys, GCP tokens) | P1-P2 |
| Read of sensitive internal service (e.g., internal admin, secrets manager) | P1-P2 |
| Internal network port scan / service fingerprint | P3 |
| Blind SSRF (DNS/HTTP callback only, no data returned) | P3-P4 |
| SSRF to non-sensitive internal resource | P4 |

## Related

- [[Lessons Learned]]
- [[Pattern - IDOR]]
- [[Pattern - CORS Misconfiguration]]
- [[Playbook - Recon]]
