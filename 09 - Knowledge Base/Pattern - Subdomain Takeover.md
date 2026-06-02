---
fileClass: KB
type: pattern
tags: [pattern, subdomain-takeover, dns, recon, cname]
added: 2026-01-01
---

# Pattern — Subdomain Takeover

## Summary

A subdomain's DNS CNAME (or A record) points to an external service that has been deprovisioned or whose namespace is claimable by an attacker. By registering the dangling resource, an attacker gains control of the subdomain, enabling phishing, cookie theft, or CSP bypass against the target's users.

## Detection Signals

- CNAME pointing to a third-party service domain (e.g., `*.s3.amazonaws.com`, `*.github.io`, `*.azurewebsites.net`, `*.herokuapp.com`) with NXDOMAIN or "no such bucket/app" response
- HTTP response body matches a known "unclaimed" fingerprint (see Grep Signatures)
- DNS resolves but HTTP returns a registration/claim page for the platform
- Subdomain still referenced in JS, cookies, or `Content-Security-Policy` headers even though the backing service is gone

## Grep Signatures

```bash
# Enumerate CNAMEs from a list of subdomains (requires dig)
while read sub; do
  cname=$(dig +short CNAME "$sub")
  [ -n "$cname" ] && echo "$sub -> $cname"
done < subdomains.txt

# Check for NXDOMAIN on the CNAME target
while read sub; do
  cname=$(dig +short CNAME "$sub" | tr -d '.')
  [ -n "$cname" ] && dig +short "$cname" | grep -q 'NXDOMAIN' && echo "DANGLING: $sub -> $cname"
done < subdomains.txt

# Scan HTTP responses for known takeover fingerprints
grep -rF \
  "There isn't a GitHub Pages site here" \
  "NoSuchBucket" \
  "No such app" \
  "This project has been deleted" \
  "This domain is available" \
  "404 Not Found" \
  responses/

# Find CNAME records in collected DNS data
grep -rn 'CNAME' dns_records/ | grep -Ei \
  's3\.amazonaws\.com|github\.io|azurewebsites\.net|herokuapp\.com|fastly\.net|cargo\.site|readme\.io|zendesk\.com|statuspage\.io'
```

## Test Methodology

1. Enumerate all subdomains of the target (passive: certificate transparency, Shodan; active: brute-force, alterations).
2. For each subdomain, resolve the CNAME chain with `dig +trace <subdomain>`.
3. Check whether the final CNAME target resolves: NXDOMAIN = strong takeover candidate.
4. Fetch the subdomain over HTTP/HTTPS; compare the response body against known fingerprints for each service (GitHub Pages, S3, Heroku, Azure, Fastly, etc.).
5. Verify the service platform allows claiming the name:
   - S3: bucket name must match subdomain exactly; check if region matters.
   - GitHub Pages: repository `<org>/<subdomain-name>` would need to exist.
   - Heroku: app name from the CNAME must be available on `heroku.com`.
6. **Do not actually claim the resource without explicit written permission from the target.** Document the dangling CNAME and fingerprint as sufficient proof-of-concept.
7. Capture DNS output (`dig +short CNAME <sub>` + NXDOMAIN proof) and HTTP response screenshot as evidence.

## Common Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Monitoring for NXDOMAIN | Some platforms return 200 with "unclaimed" page — still vulnerable |
| HTTPS certificate present | Certificate may be from CDN; subdomain can still be claimed at platform layer |
| SPF/DMARC on root domain | Does not protect subdomains from HTML/JS injection via takeover |
| Private S3 bucket | If CNAME exists and bucket is deleted, name can be re-registered publicly |
| Wildcard DNS (`*.example.com`) | Wildcard masks NXDOMAIN; test explicit subdomain, not just wildcard resolution |

## Severity Guide

| Impact | Severity |
|--------|----------|
| Takeover of auth/SSO/cookie-scoped subdomain (`auth.example.com`, `sso.example.com`) | P2 |
| Takeover of subdomain in scope of sensitive cookies (same eTLD+1) | P2-P3 |
| Takeover of generic product/API subdomain | P3 |
| Takeover of marketing or documentation subdomain | P4 |

## Related

- [[Lessons Learned]]
- [[Pattern - IDOR]]
- [[Pattern - CORS Misconfiguration]]
- [[Playbook - Recon]]
