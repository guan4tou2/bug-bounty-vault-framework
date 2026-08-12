---
type: reference-card
title: "DNS Recon Techniques 2026 — Technique Matrix and Tooling Gap Map"
tags: [dns, recon, methodology, sota-2026]
status: draft
last_updated: 2026-08-12
---

# Reference Card - DNS Recon Techniques 2026

> **TL;DR**: A technique matrix collected from public research (2024-2026) plus live testing against a public resolver, organized to show which techniques are already covered by automated fingerprinting tooling and which remain gaps. Coverage legend: ✅ tool covers it | 🟡 partial / can add a sub-mode | ❌ gap (candidate for a new module) | 🔧 pipeline-level (belongs to recon orchestration, not a single-host fingerprint tool). Safety: everything not marked ⚠️ is a single read-only query (GET-equivalent). ⚠️ = needs a scope/safety gate (do not loop or flood).
>
> Placeholders used in commands: `T` = target domain, `Z` = signed zone, `R` = resolver under test, `NS` = authoritative nameserver.

## Quick Reference

### A. Enumeration / Discovery — mostly 🔧 pipeline-level

| Technique | Reveals | Example command | Coverage | Tooling |
|---|---|---|---|---|
| Passive DNS aggregation | All subdomains seen by third-party datasets (no target contact) | `subfinder -d T -all -recursive` | 🔧 | subfinder (45 sources) / amass |
| Chaos dataset | Bug-bounty-scoped subdomain set | `chaos -d T -key $K` | 🔧 | chaos-client |
| Mass brute-force + wildcard filtering | Internal names not present passively | `puredns bruteforce wl T -r resolvers.txt` | 🔧 | puredns / shuffledns / massdns |
| Permutation / alteration | dev-/staging-/api2- style variants | `gotator -sub subs -perm words \| puredns resolve` | 🔧 | gotator / dnsgen / ripgen / altdns |
| Trusted-resolver list | Prerequisite for accurate mass resolution | `dnsvalidator -tL public-dns.info/nameservers.txt` | 🔧 | dnsvalidator / trickest resolvers |
| Wildcard detection | `*.T` existence → filters false positives | `dig +short $(openssl rand -hex 6).T` (an answer = wildcard) | 🟡 | puredns / dnsx `-wd` |
| Recursive/deep brute-force loop | Second-level subdomains, e.g. `api.dev.T` | `subfinder -recursive` fed back into a puredns loop | 🔧 | subfinder/puredns loop |

### B. Origin / CDN Discovery (bypassing WAF to find the real IP) — high bug-bounty value

| Technique | Reveals | Example command | Coverage | Tooling |
|---|---|---|---|---|
| **SVCB/HTTPS ip-hint leak** | `ipv4hint`/`ipv6hint` may expose the real IP behind a CDN | `dig HTTPS T +short` (look for `ipv4hint=`) | ✅ (`--svcb` mode) | dig ≥9.18 / dnsx `-https` / zdns |
| ECH config extraction | Whether Encrypted Client Hello (SNI hiding) is in use | `dig HTTPS T +short \| grep ech=` | ✅ (`--svcb`, ECH detection) | dig/kdig + base64 decode |
| Certificate SAN → ASN pivot | Origin IP behind a CDN (scan ASN for cert CN/SAN matches) | `echo AS.. \| asnmap \| tlsx -san -cn \| grep T` | 🔧 | CloudFlair / tlsx / CF-Hero |
| Favicon mmh3 → Shodan | IP that serves the origin directly | `shodan search 'http.favicon.hash:<mmh3>'` | 🔧 | fav-up / favUp |
| Historical DNS origin | Old A record from before CDN adoption (often still the origin) | `curl securitytrails.com/v1/history/T/dns/a` | 🔧 | SecurityTrails / ViewDNS / VT |
| Grey-cloud sibling leak | A DNS-only subdomain pointing straight at the origin | Enumerate subdomain A records, filter for hosts outside CDN ranges + confirm via Host header | 🔧 | hakoriginfinder / CloakQuest3r |
| SPF CIDR → origin | The SPF `ip4:` range is often the same segment as the origin | `dig +short TXT T \| grep spf` → `httpx -H Host:T` | 🟡 | httpx / mapcidr |

### C. Resolver Behavior / Security

| Technique | Reveals | Example command | Coverage | Safety |
|---|---|---|---|---|
| **Cache snooping (RD=0)** | What the resolver has cached — i.e., who queried what (privacy leak) | `dig @R name A +norecurse` (an answer = already cached) | ✅ (`--cache-snoop`) | read-only / cf. nmap dns-cache-snoop |
| **QNAME minimization** | Whether RFC 9156 minimization is implemented (privacy / software fingerprint) | `dig @R a.b.qnamemin-test.internet.nl TXT +short` | ✅ (`--qnamemin`) | read-only |
| DNS 0x20 case randomization | Anti-spoofing hardening (use-caps-for-id) | Mixed-case query + observe echoed case (needs an authoritative reflector or packet capture) | ❌ | read-only (needs control of the authoritative side) |
| ECS forwarding / geo-split | Whether client-subnet is forwarded to the authoritative server (privacy/geo) | `dig @R www.cdn A +subnet=1.2.3.0/24` vs `+subnet=0/0` | 🟡 | read-only (basic ECS probe exists; forwarding/geo-diff mode missing) |
| EDNS-1232 / fragmentation behavior | Flag-day compliance, TCP-fallback threshold | `dig Z DNSKEY +dnssec +bufsize=1232 @NS` (watch for TC=1) | 🟡 | read-only (TCP fallback exists; 1232 threshold mode missing) |
| Open resolver + amplification factor | Whether the resolver recurses for arbitrary clients + response/query ratio | `dig @R amiopen.openresolvers.org TXT +short` | 🟡 ⚠️ | single read only; never loop (amplification risk) |
| RRL detection | Whether the authoritative server rate-limits via token bucket (TC/drop) | `for i in {1..30}; do dig @NS name +tries=1; done` | ❌ ⚠️ | small burst only; never run at high rate |
| **DoQ (DNS-over-QUIC)** | Encrypted transport over UDP/853, distinct from DoT/DoH | `kdig +quic @R name A` / `q -p quic @R name` | ✅ (`--doq`, shells out to kdig) | read-only (requires kdig/q installed) |
| Managed DNS provider fingerprint | Who hosts the zone (Route53/CF/NS1/Akamai/…) | `dig T NS +short` (match NS suffix table) | 🟡 (SOA `--soa-intel` gives a serial→vendor hint; NS suffix table not yet added) | read-only |
| Port/TXID entropy grade (OARC) | Cache-poisoning attack surface (weak randomness = poisonable) | ~~`dig porttest.dns-oarc.net TXT @R`~~ | ❌ | **service retired (confirmed NXDOMAIN)** — needs a self-hosted replacement |
| DNS software CVE behavior tell | Implementation/version inference when the banner is hidden | NSEC3-cap / EDNS-opt / cookie-format differences | 🟡 | read-only (fpdns-style family fingerprinting exists; CVE map missing) |

### D. DNSSEC Deep Analysis

| Technique | Reveals | Example command | Coverage |
|---|---|---|---|
| Algorithm/key audit | RSASHA1 (5/7, weak) vs ECDSA (13)/Ed25519 (15), KSK/ZSK, rollover state | `dig Z DNSKEY +multi`; `dig Z DS @parent` | ✅ (`--dnssec-audit`: algo/keysize/role + deprecated flag) |
| NSEC3 iteration/opt-out/RFC 9276 | iteration>0 violates RFC 9276; opt-out weakens denial-of-existence; KeyTrap DoS surface | `dig nx.Z A +dnssec +norecurse @NS`; `dig Z NSEC3PARAM` | ✅ (`--dnssec-audit`: NSEC3PARAM iteration + 9276 violation flag) |
| Negative-response validation (NXDOMAIN/NODATA) | Whether negative responses are validated (AD bit + NSEC proof) | `dig random.signed-zone A +dnssec @R` (check AD=1) | ❌ |
| Full chain (DNSKEY/DS/RRSIG/CDS) | Signature maturity, signing dates, CDS auto-rollover | `dig Z DNSKEY/DS/CDS`; `delv Z A +rtrace` | ❌ |
| Tools | `delv` / `dnsviz probe\|grok` / Verisign DNSSEC Debugger | | |

### E. Records Intelligence — email posture is the standout gap area

| Technique | Reveals | Example command | Coverage |
|---|---|---|---|
| **SPF chain + 10-lookup audit** | Full mail infrastructure + PermError risk (>10 lookups = fail-open, spoofable) | `dig +short TXT T \| grep spf1` → recursively expand each `include` | ✅ (`--email-posture`; direct-lookup count implemented, recursive expansion pending) |
| **Full DMARC policy parse** | p/sp/pct (spoofability) + rua/ruf reveal the security vendor relationship | `dig +short TXT _dmarc.T` | ✅ (`--email-posture`) |
| **DKIM selector brute-force** | Which ESP signs mail (selector→vendor), RSA-1024 weak-key detection | `dig +short TXT selector1._domainkey.T` | ✅ (`--email-posture`; 14 selectors + RSA-1024 flag) |
| MTA-STS (TXT + policy fetch) | Authorized MX list + `mode=testing/none` = downgradeable | `dig +short TXT _mta-sts.T`; `curl https://mta-sts.T/.well-known/mta-sts.txt` | ✅ (`--email-posture`, includes HTTPS policy fetch) |
| TLS-RPT | TLS-failure telemetry vendor relationship | `dig +short TXT _smtp._tls.T` | ✅ (`--email-posture`) |
| DANE / TLSA | Certificate pinning inside DNS (backed by DNSSEC signatures) | `dig +short TLSA _25._tcp.<MX>` | ✅ (`--email-posture`, queries TLSA on the MX) |
| BIMI + VMC/CMC | Logo-asset pivot + legal-entity linkage (implies enforced DMARC) | `dig +short TXT default._bimi.T` | ✅ (`--email-posture`, presence check; VMC fetch pending) |
| CAA deep parse | Authorized CA set + `accounturi`/`iodef` contact | `dig +short CAA T` | 🟡 (contacts covered; CA set/accounturi pending) |
| SOA field intelligence | MNAME reveals hidden primary, RNAME is the admin contact, serial format hints at date/vendor | `dig +short SOA T` | ✅ (`--soa-intel`: MNAME/RNAME + serial decode) |
| NS → provider fingerprint | Who hosts DNS + split-horizon detection | `dig +short NS T` | 🟡 |
| TXT verification token reverse-lookup (~130 known) | Which SaaS/IdP is in use (a federated IdP token implies an SSO surface) | `dig +short TXT T \| grep -Ei 'verification'` | 🟡 (taxonomy exists; coverage of the ~130 known tokens needs confirming) |
| Underscore-label enumeration | `_acme-challenge` (automated cert issuance / potential takeover), `_github-challenge`, etc. | `dig +short CNAME _acme-challenge.T` | ❌ |

### F. Subdomain Takeover Fingerprinting (dangling records) — largely a gap

| Technique | Reveals | Test | Tooling |
|---|---|---|---|
| Dangling CNAME/NS takeover | CNAME points at a released cloud resource (claimable) | `dig +short CNAME sub.T` → `curl https://sub.T \| grep -Ei 'NoSuchBucket\|no such app'` | ✅ (`--takeover-check`: 15-provider fingerprint directory, only flags VULNERABLE on a matching response body) / nuclei `http/takeovers/` / BadDNS (2025) |

2025-era fingerprints: S3 `NoSuchBucket` / GitHub Pages "There isn't a GitHub Pages site here" / Heroku "No such app" / Azure (`*.azurewebsites`/`trafficmanager`/`blob.core.windows.net`, cross-subscription claimable) / Shopify / Fastly / Firebase / GCS. NS-takeover = the delegated NS's zone expired and was never re-registered.

> Note: CDN/GSLB CNAMEs are almost always false positives for takeover — always cross-check against an "own infrastructure" allowlist vs. a "claimable provider" regex before flagging.

### G. IPv6-Specific

| Technique | Reveals | Test | Coverage |
|---|---|---|---|
| `ip6.arpa` NXDOMAIN tree walk | Active hosts within a /64 (RFC 8020 empty-subtree NXDOMAIN lets you prune the search) | `nmap -6 --script dns-ip6-arpa-scan --script-args prefix=P/48` | 🔧 |
| v6 reverse-zone NSEC/whitelabel enumeration | Full PTR set for an ISP's `ip6.arpa` zone (NSEC signature walk / predictable PTR) | `dnsrecon -d P.ip6.arpa -z` / atk6-dnssecwalk | 🔧 |

> Requires an IPv6-capable vantage point — many cloud VPS providers still lack global v6 reachability; confirm before relying on this section.

## Details

### Tooling gap priority (candidates for a single-host DNS fingerprinting tool)

Ranked by single-host fingerprint fit × novelty × bug-bounty value:

1. ✅ **SVCB/HTTPS RR probing** (`--svcb`) — origin ip-hint leak + ECH + CDN fingerprint
2. ✅ **Cache snooping** (`--cache-snoop`, RD=0) — privacy leak
3. ✅ **QNAME minimization** (`--qnamemin`) — public test oracle
4. ✅ **Email posture bundle** (`--email-posture`: SPF lookup audit / DMARC / DKIM selector / MTA-STS+policy fetch / TLS-RPT / DANE / BIMI)
5. ✅ **Subdomain takeover fingerprinting** (`--takeover-check`: 15-provider directory, body-fingerprint gated VULNERABLE verdict, CNAME-only flagged for manual review)
6. **DoQ probing** (UDP/853) — fills the gap beyond DoT/DoH encrypted-transport coverage
7. **Managed-provider fingerprint + SOA serial decode** (NS suffix table + serial→date/vendor) — cheap analysis layer, data already collected
8. **DNSSEC algo/NSEC3-iteration audit** — zone walk already implemented; add iteration/opt-out/algo interpretation
9. Sub-mode expansion: ECS forwarding/geo-diff, EDNS-1232 threshold (existing probes gain a sub-mode)

**Pipeline-level (does not belong in a single-host tool, belongs to recon orchestration)**: passive aggregation, mass brute-force, permutation, CDN-origin discovery (SAN/favicon/historical), large-scale rDNS, IPv6 tree walking.

### Illustrative results from a live resolver test

The following table shows the kind of output this technique matrix produces when run against a real public recursive resolver (generalized from a live test run; specific target identity omitted).

| Technique | Result |
|---|---|
| QNAME minimization | **Not enabled** — privacy weakness |
| Cache snooping (RD=0) | **Effective** — popular third-party domains were found cached (RD=0 not blocked, leaking other users' query history) |
| SVCB/HTTPS RR | No HTTPS record present (a CDN-fronted comparison domain returned one normally) |
| ECS geo-split | Different subnet hints returned different edge IPs for a major CDN — possible forwarding/geo-split, marginal signal |
| DMARC | **Absent** — no DMARC enforcement (large legacy operators frequently lack this, enabling envelope spoofing) |
| MTA-STS / TLS-RPT / DANE / BIMI | All absent (only a bare SPF record present) |
| Managed provider | Self-hosted nameservers, not a managed DNS provider |
| OARC port/TXID entropy test | **Service retired** (confirmed NXDOMAIN) — needs a self-hosted replacement |
| DoQ (`--doq`, via kdig) | Public resolvers with known DoQ support answered; the tested ISP resolver did not (port 853 closed) |
| DNSSEC audit (`--dnssec-audit`) | Target zone unsigned; a signed comparison zone showed KSK+ZSK ECDSAP256SHA256 256-bit |
| SOA intel (`--soa-intel`) | Serial decoded cleanly to a `YYYYMMDDNN`-style date format |

> The entire test was non-invasive, read-only queries; no reportable vulnerability resulted (a missing DMARC record on a large legacy operator is a configuration observation, not a vulnerability by itself).

## Related

- [[Tool - Cloud and DNS Recon Toolkit]]
- [[subdomain-takeover]]
- [[recon-and-methodology]]
