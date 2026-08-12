---
type: playbook
title: "DNS Server Attack Surface & Red Team Methodology"
tags: [dns, recon, red-team, methodology, cache-poisoning, dnssec, subdomain-takeover, ssrf, ad-dns]
status: draft
last_updated: 2026-08-12
category: hunting
estimated_time: "45-90 min"
---

# Playbook - DNS Server Attack Surface & Red Team Methodology

> **TL;DR**: DNS is not a single service — it's a matrix of roles. The same IP can simultaneously be a recursive resolver, an authoritative server, a cache, and a DNSSEC validator, and each role has its own attack surface. The first step of this methodology is always "which role is this server playing", not "does this server have a bug". This playbook covers how to reason about DNS attack surface (role classification -> role-specific attack paths -> when to escalate into a chain), not a fixed list of specific vulnerabilities. It complements — rather than replaces — a general recon/enumeration playbook and a subdomain-takeover technique guide: this document fills the gap between "how to enumerate" and "what to do once you have role classification and detection signals."

---

## Scope / When to use

Use this playbook whenever a target exposes a DNS server (recursive resolver, authoritative nameserver, or an AD-integrated internal DNS reachable from the outside) and you need a systematic way to decide which attack paths are even applicable before spending time on any of them.

**KB purity note**: this document only covers judgment logic and detection signals that transfer to any program — no vendor-specific or competition-specific scope rules. Actually exploiting some of the paths below (real cache poisoning, building a DNS tunneling C2 channel) falls outside the GET-first boundary of authorized penetration testing in most engagements; this playbook describes **how to recognize the preconditions and detection signals**, not ready-to-fire attack payloads.

---

## Phases

### Phase 0: Role Classification (the starting point for every branch)

DNS attack surface is completely different depending on server role — classify first, then pick a path:

| Role | Detection signal | Corresponding attack surface |
|------|------------------|-------------------------------|
| Recursive resolver (open to external queries) | Responds to queries for arbitrary domains, not just its own zone | Cache poisoning, downstream dependents of DNS rebinding, amplification material |
| Authoritative-only | Only answers queries for its own managed zone, NXDOMAIN for everything else | Zone transfer (AXFR), DNSSEC NSEC/NSEC3 walking, zone-content leakage |
| Internal AD DNS (Windows Server DNS integrated with AD) | SRV records present (`_ldap._tcp.dc._msdcs.<domain>`, `_kerberos._tcp`), dynamic update enabled | Topology leakage, DC/service enumeration, dynamic-update abuse |
| DNSSEC validator | Response carries the `AD` flag, supports the `DO` bit | The validator itself is usually not the attack surface, but validation-failure behavior can reveal upstream architecture |
| DoH/DoT gateway | Extra 443/853 exposure, TLS cert subject contains DNS-related names | A channel that bypasses traditional DNS monitoring (defensive angle), useful for identifying exfiltration channels |

In practice, a DNS architecture fingerprinting tool can produce this role classification plus a coverage status (`covered` / `heuristic_only` / `intentionally_not_run`) for each section below in one pass. This playbook is the methodology body that such a tool's "red team DNS checklist" section refers back to.

---

### Phase 1: Cache Layer Attacks (Cache Poisoning / SAD DNS)

**Preconditions to judge, not attack steps:**
- The target must be a **recursive resolver** (Phase 0 role classification) — authoritative-only servers are unaffected.
- Source port randomization strength: if the source port used for queries is nearly fixed or has a narrow range, off-path forged-response hit rate increases substantially.
- Query ID entropy: a 16-bit ID combined with weak source-port randomization means the effective entropy is much lower than it looks.
- SAD DNS (Side-channel AttackeD DNS, a body of research from 2020) uses **ICMP rate-limiting as a side channel to guess which source port the middlebox is using** — it does not require blind-guessing across all 65,536 combinations.

**What to do in an authorized penetration test**:
- Use passive observation (repeated queries to the same resolver, comparing the distribution of response source ports) to gauge randomization strength — this is read-only.
- Do not attempt real poisoning against production traffic without explicit written authorization; it affects every downstream user of that resolver and counts as a highly disruptive action.
- If you suspect weak randomization exists, record it as a "conditional risk" (weak randomization + open recursion) — do not write it up as "verified exploitable" unless you fully reproduced it in an isolated test environment.

**Stop condition**: if the resolver only serves an internal/verified allowlist of sources, the attack surface collapses to "requires prior access to the same subnet/ISP" as an internal-threat model — deprioritize heavily.

---

### Phase 2: DNSSEC Weaknesses (NSEC/NSEC3 Zone Walking)

**Core logic**: DNSSEC's "negative answer" (proof of NXDOMAIN) requires proving "there is no other record between this name and its neighbors" — this mechanism inherently leaks zone content.

| Mechanism | Leakage level | How to check |
|-----------|---------------|---------------|
| NSEC | Full leakage — directly returns "the next existing name", letting you walk the entire zone | Query a non-existent name and check whether the response carries an `NSEC` record containing the plaintext next name |
| NSEC3 (unsalted or low iteration count) | Leaks a hash rather than plaintext, but can be offline-brute-forced against a common subdomain dictionary (`www`, `mail`, `api`, ...) | Check `NSEC3PARAM` iteration count and salt; low iterations + short salt = feasible |
| NSEC3 (high iteration + salted) | Substantially raises brute-force cost; usually not worth pursuing | If iterations are above a reasonable threshold, record as a stop condition and pivot to other enumeration paths |

**Reframe the question**: don't ask "is there an NSEC record here", ask "can this zone's negative-answer mechanism give me the full subdomain list without dictionary enumeration". The subdomain list obtained from zone walking feeds directly into subsequent liveness probing (general recon playbook) and CNAME checks (subdomain-takeover technique guide) — that's the real value of this attack surface: **it's a free, passive subdomain enumeration method**, more complete than dictionary brute-forcing.

---

### Phase 3: AD-Integrated DNS (SRV Record Enumeration)

Windows Server's AD-integrated DNS auto-registers a standard set of SRV records. These are **designed to be public**, but for an external attacker they're a free internal topology map:

- `_ldap._tcp.dc._msdcs.<domain>` -> hostnames of every Domain Controller
- `_kerberos._tcp.<domain>` -> Kerberos KDC location
- `_gc._tcp.<domain>` -> Global Catalog server (especially valuable in multi-domain forests)
- `_kpasswd._tcp.<domain>` -> password-change service location

**The key judgment call**: this set of SRV records is normally only queryable from the internal DNS. If the external authoritative DNS (the one exposed to the public internet) also answers these queries, it means **internal/external DNS is not properly separated (split-horizon misconfiguration)** — an external attacker gets internal topology with zero foothold required. This should be recorded as an independent finding, not just "incidentally observed information".

**Follow-up**: once you have DC hostnames, this is the starting point for lateral-movement pre-recon — the question is "what can this hostname list chain into", not "record it and stop".

---

### Phase 4: DNS Tunneling (Detection, Not Construction)

This section is written from an **authorized red-team / defensive-identification** angle — it does not provide steps to build a C2 tunneling channel. Actually building a DNS tunneling C2 channel is outside the general GET-first boundary of bug bounty work, and in most cases isn't within program scope either.

**Identification signals (used to judge whether target infrastructure is already being abused, or to assess a defensive gap)**:
- Abnormally high-frequency TXT/NULL/CNAME queries against randomized subdomains of the same parent domain (high entropy, resembling base32/base64 encoding)
- Abnormal ratio between query volume and response size (tunneling tends to stuff payloads, so individual query/response size is large and consistent)
- The queried domain was registered recently (WHOIS creation time as corroboration) with no corresponding legitimate web service

**Legitimate use in an authorized penetration test**: assessing the feasibility of a data-exfiltration channel — if the target environment's DLP/firewall only inspects common protocols (HTTP/HTTPS) but allows unrestricted outbound DNS queries, that's a worthwhile **architecture-level finding** (unrestricted outbound DNS = potential exfiltration channel). You don't need to build a full tunneling channel to prove it; a single large TXT query as PoC is sufficient and low-risk.

---

### Phase 5: Subdomain Takeover — Handoff Point

The full detection/claim workflow for subdomain takeover belongs in a dedicated technique guide; this section only covers **where DNS methodology hands off to it**:

- The complete subdomain list obtained from Phase 2's NSEC/NSEC3 zone walking is the best input for a takeover scan — more complete than dictionary enumeration, with no gaps.
- If Phase 0's role classification finds the target is authoritative-only and allows unrestricted zone transfer (AXFR with no source restriction), that also yields a complete zone content dump usable as takeover-scan input.
- For detailed per-provider fingerprints and the claim workflow, defer to the dedicated subdomain-takeover technique guide — no need to duplicate it here.

---

### Phase 6: Pivot Chains — GRE Tunnel DNS Injection & SSRF + DNS Rebinding

Both techniques share a common trait: **DNS itself is not the endpoint — it's the tool that lets another vulnerability cross a trust boundary.**

#### GRE Tunnel DNS Injection

Precondition: the target's network architecture includes a GRE tunnel (common in ISP backbones, enterprise WAN interconnects), and neither end validates the integrity of DNS traffic traversing it. The logic is: "if traffic can be injected on the GRE tunnel path, DNS queries/responses have no built-in source-authentication mechanism (UDP + predictable query ID), making DNS an easier injection point than direct off-path forgery." This is a network-layer attack, and bug bounty scope rarely authorizes testing at the level of "inject traffic into a GRE tunnel" — in most cases the value here is **understanding the threat model**: if public architecture documentation shows a GRE tunnel exists and DNS shares that path, that's an architecture risk worth flagging in a report, not something you can self-verify.

#### SSRF + DNS Rebinding Pivot

This is the combination that's **actually feasible and common** in bug bounty work, unlike the previous one:
1. The application's SSRF defense for a user-supplied URL/hostname works by "resolve DNS first, then check whether the IP is on a blocklist" (a TOCTOU pattern).
2. The attacker controls a domain with a very short DNS TTL. The first resolution returns a legitimate external IP (passes the defense check); a second resolution (when the server actually issues the request) returns an internal IP (e.g. `169.254.169.254` or `127.0.0.1`).
3. To judge whether this TOCTOU gap exists: check whether the SSRF defense "checks once and caches the result" or "re-resolves on every connection" — if code/response timing shows these are two separate steps (resolve-and-check first, connection established later), that's a suspect.

**Follow-up**: once rebinding is confirmed feasible, proceed directly into an SSRF playbook's cloud-metadata / internal-service enumeration flow — DNS here is just the key that opens the door; the real impact lives on the SSRF side.

---

## Decision Points

| Situation | Action |
|-----------|--------|
| Resolver only serves an internal allowlist of sources | Record as "conditional risk"; don't invest further in cache-poisoning verification |
| NSEC3 high iteration + salted | Stop loss, pivot to other subdomain-enumeration methods (CT logs, passive DNS) |
| SRV records only queryable internally, external DNS properly separated | Normal configuration, not a finding — skip |
| External DNS unexpectedly answers internal SRV record queries | Record independently as an architecture-level finding; evaluate what it chains into |
| SSRF defense has a TOCTOU gap | Immediately pivot to the SSRF playbook to verify impact — this is the most common actually-deliverable vulnerability path in this document |
| Proving the finding would require actually building a tunneling C2 or performing blind poisoning | Stop loss; describe as an architecture-level risk instead, do not perform the disruptive verification (violates GET-first) |

---

## Expected Outputs

- A role classification for the target DNS server(s) (recursive / authoritative-only / AD-integrated / validator / DoH-DoT gateway), with per-role coverage status.
- A conditional-risk note on cache-poisoning exposure (source-port/query-ID entropy assessment), if applicable.
- A complete subdomain list harvested via NSEC/NSEC3 zone walking or unrestricted AXFR, feeding into further liveness probing and subdomain-takeover scanning.
- An independent finding if split-horizon DNS is misconfigured (internal SRV records answered externally).
- A documented feasibility assessment for DNS-tunneling-based data exfiltration, if the target's outbound DNS is unrestricted.
- A confirmed or ruled-out SSRF + DNS rebinding TOCTOU finding, handed off to SSRF impact verification.

---

## Related

- Subdomain-takeover technique guide — full CNAME/NS/MX claim workflow
- General recon/enumeration playbook — passive/active DNS enumeration commands
- `Pattern - RFC-1918 IP Leak in Public DNS`
- `ssrf-server-side-request-forgery` skill — follow-up verification for the Phase 6 rebinding pivot
- Attack-chain review step — evaluating what an SRV/zone leak can chain into once found
