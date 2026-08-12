---
type: pattern
title: Pattern - Vendor Product Multi-Host Enumeration
description: "Once a vendor-product vulnerability is confirmed on one host, immediately enumerate every other deployment (different region / tier / subdomain) and turn 1 finding into N findings."
tags: [recon-methodology, multi-host, vendor-product, fingerprint, attack-surface-expansion, mass-enum, bb-pattern]
status: active
last_updated: 2026-05-13
---

# Pattern — Vendor Product Multi-Host Enumeration

## Core Concept

When you confirm a vendor-product vulnerability on a **single host** (e.g. a webmail gateway's `pre_cmd` parameter reflecting XSS, an outdated Z-Push build, or a Plesk source-map leak), the first instinct is often "write up this one report and submit." That is **leaving bounty on the table**.

The correct approach: **enumerate every deployment of the same product first**, then submit a single report that lists all affected hosts. Reasons:
1. **Same product = shared codebase** — the same vulnerability is ~99% consistent across hosts.
2. **Impact scales from N=1 to N=22** — triagers only assign P2+ severity once they see mass scope.
3. **"Out of scope" pushback gets much harder** — a single host is easy to dismiss as "an out-of-scope subdomain"; 22 hosts, a triager won't push all of them back.

## Detection / Trigger Conditions

Start multi-host enumeration the moment you see **any one** of these signals:

| Signal | Example |
|------|-----|
| **Vendor-product fingerprint hit** (server header / `X-Powered-By` / distinctive path / a known-CVE version) | a version-bearing custom header, a distinctive login-page structure, or a distinctive CGI path |
| **Vulnerability lives in the vendor's own codebase, not target-side customization** | the vulnerable parameter is part of the vendor's built-in CGI logic, not something the operator wrote themselves |
| **A public CVE exists** | e.g. CVE-2025-8264 (Z-Push IMAP SQLi) → find every host still running the vulnerable Z-Push version |
| **The organization uses a multi-tier / multi-region naming convention** | e.g. `vip-*` / `ms-*` / `vs-*` prefixes crossed with `tw / jp / sg / cn / us` region codes |

## 4-Step Enumeration Flow

### Step 1: Confirm the Vulnerability on the Anchor Host

```bash
# Confirm the vulnerability exists on one host
curl -s "https://vip-chief-web.example.com/cgi-bin/login?pre_cmd=javascript:alert(1)" \
  | grep -c "javascript:alert(1)"
# → 5 reflections = anchor confirmed
```

### Step 2: Extract a Fingerprint (what signature identifies the same product)

```bash
# Pull a product identifier from the anchor host
curl -sI "https://vip-chief-web.example.com/cgi-bin/login" | grep -iE "server|x-powered"
# possible hits:
#   Server: Apache/2.4.x <ProductName>/8.5
#   or the path "/cgi-bin/login" + a distinctive JS variable in the response
```

Three signature types are usable:
- **Header signature**: a version-bearing custom header (e.g. `X-Zpush-Version`), `X-Generator`, or a `Server` header carrying a version string
- **Path signature**: a vendor-specific URL pattern (e.g. a distinctive `/cgi-bin/<product>login` path)
- **Body signature**: a distinctive JS/CSS class embedded in the HTML that is unique to the product's front end

### Step 3: Generate Host Candidates (two directions in parallel)

**Direction A: from the target's own DNS / subdomain enumeration**

```bash
# Pull all subdomains from bbot/subfinder/dnsx output
cat workshop/$TARGET/recon/live_hosts.txt | grep -E "mail|chief|web|gw|smtp|imap|pop|cal|cas|eas" \
  | head -50
```

**Direction B: vendor naming pattern × region matrix**

```bash
# Example: tier prefixes (vip/ms/vs) × region suffixes (tw/jp/sg/cn/us-aws)
for TIER in vip ms vs cas eas; do
  for REGION in tw jp sg cn us-aws "" ; do
    PREFIX="${TIER}"
    [ -n "$REGION" ] && PREFIX="${TIER}-${REGION}"
    HOST="${PREFIX}-chief-web.example.com"
    echo "candidate: $HOST"
  done
done
```

### Step 4: Mass-Verify — Run the Same PoC Against Every Candidate

```bash
HOSTS=$(cat candidate_list.txt)
CONFIRMED=()
for HOST in $HOSTS; do
  # confirm the host is alive first (DNS + HTTP 200)
  DNS_OK=$(dig +short A "$HOST" | head -1)
  [ -z "$DNS_OK" ] && continue

  # run the PoC
  REFL=$(curl -s --max-time 8 "https://${HOST}/cgi-bin/login?pre_cmd=javascript:alert(document.domain)" \
    | grep -c "javascript:alert(document.domain)")
  if [ "$REFL" -ge 3 ]; then
    CONFIRMED+=("$HOST: $REFL reflections")
  fi
done

printf '%s\n' "${CONFIRMED[@]}"
# e.g. 22 hosts confirmed with 5 reflections each
```

## Case Studies

### Case A — Webmail Gateway `pre_cmd` XSS (expanded to 22 hosts over several sessions)

| Stage | Confirmed hosts | Trigger |
|------|------------|--------|
| Anchor | 1 (a single VIP-tier web host) | reflection observed on the anchor host |
| Round 2 | 3 (+2 more tier prefixes) | assumed same underlying product codebase |
| Round 3 | 15 (+12 international sites across region/tier combinations) | region-matrix enumeration |
| Round 4 | 19 (+ calendar/mail/CAS/EAS role hosts) | more mail-related subdomains surfaced from DNS enum |
| Round 5 | **22** (+ autodiscover.* + one more mail-tier host) | added the `autodiscover` naming convention |

→ One reflection on one host became **22 confirmed hosts across every region** after five rounds of enumeration.

### Case B — Outdated ActiveSync Gateway Version Fingerprint (expanded to 7 hosts)

```bash
# Step 1: anchor host shows a version-bearing header, e.g. X-Zpush-Version: master-2.5.0-...
# Step 2: signature = the X-Zpush-Version header
# Step 3: candidates = eas-* + autodiscover.* + eas.office.*
# Step 4:
for SUB in eas-vip eas-vs eas-us autodiscover.vip autodiscover.vs autodiscover.us eas.office; do
  curl -sI "https://${SUB}.example.com/Microsoft-Server-ActiveSync" \
    | grep -i "x-zpush-version"
done
# 7 hosts confirmed running the same vulnerable version (matching a public CVE)
```

### Case C — Internal Kubernetes Service Mass Enumeration

A variant on multi-host enumeration: **not customer-facing hosts, but internal services inside a single K8s cluster**. Same anchor → fingerprint → mass-verify pattern:
- Anchor: 1 internal service confirmed reachable via an SSRF primitive
- Fingerprint: the `<svc>.<namespace>.svc.cluster.local` path convention
- Candidates: pulled from a service-registry/discovery API's service-name list
- Verify: ran the SSRF oracle against 35+ discovered services

## Severity Escalation Logic

| Affected hosts | Severity impact |
|---------------|---------------|
| 1 host | base severity unchanged |
| 2-5 hosts (same region) | +0.5 CVSS (scope expansion) |
| 5-15 hosts (multi-region or multi-tier) | **+1 severity tier** (P3→P2 / P2→P1 candidate) |
| ≥15 hosts (global) | **mass scope** — usually escalates to P1 / Critical |

**Reasoning**: H1/Bugcrowd triagers weight severity partly by estimated affected-user count. 22 confirmed production hosts effectively means the entire user base of that service is affected.

## Anti-Patterns (do NOT count as a multi-host escalation)

| Situation | Why it doesn't count |
|------|------------|
| Report says "N hosts" but they're actually different paths on the same host | Path enumeration is not host enumeration |
| Candidates were listed but only 1-2 were actually confirmed | No confirmation = no impact credit |
| A different host exists but is explicitly out of scope | Not submittable |
| Multi-host but sharing the same token / same user ID | Same attack vector — does not count as mass scope |

## Related Patterns

- [[Pattern - SourceMap Endpoint Family Disclosure]] — finding an entire endpoint family from one `.map` file; conceptually the endpoint-side version of this pattern
- [[Pattern - Blind SSRF Oracle Technique]] — K8s service mass enumeration is a variant of this pattern
- [[Pattern - Internal IP Disclosure via Gateway]] — multiple gateways from the same vendor sharing an internal-IP leak

## Tooling Notes (bbflow hunter automation)

```bash
# hunt-version-header-mass-enum.sh — mass-enumerate hosts by a version-bearing header
# hunt-webmail-precmd.sh — mass reflection probe for a webmail gateway's pre_cmd parameter
# both accept a host_list.txt and run against the whole list in one pass
```

## Learned Items

1. **Start multi-host enumeration the instant a vendor-product fingerprint hits.** Reporting on 1 host alone leaves roughly 80% of the potential bounty on the table.
2. **A region × tier matrix is a free source of candidates** — a one-line nested for-loop can generate 50 candidates at zero cost.
3. **Filter by DNS before hitting HTTP** — run `dig +short A` on every candidate first, only `curl` the ones that resolve; this saves ~80% of requests.
4. **~22 hosts is a sweet spot**: triagers generally accept a "mass scope" argument once you cross roughly 15 hosts, and give P2+. Beyond that, marginal severity gains taper off (it won't push a report to P0 by itself).
5. **Report structure**: the FORM body should contain one PoC (the anchor host); the remaining hosts belong in a table showing "the same PoC reproduces identically on these hosts." Triagers won't re-test each one individually — they mainly look at how long the list is.
