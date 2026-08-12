---
type: playbook
title: "Structured Recon Flow (Step 0-4)"
tags: [playbook, recon, methodology, workflow, bb-playbook]
category: recon
status: draft
last_updated: 2026-08-12
---

# Playbook - Structured Recon Flow (Step 0-4)

> **TL;DR**: A five-step structured reconnaissance flow (Step 0-4) that expands a target from a handful of root domains into a much wider attack surface: enumerate subdomains, fingerprint each live host's tech stack, probe with paths the fingerprint recommends, filter out SPA catch-all false positives, then run automated hunters. Every step ends with a low-threshold handoff rule so ambiguous signals aren't silently dropped. Usable manually or wired into an automated recon pipeline.

## Scope / When to use

- Starting recon on any new target where you only have 1-5 known root domains.
- Recon feels "too narrow" — you're only checking a fixed path list against the root domain and yield is low.
- You want a repeatable flow that can run manually or be automated end-to-end (subdomain enum → fingerprint → probe → filter → scan).

## Phases

### Phase 1: Subdomain Enumeration + Passive Recon (Step 0)

**Goal**: expand from 1-5 root domains to dozens of attack-surface hosts.

```bash
# Active enumeration (subfinder as primary engine, 6 passive sources)
python3 bb_subdomain_enum.py TARGET --live

# Passive DNS (ip.thc.org, 5.9B records, zero active scanning)
curl -s "https://ip.thc.org/TARGET" | grep -v "^;;" | head -30

# CNAME records (find dangling CNAMEs / subdomain takeover candidates)
curl -s "https://ip.thc.org/cn/TARGET"

# Filter to live hosts
httpx -silent -mc 200,301,302,401,403 -t 50 -timeout 8
```

### Phase 2: Tech Stack Fingerprinting (Step 1)

**Goal**: identify each domain's tech stack and generate a custom probe path list from it.

```bash
python3 bb_fingerprint_probes.py SUBDOMAIN
```

**Key point**: different subdomains may run entirely different stacks. `api.target.com` might be Express while `admin.target.com` might be Laravel — don't assume one stack applies to the whole target.

### Phase 3: Custom Probing (Step 2)

**Goal**: probe with the paths the fingerprint step recommended, not a static wordlist.

```bash
for path in <paths from Phase 2 output>; do
  echo "--- $path"
  curl -sk -o /dev/null -w "%{http_code} %{size_download}" "https://SUBDOMAIN$path"
  echo
done
```

**Don't just look for 200s**:
- 200 + size > 100 → worth further verification
- 403 on a sensitive path (`/actuator`, `/admin`, `/graphql`) → something is being protected, worth a bypass attempt
- 500 + size > 5000 → possibly a debug page / stack trace
- 301/302 → follow the redirect and check the destination

### Phase 4: SPA Catch-All Filtering (Step 3)

```bash
python3 bb_spa_catchall_check.py SUBDOMAIN
# exit 2 = SPA catch-all (false positive)
# exit 0 = genuine response
```

### Phase 5: Automated Hunter Scan (Step 4)

```bash
# Full scan
cd ~/bbflow && bash bbflow.sh hunt TARGET --allow-no-scope

# Specific hunter the fingerprint step recommended
cd ~/bbflow && bash hunters/<hunter-name>.sh TARGET
```

## Decision Points

Hand off to deeper manual/automated vulnerability testing if **any** of the following hold — keep the handoff threshold deliberately low:

- 200 response that is a genuine (non-SPA) page
- 403 on a sensitive path → attempt a bypass
- 500 with a large response body → likely a debug page
- Automated hunter reports HIT / MEDIUM / HIGH
- Interesting headers present (`X-Debug`, or `Server`/`X-Powered-By` with version numbers)
- Subdomain points to a staging / dev / test / beta environment
- CNAME points to a deprovisioned service

**Signal present but not conclusive** → log it to a triage inbox instead of dropping it:

```bash
python3 bb_session_memory.py triage-add --target TARGET --signal "description" --priority medium
```

**No signal at all** → record it as a plain observation in the knowledge base (`bb_kb_learn observation`) so the host isn't re-scanned blind next time.

## Expected Outputs

- A shortlist of hosts/paths that meet a Decision Point and are ready for deep-dive testing.
- Triage inbox entries for ambiguous signals that need a second look later.
- Knowledge-base "observation" records for hosts that produced no signal, to avoid redundant re-scanning.
- Baseline effectiveness data point that motivated this flow: before adopting it, scope→vulnerability conversion was around 10% (6 out of 60), bottlenecked by scanning only root domains with a fixed path list. Adding subdomain enumeration, fingerprint-driven custom probing, and a low handoff threshold was the fix.

## Related

- [[Pattern - Tech Stack Fingerprint to Probe Mapping]]
- [[Tool - bb_fingerprint_probes]]
- [[Checklist - Recon Floor]]
