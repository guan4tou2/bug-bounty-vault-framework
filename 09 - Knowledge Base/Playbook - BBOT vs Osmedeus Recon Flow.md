---
type: playbook
title: "BBOT vs Osmedeus Recon Flow"
tags: [playbook, recon, bbot, osmedeus, automation, comparison, subdomain-enum, passive, api, iot, nxdomain, minimalist-stack, bb-playbook]
category: recon
status: draft
last_updated: 2026-08-12
---

# Playbook - BBOT vs Osmedeus Recon Flow

> **TL;DR**: For a solo bug bounty hunter running passive-first recon on a single machine, **BBOT wins** — recursive event-driven discovery, 100+ built-in modules, one-command install. Osmedeus is better suited to team/enterprise continuous scanning or distributed multi-VPS operations. A third option, a minimalist manual stack (httpx → katana → waymore → ffuf → nuclei-confirm → Burp Repeater), trades scale for high-confidence manual authorization-logic review once a target's subdomains are already known. This playbook covers the tool comparison, an end-to-end recon flow assembled from real hunting sessions, and where each high-ROI pattern (git exposure, source maps, staging APIs, NXDOMAIN-based internal proxy pivots, default credentials, IDOR) fits into the pipeline.

---

## Scope / When to use

Use this playbook when starting recon on a new bug bounty target, choosing between automated recon tooling (BBOT, Osmedeus) and manual-first approaches, or wiring up a repeatable subdomain-to-finding pipeline. It assumes an authorized program with a defined scope and OOS list.

### Canonical flow (2026-05-20)

This page is the recon "brain" note for the `bbflow` automation wrapper; execution details are governed by `$TOOLS_ROOT/BBFLOW_OPERATIONS.md`, `$TOOLS_ROOT/wiki/00-bbflow-complete-flow.md`, and `$TOOLS_ROOT/bbflow.sh`. This KB governs origination and process; your local workspace holds transient raw output/logs/PoCs/screenshots, and `bbflow` executes the actual scans. **Raw scan output does not get committed to the knowledge base** — only curated Recon notes, Attempts, Findings, Submissions, FORMs, Patterns, and Lessons go back into the KB, and any detection logic worth reusing gets promoted into a hunter script / template / profile inside `bbflow`.

### Standalone runtime boundary

`bbflow` is a standalone tool, not a plugin of this knowledge base. Its runtime **MUST NOT require the KB** and **MUST NOT require an LLM** — KB integration is optional. When `bbflow` scans, it depends only on the scope contract, host list, templates, hunters, and tool output, and delivers results as machine-readable artifacts: `run_manifest.json`, `candidates.jsonl`, `SCOPE.md`, `scope_contract.json`.

Integration contract:
- `BBFLOW_WORKSPACE` controls the local output root, defaulting to the current working directory.
- `BBFLOW_REMOTE_ROOT` controls the `bbflow` repo location on a remote VPS, defaulting to `~/bbflow`.
- The KB adapter may only read machine-readable output after a run completes, then curate it into Recon / Attempt / Finding notes.
- The KB may provide governance, dedupe, and Lessons capture, but must never be a hard dependency for `bbflow` execution.

### Recon ladder v1

| Stage | Input | Purpose | Output |
|---|---|---|---|
| Domain seed | Program scope / root domain | Establish a lawful scan starting point | `SCOPE.md` / `scope_contract.json` |
| Asset discovery | Domain seed | BBOT / Osmedeus find subdomains, cloud assets, live hosts | `bbot/subdomains.txt`, `bbot/live_hosts.txt` |
| Fingerprint | Live hosts | Tech, title, status, CDN/WAF, screenshots | Fingerprint / screenshot output |
| Path discovery | Live hosts | Archive URLs, crawler routes, JS routes, well-known paths | `archive_urls.txt`, crawl output |
| Endpoint discovery | Paths / JS | API endpoints, parameters, methods, auth boundaries | Endpoint candidates |
| CVE / template scan | Live hosts / endpoints | Nuclei / Wordfence / custom recon templates for known vulns | `nuclei_results.txt` |
| Attack entrypoint | Candidate hits | Rank candidates worth manual verification: authz, secret/config leaks, CVE, takeover | Attempt / Finding candidates |

### Current automation split

| Path | When to use | CLI / Wrapper | Behavior |
|---|---|---|---|
| **BBOT standard path** | Default recon; solo hunter; passive/low-noise first | `bbflow recon <target> --scope-file scope.yaml` | Scope gate → BBOT `subdomain-enum,cloud-enum` + `httpx,badsecrets` → `$WORKSHOP_ROOT/<target>/bbot/` |
| **Osmedeus standard path** | Need a long-running VPS job, screenshots, archive crawl, IP-space mapping | `OSMEDEUS_VPS=user@host bbflow recon <target> --scope-file scope.yaml --osmedeus` | SSH to the VPS → `$TOOLS_ROOT/vps/bbflow-vps.sh standard <target>` → `bbflow-safe` |
| Nuclei path | Have live hosts / endpoints and want to check for known vulns / template matches | `bbflow hunt <target> --only nuclei,nuclei-secrets,nuclei-panels,nuclei-wp` | Uses ProjectDiscovery templates, Wordfence CVE templates, `$TOOLS_ROOT/nuclei-templates/bb-recon/` |

`bbflow-safe` is the Osmedeus safe baseline: passive enum, DNS/HTTP probing, fingerprinting, screenshots, archive URLs, IP-space mapping, top HTTP ports — it does **not** include content fuzzing, DNS brute force, or high-noise nuclei. Before running `vulnscan` / `extensive`, confirm program scope, log the operation, and define a stop condition first.

### Nuclei template lifecycle

A self-authored template never goes straight into a live scan. The fixed pipeline is: draft → `nuclei -validate` → `example.com` null-case → scoped live canary → false-positive review → promote → write back to the KB / bbflow wiki / `CHANGELOG.md`. Until the scoped live canary step is complete, a template may only be labeled draft or experimental — it must not be claimed as field-validated.

### WAF-safe mode

WAF-safe mode is a low-noise safety boundary, not a stealth mode. The default order is passive → GET-first → low `rate-limit` → single-point verification. Payload mutation is reserved for explicitly authorized, in-scope scenarios — encoding, path normalization, header variation, parameter substitution. **Do not treat WAF bypass as a default behavior.** Before enabling `waf-bypass`, DAST, ffuf, dalfox, arjun, or high-noise nuclei, write an operation log entry and define a stop condition first.

### KB close-loop

1. Kickoff: claim the target → session-start brief → scope / dedupe / version-and-CVE pre-flight.
2. Execute: run the BBOT standard path or the Osmedeus standard path on a VPS; the local workspace holds all raw output.
3. Triage: dedupe candidate hits first; not-reproducible or duplicate → Attempt, confirmed → Finding + Submission + FORM.
4. Backfill: curate report material back into the KB; anything reusable becomes a Pattern / Lessons / Playbook entry.
5. Self-learning: anything that can be automated gets written back as a bbflow hunter, Nuclei template, or Osmedeus profile, or documented in the wiki — the bbflow wiki stores only knowledge and technique, never sensitive data or target-specific hosts/IPs/tokens/raw logs.

---

## Phases

### Phase 1: Tool comparison and selection

#### Comparison table

| Dimension | BBOT | Osmedeus |
|------|------|---------|
| **Language** | Python (asyncio) | Go |
| **Architecture** | Event-driven recursive pipeline | YAML declarative orchestrator |
| **Install** | `pipx install bbot` (one line) | `curl install.sh` (need to install every external tool separately) |
| **Built-in tools** | 100+ modules bundled | ❌ Just an orchestrator — tools must be installed separately |
| **Passive-only** | ✅ One `-rf passive` flag | ❌ Requires manually excluding active modules |
| **Recursive discovery** | ✅ Event feedback loop (20–50% more subdomains) | ❌ Linear execution |
| **Distributed compute** | ❌ Single machine | ✅ Redis workers + cloud VPS |
| **Web UI** | ❌ | ✅ |
| **REST API** | ❌ | ✅ |
| **Neo4j output** | ✅ | ❌ |
| **LLM integration** | ❌ | ✅ YAML workflow step |
| **License** | AGPLv3 | MIT |
| **GitHub stars** | 9,594 | 6,188 |
| **Maintenance** | Team (BlackLanternSecurity) | Individual (j3ssie) |
| **Resource needs (subdomain-enum)** | 100–200MB RAM, 10–30 min | Depends on external tools |

#### When to use which

| Scenario | Recommendation |
|------|------|
| Solo bug bounty hunter, single machine | ✅ **BBOT** |
| Passive-first recon | ✅ **BBOT** |
| Deep, targeted recon on a single program | ✅ **BBOT** |
| Python scripting integration | ✅ **BBOT** |
| Continuous monitoring across many programs | ✅ **Osmedeus** |
| Distributed scanning across multiple VPS | ✅ **Osmedeus** |
| Custom tool-chain orchestration | ✅ **Osmedeus** |
| Team / enterprise environment | ✅ **Osmedeus** |
| Manual, focused hunting on a small number of targets | ✅ **Minimalist stack** |

#### The third point on the spectrum: minimalist stack

A counterpoint to heavy tool automation. **Assumes subdomains are already sourced elsewhere**; the focus is manual Burp Repeater comparison of authorization logic, not fuzzing at scale. Source: [[External Writeups - 2026 Collection]] (a 2026 community writeup on a manual-first methodology).

| Phase | Tool | Philosophy |
|---|---|---|
| Filter the entry point (not discover it) | `httpx` | Filter by status / tech / redirect |
| Live crawl | `katana` | Modern JS-aware routing |
| Historical endpoints | `waymore` | Single historical crawler, no triple-source dedupe |
| Fuzz | `ffuf` | Endpoint / param / file discovery |
| Confirm (not hunt) | `nuclei` | Used conservatively — only to confirm known CVEs |
| Primary effort | **Burp Repeater** | Role comparison, state-transition testing, IDOR/authz logic |
| Exploit | `sqlmap` / `XSStrike` | Only launched after manual pre-filtering |

**Anti-patterns**: treating nuclei as the primary decision tool; blindly stacking gau + waybackurls + waymore with triple-source dedupe; letting monitoring tools (notify, interactsh) leak into an active hunting session.

**When to pick minimalist**: after a program has been tapped out with automated tooling and you're switching to manual deep-dive on a new target; when the target count is small but you need high-confidence authz-logic judgment; for a solo session with limited context window / attention budget.

**When not to**: the first pass on a brand-new program, continuous monitoring, or parallel multi-target work — use BBOT or Osmedeus instead.

---

### Phase 2: BBOT setup

#### Install

```bash
# Install (pipx isolated environment recommended)
pipx install bbot

# Verify
bbot --version

# Update
pipx upgrade bbot

# Docker (no need to install Python dependencies)
docker pull blacklanternsecurity/bbot
docker run blacklanternsecurity/bbot -t target.com -p subdomain-enum
```

#### Built-in presets

```bash
bbot --list-presets          # list all presets
bbot --list-modules          # list all modules
bbot --help
```

| Preset | Purpose | Time |
|--------|------|------|
| `subdomain-enum` | Full subdomain enumeration (API + DNS brute + mutations) | 10–30 min |
| `subdomain-enum -rf passive` | Passive subdomains only (no DNS brute) | 2–5 min |
| `web-basic` | Quick web scan (tech detect + misconfig) | 5–15 min |
| `web-thorough` | Deep web scan (extends web-basic) | 30–60 min |
| `spider` | Recursive crawler + JS link extraction | 10–30 min |
| `email-enum` | Email harvesting (OSINT + crawl) | 5–20 min |
| `cloud-enum` | S3/GCS/Azure asset discovery | 5–15 min |
| `code-enum` | GitHub/GitLab repo discovery | 5–10 min |
| `paramminer` | Web parameter discovery | 10–30 min |
| `dirbust-light/heavy` | Directory brute force | 10–60 min |
| `nuclei` | Nuclei vulnerability scan | 15–45 min |
| `nuclei-intense` | Deep nuclei (more templates) | 45–90 min |
| `lightfuzz-xss` | XSS fuzzing | 15–30 min |
| `kitchen-sink` | All of the above | 1–3 hours |

#### Zero-LLM one-shot automation

The flow below is wrapped in `$TOOLS_ROOT/bbflow.sh` (currently 47 hunter scripts), built from plain `curl + python3 stdlib + bash`, with zero LLM dependency:

```bash
"$TOOLS_ROOT/bbflow.sh" flow target.com                       # full pipeline: recon + hunter scripts
"$TOOLS_ROOT/bbflow.sh" recon target.com                      # BBOT/Osmedeus recon only
"$TOOLS_ROOT/bbflow.sh" hunt target.com                       # hunters only (when recon output already exists)
"$TOOLS_ROOT/bbflow.sh" hunt target.com --only cors,graphql   # run specific hunters
"$TOOLS_ROOT/bbflow.sh" status target.com                     # check workspace status
```

> **Note**: `$TOOLS_ROOT/hunt_all.sh` is deprecated (⚠️ DEPRECATED) — use `bbflow.sh` instead.

Each step below has an "⚡ Automation" callout pointing to the matching hunter script — the manual flow that follows is kept as reference/debugging material; production runs should just call `bbflow.sh flow`.

Output lands in `$WORKSHOP_ROOT/<target>/`; a `🔴` prefix marks a high-confidence hit. See `$TOOLS_ROOT/hunters/README.md` for details.

---

### Phase 3: End-to-end recon flow (assembled from real hunting sessions)

This flow synthesizes real-world lessons from multiple retail/IoT/consumer-hardware bug bounty programs.

#### Step 0 — Confirm scope (mandatory)

```bash
# Create $WORKSHOP_ROOT/<target>/SCOPE.md
mkdir -p "$WORKSHOP_ROOT/<target>"
cat > "$WORKSHOP_ROOT/<target>/SCOPE.md" << 'EOF'
# <Target> Scope

## In-Scope
- *.target.com
- api.target.com

## Out-of-Scope (OOS)
- Rate limiting / brute force
- Email enumeration (standalone)
- Source map (standalone)
- XMLRPC enabled

## Platform / Bounty
- Platform: Intigriti / H1 / Bugcrowd
- URL: https://...
- Bounty: $XXX - $YYYY
EOF
```

> **Lesson (Intigriti-style programs)**: read the out-of-scope (OOS) list before hunting. Classes like email enumeration / source map leaks / rate limiting are often explicitly OOS on Intigriti-hosted programs.

#### Step 1 — Passive subdomain enumeration (zero noise, run first)

```bash
TARGET="target.com"
OUTDIR="$WORKSHOP_ROOT/$TARGET"

# BBOT passive (never touches the target — pure API/OSINT)
bbot -t $TARGET -p subdomain-enum -rf passive \
  -o $OUTDIR/bbot_passive/ \
  --allow-deadly                               # allow modules like HaveIBeenPwned

# Check results
cat $OUTDIR/bbot_passive/subdomains.txt | wc -l
cat $OUTDIR/bbot_passive/subdomains.txt | head -20
```

**Data sources covered by passive mode (BBOT calls these automatically):**
- Shodan, Censys, SecurityTrails, Chaos (ProjectDiscovery)
- crt.sh, Certspotter (Certificate Transparency)
- GitHub, GitLab (subdomain/IP leaks)
- VirusTotal, AlienVault OTX, URLScan
- Wayback Machine

#### Step 1.5 — Historical / NXDOMAIN hostname corpus (internal proxy attack surface)

> Source: [[External Writeups - 2026 Collection]] — a public writeup describing a NXDOMAIN-based internal SSRF case at a large retail target.
> Core insight: **NXDOMAIN ≠ dead**. Internal resolvers will still answer for `*.corp`, `*.intranet`, and legacy decommissioned hostnames. Once you find any internet-facing proxy/edge service that lets you control the upstream Host, this list becomes the payload source for an SSRF primitive.

```bash
# Merge BBOT passive + crt.sh + wayback into a "ever seen historically" superset
cat $OUTDIR/bbot_passive/subdomains.txt > $OUTDIR/historical_all.txt
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  jq -r '.[].name_value' >> $OUTDIR/historical_all.txt
waymore -i $TARGET -mode U -oU $OUTDIR/waymore.txt 2>/dev/null
grep -oE "[a-zA-Z0-9.-]+\.${TARGET}" $OUTDIR/waymore.txt >> $OUTDIR/historical_all.txt
sort -u $OUTDIR/historical_all.txt -o $OUTDIR/historical_all.txt

# Reverse filter: keep hosts that "no longer resolve publicly" — those are internal candidates
cat $OUTDIR/historical_all.txt | while read h; do
  # dig returns nothing for A/CNAME/AAAA → NXDOMAIN candidate
  if [ -z "$(dig +short +time=2 +tries=1 "$h" @1.1.1.1)" ] && \
     [ -z "$(dig +short +time=2 +tries=1 AAAA "$h" @1.1.1.1)" ]; then
    echo "$h"
  fi
done | tee $OUTDIR/nxdomain_corpus.txt

wc -l $OUTDIR/nxdomain_corpus.txt   # target: 500-5000 entries; too few means insufficient sources
```

**When to use this**: once Step 2–5 finds any proxy/edge service that lets you set a custom Host header, URL parameter, or SNI (common in CDNs, reverse proxies, edge API gateways, service-mesh sidecars), feed `nxdomain_corpus.txt` into Burp Intruder against the Host header position and watch the response body — anything that returns real content is talking directly to an internal service.

**Do not**: run DNS brute force or public-internet probing directly against the nxdomain corpus — that just generates noise. This list only becomes a payload source once you've found a gadget that lets you control the upstream target.

**Keep this list**: save each target's `nxdomain_corpus.txt` — it can be reused immediately the next time that program stands up a new edge service.

#### Step 2 — DNS resolution and live-host filtering

```bash
# Resolve + probe (using BBOT output or your own merged list)
cat $OUTDIR/bbot_passive/subdomains.txt | \
  dnsx -silent -a -resp | tee $OUTDIR/resolved.txt

cat $OUTDIR/resolved.txt | \
  httpx -silent -status-code -title -tech-detect \
  -o $OUTDIR/live_hosts.txt

# Important: filter out OOS IP ranges
cat $OUTDIR/live_hosts.txt | grep "200\|301\|302\|403" | tee $OUTDIR/interesting.txt

# Look for staging/UAT/dev environments (high value!)
# Lesson: staging/UAT subdomains with vendor-specific naming prefixes are often
# the most valuable API surface (e.g. "sit-api.*", "uat-api.*", "e2e-*" patterns)
cat $OUTDIR/live_hosts.txt | grep -iE "uat|sit|staging|dev|test|api" | tee $OUTDIR/staging_targets.txt
```

#### Step 3 — Active subdomain brute force (optional)

```bash
# Confirm brute force is not OOS before running this
bbot -t $TARGET -p subdomain-enum \
  -o $OUTDIR/bbot_active/ \
  --allow-deadly

# Or manual DNS brute
puredns bruteforce ~/wordlists/subdomains-top1m.txt $TARGET \
  -r ~/resolvers.txt -w $OUTDIR/brute_resolved.txt
```

#### Step 4 — Port and service fingerprinting

```bash
# Fast top-1000 scan (avoid a full 65535 sweep — too noisy)
naabu -l $OUTDIR/live_hosts.txt -top-ports 1000 \
  -o $OUTDIR/ports.txt

# nmap service detection (only on interesting ports)
nmap -Pn -sV -p 80,443,8080,8443,8888,3000,4443,9200,6379,5432,3306 \
  -iL $OUTDIR/interesting.txt -oA $OUTDIR/nmap_out

# Find staging-environment naming signatures
# Lesson (SAP BTP deployments): SAP Business Technology Platform tenants often
# publish predictable staging-API subdomain naming conventions
# (e.g. "<tenant>uat-api.<domain>" style patterns) → search crt.sh for the prefix
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
  jq -r '.[].name_value' | grep -iE "uat|sit|staging|api" | sort -u
```

> ⚡ **Automation**: `$TOOLS_ROOT/hunters/hunt-nxdomain-corpus.sh target.com` — automatically aggregates BBOT passive + crt.sh + waymore → reverse-filters for NXDOMAIN → `$WORKSHOP_ROOT/<target>/scan_results/nxdomain_corpus.txt`

#### Step 5 — Web surface reconnaissance

```bash
# BBOT web recon (tech fingerprint + quick misconfig scan)
bbot -t $OUTDIR/interesting.txt -p web-basic \
  -o $OUTDIR/bbot_web/

# JS analysis (source maps + secrets)
bbot -t $TARGET -p spider -o $OUTDIR/bbot_spider/

# Extract JS URLs
cat $OUTDIR/bbot_spider/output.ndjson | \
  jq -r 'select(.type == "URL") | .data' | grep -E "\.js$" | \
  tee $OUTDIR/js_files.txt

# Check for source maps
# Lesson (multiple consumer-hardware / IoT programs): a bare source map leak
# is N/A by itself; you need to find an exploitable finding INSIDE the map
cat $OUTDIR/js_files.txt | while read url; do
  curl -sI "${url}.map" | grep -q "200" && echo "[MAP] ${url}.map"
done
```

> ⚡ **Automation**:
> - `$TOOLS_ROOT/hunters/hunt-envdata.sh <host>` — extracts `window.envData` / `__INITIAL_STATE__` / `ssInlineConfig` and greps for AWS/Google/Sentry/Mapbox keys (observed in a consumer-IoT vendor's bundled config leak)
> - `$TOOLS_ROOT/hunters/hunt-sourcemap-secrets.sh <host>` — auto-fetches `.js` → tries `.map` → decodes `sourcesContent` → greps for API keys / Bearer tokens / Stripe / JWT (observed across multiple consumer-hardware vendor bundles)

#### Step 6 — API attack-surface mapping

```bash
# Focus: API endpoint discovery (lesson: SAP Hybris OCC and exposed Swagger are high-ROI)
# Arjun: hidden parameter discovery
cat $OUTDIR/interesting.txt | while read host; do
  arjun -u "$host" -m GET -oJ $OUTDIR/arjun/${host//\//_}.json 2>/dev/null
done

# Common API path brute force
ffuf -u TARGET_URL/FUZZ -w ~/wordlists/api-endpoints.txt \
  -mc 200,201,301,302,403 \
  -o $OUTDIR/api_endpoints.json -of json

# Manual verification of core API endpoints (lesson from SAP BTP deployments):
for HOST in $(cat $OUTDIR/staging_targets.txt | grep api); do
  echo "=== $HOST ==="
  # baseSites (SAP OCC pattern)
  curl -sk "$HOST/api/v2/basesites" | jq '.baseSites[].uid' 2>/dev/null
  # Swagger
  curl -sk "$HOST/swagger-ui.html" | grep -q "Swagger UI" && echo "[!] SWAGGER: $HOST"
  # actuator (Spring Boot)
  curl -sk "$HOST/actuator/env" | jq '.activeProfiles' 2>/dev/null
done
```

> ⚡ **Automation**:
> - `$TOOLS_ROOT/hunters/hunt-hybris-occ.sh <host>` — full SAP Hybris OCC chain: default OAuth creds → baseSites enumeration → anonymous cart creation → GUID IDOR → configParam API keys (observed in a real-world retail SAP Hybris deployment)
> - `$TOOLS_ROOT/hunters/hunt-graphql-idor.sh <host>` — `__typename` + introspection + field suggestion + common list queries + sequential integer-ID IDOR probing (observed in a networking-hardware vendor RMA workflow)
> - `$TOOLS_ROOT/hunters/hunt-user-enum.sh <host>` — GET/POST validate_email differential + password reset + 20-request rate-limit probing (observed across consumer-IoT/security-hardware vendor account APIs)
> - `$TOOLS_ROOT/hunters/hunt-cors-reflect.sh <url>` — four-layer reflection check: arbitrary / null / regex-prefix / suffix bypass + `credentials:true` detection (observed across an 8-service networking-hardware vendor deployment)

#### Step 7 — .git / .env / backup exposure

```bash
# .git exposure (highest-ROI pattern)
cat $OUTDIR/live_hosts.txt | while read line; do
  HOST=$(echo $line | awk '{print $1}')
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$HOST/.git/HEAD")
  [ "$CODE" == "200" ] && echo "[GIT] $HOST"
done

# If .git is exposed → run a three-tool pipeline
git-dumper "$HOST/.git/" ./git_output/
python3 ~/tools/GitHack.py "$HOST/.git/" ./githack_output/
bash ~/tools/gittools/Dumper/gitdumper.sh "$HOST/.git/" ./gittools_output/

# After restoring
cd ./git_output
git log --oneline
git log -p --all | grep -iE "password|secret|api_key|token|client_secret"
git config --get remote.origin.url   # find the developer/agency → supply-chain analysis

# BackupFinder
backupfinder -u $HOST -w -o $OUTDIR/backups.txt

# Quick .env check
curl -sk "$HOST/.env" | grep -iE "^(DB_|APP_|AWS_|API_)" && echo "[!] ENV: $HOST"
```

> ⚡ **Automation**:
> - `$TOOLS_ROOT/hunters/hunt-git-exposure.sh <host>` — probes multiple `.git/HEAD` paths (root + robots.txt disallow entries + common CMS subpaths) + traces `.git/config` remote → supply-chain analysis. Add `--dump` to trigger the three-tool pipeline (git-dumper/GitTools/GitHack) + credential grep (payment-gateway hash keys, messaging-webhook tokens, git log history). Validated in the field reproducing an original public disclosure on an exposed `.git` directory.
> - The existing `$TOOLS_ROOT/auto_hunt.sh target.com --mode full` is a wider-net variant (basic .git/.env/actuator/swagger/ES quick checks) that complements `bbflow.sh`

#### Step 8 — Nuclei vulnerability scan

```bash
# Update templates first
nuclei -update-templates

# Scan (avoid hitting production too hard)
nuclei -l $OUTDIR/interesting.txt \
  -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -etags dos,fuzz \                            # exclude DoS/fuzz templates
  -o $OUTDIR/nuclei_out.txt \
  -j -o $OUTDIR/nuclei_out.json

# Against staging environments (can be a bit more aggressive)
nuclei -l $OUTDIR/staging_targets.txt \
  -tags misconfig,exposure,default-login \
  -o $OUTDIR/nuclei_staging.txt

# BBOT one-shot integration
bbot -t $TARGET -p nuclei -o $OUTDIR/bbot_nuclei/
```

#### Step 9 — WordPress targets (if applicable)

```bash
# wpscan (+API token unlocks the CVE database)
wpscan --url $HOST --api-token $WPSCAN_TOKEN \
  --enumerate u,vp,vt \
  -o $OUTDIR/wpscan.txt

# Lesson: wpscan only returns the full CVE list when an API token is provided
# (observed on a plugin-heavy WordPress deployment with 100+ known CVEs)

# XMLRPC batch brute force (only after confirming brute force is in scope)
# Lesson (Intigriti OOS example): brute-force testing is commonly listed as
# out-of-scope on retail/enterprise programs — check OOS before attempting,
# and don't submit if explicitly excluded
curl -sk "$HOST/xmlrpc.php" -X POST \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -q "methodName" && echo "[!] XMLRPC enabled: $HOST"
```

#### Step 10 — Triage and submission decision

Run every finding through the 7-Question Gate ([[Skill - triage-validation]]):

```
1. HTTP 200 + correct content? (not a custom error page)
2. Can a triager reproduce it within 5 minutes?
3. Does it avoid every OOS rule?
4. Does it match the scope wildcard?
5. Is there verified impact? (not theoretical)
6. Does the severity match real platform practice? (not the raw VRT suggestion)
7. Did you search disclosed reports to confirm it's not a duplicate before submitting?
```

**Severity quick reference (based on real rejection history):**

| Finding | Reasonable rating | Common mistake |
|---------|---------|---------|
| Source map exposure (standalone) | N/A | ❌ P1/P2 → always rejected |
| Unauth staging API directory read | P3–P4 | ❌ don't write "data breach" |
| Unauth write + GUID IDOR (SAP OCC) | P3 | ✅ scope it precisely |
| OAuth default creds (staging) | P3 | ✅ + confirm the production boundary |
| .git exposure + credentials | P2–P3 | ✅ submit with a direct PoC |
| User enumeration (standalone) | P5 Informational | ❌ don't submit standalone |
| CORS (requires a subdomain-takeover precondition) | N/A | ❌ prerequisite not satisfied |

---

## Decision Points

- **BBOT vs Osmedeus vs minimalist stack**: pick based on team size, target count, and whether you need distributed/continuous scanning (see Phase 1 tables). Default to BBOT for solo passive-first recon.
- **Passive vs active enumeration**: always run passive first (Step 1); only proceed to active DNS brute force (Step 3) after confirming it is not OOS.
- **When to escalate NXDOMAIN corpus into an active payload**: only after finding a proxy/edge component that accepts an attacker-controlled upstream Host/URL/SNI — never brute force or probe the corpus directly.
- **When to apply WAF-bypass / high-noise techniques**: only with explicit authorization and a logged operation + stop condition; never as a default.
- **Severity calibration**: use the quick-reference table in Step 10 rather than a raw VRT auto-suggestion — several classes (source maps alone, CORS without a takeover precondition, standalone user enum) are routinely rejected at high severity and should be scoped down or held back.

## Expected Outputs

- `SCOPE.md` / `scope_contract.json` — recorded scope and OOS boundaries
- `bbot_passive/subdomains.txt`, `resolved.txt`, `live_hosts.txt`, `interesting.txt`, `staging_targets.txt`
- `nxdomain_corpus.txt` — reusable historical-hostname corpus per target
- `js_files.txt` and any recovered source-map / secret hits
- `arjun/*.json`, `api_endpoints.json` — API surface and parameter candidates
- `nuclei_out.json`, `nuclei_staging.txt` — template scan results
- Curated Attempt / Finding / Submission / FORM notes for anything that clears the 7-Question Gate
- Reusable detection logic promoted into a `bbflow` hunter script, Nuclei template, or Osmedeus profile

---

## Custom BBOT preset (for IoT/API targets)

```yaml
# ~/.config/bbot/presets/iot-api-recon.yml
description: "IoT/API Bug Bounty Recon — passive-first, API-focused"
include:
  - subdomain-enum

modules:
  - httpx
  - sslcert
  - gowitness          # screenshots
  - wappalyzer         # tech fingerprinting
  - nuclei             # misconfig + exposure templates only

config:
  httpx:
    include_extra_headers: true
  nuclei:
    tags: misconfig,exposure,default-login,api
    severity: critical,high,medium
    etags: dos,fuzz

flags:
  - passive            # passive-first by default
```

```bash
# Use the custom preset
bbot -t target.com -p iot-api-recon
# Switch to active mode (adds DNS brute back in)
bbot -t target.com -p iot-api-recon -rf active
```

## Osmedeus setup (fallback option)

```bash
curl -sSL http://www.osmedeus.org/install.sh | bash
osmedeus install base --preset
osmedeus install workflow --preset       # install community workflows

# Usage
osmedeus run -f general -t target.com
osmedeus run -f general -T targets.txt -c 5    # batch multi-target
osmedeus assets -w target.com                  # query assets
osmedeus query vulns --severity high -w target.com

# Cloud distribution (when multiple VPS are available)
osmedeus cloud run -f general -t target.com --instances 3
```

## Known high-ROI patterns (from real-world results)

| Pattern | BBOT module/preset | Lesson source |
|---------|-------------------|---------|
| .git exposure | `git` module (after httpx probe) | Multiple small/mid-size vendor deployments |
| Source map | `spider` → JS analysis | Multiple consumer-hardware vendor cases (duplicate / N/A / accepted outcomes mixed) |
| SAP BTP staging | crt.sh + `httpx` + manual | Example: SAP BTP retail deployment |
| Subdomain takeover | `baddns` module | BBOT built-in |
| Default credentials | `nuclei` `default-login` tag | e.g., IoT vendor default OAuth credentials |
| Supply chain | `github` module + git-config tracing | Multiple small-vendor deployments with exposed `.git` remotes |
| Open S3 buckets | `cloud-enum` preset | — |
| NXDOMAIN → internal proxy | Step 1.5 + Burp Intruder on Host header | Public writeup, 2026 |
| Per-verb IDOR (GET/PUT/**DELETE**) | Burp Repeater + Arjun | Public $15K IDOR writeup, 2026 |

---

## Related

- [[Tool - Arsenal Index]] — full tool inventory
- [[Playbook - Recon Methodology]] — six-phase manual recon commands
- [[Playbook - API Attack Surface]] — detailed API attack-surface manual
- [[Pattern - Git Exposure]] — the three-tool `.git` recovery pipeline
- [[Pattern - Source Map Exposure]] — when it's actually worth reporting
- [[Lessons Learned]] — full lesson index
- [[Skill - triage-validation]] — the 7-Question Gate
- [[External Writeups - 2026 Collection]] — source summaries for the NXDOMAIN SSRF case, the $15K IDOR writeup, and the minimalist-stack methodology writeup
