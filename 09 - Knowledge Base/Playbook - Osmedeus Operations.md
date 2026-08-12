---
type: playbook
title: "Osmedeus Operations"
tags: [playbook, recon, osmedeus, automation, vps, bb-playbook]
category: recon
status: draft
last_updated: 2026-08-12
---

# Playbook - Osmedeus Operations

> **TL;DR**: A single reference for day-to-day Osmedeus usage — from first-time VPS setup, through API key configuration and workflow selection, to the post-run analysis pipeline. Osmedeus is a recon **pipeline**, not a one-shot "run it and you're done" tool: it orchestrates a chain of passive/active recon modules (subfinder, httpx, nuclei, etc.) and dumps results into a consistent workspace layout, freeing your time from repetitive commands so you can focus on manual deep-diving.

## Scope / When to use

Use this playbook whenever you are operating Osmedeus (v5.x) on a remote VPS for bug bounty reconnaissance — first-time install and health check, per-target workflow selection, API key tuning to raise passive-recon coverage, post-run triage of the output workspace, or program-scope compliance checks before running any active/aggressive module (nuclei, directory brute-force, DNS brute-force).

Osmedeus does three things:
1. **Workflow orchestration** — YAML-defined flows (`domain-lite` / a custom "safe" flow / `domain-standard` / `domain-extensive` / etc.) chain together a series of modules.
2. **Module execution** — each module wraps a shell command that calls into `external-binaries/*` (subfinder, httpx, nuclei, …).
3. **Result storage** — a consistent `~/workspaces-osmedeus/<target>/{subdomain,probing,fingerprint,archive,ipspace,vulnscan,screenshots}/` layout.

## Phases

### Phase 1: VPS Setup (first time only)

Core install steps (adapt paths/versions as needed — check the [official Osmedeus releases page](https://github.com/j3ssie/osmedeus/releases) for the current version, since the upstream `install.sh` has been known to break):

```bash
# 1. Download the binary release (verify current version first — official install.sh may be stale)
wget https://github.com/j3ssie/osmedeus/releases/download/v5.0.2/osmedeus_5.0.2_linux_amd64.tar.gz
tar -xzf osmedeus_5.0.2_linux_amd64.tar.gz
sudo install -m 755 osmedeus/osmedeus /usr/local/bin/osmedeus

# 2. First health check auto-downloads ~24 security binaries to ~/osmedeus-base/external-binaries/
osmedeus health

# 3. Add a system-wide PATH entry (a non-interactive SSH session won't source ~/.bashrc)
sudo tee /etc/profile.d/bbtools.sh > /dev/null <<'EOF'
export PATH="$PATH:$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/osmedeus-base/external-binaries"
EOF
sudo chmod +x /etc/profile.d/bbtools.sh
```

### Phase 2: API key configuration (large boost to passive-recon coverage)

**Default empty config** → subfinder falls back to key-free public sources only (crt.sh, hackertarget, anubis-db, …). Subdomain counts are typically only about a third of what's achievable with keys configured.

Free-tier keys worth grabbing, roughly in priority order:

| Key | Where to get it | Why it matters |
|-----|-----------------|-----------------|
| **GITHUB_TOKEN** | https://github.com/settings/tokens (select the `public_repo` scope) | 10x speedup for github-subdomains / github-search |
| **CHAOS_API_KEY** | https://chaos.projectdiscovery.io/ (Google sign-in) | ProjectDiscovery's own dataset — strongest signal for PD tools |
| **VIRUSTOTAL_API** | https://www.virustotal.com/gui/my-apikey | Free, 500 req/day |
| **SECURITYTRAILS_API** | https://securitytrails.com/app/account/credentials | Free, 50 req/month, but high quality |
| **BEVIGIL_API** | https://bevigil.com/ | Free, 100 req/month — mobile-APK-crawled data (niche) |
| **SHODAN_API** | https://account.shodan.io/ | Paid, but researchers often already have one |
| **LEAKIX_API** | https://leakix.net/ | Free, focused on exposed/leaked assets |
| **NETLAS_API** | https://netlas.io/ | Free tier, roughly Censys-equivalent |

Configuration flow — set the relevant environment variables and run your key-provisioning step (either a small wrapper script or a direct edit of the config file below):

```bash
# On the VPS — set everything at once via a wrapper (example name; write your own or edit the YAML directly):
GITHUB_TOKEN=ghp_xxx \
CHAOS_API_KEY=xxx-xxx \
VIRUSTOTAL_API=xxx \
SECURITYTRAILS_API=xxx \
automation/osm-apikeys.sh

# Or update a single key at a time (unset keys keep their existing value):
GITHUB_TOKEN=ghp_xxx automation/osm-apikeys.sh
```

This should update `~/osmedeus-base/external-configs/subfinder-provider-config.yaml` — you can also edit that file directly if you don't want to maintain a wrapper script.

**Verify the change took effect:**

```bash
# Run the same target before/after and compare subdomain counts
osmedeus run -f domain-lite -t example.com
wc -l ~/workspaces-osmedeus/example.com/subdomain/subdomain-example.com.txt
```

Typical results: without API keys, ~30-180 subdomains; with API keys, ~200-2000 subdomains.

### Phase 3: Workflow selection

Available flows (list them with `osmedeus workflow`):

| Flow | # Modules | Time | When to use |
|------|-----------|------|--------------|
| `fast` | 3 | ~2 min | Not recommended — functionally identical to `domain-lite` |
| **`domain-lite`** | 3 | ~2 min | First quick look at a target (safe for any program) |
| **A custom "safe" flow** (see Phase 8) | 7 | ~20 min | Adds archive + screenshots + IP-space enumeration, but **no** nuclei/brute-force |
| `domain-standard` | 9 | ~30-60 min | Adds nuclei vuln scanning + content fuzzing — violates most program rules; only run when explicitly permitted |
| `domain-extensive` | 9 | ~60-120 min | Adds DNS brute-force — very noisy, only for targets you're hunting exhaustively |
| `url` / `web-analysis` | 4 | ~10 min | Fingerprint + spider + scan a single URL |
| `cidr` | 4 | ~30 min | Recon over an IP/CIDR range |
| `sast` / `repo` | 1 | varies | SAST against a git repo |

### Phase 4: Post-run analysis pipeline

Workspace layout:

```
~/workspaces-osmedeus/<target>/
├── subdomain/subdomain-<target>.txt           ← merged subdomains (feeds takeover checks / further exploration)
├── probing/
│   ├── http-<target>.txt                       ← live HTTP hosts (with URL scheme)
│   └── dns-<target>.txt                        ← full DNS records
├── fingerprint/
│   ├── http-fingerprint-<target>.jsonl         ← full fingerprint data
│   ├── http-interesting-<target>.jsonl         ← "interesting" subset (200/401/500 etc.)
│   └── http-interesting-filtered-<target>.md   ← primary deep-dive starting point
├── archive/archive-urls-<target>.txt           ← Wayback / CommonCrawl historical URLs
├── ipspace/non-cdn-ip-<target>.txt             ← direct-connect IPs with CDN filtered out
├── screenshots/<target>-screenshots/*.png
├── vulnscan/nuclei-jsonl-<target>.txt          ← present only if a vulnscan-class flow ran
└── run-execution.log
```

The 3 files worth checking after every run:

1. **`fingerprint/http-interesting-filtered-*.md`** — hosts returning 200 / 401 / 500 / 503 (i.e., not the boring 301/302/403/404 crowd)
2. **`archive/archive-interesting-urls-*.txt`** — historical URLs; a frequent source of forgotten staging/dev subdomains
3. **`ipspace/non-cdn-ip-*.txt`** — direct-to-backend IPs, the starting point for origin-direct testing that bypasses a CDN/WAF in front

Pulling results back locally and feeding them into further tooling:

```bash
# Sync the full workspace from the VPS to local storage
automation/vps-fetch.sh example.com   # -> workshop/example.com/osmedeus/example.com/

# Feed discovered subdomains into your hunters
cp workshop/example.com/osmedeus/example.com/subdomain/*.txt workshop/example.com/subs.txt
bbflow hunt example.com --only cors,graphql,envdata

# Feed interesting hosts into a crawler
head -20 workshop/example.com/osmedeus/example.com/fingerprint/http-interesting-*.txt | \
  while read url; do automation/vps-crawl.sh "$url"; done
```

Mass-subdomain subdomain-takeover scanning:

```bash
# On the VPS, run subjack + nuclei takeover templates against the subdomain list
automation/vps-takeover.sh example.com

# Results land in ~/workspaces-osmedeus/example.com/takeover/{subjack.txt,nuclei.txt}
```

### Phase 5: Program-rules compliance (important)

Which Osmedeus modules are "runnable" vs. "not runnable":

| Module | Type | Typically program-safe? |
|--------|------|--------------------------|
| enum-subdomain (subfinder/findomain/assetfinder) | Passive | Yes — pure DNS/cert/search-index collection |
| probe-dns | Passive | Yes |
| probe-port-fp | Semi-active | Yes — scans only the default HTTP port(s) |
| probe-port (full range) | Active | Caution — violates most anti-DDoS/rate-limit rules |
| recon-http-fp | Active | Yes — one GET per host |
| recon-screenshot | Active | Yes |
| util-archive (Wayback/CommonCrawl) | Passive | Yes |
| recon-spider (katana) | Active | Caution — depth 3+ can violate "no mass crawling" rules |
| scan-content (ffuf directory brute-force) | Strongly active | No — prohibited by most programs |
| **scan-vuln (nuclei, ~14k templates)** | Strongly active | No — prohibited by most programs unless explicitly permitted or the bounty justifies asking first |
| enum-subdomain with **DNS brute-force** | Strongly active | No — violates most "no brute-force" rules |

**Adding a required header (e.g. `X-Bug-Bounty`).** Some programs require a custom header or user-agent identifying you as a bug bounty researcher. Osmedeus's nuclei invocation only sends its own default user-agent by default. Two options:

- **Environment variable**: for tools that support it in your hunting layer (e.g. a `nuclei`/`xss`/`jaeles` subcommand), setting a variable like `H1USER=myusername` before the call can auto-inject the header.
- **Avoid the aggressive flow entirely**: use the safe/standard flow (no nuclei) instead of a vulnscan-class flow.

**Stopping a running scan early**, if you discover mid-run that it violates program rules:

```bash
ssh remote-vps 'pkill -f "osmedeus run"; pkill -f nuclei; pkill -f ffuf'
```

### Phase 6: Common command reference

```bash
# Day 0
automation/vps-tools-check.sh            # verify ~30 tools are installed and on PATH
ssh remote-vps                           # interactive SSH to the VPS
automation/osm-apikeys.sh                # set API keys (run on the VPS)

# Daily recon
automation/vps-recon.sh lite <domain>       # 2 min, domain-lite
automation/vps-recon.sh standard <domain>   # 20 min, "safe" flow
automation/vps-recon.sh status <domain>     # workspace stats
automation/vps-recon.sh fetch <domain>      # rsync workspace -> local

# Follow-up deep-diving
automation/vps-recon.sh crawl <url>         # hakrawler + gau + uro
automation/vps-recon.sh params <url>        # x8 hidden-parameter discovery
H1USER=x automation/vps-recon.sh xss <url>       # dalfox
H1USER=x automation/vps-recon.sh jaeles <url>    # jaeles signature scan
automation/vps-recon.sh takeover <domain>   # subjack + nuclei takeover templates

# Quick utility scans
automation/vps-recon.sh secrets <git-url>   # trufflehog
automation/vps-recon.sh s3 <bucket>         # s3scanner
automation/vps-recon.sh dork <domain>       # pagodo

# VPS housekeeping
automation/vps-recon.sh clean <domain>      # delete workspace
ssh remote-vps 'osmedeus health'            # verify config
ssh remote-vps 'osmedeus workflow'          # list workflows
```

> The `automation/vps-*.sh` names above are illustrative wrapper scripts — Osmedeus itself has no such commands. Write your own thin wrappers around `osmedeus run -f <flow> -t <target>` plus `rsync`/`scp` for fetch, or run the underlying `osmedeus`/tool commands directly over SSH.

### Phase 7: Troubleshooting

**subfinder finishes fast but returns very few subdomains**
→ API keys are empty. Run your key-provisioning step and add at least GitHub + Chaos + VirusTotal.

**Run crashes partway through with a Go stack trace**
→ 99% of the time this is a target-type mismatch — usually caused by accidentally piping a multi-line bash heredoc's trailing content in as a second target argument. A single-line `osmedeus run -f <flow> -t <target>` avoids this.

**nuclei is running but the program prohibits brute-force / aggressive scanning**
1. `ssh remote-vps 'pkill -f nuclei'` immediately.
2. Switch to the safe/standard flow (no nuclei) instead of a vulnscan-class flow going forward.

**Workspace already exists and re-running errors out**
→ Clean it first: `automation/vps-recon.sh clean <target>` or manually `ssh remote-vps 'rm -rf ~/workspaces-osmedeus/<target>'`.

**Wrapper commands return "command not found" on the VPS**
→ The SSH session is non-interactive and never sourced `/etc/profile.d/bbtools.sh`. Use `ssh -t remote-vps 'bash -l -c "<command> ..."'`, or route through a local wrapper script that already handles this.

### Phase 8: Custom workflow authoring

Where to edit: `~/osmedeus-base/workflows/*.yaml`. Schema:

```yaml
kind: flow
name: my-custom-flow
description: "..."
modules:
  - name: enum-subdomain
    path: common/enum-subdomain.yaml
  - name: recon-http-fp
    path: common/recon-http-fp.yaml
    depends_on: [enum-subdomain]
```

Modules live under `common/*.yaml` and each one calls into a binary under `external-binaries/`.

Deploying a custom flow to the VPS:

```bash
scp my-flow.yaml remote-vps:~/osmedeus-base/workflows/my-flow.yaml
ssh remote-vps 'osmedeus health'   # validates the YAML is well-formed
osmedeus run -f my-flow -t example.com
```

A concrete example worth building for yourself is a "safe" 7-module flow (subdomain enum + probing + fingerprinting + archive + screenshots + IP-space enumeration, deliberately excluding nuclei/brute-force) that you can default to for any new, unvetted program.

## Decision Points

**Which flow to run, given where you are with a target:**

```
First contact with a new target?          -> domain-lite   (2 min, get an infra overview)
                                              -> fetch results
                                              -> manually review fingerprint/http-interesting-*.md
                                                 and pick high-value in-scope subdomains

Found a promising subdomain to dig into?  -> your "safe" 7-module flow (20 min, adds archive + IP-space)
                                              -> fetch results
                                              -> manual source-map probing + API reverse-engineering

Program explicitly allows brute-force
and the bounty justifies it?              -> vulnscan-class flow (H1USER=x for required headers)
                                              -> full nuclei run (~14k templates)

Narrow focus on a single URL?             -> the `url`/`web-analysis` flow against that one endpoint
```

**Module-safety decision**: before running anything beyond passive enumeration and single-GET fingerprinting, check the module against the Phase 5 table and the program's scope/rules page — when in doubt, treat a module as "not runnable" until the program explicitly allows it.

## Expected Outputs

- A per-target workspace under `~/workspaces-osmedeus/<target>/` containing merged subdomains, live-host probing results, HTTP fingerprints (including a curated "interesting" subset), archived historical URLs, non-CDN direct IPs, screenshots, and (if a vulnscan-class flow ran) nuclei results.
- A short list of high-value leads for manual follow-up: interesting hosts, historical/forgotten URLs, and direct-connect IPs for CDN-bypass testing.
- (Optional) a subdomain-takeover scan output (`subjack`/`nuclei` results) when a mass-subdomain list is available.
- A locally-synced copy of the workspace, ready to feed into further hunting tools (parameter discovery, crawling, XSS scanning, etc.).

## Related

- [[Playbook - Recon Methodology]] — the broader multi-phase recon pipeline this fits into
- [[Playbook - Structured Recon Flow (Step 0-4)]] — where an Osmedeus run slots into a staged recon workflow
- [[Tool - Cloud and DNS Recon Toolkit]] — complementary passive-recon tooling
- `wiki/00-bbflow-complete-flow.md` — a CLI recon/hunt pipeline that can optionally delegate to Osmedeus on a VPS via an `--osmedeus` flag
