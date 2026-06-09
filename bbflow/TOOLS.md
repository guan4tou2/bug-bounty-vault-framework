# bbflow Toolchain — Tool List

> **Reference inventory only.** This catalogs the tools that *implement* the flow
> defined in this framework. The runnable implementation (scripts, payloads,
> matchers) lives in the standalone repo
> **[`guan4tou2/bbflow`](https://github.com/guan4tou2/bbflow)** — a zero-LLM
> `bash + curl + python3` CLI (BBOT/Osmedeus recon + pattern hunters). This file
> lists *what exists and what each does*, not *how* — no payloads, no evasion.
>
> History note: bbflow began as local `tools/` (`bbflow.sh` + `hunters/`) inside
> the workspace, then was split into its own public repo (2026-04). This
> `bbflow/` spec directory is the later architecture-only abstraction.

## Runtime entry points
| Script | Role |
|--------|------|
| `bbflow.sh` | single-target hunt orchestrator |
| `auto_hunt.sh` / `batch_hunt.sh` | autonomous / batch over a target list |
| `bbflow-docker.sh` + `Dockerfile` | zero-local-dependency container runtime |
| `bin/bbot`, `bbot_preset_bugbounty.yml` | BBOT recon integration |
| `nuclei-templates/bb-recon/` | custom Nuclei templates included by `hunt-nuclei-deep.sh` |

## Pattern hunters (`hunters/hunt-*.sh`) — by category

### Recon / discovery
- `hunt-portscan` — fast port scan + service detection
- `hunt-subdomain-prefix` — active prefix subdomain scan
- `hunt-subdomain-takeover` — dangling-CNAME takeover candidates
- `hunt-nxdomain-corpus` — historical hostname superset → dangling filter
- `hunt-wayback-endpoints` — Wayback CDX endpoint mining
- `hunt-shodan-ip` — Shodan InternetDB passive port/CVE lookup
- `hunt-crawl-chain` — URL/param discovery + fuzzing chain
- `hunt-ffuf-dirs` / `hunt-param-fuzz` / `hunt-arjun-params` — directory / param discovery
- `hunt-swagger` — Swagger / OpenAPI spec discovery

### Exposure / config & source leak
- `hunt-actuator-deep` — Spring Boot Actuator deep surface
- `hunt-config-leak` — config-file leak scan
- `hunt-backup-files` — backup / old-version file exposure
- `hunt-git-exposure` / `hunt-git-deep` — `.git` exposure + object extraction
- `hunt-devops-unauth` — unauthenticated DevOps/infra endpoints
- `hunt-gitlab-anon` — GitLab anonymous fingerprint + open signup
- `hunt-envdata` — `window.envData` / `__INITIAL_STATE__` extraction
- `hunt-version-json` — version/env mapping JSON leak
- `hunt-vite-spa-json-config` — Vite/Vue/React SPA env config JSON leak
- `hunt-sourcemap-secrets` / `hunt-sourcemap-endpoint-family` — source-map → secrets / API families

### Secrets
- `hunt-hardcoded-js-secrets` — hardcoded secrets in live JS bundles
- `hunt-trufflehog-secrets` — deep git secret scan
- `hunt-google-api-key` — Google API key validation
- `hunt-sms-static-cred` — SMS gateway static credentials

### Auth / access control
- `hunt-cors-reflect` — reflective CORS / null-origin / regex-prefix
- `hunt-jwt` — JWT decode + weakness probe
- `hunt-open-redirect` — open redirect + OAuth-chain candidates
- `hunt-user-enum` — login/signup/reset account enumeration
- `hunt-weak-login` / `hunt-monitor-bypass` — default-cred / admin-panel auth bypass
- `hunt-cert-bypass` — SSO `/cert` passwordless token issuance
- `hunt-mcp-oauth-scope` — MCP OAuth scope / consent mismatch

### Injection / DAST
- `hunt-dalfox-xss` — XSS (gf → dalfox, blind + DOM)
- `hunt-graphql-idor` — unauth GraphQL resolver + integer IDOR
- `hunt-ssrf-oracle-probe` — blind-SSRF → impact oracle
- `hunt-nuclei-deep` — extended nuclei surface (per-category tags + `bb-recon/` templates)
- `hunt-waf-bypass` — WAF/firewall bypass testing

### Vendor / stack-specific
- `hunt-hybris-occ` — SAP Hybris OCC / Commerce Cloud
- `hunt-mail2000-pre-cmd` — Openfind Mail2000 CGI pre_cmd/job
- `hunt-zpush-version` — Z-Push version fingerprint + CVE-2025-8264 precheck
- `hunt-electron-open-external` — Electron `shell.openExternal` static triage

### OSINT / breach corpus
- `hunt-cloud-bucket` — cloud bucket enumeration
- `hunt-email-security` — SPF/DMARC/DKIM/BIMI/MTA-STS audit
- `hunt-hudson-rock` — HudsonRock breach-corpus lookup

## Integration points
- **Hermes (VPS agent)** wraps bbflow via `bbflow_tool.py` (`bbflow-runner` agent runs hunters, parses hits, updates RECON_DB). The Hermes layer is a *separate* repo (`tools/bb_tools.py`); see the vault `reference_bbflow_vs_framework_vs_bbtools` note.
- **Vault** consumes only machine-readable output (`run_manifest.json`, `candidates.jsonl`) after a run — never the reverse (see `output-contract.md`).
