---
type: pattern
title: Pattern - Docker Hub Config.Env Exfil via crane (no pull needed)
tags: [pattern, cwe-522, cwe-312, docker, supply-chain, credential-exfil, bb-pattern]
status: verified
first_seen: 2026-04-24
severity: P5 today (stale) → P1 (live infra)
---

# Pattern - Docker Hub Config.Env Exfil via `crane` (no image pull)

## TL;DR

Public Docker images — even from anonymous / accidental publishers — often embed credentials in the **image config `Env` array** that can be read via **`crane config <image>` without downloading any layer** (typically ~2 KB HTTP GET to registry manifest + config endpoints). This bypasses the common assumption that "secret scanning requires `docker pull` + filesystem traversal."

**Impact class**:
- **P1 if infrastructure is live**: full admin access via leaked DB / Hasura / AWS / Azure credentials
- **P5 today if infra dead**: still reveals password patterns / naming conventions / historical secrets for static-audit context

## Root cause

Docker image metadata has two related fields:

1. **Image config `Env`**: `["FOO=bar", "DB_URL=..."]` — injected at build time via `ENV` instruction or `--env` flag at `docker commit`. **Persists in the registry manifest**, readable without downloading layers.
2. **Image layers**: filesystem diffs. Require full `docker pull` to traverse.

Developers pushing "working builds" (usually contractors committing a running container from their dev VM) capture the runtime environment variables **into the image config**. These env vars frequently include:

- Database connection strings (`postgres://user:pass@host:port/db`)
- Hasura / GraphQL admin secrets
- AWS access keys, GCP service accounts, Azure SAS tokens
- JWT signing secrets
- Webhook URLs / internal API endpoints

## Detection (no pull required)

```bash
# Install crane (Google Container Tools)
brew install crane
# or: go install github.com/google/go-containerregistry/cmd/crane@latest

# Dump image config (includes Env array)
crane config <org>/<image> | jq '.config.Env'

# Dump history (Dockerfile-ish commands leaking inline secrets)
crane config <org>/<image> | jq '.history[] | {created_by, comment}'

# Manifest + layer digests (size filter)
crane manifest <org>/<image>
```

Total bandwidth: ~10 KB. Total time: < 5 sec. No disk space needed. No Docker daemon required.

## Mass-scanning approach

```bash
# Search Docker Hub for target-related images
curl -s "https://hub.docker.com/v2/search/repositories/?query=<target>&page_size=100" \
  | jq -r '.results[].repo_name' > images.txt

# Batch-extract configs
while read img; do
    echo "=== $img ==="
    crane config "$img" 2>/dev/null | jq -c '.config.Env // empty'
done < images.txt | grep -E 'PASSWORD|SECRET|KEY|TOKEN|URL.*://.*:.+@' > hits.txt
```

## Search-term strategies for bug bounty

1. **Target org name**: `<vendor>`, `<vendor>docker`, `<vendor>_`, `<vendor>-`
2. **Product slug**: `acme-app`, `vendor-sms`, `vendor-chat`
3. **Common middleware**: `<vendor>_hasura_image`, `<vendor>-wordpress`, `<vendor>-backend`, `<vendor>-api`
4. **Contractor usernames**: LinkedIn → DockerHub username cross-ref
5. **Accidental terms**: `staging`, `test`, `dev`, `backup`, `private` in image tag

## Attribution rules

- **Anonymous publisher ≠ illegitimate**. Contractor side-accounts are a common source of leaks.
- Confirm vendor-vs-squatter by content:
  - Hostname references (`acme-hasura-server`)
  - Database names (`acme_production`)
  - Docker-compose labels / ownership tags
  - Vendor-specific password patterns
- If publisher has 1 image + anonymous profile + matches target internal naming → high confidence contractor leak.

## Remediation (vendor-side)

1. **Take down the image** via Docker Hub DMCA / namespace claim
2. **Rotate all leaked credentials immediately** even if infra appears dead (check for forks / mirrors / archive.org snapshots)
3. **Audit password convention** — if pattern is `{VendorName}_{digits}`, search internal source for static references
4. **Contractor / HR audit** — who pushed this? Are there more accidentally-public assets?
5. **Pre-commit hook** for `docker commit` workflows: strip `Env` of any `*SECRET*|*PASSWORD*|*KEY*|*TOKEN*` entries before push

## Remediation (researcher-side / ethical)

- **Stop at "credential identified"**. Do NOT use leaked credential to probe live services.
- Redact in report: first-4 + last-4 chars only (`Vendo...1234` or `AKIA...xxxx`)
- Private disclosure to vendor first; Docker takedown coordinated via vendor
- If DB/service is confirmed DEAD (NXDOMAIN / Shodan 0-hit), severity drops to P5 informational — note this explicitly in the report to prevent triager over-scoring

## Case studies

### Example Vendor `contractor123/acme-app_hasura_image` (generic)

- Anonymous Docker Hub publisher (1 repo, no bio)
- Image pushed years ago (~100 pulls)
- `crane config` dumps:
  ```
  PG_DATABASE_URL=postgres://postgres:REDACTED@db.example.com:5432/acme_app
  HASURA_GRAPHQL_ADMIN_SECRET=REDACTED
  ```
- Azure Postgres FQDN NXDOMAIN today → **P5/P4 today** (infra dead)
- Would have been **P1 when live**: unauthenticated full Hasura admin console + DB RW
- **Operational intel**: `Vendor_{digits}` password pattern is likely vendor password convention → **static source-code audit only**, do NOT probe live with guessed variants

Finding: [[Target - Example Vendor]] ACME-001.

## Pre-submit checklist

- [ ] Image confirmed to belong to target org (hostname/DB/namespace reference)
- [ ] Credentials identified via `crane config` only (no full pull unless necessary)
- [ ] Secrets redacted in deliverable (first-4 + last-4)
- [ ] Live-status check done (resolve hostname, Shodan lookup) — informs severity
- [ ] Password pattern extracted (without live probe)
- [ ] Disclosure channel: private vendor first, then Docker Hub takedown

## Related

- [[Pattern - Hardcoded Credentials]]
- [[Pattern - Supply Chain Analysis]]
- [[Tool - Arsenal Index]] — crane is part of Phase 1 secret-scanning
- [[Target - Example Vendor]] — primary case study (ACME-001)
- [[Lessons Learned]] — 2026-04-24 Docker Hub exfil lesson
