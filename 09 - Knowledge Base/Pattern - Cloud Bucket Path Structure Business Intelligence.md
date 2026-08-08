---
type: pattern
title: Pattern - Cloud Bucket Path Structure Business Intelligence
tags: [pattern, cwe-200, gcs, s3, bucket, information-disclosure, business-intelligence, osint, bb-pattern]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
severity: P3 Medium (info disclosure) / P2 if PII or secrets in objects
precedents: vendor-chat (GCS context-pro/sat/dev listing reveals enterprise clients via OSS/Brand/{brand}/)
---

# Pattern - Cloud Bucket Path Structure Business Intelligence

## TL;DR

Publicly listable cloud storage buckets (GCS/S3/Azure Blob) often organize files in hierarchical paths that **reveal business relationships, internal environments, and client identities** — even when the file contents themselves aren't sensitive.

## What path structures reveal

### Client/partner enumeration

```
gs://company-assets/
  ├── OSS/Brand/ClientA/logo.png
  ├── OSS/Brand/ClientB/banner.jpg
  └── OSS/Brand/ClientC/icon.svg
```

**Impact**: Directory listing reveals all enterprise clients. Competitors can map the vendor's customer base. Combined with member enumeration (e.g., API oracle), confirms which organizations use the service.

### Environment enumeration

```
gs://company-context-pro/     ← Production
gs://company-context-sat/     ← Staging (SAT)
gs://company-context-dev/     ← Development
```

**Impact**: Naming convention reveals environment structure. Dev/staging buckets often have weaker ACLs or contain debug data.

### Internal project codenames

```
s3://company-releases/
  ├── phoenix/v2.3.1/
  ├── hydra/v1.0.0-beta/
  └── titan/nightly/
```

**Impact**: Codenames map to unreleased products or internal initiatives.

## Detection

### GCS (Google Cloud Storage)

```bash
# List bucket contents (if publicly listable)
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o?maxResults=100" | jq '.items[].name'

# Try common bucket naming patterns
for env in pro sat dev staging prod test uat; do
  curl -sI "https://storage.googleapis.com/storage/v1/b/COMPANY-context-${env}/o" \
    | head -1
done

# gsutil (if installed)
gsutil ls gs://BUCKET_NAME/
```

### S3 (AWS)

```bash
# List objects
aws s3 ls s3://BUCKET_NAME/ --no-sign-request 2>/dev/null

# Try region-specific URLs
curl -s "https://BUCKET_NAME.s3.amazonaws.com/?list-type=2&max-keys=100" | xmllint --format -
```

### Azure Blob

```bash
# List containers
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```

## Extraction methodology

### Step 1: Enumerate bucket names

```bash
# From DNS/subdomain enumeration
# From JavaScript source (API endpoints, CDN references)
# From mobile app traffic (proxy capture)
grep -oP 'storage\.googleapis\.com/[a-zA-Z0-9._-]+' js_bundle.js
grep -oP 's3\.amazonaws\.com/[a-zA-Z0-9._-]+' js_bundle.js
```

### Step 2: Map path hierarchy

```bash
# Get full path listing
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o?maxResults=1000" \
  | jq -r '.items[].name' | sort > paths.txt

# Extract top-level directories
cut -d'/' -f1 paths.txt | sort -u

# Extract second-level (often client/brand names)
cut -d'/' -f1-2 paths.txt | sort -u
```

### Step 3: Classify intelligence

| Path pattern | Intelligence type |
|-------------|-------------------|
| `Brand/{name}/` or `Client/{name}/` | Enterprise client list |
| `pro/` `sat/` `dev/` `uat/` | Environment structure |
| `v{X.Y.Z}/` or `build-{N}/` | Release cadence |
| `{codename}/` | Internal project names |
| `backup/` `export/` `dump/` | Potential sensitive data |
| `config/` `env/` `.env` | Secrets (escalate severity) |
| `CA/` `certs/` `*.pem` `*.zip` | TLS cert CN → customer identity |

## Severity assessment

| What's exposed | Severity |
|---------------|----------|
| Path structure only (no file access) | **P4 Info** |
| Client/partner names via path listing | **P3 Medium** |
| Environment names + accessible dev/staging data | **P3** |
| PII in file contents (user data, exports) | **P2 High** |
| Secrets in files (API keys, credentials) | **P1-P2** |
| Source code or database backups | **P1 Critical** |

## Real-world example

- **Buckets found**: `context-pro`, `context-sat`, `context-dev` (3 environments)
- **Path pattern**: `OSS/Brand/{brand_name}/` — listed enterprise client logos
- **Intelligence**: Revealed which government agencies and corporations use the vendor's IM service
- **CA directory extension**: `OSS/CA/vendor-chat/pix/` contained 49 TLS certificate ZIPs; cert CNs revealed enterprise customer domains
- **Combined with member enumeration**: API confirmed individual users within those organizations
- **Combined with Android NSC**: `network_security_config.xml` customer domains cross-validated bucket discovery (see [[Pattern - Android Config Files Business Intelligence]])
- **Impact**: Competitor could map the vendor's entire enterprise customer base; targeted phishing against confirmed users

## Report framing tips

1. **Don't just say "bucket is public"** — explain what the path structure reveals
2. **Quantify**: "listing reveals N enterprise client names" is stronger than "information disclosure"
3. **Chain with other findings**: Bucket listing + member enumeration = confirmed user targeting
4. **Include business impact**: "competitors can enumerate customer base" resonates with business stakeholders

## Remediation

1. Set bucket ACL to private (remove `allUsers` / `allAuthenticatedUsers`)
2. Use signed URLs for authorized access
3. If listing must be public, flatten path structure (UUIDs instead of client names)
4. Separate environments into different projects/accounts with independent IAM
