---
type: wiki
category: attack
tool: cloud
status: active
last-updated: 2026-04-21
---

# Cloud Key / Credential Abuse

> **Purpose:** How to verify "what can it do" + "how severe is it" for cloud keys found in frontend JS, source maps, or `.git` history.
> Principle: **verification ≠ abuse**. Only do read-only / list / describe — never create/delete/modify actual resources.

## ⚠️ Safety Principles (mandatory)

1. ✅ Allowed: `list`, `describe`, `get` — read-only only
2. ❌ Forbidden: `create`, `delete`, `update`, `modify`, `put` — touches real data
3. ✅ Allowed: testing under your own account (spin up a separate test account)
4. ❌ Forbidden: using the victim's key to pay for services (burns their money)
5. Attach to the report: output of `sts get-caller-identity` or equivalent + list results (redact sensitive names)

---

## 1. AWS

### 1.1 Detecting Access Key IDs

```bash
# Format: AKIAxxxxxxxxxxxxxxxx (20 chars)
# Or ASIA (session), AGPA (group), AIDA (user), AROA (role)

# Prefix reference
echo "AKIAIOSFODNN7EXAMPLE" | cut -c1-4
# AKIA = long-term Access Key
# ASIA = temporary (comes with a session token, standalone AKID is useless)
# AIDA = User ID (not a key, don't confuse it)
# AROA = Role ID
```

### 1.2 Basic verification (when there's no secret)

```bash
# Only an Access Key ID with no Secret → almost useless, except:
# 1. Identifying the account (detects Account ID)
aws sts get-access-key-info --access-key-id AKIAxxxxxxxxxxxx
# → returns Account ID (even if the key has been rotated)
# Reportable as: P5 Info disclosure (account ID leak)
```

### 1.3 Verification when you have the secret

```bash
# Configure a new profile (don't pollute the default)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
# (session keys need one more)
export AWS_SESSION_TOKEN=...

# Step 1: caller identity
aws sts get-caller-identity
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/ci-deploy"
# }

# Step 2: check permissions (list attached policies)
aws iam list-attached-user-policies --user-name ci-deploy
aws iam list-user-policies --user-name ci-deploy
aws iam list-attached-role-policies --role-name rolename
```

### 1.4 Automated permission enumeration (enumerate-iam)

```bash
# https://github.com/andresriancho/enumerate-iam
git clone https://github.com/andresriancho/enumerate-iam
cd enumerate-iam && pip3 install -r requirements.txt

python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key ... \
  --region us-east-1
# → automatically brute-tests 100+ APIs and lists allowed actions
```

### 1.5 CloudFox (strongest recon tool)

```bash
# https://github.com/BishopFox/cloudfox
go install github.com/BishopFox/cloudfox@latest

# Full check suite
cloudfox aws all-checks --profile target_key

# Find secrets / keys embedded in cloud resources
cloudfox aws secrets --profile target_key

# S3 enumeration
cloudfox aws buckets --profile target_key

# RDS / EC2 / Lambda
cloudfox aws instances --profile target_key
cloudfox aws lambdas --profile target_key
```

### 1.6 S3 abuse (common)

```bash
# Detect public buckets
aws s3 ls s3://bucket-name/ --no-sign-request

# List using the key
aws s3 ls s3://bucket-name/ --profile target_key

# Download (read-only, legitimate)
aws s3 cp s3://bucket-name/file.txt . --profile target_key

# Recursive listing (for severity assessment)
aws s3 ls s3://bucket-name/ --recursive --profile target_key | head -100

# ⚠️ Do NOT do: aws s3 cp file s3://... (upload = modification)
# ⚠️ Do NOT do: aws s3 rm s3://... (delete = destruction)
```

### 1.7 List Lambda functions + read env

```bash
# List all functions
aws lambda list-functions --profile target_key

# Read env (often contains secrets)
aws lambda get-function-configuration --function-name FN_NAME --profile target_key
# → check Environment.Variables, often has DB passwords, API keys

# Read code (ZIP download)
aws lambda get-function --function-name FN_NAME --profile target_key
# → returns Code.Location = S3 presigned URL, ZIP can be downloaded
```

### 1.8 IAM privilege escalation

```bash
# Check whether your attached policy allows iam:CreateAccessKey / iam:PassRole
aws iam get-account-authorization-details --profile target_key > full_iam.json

# Use PMapper to automatically analyze privilege escalation paths
# https://github.com/nccgroup/PMapper
pmapper --profile target_key graph create
pmapper --profile target_key visualize
pmapper --profile target_key query "who can do iam:* with *"
```

### 1.9 AWS Location Service verification (geo keys)

```bash
# Commonly found as AWS_LOCATION_API_KEY in web SPAs
curl -s "https://maps.geo.us-east-1.amazonaws.com/maps/v0/maps/MAP_NAME/tiles/0/0/0?key=v1.public.xxx"
# If it returns a tile → confirms the key is valid
# Impact assessment: check the map style pricing (usually $0.50/1000 requests)
```

---

## 2. GCP

### 2.1 Service Account JSON

Found via `.env`, source maps, `.git` history — files like `{"type":"service_account",...}`.

```bash
# Configure
gcloud auth activate-service-account --key-file=sa.json
gcloud config set project $(jq -r .project_id sa.json)

# Verify identity
gcloud auth list
gcloud config list
```

### 2.2 List projects + resources

```bash
# List projects
gcloud projects list

# Permissions
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format='table(bindings.role)' \
  --filter="bindings.members:serviceAccount:NAME"

# Storage bucket
gsutil ls
gsutil ls -r gs://bucket-name/

# Compute
gcloud compute instances list

# Functions
gcloud functions list
gcloud functions describe FN_NAME
```

### 2.3 Firebase / Firestore key

```bash
# Firebase key format: AIzaSy...
# See wiki 21 - gau / 48 - gkey for verification methods

# Firebase Realtime DB (if rules are public)
curl -s "https://PROJECT.firebaseio.com/.json?auth=AIzaSy..."
# returns { ... } → readable

# Firestore (REST)
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/USERS?key=AIzaSy..."
```

### 2.4 Google Maps API key (common)

```bash
# Need to test multiple services to know what the key can do
# See wiki/48-hunter-gkey.md for details (if present)
# Or tools/hunters/hunt-google-api-key.sh AIzaSy...

# Manual testing
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=AIzaSy..."
curl -s "https://vision.googleapis.com/v1/images:annotate?key=AIzaSy..." \
  -d '{"requests":[{"image":{"source":{"imageUri":"https://example.com/x.jpg"}},"features":[{"type":"LABEL_DETECTION"}]}]}'
curl -s "https://translation.googleapis.com/language/translate/v2?key=AIzaSy..." \
  -d '{"q":"hi","target":"zh"}'
```

### 2.5 gcp_enum

```bash
# https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
git clone https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
bash gcp_enum.sh
```

---

## 3. Azure

### 3.1 Service Principal

```bash
az login --service-principal \
  -u APP_ID \
  -p SECRET \
  --tenant TENANT_ID

az account show
az account list-locations
az resource list
az storage account list
az vm list
```

### 3.2 ROADtools (Azure AD specific)

```bash
# https://github.com/dirkjanm/ROADtools
pip3 install roadrecon
roadrecon auth -u USER -p PASS
roadrecon gather
roadrecon gui  # localhost:5000
```

### 3.3 MicroBurst

```bash
# https://github.com/NetSPI/MicroBurst
# PowerShell, Azure recon
Invoke-EnumerateAzureSubDomains -Base target
Invoke-EnumerateAzureBlobs -Base target
```

---

## 4. Other common SaaS keys

### 4.1 Mapbox (pk.eyJ...)

```bash
# Verification: call the tile endpoint directly
curl -s "https://api.mapbox.com/v4/mapbox.streets/0/0/0.png?access_token=pk.eyJ..."
# 200 → key is valid
# Check account limits: api.mapbox.com/tokens/v2?access_token=...
```

### 4.2 Algolia (32 chars long)

```bash
# Needs App ID + API Key
curl -X POST "https://${APP_ID}-dsn.algolia.net/1/indexes/*/queries" \
  -H "X-Algolia-Application-Id: $APP_ID" \
  -H "X-Algolia-API-Key: $KEY" \
  -d '{"requests":[{"indexName":"*","params":"query="}]}'
# If it's an admin key → can list all indexes, modify data → P2
```

### 4.3 SendGrid (SG.xxx.xxx)

```bash
curl -X GET https://api.sendgrid.com/v3/user/account \
  -H "Authorization: Bearer SG.xxx.xxx"
# ⚠️ Don't send any email, only verify existence
```

### 4.4 Twilio (AC... + token)

```bash
curl -X GET https://api.twilio.com/2010-04-01/Accounts/AC..../Balance.json \
  -u AC....:TOKEN
# Only check the balance / subaccounts, don't make calls
```

### 4.5 Stripe (sk_live_... / pk_live_...)

```bash
# Public key pk_live_ = not sensitive (designed to be public)
# Secret key sk_live_ = critical, can charge / refund / read customers / create charges
# Verification
curl https://api.stripe.com/v1/balance -u sk_live_xxx:
# ⚠️ sk_test_ is fine, but if you hit sk_live_ report it, don't call it further
```

### 4.6 Discord / Slack webhook

```bash
# Discord: https://discord.com/api/webhooks/ID/TOKEN
# Verification (GET webhook info is read-only)
curl https://discord.com/api/webhooks/ID/TOKEN
# ⚠️ Don't POST a message

# Slack webhook (https://hooks.slack.com/services/...)
# Verification method: it can only send, so just attach the URL in the report without testing
```

### 4.7 GitHub PAT (ghp_xxx)

```bash
# Verify identity
curl -H "Authorization: token ghp_xxx" https://api.github.com/user

# List repo permissions
curl -H "Authorization: token ghp_xxx" https://api.github.com/user/repos?per_page=1
curl -H "Authorization: token ghp_xxx" https://api.github.com/user/orgs
```

### 4.8 Docker Hub (dckr_pat_xxx)

```bash
curl -H "Authorization: Bearer $TOKEN" https://hub.docker.com/v2/users/USERNAME/
```

### 4.9 Heroku / Netlify / Vercel API

```bash
# Heroku
curl -H "Authorization: Bearer $TOKEN" https://api.heroku.com/account \
  -H "Accept: application/vnd.heroku+json; version=3"

# Netlify
curl -H "Authorization: Bearer $TOKEN" https://api.netlify.com/api/v1/user
```

---

## 5. Automation: nuclei + trufflehog

### 5.1 trufflehog verification (most important)

```bash
# TruffleHog automatically calls the corresponding API to verify key validity
trufflehog filesystem ./source --only-verified

# GitHub
trufflehog github --repo=https://github.com/target/repo --only-verified

# S3 bucket
trufflehog s3 --bucket=target-bucket --only-verified
```

`--only-verified` automatically filters out keys that are already invalid (greatly reduces false positives).

### 5.2 nuclei cloud templates

```bash
nuclei -u https://target.com \
  -t http/exposures/tokens/ \
  -t http/exposures/apis/ \
  -severity high,critical
```

---

## 6. Severity assessment (important)

| Key type | What it can do | Severity |
|---------|---------|-------|
| Public JS key (Google Maps public, Firebase config) | Designed to be public | P5 Info (don't report alone) |
| Google Maps key without restrictions | All Google Cloud APIs | P3-P4 (needs actual verification) |
| AWS AKIA + Secret | Depends on IAM policy (could be full admin) | P1-P2 |
| AWS ASIA (session) | Temporary, <12h | Depends on permissions, P1-P3 |
| GCP service account JSON | Depends on role (editor/viewer/owner) | P1-P2 |
| Azure SP credential | Depends on role assignment | P1-P2 |
| SendGrid full access | Forge emails (phishing / password reset) | P2-P3 |
| Stripe sk_live_ | Payments | P1 |
| GitHub PAT (org admin) | Private repo read/write + source code | P1-P2 |
| Twilio full | Make calls / SMS / eavesdropping | P2 |
| Algolia admin key | Modify index data | P2-P3 |
| Mapbox public | Designed to be public | P5 |
| Mapbox secret | Account management | P2 |

---

## 7. Report template

```markdown
## Vulnerability Summary
https://target.com/static/main.js.map exposes AWS Access Key `AKIAxxx...`,
verified via `aws sts get-caller-identity` to belong to production IAM user `prod-api-worker`,
which has S3 read-write permissions and can read 100+ buckets containing customer PII.

## Discovery Process

### Step 1: Found in source map
curl -s https://target.com/static/main.js.map | \
  jq -r '.sourcesContent[]' | grep -E 'AKIA[A-Z0-9]{16}'
# → AKIAIOSFODNN7EXAMPLE

### Step 2: Verify identity (no abuse)
aws configure --profile poc
# enter the key
aws sts get-caller-identity --profile poc
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/prod-api-worker"
# }

### Step 3: Enumerate permissions
aws iam list-attached-user-policies --user-name prod-api-worker --profile poc
# → AdministratorAccess

### Step 4: Demonstrate impact scope (list-only)
aws s3 ls --profile poc | wc -l
# 127 buckets
aws s3 ls s3://target-customer-data/ --profile poc | head -3
# [filenames redacted]

### Step 5: Immediately notify + disable
[At this point stop listing further data, contact PSIRT instead]

## Impact
- Full AWS account takeover (AdministratorAccess)
- 127 S3 buckets readable/writable
- Contains customer PII (confirmed via file listing)
- Lambda / RDS / EC2 can all be operated on

## Severity
P1 / Critical

## Remediation
1. Immediately rotate AKIAxxx
2. Check CloudTrail usage logs from 2026-04-14 to today
3. Remove the source map or set access restrictions
4. Add trufflehog pre-commit to the build pipeline
```

---

## 8. bbflow integration

```bash
# Find keys in source maps / JS
bbflow hunt target.com --only sourcemap,js-secrets,envdata,trufflehog

# Found AIza* Google key → auto-verify
tools/hunters/hunt-google-api-key.sh AIzaSy...

# For AWS keys, verify manually with enumerate-iam
# For GCP SA JSON, use gcloud
```

---

## Related documents

- [../hunters/hunt-envdata.sh](../hunters/hunt-envdata.sh) — extracts window.envData from JS
- [../hunters/hunt-sourcemap.sh](../hunters/hunt-sourcemap.sh) — mines sourcesContent
- [../hunters/hunt-trufflehog.sh](../hunters/hunt-trufflehog.sh) — scans git history
- [27-tool-trufflehog.md](27-tool-trufflehog.md) — 100+ detectors
- NCC Group Cloud Security Report: https://github.com/nccgroup/ScoutSuite
- SadCloud: https://github.com/nccgroup/sadcloud
