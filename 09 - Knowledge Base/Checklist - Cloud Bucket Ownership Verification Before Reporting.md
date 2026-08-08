---
type: reference
category: Checklist
tags: [checklist, cloud-bucket, s3, gcs, azure-blob, ownership-verification, false-attribution, recon, surface-mapping, submission-gate]
last_updated: 2026-06-04
source: "private-runtime false attribution incident — example-target bucket scan returned LISTABLE buckets actually owned by third-party-one/third-party-two; root cause: LISTABLE confirmation treated as ownership confirmation. Gap confirmed against existing KB: Pattern - Cloud Bucket Path Structure Business Intelligence (covers path-as-BI, not false attribution), Pattern - S3 Bucket Takeover (covers unclaimed bucket, not misattributed live bucket), Lesson #14 (subdomain takeover pre-claim, not bucket ownership). No existing gate required content-based ownership verification."
related_patterns:
  - Pattern - Cloud Bucket Path Structure Business Intelligence
  - Pattern - S3 Bucket Takeover
  - Checklist - Attack Surface Coverage
---

# Checklist — Cloud Bucket Ownership Verification Before Reporting

> **Purpose**: After any LISTABLE or publicly accessible cloud bucket is discovered, this checklist is mandatory before attributing the bucket to the target and before opening a Finding or Submission. LISTABLE status alone is NOT sufficient to attribute a bucket to a target.
>
> **Root cause**: private-runtime automated scanning falsely attributed buckets to example-target (target) because those buckets were LISTABLE and matched subdomain or naming patterns. The actual bucket owners were third-party-one and third-party-two (unrelated third parties). The existing KB patterns (S3 Bucket Takeover, Cloud Bucket Path-as-BI) do not cover this false attribution failure mode.
>
> **Scope**: AWS S3, Google Cloud Storage, Azure Blob Storage, and any CDN-served bucket (CloudFront, Fastly, Akamai origin buckets). Applies to automated scanner output (private-runtime, bbflow, nuclei) and manual recon.
>
> **Time budget**: 5–10 minutes per bucket before opening any Finding.

---

## Stage 0 — Trigger Conditions（何時必須跑此 checklist）

Run this checklist for every bucket discovery that passes any of the following:

- Automated scanner reports a bucket as LISTABLE, public, or misconfigured ACL
- `aws s3 ls s3://<bucket>` returns file listings without authentication
- `curl https://storage.googleapis.com/<bucket>/` returns `<ListBucketResult>`
- Bucket URL appears in subdomain enumeration output (e.g., `<bucket>.s3.amazonaws.com`)
- Bucket is referenced in target's HTML, JS, or API responses

**Do NOT open a Finding or Submission until all Stage 1 and Stage 2 gates pass.**

---

## Stage 1 — Content-Based Ownership Check（必須至少通過一項）

A bucket is attributed to the target only if at least one content-based ownership signal is confirmed. The following gates are ordered by cost (cheapest first).

### Gate 1.1 — File Content References Target Domain or Brand

- [ ] **Sample at least 10 files from the bucket and inspect their content for references to the target's domain, brand name, or product names.**

  Minimum sampling commands:

  ```bash
  TARGET_DOMAIN="target.com"
  BUCKET="bucket-name-from-scanner"

  # AWS S3 — list top-level keys
  aws s3 ls "s3://$BUCKET/" --no-sign-request 2>/dev/null | head -30

  # Sample first 5 files (adjust path as needed)
  aws s3 cp "s3://$BUCKET/<file1>" - --no-sign-request 2>/dev/null | strings | grep -i "$TARGET_DOMAIN"

  # GCS
  gsutil ls "gs://$BUCKET/" 2>/dev/null | head -30
  gsutil cat "gs://$BUCKET/<file1>" 2>/dev/null | strings | grep -i "$TARGET_DOMAIN"

  # HTTP/HTTPS direct (public buckets)
  curl -s "https://$BUCKET.s3.amazonaws.com/?list-type=2&max-keys=20" \
    | grep -oE "<Key>[^<]+" | sed 's/<Key>//' | head -10

  # Fetch and inspect one file
  curl -s "https://$BUCKET.s3.amazonaws.com/<sampled-key>" \
    | strings | grep -iE "$TARGET_DOMAIN|<brand>|<product>"
  ```

  **PASS**: At least one file contains the target domain, brand name, or product-specific string.
  **FAIL**: Files reference unrelated domains, unrelated brands, or generic CDN content. Do not attribute.

### Gate 1.2 — Filenames or Key Paths Match Target Product Names

- [ ] **Inspect the bucket key listing for directory names or filenames that match the target's known product names, internal service names, or branding.**

  ```bash
  # List all top-level prefixes (directories)
  aws s3 ls "s3://$BUCKET/" --no-sign-request 2>/dev/null

  # Check for target-specific naming
  aws s3 ls "s3://$BUCKET/" --no-sign-request 2>/dev/null \
    | grep -iE "<product-name>|<internal-service>|<app-name>"
  ```

  Signal examples that count as positive:
  - Directory `acme-app-uploads/`, `vendor-chat-avatars/`, `target-app-ios/`
  - Files named `target-logo.png`, `product-v2.3-release.zip`
  - Prefixes that match internal service names found in the target's RECON_DB

  Signal examples that do NOT count:
  - Generic prefixes (`uploads/`, `media/`, `assets/`, `tmp/`, `backup/`)
  - Numeric-only directory names (`2024/`, `001/`)
  - Prefixes that match common SaaS platform names unrelated to target

  **PASS**: At least one prefix or filename matches target-specific naming (not generic).
  **FAIL**: All prefixes are generic or match unrelated brands. Gate fails.

### Gate 1.3 — At Least One of: robots.txt, CNAME Chain, or App Reference

- [ ] **Verify at least one of the three independent ownership signals below:**

  **Option A — Application References the Bucket URL**

  The target's web application, mobile app, API responses, or source maps must directly reference the bucket URL or bucket name:

  ```bash
  # Search RECON_DB and any captured JS/HTML for bucket reference
  grep -rn "$BUCKET" "$WORKSHOP_ROOT/<target>/" 2>/dev/null

  # Search source maps and JS bundles
  grep -rn "$BUCKET" "$WORKSHOP_ROOT/<target>/js_dump/" 2>/dev/null

  # Grep captured API responses
  grep -rn "$BUCKET" "$WORKSHOP_ROOT/<target>/api_responses/" 2>/dev/null
  ```

  PASS condition: Bucket name or URL appears in target's own application content.

  **Option B — CNAME Chain Resolves to Bucket**

  The bucket is served via a subdomain of the target's domain through a CNAME record:

  ```bash
  TARGET_SUBDOMAIN="assets.target.com"  # or cdn.target.com, static.target.com, etc.

  # Check CNAME chain
  dig CNAME "$TARGET_SUBDOMAIN" +short
  # Expect: <bucket>.s3.amazonaws.com or <bucket>.storage.googleapis.com

  # Confirm bucket name matches
  dig CNAME "$TARGET_SUBDOMAIN" +short | grep -i "$BUCKET"
  ```

  PASS condition: A subdomain of the target's apex domain (or registered TLD+1) has a CNAME pointing to this specific bucket.

  **Option C — robots.txt or site-level configuration references bucket**

  ```bash
  curl -s "https://target.com/robots.txt" | grep -i "$BUCKET"
  curl -s "https://target.com/sitemap.xml" | grep -i "$BUCKET"
  ```

  PASS condition: Target's own site references the bucket by URL.

  **All three options FAIL**: The bucket is not attributed to the target. Record in RECON_DB as unattributed.

---

## Stage 2 — Negative Attribution Check（排除第三方擁有者）

Even if Stage 1 passes, confirm no stronger signal points to a different owner.

### Gate 2.1 — Unrelated Brand or Domain in File Content

- [ ] **If any sampled file contains references to a different company's domain or brand name, check whether that third-party company is the actual owner.**

  ```bash
  # Identify any domain or brand names in sampled files
  aws s3 cp "s3://$BUCKET/<file>" - --no-sign-request 2>/dev/null \
    | strings | grep -oE "[a-z0-9.-]+\.(com|io|net|org|co)" | sort | uniq -c | sort -rn | head -20
  ```

  If a third-party brand dominates the content:
  - Search the third-party brand name + bucket name in Google/Shodan
  - Check if the third-party uses this bucket in their own application
  - If the third-party is the clear owner, discard this bucket from the target's Finding scope entirely

  **Common false-attribution patterns private-runtime has hit**:
  - SaaS platforms that provision buckets on behalf of customers (e.g., bucket named after target but owned by the SaaS vendor's account)
  - CDN vendors with bucket names matching customer domains
  - Previously acquired companies whose buckets were migrated to a new owner

### Gate 2.2 — Automated Scanner Hit Must Be Manually Verified Before Attributing

- [ ] **If the bucket discovery originated from an automated scanner (private-runtime, bbflow, nuclei, S3Scanner, GrayhatWarfare), confirm the attribution was not based solely on name-pattern matching.**

  Automated scanner false-attribution causes:
  1. Bucket name contains target keyword (`target-cdn-backup`) but is owned by a service provider
  2. Subdomain resolves to S3 but the bucket itself is owned by a CDN provider
  3. Scanner matches bucket to target based on CNAME subdomain without verifying content ownership

  Required manual step:
  ```bash
  # 1. Check bucket owner's AWS account (if public ACL allows)
  aws s3api get-bucket-acl --bucket "$BUCKET" --no-sign-request 2>/dev/null \
    | grep -i "DisplayName\|ID"

  # 2. Check bucket location
  aws s3api get-bucket-location --bucket "$BUCKET" --no-sign-request 2>/dev/null

  # 3. Inspect file metadata for owner indicators
  aws s3api head-object --bucket "$BUCKET" --key "<sampled-key>" \
    --no-sign-request 2>/dev/null
  ```

---

## Stage 3 — Finding Creation Gate

### Gate 3.1 — Attribution Confidence Level

Before creating a Finding, assign an attribution confidence level:

| Level | Criteria | Action |
|---|---|---|
| **Confirmed** | Stage 1 gate passes (content refs target domain) + Stage 2 negative check clean | Open Finding; set `verified_evidence: live` |
| **Probable** | Filename/key matches + CNAME chain, but no file content check possible (empty bucket or access-denied on files) | Open Finding with explicit caveat; set `verified_evidence: static` |
| **Unattributed** | Stage 1 all gates fail | Do NOT open Finding. Record in RECON_DB as `[UNATTRIBUTED BUCKET]` |
| **Third-party owned** | Gate 2.1 reveals different owner | Do NOT open Finding for this target. Consider whether to investigate the third party's scope. |

### Gate 3.2 — RECON_DB Record Format

For every bucket found, record the result in `RECON_DB.md` regardless of outcome:

```markdown
## Cloud Bucket Ownership Check — <date>

Bucket: <bucket-name>
Provider: [AWS S3 / GCS / Azure Blob]
Discovered by: [private-runtime / manual / bbflow nuclei]
LISTABLE: [yes / no]
Public files: [yes / no / partial]

Ownership verification:
- Gate 1.1 (content refs target domain): [PASS / FAIL — <evidence or reason>]
- Gate 1.2 (filenames match target product): [PASS / FAIL — <evidence or reason>]
- Gate 1.3 (CNAME / app reference / robots.txt): [PASS / FAIL — option used: <A/B/C>]
- Gate 2.1 (no third-party brand dominant): [PASS / FAIL — <third-party name if found>]
- Gate 2.2 (scanner hit manually verified): [PASS / FAIL]

Attribution confidence: [Confirmed / Probable / Unattributed / Third-party owned]
Finding opened: [yes / no — reason if no]
```

**Submission block condition**: If attribution confidence is `Unattributed` or `Third-party owned`, the submission system must block. Flag text for Finding frontmatter:

```yaml
attribution_warning: "attributed to target without content-based ownership check — BLOCK SUBMISSION"
```

Any Finding with this flag must not advance to Submission until the flag is resolved by completing this checklist.

---

## Stage 4 — Report Content Requirements

### Gate 4.1 — Ownership Evidence Section in Report

- [ ] **Every bucket-related report must include an explicit ownership attribution section.**

  Required section in Submission/FORM:

  ```markdown
  ## Bucket Ownership Attribution

  This bucket has been attributed to [target] based on the following evidence:

  1. **Content reference**: [e.g., "Files inside the bucket contain references to target.com domain in their content, including <specific example>"]
  2. **Key naming**: [e.g., "Bucket keys include prefixes matching target's known product names: <example>"]
  3. **Application reference / CNAME**: [e.g., "The bucket URL appears in the target's JS bundle at <URL>, or the subdomain <sub>.target.com has CNAME pointing to this bucket"]

  Attribution confidence: [Confirmed / Probable]
  ```

  **Do not write**: "This bucket was found via scanner and appears to belong to the target."
  **Write instead**: "This bucket is attributed to the target because [specific content-based evidence]."

### Gate 4.2 — Anti-Overstatement on LISTABLE-Only Buckets

- [ ] **If the bucket is LISTABLE but files cannot be read (403 on objects), adjust impact language accordingly.**

  | Condition | Accurate language | Prohibited language |
  |---|---|---|
  | Bucket LISTABLE, files readable | "An unauthenticated attacker can enumerate and download files including <examples>" | "Attacker has full read access to all stored data" |
  | Bucket LISTABLE, files not readable (403) | "An unauthenticated attacker can enumerate file names and directory structure" | "Attacker can access sensitive files" |
  | Bucket LISTABLE, files empty | "Bucket is publicly enumerable with no files currently present" | "Exposed cloud storage bucket leaking data" |
  | Bucket name-guessable but not LISTABLE | Does not meet threshold for standalone finding | — |

---

## Quick Reference — Gate Summary

| # | Gate | Stage | Fail action |
|---|---|---|---|
| 1.1 | File content references target domain | Content ownership | Do not attribute; record UNATTRIBUTED |
| 1.2 | Filenames match target product names | Content ownership | Combine with other gates; cannot pass alone |
| 1.3 | CNAME / app reference / robots.txt | Structural ownership | At least one required alongside 1.1 or 1.2 |
| 2.1 | No unrelated brand dominant in file content | Negative check | Discard from target scope; investigate third party |
| 2.2 | Scanner attribution manually verified | Automation check | Manual verification required before Finding |
| 3.1 | Attribution confidence assigned | Finding gate | Unattributed/Third-party → block Finding creation |
| 3.2 | RECON_DB record created | Record gate | Required for every bucket, attributed or not |
| 4.1 | Ownership evidence section in report | Report gate | Required field before Submission |
| 4.2 | Impact language matches actual file access | Report gate | Replace overstatement per table |

---

## Common False-Attribution Patterns (Do Not Report)

| Situation | Correct disposition |
|---|---|
| Bucket name contains target's brand but files reference a different company | Third-party owned — do not report against target |
| Subdomain CNAME to bucket, but bucket name registered by SaaS platform providing service TO target | SaaS vendor owns the bucket — report is against vendor, not target (check vendor's program) |
| Scanner matched bucket based on keyword overlap (target is "example-target", bucket is "privy-cdn" but owned by third-party-one) | Unattributed — do not report |
| Bucket is LISTABLE but contains only public assets (logos, marketing images, fonts) that are intentionally public | Not a finding unless file content confirms access control misconfiguration on non-public data |
| Bucket discovered via GrayhatWarfare or S3Scanner without manual ownership verification | Requires Gate 2.2 completion before any attribution |

---

## Related

- [[Pattern - Cloud Bucket Path Structure Business Intelligence]] — covers the BI angle of path analysis (not attribution)
- [[Pattern - S3 Bucket Takeover]] — covers unclaimed bucket registration (different problem: bucket does not exist yet)
- [[Checklist - Attack Surface Coverage]] §7 Files / Uploads / Storage — upstream gate where bucket is first flagged
- [[Checklist - Web Vuln Technique Coverage]] — broader vuln matrix
- 教訓 #100 — Cloud Bucket 路徑結構 = 商業情報（path-as-BI lesson）
- Memory: `feedback_bucket_namespace_ownership.md` — LISTABLE ≠ owned by target; content-based ownership verification
