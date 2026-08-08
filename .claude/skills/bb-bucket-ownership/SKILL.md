---
name: bb-bucket-ownership
description: Use when a LISTABLE / publicly-accessible cloud bucket (S3 / GCS / Azure Blob / CDN origin) is found — BEFORE attributing it to the target or opening a Finding/Submission. LISTABLE does not equal owned-by-target; verify content-based ownership to avoid false attribution to a third party / CDN / shared bucket. Triggers: LISTABLE bucket / public S3 / GCS bucket / azure blob / bucket ACL misconfig / scanner reports bucket.
---

# Bug Bounty — Cloud Bucket Ownership Verification Gate

Born from a real **false-attribution incident**: an automated scan reported LISTABLE buckets as belonging to the target, but the actual owners were unrelated third parties (matched only on naming/subdomain pattern). **LISTABLE / public status alone does NOT attribute a bucket to the target.** This gate blocks the Finding until ownership is proven from bucket *content*, not from the name.

## Trigger (fire on ANY match — before opening a Finding)

- Automated scanner (nuclei / custom hunters) reports a bucket as LISTABLE / public / ACL misconfigured
- `aws s3 ls s3://<bucket>` / GCS / Azure lists objects without authentication
- Bucket name "looks like" the target (subdomain / brand / naming pattern) — **this is the most dangerous trap**

## Hard Gate (LISTABLE does not equal owned)

1. **Never attribute a bucket to the target based solely on LISTABLE status or name similarity.** Name matching is a common source of coincidence (CDNs, shared buckets, third-party SaaS providers).
2. **Verify ownership from content**: list objects, examine actual ownership evidence inside files (domain references, company names, client-specific paths, metadata). Confirm the data belongs to the target — not to a third party (CDN origin / upstream vendor / another SaaS provider's bucket). Follow the checklist stages below.
3. **Third-party bucket exclusion**: if objects show ownership by an unrelated third party, this is **not the target's finding**. Record it via `bb-attempt-recorder` as a false-attribution attempt and stop.
4. Time-box: 5-10 minutes per bucket.

## Ownership Verification Checklist

### Stage 1 — Object Listing & Sampling

- List bucket contents (first 100-200 objects).
- Look for naming patterns: do file names/paths contain the target's domain, product names, or internal project names?
- Sample 3-5 representative files (prefer HTML, config, or text files) and inspect for target-specific references.

### Stage 2 — Content Attribution

Evidence that **supports** attribution:
- Files containing the target's domain, brand name, or product identifiers
- HTML pages with the target's branding, favicon, or copyright notices
- Configuration files referencing the target's infrastructure (internal hostnames, API endpoints)
- Metadata (EXIF, HTTP headers from origin) pointing to the target's systems

Evidence that **refutes** attribution:
- Files referencing a different company or brand
- Generic CDN content with no target-specific markers
- Content clearly belonging to a SaaS platform used by multiple tenants
- Bucket serves as a shared upstream (multiple unrelated clients' data)

### Stage 3 — Verdict

- **Owned by target** (strong content evidence) -> proceed to severity assessment
- **Likely owned but inconclusive** -> note uncertainty; gather more evidence before proceeding
- **Not owned / third-party** -> stop; record as false attribution via `bb-attempt-recorder`
- **Cannot determine** -> do not open a Finding; record the attempt

## After Passing the Gate

- Attribution confirmed (target-owned) -> assess severity: LISTABLE is not equal to writable, which is not equal to containing secrets/PII. Evaluate actual impact.
- Proceed through `bb-evidence-readiness` -> `bb-submission-readiness`.
- Attribution **cannot** be proven from content -> do not open a Finding; record the attempt.

## Integration Points

- `bb-evidence-readiness` / `bb-submission-readiness`: any bucket finding should invoke this gate before creating a Finding or submitting.
- Related patterns: S3 Bucket Takeover (unclaimed bucket — different mode), Cloud Bucket Path Structure Business Intelligence (path-as-BI).
- See the External Skills Catalog for additional cloud-specific technique references.
