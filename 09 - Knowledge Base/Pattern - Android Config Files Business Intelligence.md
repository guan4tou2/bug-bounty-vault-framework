---
type: pattern
title: Pattern - Android Config Files Business Intelligence
tags: [pattern, cwe-200, android, apk, network-security-config, manifest, business-intelligence, osint, bb-pattern]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
severity: P3 Medium (info disclosure) / P4 if only generic domains
---

# Pattern - Android Config Files Business Intelligence

## TL;DR

An Android APK's `network_security_config.xml` and `AndroidManifest.xml` don't just expose technical configuration — the **domain lists and branded activity names** they contain directly leak enterprise-customer identity and deployment topology.

## Intelligence Source #1: network_security_config.xml

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <!-- Vendor's own domains -->
    <domain includeSubdomains="true">app.vendor.example</domain>
    <domain includeSubdomains="true">vendor-corp.example</domain>

    <!-- Customer domains = business intelligence -->
    <domain includeSubdomains="true">chat.customer-a.example</domain>   <!-- e-government customer -->
    <domain includeSubdomains="true">portal.customer-b.example</domain> <!-- financial-sector customer -->
    <domain includeSubdomains="true">comms.customer-c.example</domain>  <!-- enterprise customer -->
    <domain includeSubdomains="true">service.customer-d.example</domain><!-- AI/SaaS customer -->
  </domain-config>
</network-security-config>
```

**Why are customer domains present?** Certificate pinning requires explicitly listing every deployment domain. White-label / OEM products typically bundle the pin configuration for every customer into one APK.

## Intelligence Source #2: AndroidManifest.xml

```xml
<!-- Branded launcher activities -->
<activity android:name=".AppPartnerAMainActivity" />      <!-- internal / reseller build -->
<activity android:name=".AppPartnerBMainActivity" />       <!-- customer B -->
<activity android:name=".AppPartnerCMainActivity" />       <!-- customer C -->
<activity android:name=".AppPartnerDMainActivity" />       <!-- customer D -->
```

**Why are branded activities present?** White-label apps use a different launcher Activity to load each brand's UI, all packaged into the same APK.

## Detection Method

```bash
# 1. Unpack the APK
apktool d target.apk -o decoded/

# 2. Extract domains from the network security config
grep -oP 'domain[^>]*>[^<]+' decoded/res/xml/network_security_config.xml | \
  grep -oP '>[^<]+' | sed 's/>//' | sort -u

# 3. Extract branded activities from the manifest
grep -oP 'android:name="[^"]*Main[^"]*Activity"' decoded/AndroidManifest.xml

# 4. Extract Firebase / GCP project references from strings.xml
grep -E "firebase|google_app_id|project_id|google_storage_bucket" \
  decoded/res/values/strings.xml
```

## Cross-Verifying the Intelligence

| APK source | Cross-verification method |
|----------|------------|
| NSC domains | Verify the domain resolves via DNS + confirm the owning org via whois |
| Manifest activities | Search for the corresponding brand's Google Play listing |
| Firebase project ID | Try `https://<project>.firebaseio.com/.json` (may return permission-denied or actual data) |
| GCS bucket | `gsutil ls gs://<bucket>/` to check if it's public |

## Complementary to Cloud Bucket Business Intelligence

| Intelligence source | Discovery location | What it leaks |
|--------|---------|---------|
| Cloud bucket path structure | GCS/S3 listing | Customer brand logos, environment names |
| **Android NSC (this pattern)** | APK static analysis | Customer domains, pin configuration |
| **Android Manifest (this pattern)** | APK static analysis | Branded activities, Firebase project |
| Cloud TLS certificates | GCS CA directory | TLS cert CN → customer identity |

**Combined effect**: APK NSC domains + GCS bucket customer directories + member-enumeration APIs together produce a complete customer topology map.

## Real-World Example

- **NSC domains**: 9 domains total, 4 of them belonging to third-party customers rather than the vendor itself
- **Manifest activities**: 4 branded launcher activities for different resellers/customers
- **GCS CA directory (cross-pattern)**: TLS cert CNs revealed two regulated-sector customer subdomains
- **Impact**: the customer roster for a security-sensitive communication app was publicly derivable — supply-chain risk intelligence

## Severity

| Leaked content | Severity |
|---------|----------|
| Only the vendor's own domains + public CDN | **P5 Info** (expected behavior) |
| Includes non-public customer domains | **P3 Medium** |
| Includes government/financial customer identity | **P3 Medium** (can be escalated by chaining) |
| Domains + accessible Firebase/GCS | **P2 High** |

## Related

- [[Pattern - Cloud Bucket Path Structure Business Intelligence]] — the equivalent intelligence source on the cloud side
