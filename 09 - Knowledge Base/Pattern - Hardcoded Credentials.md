---
type: pattern
title: "Pattern - Hardcoded Credentials"
tags: [pattern, cwe-798, cwe-321, hardcoded-credentials, firmware, apk, git-exposure, bb-pattern]
status: verified
vuln_class: info-leak
severity_range: P2-P5
seen_in: [iot-firmware, android-apk, spa-js-bundle, git-exposure]
prerequisites: []
last_updated: 2026-04-06
---

# Pattern - Hardcoded Credentials & Cryptographic Keys

> **TL;DR**: "A key exists in the binary/bundle" is not, by itself, a vulnerability — you must prove the key is currently valid and demonstrate concrete impact (successful auth, successful decryption, or a working forged token). Hardcoded secrets are found in firmware, decompiled APKs, SPA JS bundles, and leaked source repos; the severity depends entirely on whether you can complete the end-to-end proof-of-concept.

## Category Matrix

| Type | Typical location | Severity | PoC required |
|------|-------------------|----------|---------------|
| Hardcoded admin credentials | firmware `/etc/passwd`, APK | Critical | Screenshot of a real login on the live device/service |
| Hardcoded API secret | SPA JS bundle, APK | High | A working API call that proves the secret is still valid |
| Hardcoded OAuth `clientSecret` | SPA JS bundle | Medium-High | Server response differential confirming validity |
| Hardcoded AES/ECDH key | APK, native binary | Medium | Working decryption of captured traffic |
| Hardcoded JWT signing secret | backend source | Critical | A forged token that is accepted by the server |
| Default credentials (documented) | config XML/JSON | Low-Medium | Successful login on the live device/service |

## Case Studies (sanitized/generalized)

### IP camera / NVR vendor Android app — 18 findings including hardcoded credentials

- A fixed `<brand>:<brand-word>` pair was used for HTTP Basic Auth across the entire API.
- A second fixed string served as the AES encryption key.
- The default P2P pairing password was a trivial 4-digit constant.
- **PoC**: `curl` with the hardcoded Basic Auth credential retrieved a live camera stream.
- **Lesson**: decompile the APK with `jadx`, then grep for `password`, `secret`, `key`, `token` across the decompiled source tree.

### Smart-device vendor — hardcoded ECDH/AES key (marked Duplicate)

- The APK contained a hardcoded ECDH public key plus an AES-128 key.
- **Problem**: only the key's *existence* was demonstrated — there was no end-to-end proof of bypassing the encryption it protected.
- **Result**: Duplicate/Informative (an earlier, more complete report had already been filed).
- **Lesson**: a hardcoded crypto key needs an end-to-end decrypt/bypass PoC — a screenshot of the key alone is not enough to establish severity or uniqueness.

### SaaS vendor developer console — OAuth `clientSecret` in SPA JS (not submitted)

- A developer-facing SPA's JS bundle contained a hardcoded OAuth `clientSecret`.
- A server response differential confirmed the secret was live and valid.
- **Decision**: not submitted — the asset fell under a "client-side / source-derived disclosure" category the program's scope explicitly excluded.
- **Lesson**: check scope carefully before investing further; many programs explicitly exclude this class of client-side-secret finding.

### Web platform — `database.php` credentials via `.git` exposure

- A `.git` directory dump recovered `application/config/database.php` containing plaintext database credentials.
- **PoC**: confirmed the MySQL service was reachable from the public internet using the recovered credentials.
- **Impact**: access spanned roughly two dozen databases with full privileges.

### Web platform — weak shared admin credentials across multiple sites

- Three related sites shared the same weak admin password (recovered via hash cracking).
- **PoC**: successful admin-panel login, screenshotted.
- **Escalation**: chained with an unrestricted file-manager upload feature into remote code execution.

## Detection: APK Analysis Workflow

```bash
# 1. Decompile
jadx -d ./decompiled/ app.apk

# 2. Grep for hardcoded secret-shaped values
grep -r "password\|secret\|apikey\|token\|key\b" ./decompiled/ \
  --include="*.java" -i | grep -v "//\|test\|mock\|example"

# 3. Confirm validity (server response differential, or a real API call)
curl -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  https://target.example.com/api/endpoint
```

## Detection: Firmware Analysis Workflow

```bash
# 1. Unpack
binwalk -Me firmware.bin

# 2. Look for credentials
cat squashfs-root/etc/passwd
cat squashfs-root/etc/shadow
strings squashfs-root/usr/bin/* | grep -i "password\|secret\|admin"

# 3. Confirm which default services are actually enabled
cat squashfs-root/etc/inittab
cat squashfs-root/etc/inetd.conf
```

## Additional Techniques

- **API-documentation embedded credentials (CWE-259)**: if a "test" credential published in official developer documentation still works against production, treat it with the same severity as a source-code-embedded hardcoded credential. Verify by calling an auth-required endpoint (e.g. `/api/v1/me`) with the documented credential.
- **Scope multiplier**: if the same key/credential is valid across multiple subdomains or endpoints, that widens the blast radius and typically justifies bumping severity one tier. List every endpoint where you confirmed validity in the report.
- **.NET AES key extraction**: `grep -r "AES\|set_Key\|SQLiteConnection" <binary_dir>` to locate candidates, then decompile with `ilspycmd <dll>` to find the hardcoded byte array.
- **SSH key fingerprint validation**: compare the server's live public-key fingerprint against the hardcoded value found in the client — this proves the hardcoded key is actually in use, not just present in the codebase.

## Impact Assessment

- **Verified impact** requires one of: a successful live login, a successful decryption of real traffic, a working forged token accepted by the server, or a confirmed-reachable service using the recovered credential.
- **Unverified** ("the key exists in the binary") should be reported, if at all, as a lower-severity finding with the caveat spelled out explicitly — do not claim Critical/High severity on key-existence alone.

## Stop-Loss

- If you can decompile the key/credential but cannot reach the service it authenticates to (dead infrastructure, DNS gone, service decommissioned), downgrade to informational and note the live-status check explicitly in the report.
- If the only asset containing the secret falls under an explicit program scope exclusion (e.g., client-side/source-derived disclosure category), do not submit — record it as a stop-loss note and move on.
- Don't spend further effort trying to "prove" a hardcoded crypto key once a Duplicate/Informative result confirms someone already filed a more complete PoC for the same root cause.

## Bypass Techniques

N/A — this pattern is about locating and validating a secret rather than bypassing a control. The relevant "bypass" consideration is scope: platform/program rules that exclude client-side or source-derived secret disclosure (see the SaaS-vendor case study above).

## Submission Platform Guidance

| Finding type | Suggested platform |
|---------------|---------------------|
| Firmware credentials + RCE | National/regional CERT coordination programs (CVE path) |
| APK credentials + cloud-service impact | HackerOne / Bugcrowd |
| `.git` dump credentials (regional vendor) | Regional zero-day coordination platforms (e.g. HITCON ZeroDay) |
| OAuth `clientSecret`, out of scope | Do not submit |

## References

- [[Pattern - Harbor Registry Enumeration]] — `.git`/config exposure is one of the most common paths to discovering hardcoded credentials
- [[Pattern - Docker Hub Config Env Exfil]]
