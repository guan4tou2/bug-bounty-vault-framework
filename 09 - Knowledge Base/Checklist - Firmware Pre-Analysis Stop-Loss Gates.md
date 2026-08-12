---
type: checklist
title: "Firmware Pre-Analysis Stop-Loss Gates"
tags: [checklist, firmware, stop-loss, cve-precheck, qemu]
status: active
last_updated: 2026-06-04
source: internal session learning
---

# Checklist — Firmware Pre-Analysis Stop-Loss Gates

> **Trigger condition**: any time you obtain a firmware / binary image and are about to unpack it or run static analysis.
> Complements the Firmware Static Analysis Quality Gates checklist (this document is "stop-loss before you start"; that one is "static analysis quality").

## Mandatory steps (in order — any STOP condition halts further work)

- [ ] **§0 Version confirmation** — record the firmware version string (from strings, headers, or path extraction, whichever is available)
- [ ] **§1 CVE pre-flight** — search NVD/Exploit-DB/vendor advisories; if a known CVE exists and is not out of program scope → STOP (hand off to the version/CVE pre-check workflow)
- [ ] **§2 Latest-version confirmation** — confirm the downloaded image is the vendor's latest stable release; an older version carries a high risk of colliding with prior findings → switch to the latest version or document the reason for not doing so
- [ ] **§3 Architecture compatibility** — does QEMU user-mode emulation support the target ABI (MIPS BE/LE/ARM/AARCH64)? If not → tag as "qemu-ceiling", fall back to static analysis and scope claims accordingly
- [ ] **§4 CMS/flash dependency** — after binwalk extraction, confirm whether there's a flash-dependent init path (CMS, `/proc/mtd`, NAND read); if so → the dynamic-testing ceiling is clear, downgrade the report to static-only
- [ ] **§5 Cross-generation tracking for the same vendor** — if a CVE pattern has already been tracked across this vendor's product generations, confirm whether this version falls within the fixed range; if so → SKIP, don't re-analyze
- [ ] **§6 Advisory version ≠ downloaded version** — compare the version fixed in the advisory against the version on the actual download page; if they differ → treat the download page as authoritative and document the discrepancy

## Stop-loss conditions (any one triggers → STOP + log an attempt)
- CVE fully matches and is already known to the program → log an attempt, do not open a Finding
- Firmware version ≡ a version already analyzed (matching hash or version string) → STOP immediately
- ABI unsupported + no static-analysis path available → STOP, tag as qemu-ceiling

## Fallback paths
- Static analysis results: scope the claim down to a static-evidence label, do not infer dynamic triggerability
- Dynamic verification failure: log the attempt, do not open a Finding

## Related
- Checklist - Firmware Static Analysis Quality Gates
- Pattern - Firmware CGI Command Injection Grep
- Lessons Learned log
