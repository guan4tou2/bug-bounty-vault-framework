---
type: reference-card
title: "Android RE Toolchain Gap Map"
tags: [android, reverse-engineering, toolchain, gap-analysis, mobile]
status: draft
last_updated: 2026-08-12
---

# Reference Card - Android RE Toolchain Gap Map

> **TL;DR**: A gap analysis of the Android reverse-engineering toolchain against a curated tool list (based on `user1342/Awesome-Android-Reverse-Engineering`), mapped onto what dynamic-testing-focused Android skills already cover. The existing coverage is strong on **SSL pinning bypass, exported-component abuse, WebView, intent redirection, root/integrity bypass, and backup/data extraction**. The gaps cluster into four areas: (1) static analysis / SAST automation, (2) de-obfuscation, (3) native (`.so`/JNI) layer RE + dynamic tracing, and (4) firmware/kernel/baseband + malware triage.

## Quick Reference

### Already covered (dynamic testing skills)

| Phase | Tools / techniques | Coverage area |
|---|---|---|
| HTTPS interception / pinning bypass | Frida, Objection, Xposed/LSPosed (JustTrustMe/TrustMeAlready), reflutter, apk-mitm, Burp/mitmproxy | SSL pinning bypass playbook |
| Component abuse | Drozer, `adb am/content`, exported activity/provider/service/receiver | Android pentesting playbook |
| WebView / intent redirect / tapjacking | — | Android pentesting playbook |
| Root / Play Integrity / anti-tamper bypass | Magisk DenyList, Shamiko, PIF, RootBeer hook | Android pentesting playbook |
| Data extraction | `adb backup`, run-as, shared_prefs/sqlite | Android pentesting playbook |
| Decompilation (used inline) | JADX, Apktool, dex2jar, apksigner/zipalign | Referenced throughout both playbooks |

### Gaps, ranked by ROI

| # | Area | Why it matters |
|---|---|---|
| 1 | Static analysis / SAST automation | No automated static-triage pass exists for a fresh Android target — this is the "first scan" gap before hunting begins |
| 2 | De-obfuscation | Complete gap — no SOP for ProGuard/R8/DexGuard-obfuscated APKs |
| 3 | Native (`.so`/JNI) layer + dynamic tracing | Existing coverage focuses on the Java layer; native library RE and syscall tracing are absent |
| 4 | Firmware / kernel / baseband + malware triage | A generic firmware workspace exists, but Android-specific baseband/kernel and malware classification does not |

## Details

### Gap 1 — Static analysis / SAST automation

| Tool | Purpose | Where it fits |
|---|---|---|
| **MobSF** | Combined static+dynamic framework; produces manifest/permission/secret/certificate reports | First step on a new target — fills the mobile branch of surface-mapping |
| **QARK** | Automated vulnerability scanner (exported components, WebView, insecure storage) | Quick low-hanging-fruit pass |
| **AndroBugs** | Security-issue scanner (older but broad pattern coverage) | Cross-validate against MobSF |
| **Quark Engine** | Behavior scoring + scriptable rule API | Quantify suspicious/malicious behavior |
| **Androguard** | Python RE library (DEX/manifest parsing, call graphs) | Base for custom analysis scripts |
| **Dexcalibur** | Bridges static findings to dynamic hooks | Converts static output directly into runtime Frida hooks |
| **COVA** | Path-constraint solver (conditions to reach a given sink) | Deep data-flow analysis |
| **APK Dependency Graph / DIS{integrity}** | Class dependency visualization / detects root+integrity+tamper mechanisms | Map defenses before planning a bypass |

### Gap 2 — De-obfuscation (complete gap)

| Tool | Purpose |
|---|---|
| **simplify** | Android VM emulation + de-obfuscation (restores control flow/constants) |
| **deoptfuscator** | Targets control-flow obfuscation specifically |
| **Obfu[DE]scate** | Fuzzy matching to recover symbol names across versions |
| **TinySmaliEmulator** | smali emulator to "decrypt" obfuscated strings |

### Gap 3 — Native (`.so`/JNI) layer + dynamic tracing

| Tool | Purpose |
|---|---|
| **Ghidra / IDA Pro / radare2** | Disassemble native `.so` libraries (JNI logic often lives here) |
| **jnitrace** | Frida-based JNI API tracing (Java↔native boundary) |
| **Binder Trace** | Intercept and parse Binder IPC messages (cross-process attack surface) |
| **FriDump** | Frida memory dump (extract runtime secrets/keys) |
| **RMS** | Frida web UI (interactive hooking, lower barrier to entry) |
| **jtrace / sesearch** | Android syscall tracing / SELinux policy queries |
| **disarm** | ARM64 instruction-parsing CLI |

### Gap 4 — Firmware / kernel / baseband + malware triage

| Tool | Purpose |
|---|---|
| **FirmWire** | Baseband firmware dynamic-analysis platform (rarely touched = high yield) |
| **Android Kernel Exploits** | Kernel vulnerability/technique collection |
| **Binwalk / AFLSmart** | Firmware unpacking / firmware-aware fuzzing |
| **imjtool** | Multi-vendor firmware unpacking |
| **DroidDetective / CuckooDroid / androwarn** | ML/sandbox/static malware classification (triage suspicious APKs) |

### Supplementary tools (misc, use as needed)

- **LADB** — run ADB locally on-device without a PC
- **uber-apk-signer** — batch signing/zipalign
- **AutoDroid** — bulk APK collection and analysis
- **Broken Droid Factory** — generates practice-vulnerable APKs
- **Crackmes**: OWASP UnCrackable, CyberTruckChallenge19, KGB Messenger (practice de-obfuscation / native RE)

### Suggested action plan

1. **Highest ROI**: fold the Gap 1 flow (MobSF/QARK/Dexcalibur) into the mobile branch of surface-mapping methodology, so any new Android target gets an automatic static-triage pass.
2. **De-obfuscation (Gap 2)** and **native tracing (Gap 3)** are natural additions to an Android pentesting playbook as new sections (de-obfuscation; native/JNI layer).
3. **Firmware/baseband (Gap 4)** is its own domain — link it to an existing firmware-analysis workspace rather than treating it as part of the main web/app track; pursue opportunistically (cold/rare surfaces tend to be high-yield).

A prior pass at this gap map (tracked via a graph-based knowledge extraction over this tool list) reduced the open gaps from 4 to 1: anti-instrumentation/hook-detection bypass, de-obfuscation, and the native/JNI layer were folded into the Android pentesting playbook as new sections; static SAST automation (MobSF/QARK/AndroBugs/JADX/Dexcalibur) was folded into the mobile branch of a surface-mapping procedure. The only gap remaining open by design is firmware/baseband, which stays linked to the separate firmware-analysis workspace.

## Related

- [[android-pentesting-tricks]]
- [[mobile-ssl-pinning-bypass]]
- [[bb-surface-mapping]]
