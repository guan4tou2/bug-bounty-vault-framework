---
type: pattern
title: Static IV in AES-GCM
vuln_class: cryptographic-issues
last_updated: 2026-06-03
status: active
tags:
  - bb-pattern
---
# Pattern: Static IV in AES-GCM

> A hardcoded or static IV (nonce) in AES-GCM / AES-CBC breaks both confidentiality and integrity guarantees. Reusing a (key, IV) pair leads to keystream reuse and forgery. Detectable from client/firmware source by grepping for fixed IV constants.

## Background

A mobile IM app's Android client used AES-GCM to encrypt messages, but derived the IV from `Settings.Secure.getString(ANDROID_ID).substring(0, 16)` — a 16-byte string that is permanently fixed per device.

```java
byte[] iv = deviceId.substring(0, 16).getBytes();   // ★ IV is permanently fixed for a given device
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
```

AES-GCM requires every (key, IV) pair used for encryption to be unique. Reusing the same pair leads to:

1. **C1 ⊕ C2 = P1 ⊕ P2** — knowing one plaintext lets you recover the other (keystream reuse)
2. **The GHASH key H can be recovered from two messages** → allows forging a valid authentication tag under any IV (integrity broken)

Verification tier A (PoC): decompile with jadx to confirm the IV source, plus a mathematical demonstration that C1 ⊕ C2 = P1 ⊕ P2.

## Detection Signals

| Signal | Where found | Meaning |
|------|---------|------|
| IV derived from a device ID / fixed string | Android Java/Kotlin, iOS Swift/ObjC, firmware C | Static IV — direct hit |
| `GCMParameterSpec(128, HARDCODED_BYTES)` | Decompiled APK | Hardcoded IV constant |
| `IvParameterSpec(CONST_BYTES)` | CBC mode; equally severe | |
| IV is all-zero, all `0x00`, or a debug constant | Firmware / binary `strings` | Weakest case |
| IV derived from a predictable value (low bits of a timestamp or counter) | Deeper audit | High nonce-collision probability |
| `Cipher.getInstance("AES/GCM/NoPadding")` with no nearby `SecureRandom` | No randomness source in the path | Strong suspicion of a fixed IV |

## Test / Grep Methodology

### APK (Android)

```bash
# 1. Decompile
jadx -d ./decompiled target.apk

# 2. Find AES-GCM init sites
grep -rn "AES/GCM\|AES/CBC\|GCMParameterSpec\|IvParameterSpec" ./decompiled/sources/ -l

# 3. Trace the IV source (find assignments to an "iv" variable)
grep -rn "GCMParameterSpec\|IvParameterSpec" ./decompiled/sources/ -A 3 | grep -v "SecureRandom"

# 4. Find hardcoded constants
grep -rn "byte\[\] iv\|byte\[\] IV\|ivBytes\|nonce" ./decompiled/sources/ | grep -v "random\|Random\|SecureRandom"

# 5. Find device-ID-derived IVs
grep -rn "ANDROID_ID\|getDeviceId\|substring.*iv\|iv.*substring" ./decompiled/sources/
```

### Firmware / Binary

```bash
# Find fixed IV constants (16 bytes = AES block size)
strings firmware_binary | grep -E "^.{16}$" | sort | uniq -c | sort -rn | head -20

# Find AES IV-related symbols
nm binary 2>/dev/null | grep -i "iv\|nonce\|aes_key"
objdump -d binary | grep -A 5 "AES_set_encrypt_key\|AES_cbc_encrypt\|EVP_EncryptInit"
```

### Mathematical verification PoC (AES-GCM IV reuse)

```python
# Given two ciphertexts C1, C2 (without the tag) encrypted under the same (key, IV)
# if part of P1's plaintext is known, the corresponding part of P2 can be recovered
keystream_xor = bytes(a ^ b for a, b in zip(C1_body, C2_body))
P2_candidate = bytes(a ^ b for a, b in zip(keystream_xor, known_P1_body))
# P2_candidate should equal the real P2 plaintext → confirms confidentiality is broken
```

## Variants

### Variant A — Static device ID used as IV

IV = `DeviceID[0:16]`; every message from the same device shares an IV, and if the key doesn't rotate per message the scheme is completely broken. Commonly seen in custom Android IM / fintech apps designed to "keep decryption working across sessions."

### Variant B — All-zero / all-one hardcoded IV

```java
byte[] iv = new byte[16];  // all zeros
```
Common in firmware (legacy devices, IoT). Easiest to find and easiest to argue severity for.

### Variant C — Truncated counter as IV (CBC)

The AES-CBC IV is derived from the low bits of a message sequence number (e.g. `int msgId & 0xFFFF`), giving an extremely small IV space (65536) that's brute-forceable combined with a chosen-plaintext attack.

### Variant D — Derived IV but with attacker-controllable HKDF input

The IV is derived via HKDF, but the `info` parameter includes an attacker-controllable field (username, timestamp string), which can be used to force an IV collision. Requires deeper analysis to confirm.

## Severity Guide

| Condition | Severity | CVSS example |
|------|----------|-----------|
| Static IV + key constant across messages + PoC (C1⊕C2=P1⊕P2) | P3 Medium | 6.3 (AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N) |
| All-zero IV + key known / obtainable | P2 High | 7.4 |
| Static IV + forgery PoC (GHASH H recovered) | P2 High | 7.5 |
| Static-analysis-only confirmation of a fixed IV (no PoC) | P4 Low–Medium | 5.0 |

**Required before submission**: a mathematical argument (the keystream-reuse formula) plus a jadx screenshot pointing at the IV assignment line. Don't just screenshot the key or IV existing — explain why it's a vulnerability (the AES-GCM nonce-reuse consequence).

## Cross-reference

- Pattern — Hardcoded Credentials: hardcoded AES/ECDH key cases; a key existing alone ≠ a vulnerability, an end-to-end bypass PoC is required.
