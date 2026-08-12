---
type: pattern
title: Pattern - Firmware Shipped SSH authorized_keys Backdoor (cross-SKU)
tags: [pattern, cwe-798, cwe-284, firmware, ssh, authorized-keys, backdoor, supply-chain, odm, cross-sku, bb-pattern]
status: verified
last_updated: 2026-06-19
---

# Pattern - Firmware Shipped SSH authorized_keys Backdoor (cross-SKU)

## Principle

A firmware image shipped from the factory with a **pre-installed SSH `authorized_keys`** (a development/debug/ODM-leftover public key) plus `PermitRootLogin yes` means anyone holding the corresponding private key (or anyone who can infer risk from a leaked public key) has a pre-loaded root backdoor. **The key amplifier: when a single ODM (original design manufacturer) builds firmware for multiple vendor SKUs, the same key can propagate across an entire product line** — one leaked key can backdoor N different models. This is a variant of the "shared codebase = impact multiplier" principle.

## Checkpoints (after firmware extraction)

```bash
# 1. all authorized_keys (root + every account + dropbear)
find <rootfs> -name "authorized_keys*" -o -name "*.pub" 2>/dev/null
find <rootfs> -path "*dropbear*" -name "authorized_keys"
# 2. is sshd/dropbear configured with PermitRootLogin yes / key auth allowed?
grep -rn "PermitRootLogin\|PubkeyAuthentication" <rootfs>/etc/
# 3. key comment reveals the source (dev machine / ODM) — high-signal
grep -rhE "ssh-(rsa|ed25519|dss) " <rootfs> | grep -oE "[^ ]+@[^ ]+$"  # e.g. root@some-dev-host
```

## Real-World Case Study (consumer router vendor / shared ODM)

- Multiple SKUs from the same router vendor's latest firmware line shipped with a **developer's personal SSH public key** baked into `authorized_keys`, plus `PermitRootLogin yes` — **confirmed identical across 5 SKUs** (traced to a shared ODM build).
- The key's comment field identified a developer's personal Kali machine — a leftover from a development environment that was never cleaned up before shipping.
- The same firmware image also leaked an internal `known_hosts` entry, an internal build path, a developer email address, and an expired TLS certificate — the firmware effectively **was a snapshot of a developer's environment**, and the authorized_keys backdoor was only one symptom of that.

## Severity / Filing

- **P1-P2**: a pre-loaded key means pre-auth root (if the private key is obtainable or inferable); even without the private key, "factory-shipped unexpected SSH public key + PermitRootLogin yes" is itself a reportable supply-chain backdoor (the vendor should remove it).
- Anti-overclaim: without the private key, frame the finding as a "shipped backdoor key (vendor-left)," not "I can log in" (unless actually demonstrated). The success criterion for this class is "key present + root login enabled" — actually logging in is a higher evidence grade, not a prerequisite for reporting.
- Cross-SKU findings should be filed as a single aggregate report covering the whole affected product line, not one report per SKU.

## Related

- [[Pattern - Default Credentials in Firmware]] (weak passwords; this pattern is the key-based-backdoor complement)
- [[Pattern - Firmware CGI Command Injection Grep]]
