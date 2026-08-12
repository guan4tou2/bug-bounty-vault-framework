---
type: pattern
title: Pattern - Coturn Default TURN Credentials (hardcoded secret + relay abuse)
tags: [pattern, cwe-798, cwe-284, cwe-200, coturn, turn, jitsi, webrtc, relay-abuse, ssrf, bb-pattern]
status: verified
first_seen: 2026-04-25
last_updated: 2026-04-25
severity: P3 (CVSS 7.5 High when live-confirmed relay allocation)
precedents: CVE-2020-26262, CVE-2020-6061, CVE-2020-6062, CVE-2024-25887 (Coturn)
---

# Pattern - Coturn Default TURN Credentials

## TL;DR

Jitsi Meet / WebRTC deployments commonly use Coturn as their TURN server. **Coturn's time-based REST API credential scheme** has server and client share a single `static-auth-secret`; the client computes its password as `HMAC-SHA1(secret, "{timestamp}:{username}")`, base64-encoded.

The trap: developers sometimes place this `static-auth-secret` in **frontend config** (`config.js`, `Settings.js`, `turn.json`), reasoning that "the client needs it to compute the password anyway." In practice, once the secret leaves the server side it means **anyone can allocate a relay** — an attacker who obtains the secret can mint unlimited valid TURN credentials.

## Root-Cause Ingredients

### Ingredient 1: Coturn `use-auth-secret` mode

```ini
# /etc/coturn/turnserver.conf
use-auth-secret
static-auth-secret=REDACTED_SECRET
realm=turn.acme-corp.example
listening-port=3478
```

The server accepts `username = "{timestamp}:{user_label}"` with `password = base64(hmac-sha1(secret, username))`, where the timestamp must be in the future (typically a 1-hour validity window).

### Ingredient 2: The Secret Leaks to the Frontend

```javascript
// jitsi.acme-corp.example/config.js
//config.p2p.stunServers = [{
//  "url":"turn:turn.acme-corp.example:3478?transport=tcp",
//  "username": "rd",
//  "credential":"",
//  "isdynamicpwd": true,
//  "secretpwd":"REDACTED_SECRET"   // ← plaintext, directly in the config
//}];
```

Even if it's a "commented-out legacy config," a "dev/staging test password," or a "workshop-only user" — as long as it still appears in a production-facing config, it's CWE-798.

### Ingredient 3: Reachability

A TURN server typically requires:
- TCP/UDP 3478 open (STUN/TURN)
- TCP 5349 (TURN over TLS, optional)
- TCP 80/443 (admin web, optional)
- a relay port range (commonly UDP 49152–65535)

Production WebRTC deployments **must have 3478 open**, and firewall traversal usually doesn't restrict by source IP → **reachable from anywhere on the internet**.

## Detection Methodology

1. **Find exposed TURN config**: `grep -r "static-auth-secret\|use-auth-secret\|secretpwd\|turnserver.conf" public/ static/ js/`
2. **Search inside JS bundles**: `grep -E "turn:|stun:|secretpwd|static-auth-secret"` against the extracted bundle
3. **Jitsi-specific**: fetch `/config.js`, `/static/config.js`, `/external_api.js` from any Jitsi domain
4. **Confirm the server is alive with a STUN Binding Request**:
   ```python
   import socket
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   s.sendto(bytes.fromhex("000100002112a44200000000000000000000000000000000"), ("turn.target.example", 3478))
   data, _ = s.recvfrom(1024)
   print(data.hex())   # 0x0101 = Binding Success
   ```
5. **Parse the SOFTWARE attribute to confirm the Coturn version**: parse the 0x8022 attribute → e.g. `Coturn-4.5.1.1 'dan Eider'`

## Live Verification SOP

```python
import hmac, hashlib, base64, socket, struct, time

SECRET = "REDACTED_SECRET"
HOST = "turn.target.example"
PORT = 3478
REALM = "turn.target.example"

# Step 1: Binding Request (STUN)
def stun_binding():
    txid = b"\x21\x12\xa4\x42" + b"\x00" * 12
    msg = struct.pack(">HH", 0x0001, 0) + txid
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg, (HOST, PORT))
    data, _ = s.recvfrom(2048)
    print("[Binding]", data[:2].hex())   # expect 0101
    return data

# Step 2: Generate credential
ts = int(time.time()) + 3600
username = f"{ts}:researcher"
credential_b64 = base64.b64encode(
    hmac.new(SECRET.encode(), username.encode(), hashlib.sha1).digest()
).decode()
ha1 = hashlib.md5(f"{username}:{REALM}:{credential_b64}".encode()).digest()
print(f"[Cred] user={username} pwd={credential_b64}")

# Step 3: Allocate Request with MESSAGE-INTEGRITY
# (omitted — pystun3 / aiortc are better suited for this)
# Expected: 0x0103 Allocation Success → relay address (4-byte IPv4 + 2-byte port)
```

**How to judge live confirmation**:
- An authenticated Allocate returning `0x0103 Allocation Success`
- Obtaining a relay IP + port (e.g. `203.0.113.42:57311`) → **A-grade evidence**
- Include the relay IP and a time-bounded credential example in the PoC

### Bidirectional Test SOP (mandatory)

**An outbound-only CreatePermission SUCCESS does not imply an exploitable bidirectional SSRF**. The Coturn relay may be firewalled to blind outbound-only traffic (packets sent, but no Data Indication returned).

Before filing an SSRF advisory, run at least 6 tests:

| Test | Path | Expected | Interpretation |
|------|------|------|------|
| A | `relay → server:3479` (hairpin to the server's own STUN port) | Data Indication | Confirms the relay can reach the server itself |
| B | `relay → 8.8.4.4:123` (NTP) | Data Indication containing an NTP response | Full bidirectional confirmation |
| C | `relay → 1.1.1.1:53` (DNS) | Data Indication containing a DNS response | Same as above |
| D | `relay → cloud-internal DNS on the link-local metadata range` | Data Indication (may be cloud-environment-only) | Cloud SSRF |
| E | `relay → an attacker UDP listener` | Data Indication containing the attacker's payload | Full round-trip confirmation |
| F | `relay → the relay's own ports` (3478/3479) | Hairpin behavior | Detects self-directed firewall restrictions |

**Interpreting results**:
- 6/6 Data Indications received → **full bidirectional SSRF** (C:H is justified, data exfiltration possible)
- 0/6 Data Indications → **blind outbound-only SSRF** (C:L only, no data exfil, but still DoS + IP abuse + blind port probing)
- Partial reception → document exactly which paths work (affects the CVSS S/C metric)

**Example real-world result**: 6/6 tests came back one-way — every CreatePermission returned SUCCESS but 0 Data Indications were received → classified as blind outbound-only. CVSS dropped from C:H to C:L but gained A:H (DoS), moving overall score from 7.5 to 8.2.

## Known Coturn CVEs (reference)

| CVE | CVSS | Affected | Required port | Note |
|-----|------|----------|---------------|------------------------|
| **CVE-2020-6061** | 9.8 | Coturn 4.5.1.1 web server POST | TCP 80/443/8080/8443 (admin web) | Only exploitable if the admin port is exposed |
| **CVE-2020-6062** | 7.5 | DoS via crafted POST | Same as above | Only exploitable if the admin port is exposed |
| **CVE-2020-26262** | 9.8 | Loopback access bypass (IPv4 + IPv6) | 3478 | Depends on IPv6 being enabled on the relay |
| **CVE-2024-25887** | 9.8 | XSS in admin web | TCP 80/443 admin | Only exploitable if the admin port is exposed |

**Important**: a CPE match (e.g. `cpe:2.3:a:coturn_project:coturn:4.5.1.1`) only matches the version string; it does **not** confirm the deployment's actual protocol family or port exposure. Verify against the live host before filing an advisory.

## Variants

### Variant A: Plaintext Secret in Production Config

Most common. `static-auth-secret` appears in `config.js` / `turn.json` / a publicly downloadable frontend bundle.

### Variant B: Commented-Out Staging Config Left In Place

A developer commented out an old setting rather than deleting it. A web crawler, source map, or `view-source:` can still recover it.

### Variant C: Jitsi Meet `interfaceConfig.js` Exposed

`interfaceConfig.js` / `external_api.js` may contain `turnCredentials` or an embedded `staticAuthSecret`. Fetchable directly.

### Variant D: Admin Web Port Open + Default Password

Coturn's `cli-password` / web-admin credentials are set to `admin:admin` or another default. Use `nmap -p 5349,80,8080,8443` to confirm admin-port state.

### Variant E: TURN Allocation to an Internal IP (blind UDP SSRF — live confirmed)

Coturn by default only blocks `127.0.0.0/8` and does not block RFC1918 ranges. An attacker with a valid credential can `Allocate` + `CreatePermission` against `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` → **blind UDP SSRF into the internal network**. CWE-918.

**Example live confirmation** (Coturn 4.5.1.1 and 4.5.2):

```
CreatePermission 10.0.0.1     → 0x0108 SUCCESS ✅
CreatePermission 172.16.0.1   → 0x0108 SUCCESS ✅
CreatePermission 192.168.1.1  → 0x0108 SUCCESS ✅
CreatePermission 169.254.0.1  → 0x0108 SUCCESS ✅ (link-local)
CreatePermission 0.0.0.0      → 0x0108 SUCCESS ✅
CreatePermission 127.0.0.1    → 403 Forbidden IP ✅ blocked (loopback only)
```

**Important**: a CreatePermission SUCCESS is not the same as an exploitable bidirectional SSRF — the bidirectional test SOP above must be run to determine whether it's full SSRF or blind outbound-only.

### Variant F: Multi-Server Hardcoded Secret Reuse

Vendors deploying multiple TURN servers (different regions, clusters, or environments) commonly reuse the **same hardcoded secret** across all of them — for operational convenience and CI/CD uniformity.

Example live confirmation: two TURN servers hosted in different cloud regions with different Coturn versions both accepted the **same secret**, and both had the same RFC-1918 misconfiguration — doubling the attack surface.

**Detection SOP**:
- Naming conventions to look for: `turn1`/`turn2`/`turn3`, `prod-1`/`prod-2`, `turn-east`/`turn-west`, regional suffixes
- DNS enumeration: `dnsx -d target.example -w wordlist.txt` plus CT log queries for all subdomains
- Confirm the STUN Binding Response comes from different IPs → different servers
- Test the same credential against every discovered server

## Real-World Examples

| Deployment type | Variant | Note |
|------------------|---------|------|
| Jitsi demo instance | A + B | Plaintext secret in commented-out `config.js` → relay live-confirmed |
| Self-hosted Jitsi deployments generally | A | A common misconfiguration seen repeatedly across HackerOne reports |
| Coturn admin web XSS (CVE-2024-25887) | D | Requires the admin port to be exposed |

## Defense

```ini
# ❌ vulnerable
use-auth-secret
static-auth-secret=plaintext_secret_in_config_js

# ✅ safe
# 1. Don't put the secret in the frontend — have the server issue a short-lived credential to the client
# 2. Provide a credentials API endpoint
#    GET /turn-credentials → server computes username/password server-side using its secret and returns it
# 3. Keep credential validity short (5–15 min)
# 4. denied-peer-ip should cover all of RFC1918 + link-local
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
# 5. Don't expose the admin web port externally
no-cli-cert    # disable TLS-CLI if not needed
no-tls         # disable TURN-TLS if not needed
listening-port=3478
# Don't open 5349/8080/8443 admin ports
```

## Filing & Severity

- **CWE-798** (Hardcoded Credentials) — primary classification
- **CWE-284** (Improper Access Control) — relay abuse
- **CWE-200** (Information Exposure) — version leak via the SOFTWARE attribute
- **CWE-918** (SSRF) — if `denied-peer-ip` omits RFC1918, applies to Variant E
- **CVSS solo (relay abuse)**: 7.5 High (`AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L`)
- **CVSS chained with SSRF**: 8.5–9.0
- **Live evidence is required**: a static `secretpwd` in the config alone isn't enough — demonstrate an actual Allocation Success plus a relay IP
- **Don't overclaim a CVE**: only cite an NVD-verified, CPE-matched CVE **after confirming the live host's actual protocol family / port exposure**

## Chains

```
config.js secret leak (CWE-798)
  → Coturn REST credential generation (HMAC-SHA1 + base64 + MD5 STUN auth key)
  → Allocate Request → relay
  → Variant 1: use as a free TURN proxy (evading IP blocks)
  → Variant 2: CreatePermission to an internal IP → blind UDP SSRF (if denied-peer-ip is misconfigured)
  → Variant 3: confirm the version + admin port → cross-reference CVE-2020-6061/6062 / CVE-2024-25887
```

## Related

- [[Pattern - SSRF]]
- [[Pattern - SSRF Cloud K8s Attack Chain]]

## Session-Mined Additions

- **Frontend JS bundle HMAC secret**: if a TURN HMAC secret is present in plaintext in a frontend JS bundle, anyone can compute a valid TURN credential themselves (`username:timestamp` + `HMAC-SHA1(secret)`) and allocate relay bandwidth for free.
- Test by grepping the JS bundle for `turnSecret` / `credential` / `iceServers`, extracting the secret, then validating with Coturn's `turnadmin` tool or an RFC 5766 flow.
