---
fileClass: Playbook
type: playbook
title: Playbook - Exchange ProxyShell Chain
status: active
tags: [bb-playbook, exchange, proxyshell, owa, rce, cve-2021-34473]
source: 2026-06-19 gap-analysis research
added: 2026-06-19
---

# Playbook - Exchange ProxyShell Chain

> Goal: take an on-prem Microsoft Exchange target from "confirmed exposure / SSRF
> forwarding signs" to a **read-only, non-destructive** judgment of whether the
> ProxyShell chain is actually exploitable — and if so, what the full chain looks
> like — without dropping a webshell or otherwise causing impact.
>
> **Reasoning discipline:** every probe below is GET-first and read-only. Any step
> that writes to disk or executes code is explicitly marked **[WRITE — needs
> authorization + informed consent]** and is documented for *understanding the
> chain*, not for unauthorized execution. Treat all impact claims as conditional
> ("if X returns Y, then Z is likely exploitable") until dynamically verified.

---

## 0. TL;DR decision

ProxyShell only applies to **old, unpatched builds (≤ April/May 2021 SU level)**.
A build released *after* mid-2021 is patched against ProxyShell by definition and
the relevant chain shifts to **ProxyNotShell** (Nov 2022) or, for very old builds,
**ProxyLogon** (Mar 2021). **The first action on any Exchange target is to pin the
exact build number and map it against the table in §1** — this single check decides
whether you are even chasing the right CVE class.

---

## 1. Version applicability (pin the build FIRST)

ProxyShell = three chained CVEs, fixed across two 2021 Patch Tuesdays:

| CVE | Role in chain | Type | Patched by |
|-----|---------------|------|-----------|
| CVE-2021-34473 | Pre-auth path confusion → ACL bypass / SSRF to backend | RCE-class (CVSS 9.1) | KB5001779 (Apr 13 2021) |
| CVE-2021-34523 | Elevation of privilege on the PowerShell backend (`X-Rps-CAT`) | EoP | KB5001779 (Apr 13 2021) |
| CVE-2021-31207 | Post-auth arbitrary file write → RCE (`New-MailboxExportRequest`) | Security feature bypass | KB5003435 (May 11 2021) |

**Full ProxyShell protection requires the May 2021 SU (KB5003435).** The April SU
(KB5001779) only closes two of the three.

### Affected vs not-affected (ProxyShell)

| Exchange version | Vulnerable to ProxyShell? |
|---|---|
| 2013 ≤ CU23 (without May-2021 SU) | Yes |
| 2016 ≤ CU20 (without May-2021 SU) | Yes |
| 2019 ≤ CU9 (without May-2021 SU) | Yes |
| Any build with May 2021 SU (KB5003435) or later | **No — patched** |

### The specific build in this engagement

- **Exchange 2019 CU12 = build 15.2.1118**, released **20 Apr 2022** (KB5011156),
  with subsequent SUs (15.2.1118.9 May22, .12 Aug22, .15 Oct22).
- CU12 shipped **~11 months after ProxyShell was patched.** A CU12 box —
  even at RTM (15.2.1118.7) with no later SU — already contains the ProxyShell
  fixes that were rolled forward into every CU after mid-2021.
- **Conclusion: a clean Exchange 2019 CU12 build is NOT exploitable via
  ProxyShell.** The observed SSRF-forwarding signs (HTTP 400 + `X-BEServer`
  response header) are explained as **normal Exchange front-end → back-end proxy
  behavior**, not as a working ProxyShell SSRF. (Confirm by build pinning, below.)

> Reframe: on a CU12 target, treat the "SSRF transfer" evidence as a
> **fingerprint of the FE/BE proxy architecture**, useful for reconnaissance, and
> pivot your exploitability question to **ProxyNotShell** (see §5). Do not write
> ProxyShell up as exploitable against a CU12 build without a build-level
> contradiction (e.g., the target is actually reporting a spoofed/old version, or
> is an unpatched 2013/2016/≤CU9-2019 host behind the same name).

---

## 2. Step 1 — Pin the exact build (read-only)

Exchange leaks its version in several read-only places. Cross-check at least two:

1. **OWA static resource path** — the version string is embedded in the
   `/owa/auth/<build>/...` resource URLs and in the logon page. GET the OWA logon
   page and grep for the `15.x.xxxx.xx` pattern.
2. **`X-OWA-Version` / `X-FEServer`** response headers on OWA/ECP responses.
3. **`/ecp/Current/exporttool/...`** and other versioned virtual-dir paths.
4. Map the discovered `15.2.xxxx.xx` to a CU/SU via the canonical Microsoft build
   table (Sources). Record the exact build in RECON_DB.

> Anti-overclaim: a build number is a claim by the server. If everything else says
> "patched" but you suspect an old host, corroborate with behavioral probes (§3)
> before concluding either way.

---

## 3. Step 2 — Safe SSRF / reachability probe (GET-first, read-only)

The ProxyShell entry point is a **path-confusion SSRF** in
`EwsAutodiscoverProxyRequestHandler`. The handler only validates the URL *suffix*
when deciding `IsAutodiscoverV2PreviewRequest`, so an attacker-supplied explicit
logon address + `Email=` query erases part of the path during normalization and
reaches an arbitrary backend URL.

Canonical path-confusion shape (Orange Tsai):

```
/autodiscover/autodiscover.json?@foo.com/<backend-path>&Email=autodiscover/autodiscover.json%3f@foo.com
```

### Read-only confirmation matrix

Send **GET** requests only. Do not append `powershell`, `mapi/emsmdb`, or
`X-Rps-CAT` payloads that would drive the backend toward an authenticated action —
limit the backend path to a benign endpoint and read the response metadata.

| Signal | Vulnerable (ProxyShell reachable) | Patched / not exploitable |
|---|---|---|
| HTTP status on the `@`-confusion path | 200 / 301 / **302** (backend reached) | **400 / 401 / 404** (normalization rejected) |
| `X-CalculatedBETarget` header | Present, names a backend mailbox server | Absent or front-end only |
| `X-BEServer` / `X-FEServer` | BE target differs from FE (proxy followed the confused path) | BE = FE / generic proxy 400 |

**Interpretation for the engagement evidence (HTTP 400 + `X-BEServer`):**
- A plain **400 with `X-BEServer`** is the *patched / normal-proxy* signature, not
  the *vulnerable* one. The front-end forwarded to a backend and the backend
  rejected the malformed/normalized request. This matches §1's CU12 conclusion.
- To call ProxyShell exploitable you would need a **302/200 on the confusion path
  plus an `X-CalculatedBETarget` that you steered**, which a patched build will not
  give you.

> Stop-loss A: if the `@`-confusion path returns 400/401/404 and the build is
> post-May-2021, **stop the ProxyShell line of inquiry.** Record "ProxyShell not
> applicable (build patched, normalization enforced)" and pivot to §5.

---

## 4. Full chain logic (for understanding — do NOT execute unauthorized)

This is the mechanism so you can recognize each stage and reason about a real PoC.
Stages 2–3 are **[WRITE / privileged]** and only ever run against a target with
explicit written authorization and informed consent of consequences.

**Stage 1 — Pre-auth SSRF to the PowerShell backend (CVE-2021-34473).**
Use the path-confusion URL to reach `…/powershell` on the backend. This is the
ACL bypass: the request that should require authentication is proxied through.

**Stage 2 — Impersonate admin on the backend (CVE-2021-34523).** When the
PowerShell backend cannot find an `X-CommonAccessToken` header, it deserializes /
restores the caller identity from the **`X-Rps-CAT`** query-string parameter —
intended for internal Exchange PowerShell intercommunication. Supplying a crafted
`X-Rps-CAT` lets the attacker assume an admin identity on the Remote PowerShell
endpoint. **[WRITE — needs authorization]**

**Stage 3 — Arbitrary file write → RCE (CVE-2021-31207).** With admin PowerShell:
1. `New-ManagementRoleAssignment …` to grant the **Mailbox Import Export** role.
2. `New-MailboxExportRequest -Mailbox <user> -FilePath \\127.0.0.1\C$\inetpub\…\shell.aspx`
   writes a PST to an attacker-chosen path. The webshell body is **PST-encoded**
   beforehand so that when Exchange saves+encodes the export, it round-trips back
   into valid `.aspx` on disk → webshell → RCE as the Exchange app pool.
   **[WRITE — needs authorization + informed consent; this is the impact step]**

> Non-destructive equivalent for a PoC write-up: demonstrate Stage 1 reachability
> (302 + steered `X-CalculatedBETarget`) and, at most, a **benign read-only
> PowerShell command** under explicit authorization (e.g., `Get-Mailbox` count) to
> prove backend command execution — never the `New-MailboxExportRequest` webshell
> drop unless the program explicitly permits proof-of-RCE artifacts and you have a
> rollback/cleanup plan.

---

## 5. Adjacent chains — which build maps to which CVE class

When ProxyShell is patched (as on CU12), evaluate these before closing the target:

| Chain | CVEs | Auth needed | Applies to | Quick relevance to CU12 |
|---|---|---|---|---|
| **ProxyLogon** | CVE-2021-26855 (SSRF) + write→RCE | **Pre-auth** | 2013/2016/2019 unpatched ≤ Mar 2021 | Not applicable — CU12 far newer |
| **ProxyShell** | 34473 / 34523 / 31207 | **Pre-auth** | ≤ Apr/May 2021 SU level | Not applicable — patched ~Apr 2022 build |
| **ProxyNotShell** | CVE-2022-41040 (SSRF) + CVE-2022-41082 (RCE) | **Authenticated standard user** | 2013/2016/2019, patched **Nov 2022** | **Most relevant** — CU12 RTM/May/Aug22 builds predate the Nov 2022 SU |

**Action on a CU12 target:** the highest-value pivot is **ProxyNotShell**, because
the CU12 SU line (15.2.1118.7 / .9 / .12 / .15) all predate the November 2022
fixes. ProxyNotShell requires a single valid standard-user credential — so it is
only in play if the engagement provides (or allows obtaining) authenticated
access. Confirm the build is below the Nov-2022 SU, then evaluate the
authenticated-SSRF (41040) → backend PowerShell RCE (41082) path under the same
GET-first / authorized-write discipline as above.

---

## 6. Stop-loss conditions (when to close the ProxyShell line)

- **Build is post-May-2021 SU** (any 2019 ≥ CU10/CU11/CU12, or any build with
  KB5003435+): ProxyShell not applicable. Record and pivot. *(This case.)*
- **`@`-confusion path returns 400/401/404** with no steerable
  `X-CalculatedBETarget`: normalization is enforced → not exploitable.
- **`X-BEServer` present on a 400** with no 302/200 confusion success: this is
  normal FE→BE proxy behavior, not a working SSRF. Do not write up as ProxyShell.
- **No standard-user credential available** and target is patched against the
  pre-auth chains: ProxyNotShell is blocked too → park unless creds are obtainable
  in scope.

---

## 7. Evidence to record (RECON_DB / Finding)

- Exact build string + CU/SU mapping (with the two read-only sources used).
- The `@`-confusion probe URL, the HTTP status, and the full response headers
  (`X-BEServer`, `X-FEServer`, `X-CalculatedBETarget`).
- The explicit conclusion sentence: "Build is patched against ProxyShell;
  observed 400 + `X-BEServer` = normal proxy behavior" **or** "302 + steered BE
  target = ProxyShell SSRF reachable, escalation not executed (read-only)".
- If pivoting: the ProxyNotShell SU-gap assessment and credential availability.

---

## Sources

- Orange Tsai, "ProxyLogon is Just the Tip of the Iceberg: A New Attack Surface on Microsoft Exchange Server" (Black Hat USA 2021 handout, PDF): https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf
- Zero Day Initiative, "From Pwn2Own 2021: A New Attack Surface on Microsoft Exchange - ProxyShell!": https://www.thezdi.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell
- Viettel Cyber Security, "Pwn2Own 2021 Microsoft Exchange Exploit Chain": https://blog.viettelcybersecurity.com/pwn2own-2021-microsoft-exchange-exploit-chain/
- Mandiant / Google Cloud, "PST, Want a Shell? ProxyShell Exploiting Microsoft Exchange Servers": https://www.mandiant.com/resources/blog/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers
- Rapid7, "ProxyShell: More Widespread Exploitation of Microsoft Exchange Servers": https://www.rapid7.com/blog/post/2021/08/12/proxyshell-more-widespread-exploitation-of-microsoft-exchange-servers/
- Tenable, "ProxyShell: Attackers Actively Scanning for Vulnerable Microsoft Exchange Servers (CVE-2021-34473)": https://www.tenable.com/blog/proxyshell-attackers-actively-scanning-for-vulnerable-microsoft-exchange-servers-cve-2021-34473
- Qualys ThreatPROTECT, "ProxyShell – A New Attack Surface on Microsoft Exchange Server (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)": https://threatprotect.qualys.com/2021/08/10/proxyshell-a-new-attack-surface-on-microsoft-exchange-server-cve-2021-34473-cve-2021-34523-cve-2021-31207/
- Sophos News, "ProxyShell vulnerabilities in Microsoft Exchange: What to do" (affected CU/build ranges): https://news.sophos.com/en-us/2021/08/23/proxyshell-vulnerabilities-in-microsoft-exchange-what-to-do/
- Microsoft Support, "Description of the security update for Microsoft Exchange Server 2019, 2016, and 2013: April 13, 2021 (KB5001779)": https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064
- Microsoft Learn, "Exchange Server build numbers and release dates": https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
- Microsoft Download Center, "Cumulative Update 12 for Exchange Server 2019 (KB5011156)": https://www.microsoft.com/en-us/download/details.aspx?id=104131
- Microsoft Sentinel Analytic Rules, "Exchange SSRF Autodiscover ProxyShell - Detection" (probe paths / header artifacts): https://analyticsrules.exchange/analyticrules/968358d6-6af8-49bb-aaa4-187b3067fb95/
- Azure-Sentinel detection rule, ProxyShell Pwn2Own (IIS log signatures): https://github.com/Azure/Azure-Sentinel/blob/master/Detections/W3CIISLog/ProxyShellPwn2Own.yaml
- Unit 42 (Palo Alto Networks), "Threat Brief: CVE-2022-41040 and CVE-2022-41082 (ProxyNotShell)": https://unit42.paloaltonetworks.com/proxynotshell-cve-2022-41040-cve-2022-41082/
- Securelist (Kaspersky), "CVE-2022-41040 and CVE-2022-41082 – zero-days in MS Exchange": https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/
- TechTarget, "ProxyShell vs. ProxyLogon: What's the difference?": https://www.techtarget.com/whatis/feature/ProxyShell-vs-ProxyLogon-Whats-the-difference
- F5 Labs, "Microsoft Exchange ProxyShell Scanning Doubles in April 2026" (post-compromise hunting / IIS log paths): https://www.f5.com/labs/articles/microsoft-exchange-proxyshell-scanning-doubles-in-april-2026-as-two-distinct-campaign-clusters
- FDlucifer/Proxy-Attackchain (consolidated Proxylogon/Proxyshell/Proxytoken reference): https://github.com/FDlucifer/Proxy-Attackchain
