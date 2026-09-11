---
type: playbook
category: playbook
tags:
  - playbook
  - firmware
  - iot
  - router
  - twcert
  - bb-playbook
  - session-lifecycle
last_updated: 2026-06-04
precedents:
  - Tenda W15E
  - D-Link consumer routers
  - NETGEAR WAX620/WAX630/RAX50
  - "Camera vendors"
  - Sapido RB-1732
---

# Playbook — IoT Firmware Analysis Session

> **One-liner**: From vendor download page to TWCERT-ready report — a single-document session lifecycle for IoT/router firmware bug bounty.

No existing playbook covers the end-to-end IoT firmware analysis workflow. This playbook consolidates the most repeated corrections across sessions (items 2, 5, 8, 15, 19, 21, 23, 24, 36, 37, 39, 40, 43, 57, 58, 62, 68) into a mandatory, gate-enforced flow. The existing [[Pattern - Firmware CGI Command Injection Grep]] covers detection; this playbook covers everything before and after it.

---

## Phase 0 — Pre-flight（強制 — 分析前必做，禁止跳過）

**Gate**: Do not proceed past Phase 0 until all three sub-tasks are complete.

### 0a. Run `bb-version-cve-precheck`

Before touching any firmware file or initiating a download:

```bash
# Confirm vendor latest stable version from official download page (not WebSearch)
# Pattern: HEAD https://www.vendor.com/support/download/<model>
# Then cross-reference with CVE/advisory databases

# Trigger the skill
# (in Claude session: Skill: bb-version-cve-precheck)
```

**Stop-loss criteria** (quit Phase 0 and abort session):
- Firmware version matches an existing CVE you did not find (撞洞風險).
- Vendor advisory says this model is EOL **and** TWCERT does not accept TVN for EOL-without-patch (verify with TWCERT policy first — EOL/defunct vendor may still qualify).
- Target has already been analyzed in a prior session with no deferred actions outstanding.

If the version pre-check is clean, record in `RECON_DB.md`:

```markdown
## §0g Pre-flight
- Model: <MODEL>
- Firmware version confirmed: <VERSION>
- Source URL: <URL> (retrieved YYYY-MM-DD)
- CVE search: NVD, ExploitDB, vendor advisories — no matching CVE found
- Prior session check: FINDINGS_QUICK_REF.md reviewed, no overlap
```

### 0b. Read `HANDOFF.md` for deferred actions from prior sessions

```bash
cat workshop/<target>/HANDOFF.md
```

Any item tagged `MANDATORY_SESSION_OPEN` must be acted on **before** proceeding. Examples:
- "Deferred RCE trigger — requires physical access to LAN port; confirm feasibility."
- "SPK download mismatch — recheck vendor page for updated binary."
- "MD5 sibling-model check pending — grab WAX630E and WAX610Y squashfs-root."

Do not skip deferred items on the assumption they are resolved. They are in HANDOFF.md because they were not confirmed.

### 0c. Confirm workspace state to avoid re-analysis

```bash
bash automation/session_start_brief.sh <target> "<keyword>" "<host>"
```

If `RECON_DB.md` shows a completed extraction pass (squashfs-root MD5 recorded, binary strings dumped, CGI audit done), do not re-run binwalk. Extend from the last known state.

---

## Phase 1 — Firmware Acquisition

### 1a. Primary source: vendor FTP / official download page

Use the vendor's official download page or FTP, not a WebSearch result. WebSearch may surface outdated mirrors, incorrect model variants, or redistributed binaries.

```bash
# Retrieve download page directly
curl -s "https://www.vendor.com/support/download/<model>" | grep -i "\.bin\|\.zip\|\.img" | head -20

# Or enumerate known FTP structure
curl --list-only ftp://ftp.vendor.com/firmware/<model>/
```

Record the exact URL and retrieval timestamp in `RECON_DB.md §§ Operation Log`.

### 1b. Regional mirror fallback

If the primary source is unavailable (403, rate-limited, geoblocked):

1. AU distributor site (often mirrors US release within 24-48h).
2. EU distributor site (separate regulatory release cycle — may have older version).
3. GitHub mirrors: search `github.com <vendor> <model> firmware` — community repacks are acceptable for static analysis but flag in report as `[audit:community-mirror]`.

Do not use torrents or third-party file hosts — hash verification becomes unreliable.

### 1c. NETGEAR naming: enumerate suffix variants with HEAD requests first

NETGEAR releases firmware under model suffixes (WAX630E, WAX630EX, WAX610Y, WAX610Y-100AJS) that share binaries or differ by region. Before attempting a full download:

```bash
# HEAD-request each candidate — 200 = exists, 404 = skip
for suffix in "" "E" "EX" "Y" "-100AJS"; do
  url="https://www.downloads.netgear.com/files/GDC/WAX630${suffix}/WAX630${suffix}-V3.0.X.X.zip"
  code=$(curl -s -o /dev/null -w "%{http_code}" --head "$url")
  echo "WAX630${suffix}: $code"
done
```

Only download confirmed 200 responses. Record every suffix tested and the response code.

### 1d. SPK/version mismatch — confirm available version before download

If the advisory lists version X.Y.Z but the download page only offers X.Y.W:

1. Do **not** assume X.Y.W contains the same code. Check the changelog.
2. Do **not** download and analyze X.Y.W against advisories written for X.Y.Z.
3. Record the mismatch in `MASTER_STATUS.md` and wait for either: (a) vendor posts X.Y.Z, or (b) you can confirm from the changelog that X.Y.W supersedes X.Y.Z.

```markdown
## SPK mismatch — <MODEL> (recorded YYYY-MM-DD)
- Advisory version: X.Y.Z
- Available on download page: X.Y.W
- Action: parked pending vendor update or changelog confirmation
```

### 1e. Encrypted firmware — immediate stop-loss

If binwalk entropy analysis shows high entropy throughout (>7.5 bits/byte) with no identifiable filesystem signature:

```bash
binwalk -E firmware.bin  # entropy graph
# If flat high entropy across entire file → encrypted
```

**Do not invest further in this firmware image.** Update `MASTER_STATUS.md` immediately:

```markdown
## <MODEL> firmware — ENCRYPTED — STOP LOSS (YYYY-MM-DD)
- binwalk entropy: flat ~7.9 bits/byte, no FS signature
- No decryption key available
- Action: deprioritized; revisit only if decryption key surfaces (vendor leak, hardware dump)
```

Do not attempt XOR brute-force or padding oracle speculation unless you have a concrete lead. Time spent on encrypted firmware without a key is unbounded.

---

## Phase 2 — Initial Triage

### 2a. Squashfs-root MD5 across sibling models — confirm shared codebase

Before writing separate reports for WAX620, WAX630, WAX610Y, check whether they share the same squashfs-root:

```bash
md5sum _WAX620.bin.extracted/squashfs-root/usr/sbin/httpd
md5sum _WAX630.bin.extracted/squashfs-root/usr/sbin/httpd
md5sum _RAX50.bin.extracted/squashfs-root/usr/sbin/httpd
```

If hashes match: one finding covers all models. State in every report: "Confirmed identical binary (MD5: `<hash>`) across WAX620/WAX630/RAX50."

If hashes differ: run the full analysis per model; do not assume the vulnerability exists in all.

### 2b. .NET applications — ilspycmd decompile + grep crypto constants

For firmware containing `.dll` or `.exe` (NAS web UI, Synology SPK, Windows embedded):

```bash
# Install ilspycmd if not present
dotnet tool install -g ilspycmd

# Decompile target assembly
ilspycmd /path/to/firmware/webui.dll -o /tmp/decompiled/

# Grep for hardcoded crypto
grep -rn "AES\|DES\|3DES\|RC4\|MD5\|SHA1" /tmp/decompiled/ | grep -v "//\|using " | head -30
grep -rn '"[A-Za-z0-9+/=]\{16,\}"' /tmp/decompiled/ | head -20  # potential base64 keys
grep -rn "new.*Key\|KeySize\|IV\s*=\|InitVector\|hardcoded\|private.*key" /tmp/decompiled/ | head -20
```

For AES-GCM, flag static IV usage:

```bash
grep -rn "new byte\[\]\|GcmParameterSpec\|IvParameterSpec\|nonce\s*=" /tmp/decompiled/ | head -20
```

Cross-reference with [[Pattern - Static IV in AES-GCM]] and [[Pattern - Hardcoded Credentials]].

### 2c. Identify QEMU/chroot feasibility for target ABI

Dynamic emulation has hard limits. Assess before committing time:

```bash
file squashfs-root/usr/sbin/httpd
# Output examples:
# ELF 32-bit LSB executable, MIPS, MIPS32 rel2  → qemu-mips-static feasible
# ELF 32-bit LSB executable, ARM, EABI5          → qemu-arm-static feasible
# ELF 64-bit LSB executable, AArch64             → qemu-aarch64-static feasible
```

**Feasibility checklist**:

| Condition | Decision |
|-----------|----------|
| ABI matches available qemu-*-static binary | Proceed with chroot |
| Firmware mounts flash (CMS/JFFS2 with runtime-only paths) | Static analysis only — note `[audit:static]` |
| Binary requires proprietary kernel module | chroot will fail; use static only |
| ABI mismatch (e.g., MIPS64 with MIPS32 static) | Stop; static only |

If emulation ceiling is hit, record it in RECON_DB and proceed with static. Do not waste time debugging chroot failures past 30 minutes.

---

## Phase 3 — Vulnerability Hunting

Follow [[Pattern - Firmware CGI Command Injection Grep]] as the primary detection pipeline.

### 3a. Extended sink list (beyond Pattern)

In addition to the pattern's `system()` / `popen()` grep, cover:

```bash
# Stack buffer overflow candidates
grep -rn "strcpy\|strcat\|sprintf\|gets\|scanf" squashfs-root/usr/sbin/ | \
  grep -v "//\|#define\|strncpy\|snprintf" | head -40

# Hardcoded credentials (post-Pattern)
grep -rn "admin\|password\|passwd\|secret\|default" squashfs-root/etc/ | \
  grep -v ".pyc\|Binary" | head -30
strings squashfs-root/usr/sbin/httpd | grep -iE "admin|root|password|1234|default" | head -20

# Exposed debug interfaces
grep -rn "telnetd\|dropbear\|sshd" squashfs-root/etc/init.d/ squashfs-root/etc/rcS 2>/dev/null
find squashfs-root/etc -name "*.conf" | xargs grep -l "telnet\|debug\|uart" 2>/dev/null
```

### 3b. Auth flag audit — dual dispatch pattern

Monolithic httpd binaries (GoAhead, Boa, custom) often have two dispatch paths: one with auth check, one without. Identify the non-auth path:

```bash
# Look for auth bypass flag in CGI dispatch table
grep -rn "AUTH_REQUIRED\|needAuth\|isAuth\|bypass\|skipAuth\|noAuth" \
  squashfs-root/usr/sbin/httpd | head -20

# SOAP vs CGI split (D-Link/NETGEAR pattern)
strings squashfs-root/usr/sbin/httpd | grep -i "soap\|action\|service" | head -20
```

Non-standard flags (e.g., `AUTH_REQUIRED = 0` set explicitly) are the primary target list. Each flag=0 entry is a potential pre-auth endpoint.

### 3c. Dedup by root cause before creating Findings

Same root cause = one Finding, multiple affected endpoints listed in "Affected Endpoints" table. Do not create one Finding per endpoint.

Examples:
- "5 CGI handlers all lack input sanitization on the `pingAddr` / `host` / `ip` parameter pattern" = 1 Finding (CGI CMDi).
- "3 endpoints use `strcpy` into a 256-byte stack buffer" = 1 Finding (Stack BOF) with 3 rows in the table.
- "Telnetd enabled by default AND default root:admin credentials" = 1 Finding (Default Credentials + Attack Vector) if they share root cause.

---

## Phase 4 — Report Writing

### 4a. Same-series report N uses report N-1 as template

For NETGEAR WAX610Y report when WAX620 report already exists:

1. Copy the WAX620 Submission file.
2. Diff fields: model name, firmware version, MD5 hash, CVSS vector (if reachability differs), affected endpoint list.
3. Fill only the diff. Do not rewrite narrative sections if they are model-agnostic.
4. Verify the binary hash confirms identical vulnerability (Phase 2a).

This saves 80% of write time per sibling model report. The TWCERT submission form accepts "same vulnerability, different model" framing explicitly.

### 4b. Conditional CVSS — SSH/Telnet reachability

If the vulnerability is pre-auth but only reachable over LAN (typical for home routers), provide two CVSS scores with explicit conditions:

```markdown
## CVSS Scores

**Internet-facing (Attack Vector: Network)**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — Base: 9.8 (Critical)
*Applicable when: web management interface exposed on WAN port (common in ISP-deployed units)*

**LAN-only (Attack Vector: Adjacent)**
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — Base: 8.8 (High)
*Applicable when: web management interface accessible only on LAN*
```

Do not pick the higher score and omit the condition. TWCERT reviewers will flag inconsistency.

### 4c. No internal IDs in report body

Internal tracking IDs (e.g. VENDOR-001, VENDOR-F-007, VENDOR-RCE-02) must not appear in the submitted report body, title, or CVSS string.

Acceptable locations: Vault Finding file frontmatter, FINDINGS_QUICK_REF.md, personal notes.

Violation example (do not do):
> "As documented in an earlier finding, the endpoint /goform/formSetQos..."

Correct:
> "The endpoint `/goform/formSetQos` passes the `wan_ip` parameter directly to `system()`..."

### 4d. EOL/defunct vendor — TWCERT TVN without vendor patch

If the vendor is EOL or unreachable, TWCERT can publish a TVN (Taiwan Vulnerability Note) without a vendor-supplied patch. Include in the report:

```markdown
## Vendor Status
Vendor <NAME> has been confirmed EOL / unreachable as of <DATE>. No patch coordination is possible. Requesting TWCERT publish TVN per TWCERTCC Vulnerability Disclosure Policy v2.2 §4.3 (no-response / EOL exception).
```

Verify the specific section number from the current TWCERT policy PDF before filing. Do not cite from memory.

---

## Phase 5 — Cross-Session Deferred Actions

### 5a. What must go into HANDOFF.md

Any of the following must be recorded in `workshop/<target>/HANDOFF.md` before ending the session, tagged `MANDATORY_SESSION_OPEN`:

| Deferred item type | Example |
|-------------------|---------|
| Unconfirmed RCE (trigger-dependent) | "Stack BOF in formSetRoute confirmed via strings; need QEMU dynamic trigger to confirm exploitability. Attempt on next session with MIPS chroot." |
| Version mismatch unresolved | "Advisory says V3.2.1 but only V3.2.0 on download page — recheck vendor page next session." |
| Sibling-model MD5 check pending | "WAX630E and WAX610Y not yet downloaded; cannot confirm shared codebase with WAX620." |
| Encrypted firmware lead | "Vendor support forum post mentions debug UART interface on J6 header — physical dump may yield key." |
| TWCERT filing blocked | "TWCERT form requires vendor official response date; email sent YYYY-MM-DD, await reply." |

### 5b. HANDOFF.md format

```markdown
# HANDOFF — <TARGET> — <DATE>

## MANDATORY_SESSION_OPEN

- [ ] [DEFERRED-RCE] formSetRoute stack BOF: confirm exploitability via MIPS QEMU dynamic trigger. Binary: `usr/sbin/httpd` (MD5: abc123). GDB attach command: `qemu-mips-static -g 1234 ./httpd`. Last state: segfault at offset 300 in `pingAddr` buffer.
- [ ] [VERSION-MISMATCH] WAX630 V3.2.1 (advisory) vs V3.2.0 (download page). Recheck: https://www.downloads.netgear.com/files/GDC/WAX630/
- [ ] [SIBLING-MD5] Download WAX630E + WAX610Y, run MD5 against httpd binary, record in RECON_DB.

## Session end state
- Findings created: <N>
- TWCERT forms ready: <N>
- Next priority: <one-liner>
```

### 5c. Cross-session dedup discipline

At the start of every session on a target that has HANDOFF.md items, resolve them first. Do not start new hunting while mandatory deferred items are open. The deferred item may invalidate work done in the new hunting session (e.g., if the SPK mismatch means you analyzed the wrong version).

---

## Lifecycle Map

```
[Phase 0: Pre-flight]
  ↓ bb-version-cve-precheck → clean
  ↓ HANDOFF.md deferred items → resolved or noted
  ↓ workspace state → confirmed (no re-analysis)
       ↓
[Phase 1: Firmware Acquisition]
  ↓ official download page → confirmed version
  ↓ SPK mismatch? → park and stop
  ↓ encrypted? → stop-loss immediately
       ↓
[Phase 2: Initial Triage]
  ↓ squashfs-root MD5 → shared codebase confirmed/denied
  ↓ .NET? → ilspycmd decompile + crypto grep
  ↓ ABI → QEMU feasibility decision
       ↓
[Phase 3: Vulnerability Hunting]
  ↓ Pattern - Firmware CGI Command Injection Grep
  ↓ extended sinks (strcpy, hardcoded creds, telnetd)
  ↓ auth flag audit (dual dispatch)
  ↓ dedup by root cause → N findings (not N×endpoints)
       ↓
[Phase 4: Report Writing]
  ↓ sibling-model → copy N-1 template, fill diff only
  ↓ conditional CVSS (LAN vs WAN)
  ↓ no internal IDs in report body
  ↓ EOL vendor → TWCERT TVN exception
       ↓
[Phase 5: Cross-Session Deferred Actions]
  ↓ all unconfirmed RCE / version mismatches → HANDOFF.md
  ↓ session_end_checklist.sh <target>
  ↓ vault-sync agent
```

---

## Session-end Gate Checklist

```
FIRMWARE SESSION GATE (run before marking session complete)
□ Phase 0: bb-version-cve-precheck recorded in RECON_DB §0g
□ Phase 0: HANDOFF.md deferred items resolved or re-documented
□ Phase 1: Firmware source URL + retrieval date in RECON_DB Operation Log
□ Phase 1: SPK/version mismatch (if any) recorded in MASTER_STATUS.md
□ Phase 2: squashfs-root MD5 recorded for each model analyzed
□ Phase 2: QEMU feasibility decision documented
□ Phase 3: Dedup by root cause applied — no N-endpoint split on same sink
□ Phase 4: No internal IDs in any report body
□ Phase 4: CVSS scores conditional if reachability variable
□ Phase 5: All unconfirmed deferred actions in HANDOFF.md as MANDATORY_SESSION_OPEN
□ bash automation/session_end_checklist.sh <target> passed
```

---

## Cross-Reference

- [[Pattern - Firmware CGI Command Injection Grep]] — Phase 3 primary detection pipeline
- [[Pattern - Hardcoded Credentials]] — Phase 3 extended sink search
- [[Pattern - Static IV in AES-GCM]] — Phase 2b .NET crypto grep follow-up
- [[Pattern - Supply Chain Analysis]] — shared SDK = same vuln across vendors (sibling MD5 extension)
- [[Checklist - Web Vuln Technique Coverage]] — for web-accessible CGI endpoints
- [[Reference Card - TWCERT CVE Form]] — Phase 4 TWCERT filing format
- `bb-version-cve-precheck` skill — Phase 0a mandatory trigger
- `bb-dedup-finding` skill — Phase 3 dedup gate before creating Findings
- `bb-evidence-readiness` skill — Phase 4 pre-report evidence check
- [[Lessons Learned]] #7, #15, #19, #21, #23, #24, #36, #37, #39, #40, #43, #57, #58, #62, #68, #99
