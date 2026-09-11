---
type: reference
category: Checklist
tags: [checklist, firmware, static-analysis, quality-gate, PoC, TWCERT, stop-loss, verification-boundary, QEMU, chroot]
last_updated: 2026-06-04
source: multiple separate sessions with explicit corrections on static analysis over-statement, missing dynamic gates, large-session near-zero yield
---

# Checklist — Firmware Static Analysis Quality Gates

> **Purpose**: Prevent static analysis findings from being over-stated, over-reported, or produced after sessions of near-zero yield. This checklist is mandatory at three stages: before analysis begins (pre-analysis gates), during binary examination (during analysis gates), and before any report output is produced (output gates).
>
> **Root cause of this checklist**: many session items express the same high-frequency pain across separate sessions — static results over-stated, dynamic confirmation gates missing, and large sessions concluding with only "binary confirmed as ELF." No existing checklist covered this. `bb-version-cve-precheck` handles pre-flight CVE lookup; this checklist handles everything from session scope-setting through report output quality.
>
> **Time budget**: Pre-analysis gates 10 min / Per-binary analysis 90 min max / Output gates before any report creation.

---

## Stage 1 — Pre-analysis Gates (Before analysis begins; any FAIL = immediate stop-loss)

### Gate 1.1 — Environment Availability

- [ ] **QEMU user-mode or chroot environment is available and tested** before committing >2 hours to static analysis.

  Quick smoke test:
  ```bash
  # QEMU user-mode (must match firmware ABI — MIPS, ARM, etc.)
  file <target_binary>                          # confirm ELF arch + ABI
  qemu-mips-static <target_binary> --help 2>&1 | head -5

  # chroot (requires matching sysroot)
  sudo chroot <rootfs_path> /bin/sh -c "uname -a"
  ```

  - If QEMU exits with `Invalid ELF image` or `Exec format error` → ABI mismatch → document ceiling, do not proceed with dynamic plans.
  - If chroot fails on missing shared libs → document missing libs, assess whether static analysis can be fully conclusive without dynamic confirmation.
  - **If neither QEMU nor chroot is available and the session plan assumes dynamic verification → declare environment ceiling in RECON_DB before any analysis. Do not spend >2h on static analysis expecting Grade A output.**

- [ ] **ABI confirmed**:

  | Firmware arch | QEMU binary to use |
  |---|---|
  | MIPS 32-bit LE | `qemu-mipsel-static` |
  | MIPS 32-bit BE | `qemu-mips-static` |
  | ARM 32-bit | `qemu-arm-static` |
  | ARM 64-bit | `qemu-aarch64-static` |
  | x86-64 | native chroot (no QEMU needed) |

  Mismatch → emulation will silently fail or produce wrong results. Confirm before spending time.

### Gate 1.2 — bb-version-cve-precheck (Mandatory §0g)

- [ ] **Run `bb-version-cve-precheck` skill before any binary analysis begins.**

  Minimum checks:
  ```bash
  # 1. Confirm firmware version from target binary or extracted rootfs
  strings <target_binary> | grep -iE "version|v[0-9]+\.[0-9]"
  cat <rootfs>/etc/version 2>/dev/null || cat <rootfs>/etc/firmware_version

  # 2. Check vendor download page for latest stable
  #    (Advisory version ≠ released version — always verify download page)

  # 3. Search NVD + vendor advisories
  #    NVD: https://nvd.nist.gov/vuln/search?query=<vendor>+<model>
  #    ExploitDB: https://www.exploit-db.com/search?q=<vendor>+<model>
  ```

  **Stop-loss trigger**: If a CVE matching the current firmware version and the vulnerability type you are investigating already exists in NVD or a published advisory → **stop immediately**. Record in RECON_DB:
  ```
  [STOP-LOSS] Existing CVE <ID> covers this attack surface on version <X>. No new finding.
  Ref: <NVD URL>
  ```
  Do not spend 6h confirming what a 5-minute search could have revealed. (See lessons; e.g. the CVE-2023-50358 case.)

### Gate 1.3 — Session Time-Box for Large Binaries

- [ ] **If target binary is >400 KB, time-box the session to 90 minutes before pivoting.**

  Rationale: Monolithic httpd binaries (Grandstream, NETGEAR RAX series, D-Link httpd) routinely exceed 2 MB and contain hundreds of CGI handler branches. Static analysis without dynamic confirmation cannot conclusively prove exploitability within a single session. 90 minutes is the functional ceiling for a single analyst.

  At 90-minute mark, mandatory decision:
  - If a specific exploitable call chain has been traced from user-controlled input to dangerous sink → proceed to Output Gates.
  - If analysis has produced only a list of suspicious functions without traced call chains → declare stop-loss, document in HANDOFF, schedule QEMU session.

  Time tracking:
  ```
  SESSION_START=$(date +%s)
  # ... analysis ...
  SESSION_NOW=$(date +%s)
  echo "Elapsed: $(( (SESSION_NOW - SESSION_START) / 60 )) minutes"
  ```

---

## Stage 2 — During Analysis Gates (mandatory checkpoints during analysis)

### Gate 2.1 — Caller Auth Check for system()/popen() Hits

- [ ] **For each `system()` or `popen()` grep hit, trace the caller chain and confirm whether authentication is checked before the call site is reached.**

  Required grep set:
  ```bash
  ROOTFS=/path/to/extracted/rootfs
  TARGET_BIN=$ROOTFS/usr/sbin/httpd   # adjust per target

  # Find all dangerous sinks
  objdump -d "$TARGET_BIN" | grep -E "call.*<system>|call.*<popen>|call.*<execv|bl.*system" > /tmp/sinks.txt

  # Cross-reference with strings to find CGI path associations
  strings "$TARGET_BIN" | grep -E "\.cgi|REQUEST_METHOD|QUERY_STRING|HTTP_" | head -30
  ```

  For each sink, answer all four questions before classifying as exploitable:

  | Question | Required Answer for "Exploitable" |
  |---|---|
  | Is the sink reachable from an HTTP handler? | Yes — CGI dispatch, SOAP handler, or URL routing reaches this function |
  | Is user-controlled input passed to the sink unsanitized? | Yes — `QUERY_STRING`, POST body, or HTTP header value flows to `system()`/`popen()` argument |
  | Is an authentication check performed before the sink is reached? | No auth check, or auth check can be bypassed |
  | Does the auth flag apply to this specific handler? | Confirmed by tracing the dispatch path (not assumed) |

  **If any question cannot be answered from static analysis → mark as `[needs dynamic confirmation]`, not as exploitable.**

  Reference: Monolithic httpd dual-dispatch pattern (Lesson: SOAP dispatch has auth flag; CGI dispatch may not — non-standard flag = target of analysis, not assumption).

### Gate 2.2 — Shared Library False-Positive Filter

- [ ] **If the same `sprintf`/`strcpy`/`system()` pattern appears in 3 or more unrelated binaries, test for shared library origin before opening findings.**

  Detection:
  ```bash
  # Find identical function patterns across binaries
  for bin in $ROOTFS/usr/bin/* $ROOTFS/usr/sbin/*; do
    strings "$bin" | grep -c "dangerous_pattern_string" 2>/dev/null
  done | sort -n | tail -20

  # Check if binaries share a common dynamic library
  for bin in $ROOTFS/usr/bin/* $ROOTFS/usr/sbin/*; do
    objdump -p "$bin" 2>/dev/null | grep NEEDED
  done | sort | uniq -c | sort -rn | head -10
  ```

  **Rule**: If the same `sprintf(buf, format, user_input)` pattern appears in 3+ binaries that have no logical relationship to each other (e.g., `ftpd`, `telnetd`, and `httpd`), the pattern likely originates in a shared library or vendored object file — not in each binary independently.

  Classification:
  - Shared lib confirmed → mark the pattern `[SAFE — shared lib, not per-binary vuln]`. Open one finding for the shared library, not N findings for N binaries.
  - Shared lib unconfirmed but suspected → mark `[needs shared-lib origin check]` before filing.

### Gate 2.3 — Double-Quote Wrapping Does Not Auto-Mitigate

- [ ] **When `system()` or `popen()` argument uses double-quote wrapping around user input, do NOT mark as mitigated. Mark as `[needs two-stage bypass test]`.**

  Pattern that is NOT safe:
  ```c
  // "Protected" by double quotes — still injectable
  snprintf(cmd, sizeof(cmd), "ping -c 1 \"%s\"", user_input);
  system(cmd);
  ```

  Two-stage bypass techniques to test:
  ```
  # Stage 1: close the double quote
  "; id; echo "

  # Stage 2: subshell within quotes (bash)
  $(id)

  # Stage 3: backtick within quotes (sh/ash)
  `id`

  # Newline injection (if input passes through HTTP header)
  %0a id %0a
  ```

  Required note in Finding or analysis notes:
  ```
  double_quote_wrap: present
  bypass_test: [needs dynamic test — two-stage bypass not confirmed/refuted by static analysis]
  verified_evidence: static
  ```

  Do not write "double-quote wrapping prevents exploitation" in a report unless you have dynamically confirmed it on the actual shell binary present in the firmware (sh/ash/bash have different behaviors).

---

## Stage 3 — Output Gates (mandatory checkpoints before writing a report)

### Gate 3.1 — Conditional Language for Non-Dynamically-Verified Findings

- [ ] **All report sections describing attack impact must use conditional language if the finding has NOT been dynamically verified on real hardware or a confirmed emulation environment.**

  Required language substitution table:

  | Prohibited (over-statement) | Required (accurate) |
  |---|---|
  | "allows attackers to execute arbitrary commands" | "may allow attackers to execute arbitrary commands if exploitable" |
  | "an attacker can inject OS commands" | "static analysis indicates an attacker may be able to inject OS commands" |
  | "vulnerable to command injection" | "contains a pattern consistent with command injection; requires dynamic verification" |
  | "confirmed RCE" | "static analysis indicates potential RCE; dynamic verification pending" |
  | "attacker can read any file" | "static analysis suggests path traversal may allow file reads; not confirmed on device" |

  Automated self-check before saving any report draft:
  ```bash
  # Grep for over-statement language in report
  grep -E "attacker can|allows .* to execute|confirmed RCE|is vulnerable to|an attacker can read" report_draft.md
  # Any hit → replace with conditional form before saving
  ```

### Gate 3.2 — Verification Boundary Header in TWCERT Reports

- [ ] **Every TWCERT report must include a `## Verification Boundary` section.**

  Template:
  ```markdown
  ## Verification Boundary

  This report is based on [static analysis of firmware version X.Y.Z / dynamic testing on real device / QEMU user-mode emulation].

  Verification scope:
  - Binary analyzed: <path/to/binary> (SHA-256: <hash>)
  - Emulation environment: [QEMU <arch>-static / chroot on <arch> / real device <model>] OR [not available — static only]
  - Dynamic confirmation: [Performed — see PoC section] / [Not performed — Grade B static analysis]
  - Conditions assumed but not verified: [list any assumptions, e.g., "assumes httpd is started as root", "assumes attacker has network access to management interface"]
  ```

  This section is mandatory because TWCERT reviewers have flagged the absence of verification scope statements in past reports. It also protects against severity inflation by making the evidence boundary explicit.

### Gate 3.3 — Grade Assignment (A / B)

- [ ] **Assign the correct grade before submission. Grade determines submission strategy.**

  | Grade | Verification | Acceptable for |
  |---|---|---|
  | **Grade A** | Dynamic PoC on real hardware OR QEMU/chroot confirmed execution (not just process start) | HackerOne P1-P2 bounty; TWCERT high-severity; HITCON ZD |
  | **Grade B** | Static analysis only; call chain traced but not executed | TWCERT standard disclosure; HITCON ZD with explicit static notation |
  | **Grade C** | Grep hit only; call chain not traced | KB note only — do NOT submit |
  | **Grade D** | Shared-lib false positive or double-quote bypass unconfirmed | SAFE or needs bypass test — do NOT submit |

  Grade A requires:
  ```bash
  # Minimum dynamic evidence for Grade A
  # 1. Binary executes in QEMU/chroot without crash before reaching the vulnerable path
  qemu-mipsel-static -L $SYSROOT $TARGET_BIN &
  # 2. PoC payload reaches the system() call and executes
  curl "http://127.0.0.1:<port>/<cgi_path>?param=<payload>"
  # 3. Output captured (id, whoami, or injected file creation)
  ```

  Grade B requires:
  - Full call chain traced from HTTP input to `system()`/`popen()` in disassembly or decompiled output.
  - Explicit note: `verified_evidence: static` in Finding frontmatter.
  - `[audit:static]` reference in Discovery Log.

### Gate 3.4 — No Credentials in PoC URLs

- [ ] **Remove all credentials, API keys, session tokens, and internal IP addresses from PoC URLs and curl commands before including them in any report.**

  Rationale: PoC URLs in reports are stored in vendor tracking systems and may be logged by proxies. Embedding credentials exposes them in server logs, ticket histories, and potentially in disclosed reports.

  Mandatory scrub before report finalization:
  ```bash
  # Check report for credential patterns
  grep -E "password=|passwd=|token=|api_key=|Authorization:|Cookie:|session=" report_draft.md

  # Replace with placeholder format
  # BEFORE: curl "http://192.168.1.1/cgi-bin/login?user=admin&password=admin123"
  # AFTER:  curl "http://<device-ip>/cgi-bin/login?user=<user>&password=<password>"
  ```

  Also remove:
  - Internal IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x) — replace with `<device-ip>` or `<target-ip>`
  - Actual session cookies from test sessions — replace with `<captured-session-cookie>`
  - Any API key or token used during testing — replace with `<api-key>`

---

## Stage 4 — Large Session Stop-Loss Gate

### Gate 4.1 — 100-Turn Stop-Loss

- [ ] **If the session has exceeded 100 turns and the primary conclusion is still only "binary confirmed as ELF" or "function X exists at address Y" — declare stop-loss immediately.**

  Stop-loss declaration format for HANDOFF.md:
  ```markdown
  ## [STOP-LOSS] <target> firmware static analysis — <date>

  Session turns: >100
  Conclusion reached: <e.g., "httpd binary is MIPS ELF, contains system() calls at 0x4087a0 and 0x40b240">
  Exploitability status: NOT CONFIRMED — call chain not traced, auth check not verified
  Reason for stop-loss: Session exceeded 100 turns without reaching a traceable exploit path
  Next action required:
  - [ ] Set up QEMU mipsel-static emulation environment
  - [ ] Trace call chain from CGI dispatcher to system() at 0x4087a0
  - [ ] Verify auth flag applicability to target CGI path
  Estimated time to complete: <X> hours in next session
  Do NOT open a Finding until call chain is fully traced and auth bypass is confirmed.
  ```

  **A 100-turn session that produces only "ELF confirmed" is a net-negative session** — it consumes context without advancing evidence. Stop-loss + HANDOFF is always better than pushing to 200 turns hoping something will click.

---

## Quick Reference — Gate Summary

| # | Gate | Stage | Fail action |
|---|---|---|---|
| 1.1 | QEMU/chroot available before >2h investment | Pre | Declare environment ceiling in RECON_DB |
| 1.2 | bb-version-cve-precheck — existing CVE match | Pre | Stop-loss immediately |
| 1.3 | Binary >400 KB → 90-min time-box | Pre | Pivot after 90 min or declare stop-loss |
| 2.1 | system()/popen() hit → trace caller auth check | During | Mark `[needs dynamic confirmation]` |
| 2.2 | Same pattern in 3+ binaries → shared-lib test | During | Mark `[SAFE — shared lib]` or needs check |
| 2.3 | Double-quote wrap → NOT auto-mitigated | During | Mark `[needs two-stage bypass test]` |
| 3.1 | Conditional language if not dynamically verified | Output | Replace prohibited language per table |
| 3.2 | Verification Boundary header in TWCERT reports | Output | Add section before submission |
| 3.3 | Grade A = dynamic PoC; Grade B = static traced | Output | Assign grade, adjust submission target |
| 3.4 | No credentials in PoC URLs | Output | Scrub before finalization |
| 4.1 | >100 turns + "ELF confirmed" only → stop-loss | Ongoing | HANDOFF + next-session action list |

---

## Related

- [[bb-version-cve-precheck]] — skill for pre-flight CVE/advisory check (Gate 1.2)
- [[Pattern - Firmware CGI Command Injection Grep]] — grep methodology for Gates 2.1–2.3
- [[Reference Card - TWCERT CVE Form]] — Gate 3.2 verification boundary field placement
- [[Lessons Learned]] — three must-dos for firmware analysis; static architectural conclusions must be dynamically verified; CGI command injection grep + trace back one layer
- [[Checklist - Attack Surface Coverage]] — upstream gate before firmware analysis begins
