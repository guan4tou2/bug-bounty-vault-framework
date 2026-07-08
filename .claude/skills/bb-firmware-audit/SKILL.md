---
name: bb-firmware-audit
description: Use when analyzing router / IoT / camera firmware or an embedded binary — after bb-version-cve-precheck, to run the unpack → triage → grep-hunt → graded-report session with explicit stop-loss and quality gates. Triggers: firmware / binwalk / squashfs / CGI command injection / router / IoT firmware / default creds / authorized_keys backdoor.
---

# Bug Bounty — Firmware Audit (firmware session lifecycle)

End-to-end firmware session: **unpack → triage → grep-driven hunt → graded report**, with hard STOP-LOSS gates up front (is this even worth unpacking?) and QUALITY gates before any claim leaves as a report. This skill is the **orchestration layer** — the detection recipes are inlined below at the phase where you need them.

**Composes with `bb-version-cve-precheck` (runs FIRST).** That skill owns version confirmation + CVE/advisory lookup. Do not re-run its logic here — this skill assumes the precheck already passed and picks up at acquisition/unpack. If you haven't run it, stop and run it now.

## Trigger

Any firmware / embedded-binary target: `.bin` / `.img` / SPK / squashfs / JFFS2 / UBI in hand, a router / IP-camera / NAS / IoT model, or "start analyzing this firmware" / "unpack this firmware".

---

## Phase 0 — Pre-analysis STOP-LOSS gates (before touching it; any FAIL = stop immediately)

Do not unpack until all pass:

1. **CVE pre-flight** — `bb-version-cve-precheck` clean (no CVE matches this version + vuln type). A match → record the stop-loss in RECON_DB, no Finding.
2. **Latest-stable** — you downloaded the vendor's newest stable from the **official** page/FTP (not a search-engine mirror). An old version = high collision risk (a common lesson: old firmware is far more likely to collide with an already-reported bug). If the advisory version ≠ the download-page version → trust the download page, record the discrepancy.
3. **Version already analyzed** — this firmware hash/version ≡ a prior session's → STOP, extend from the last state, don't re-binwalk.
4. **ABI feasibility** — `file <binary>` → is there an available `qemu-<arch>-static` match (MIPS BE/LE, ARM, AArch64)? No match → mark it `qemu-ceiling`, static-only, and **limit every claim accordingly** (a usermode QEMU without a matching ABI cannot prove execution).
5. **Encrypted image** — `binwalk -E` shows flat high entropy (>7.5 bits/byte, no filesystem signature) → immediate stop-loss; no XOR/padding-oracle speculation without a concrete key lead.
6. **CMS/flash dependency** — flash-dependent init (`/proc/mtd`, NAND read, CMS) → the dynamic ceiling is explicit; the report is static-only.

Also: resolve any deferred "must-do at session open" items from your handoff notes before new hunting.

---

## Phase 1 — Unpack & triage

```bash
binwalk -Me firmware.bin          # squashfs; jefferson=JFFS2, ubi_reader=UBI
cd _firmware.bin.extracted/squashfs-root/
file usr/sbin/httpd               # arch/ABI → confirms Phase-0 gate 4
```

- **Sibling-model hash** — before writing per-model reports, `md5sum` the httpd/main binary across sibling SKUs. Identical hash = **one Finding covers all models** (state the shared hash in the report). Different = analyze each.
- **Time-box**: a binary >400 KB → 90-minute ceiling before you pivot or write a handoff. A monolithic httpd cannot be conclusively proven safe by static analysis alone in one session.

---

## Phase 2 — Grep-driven hunting

Primary detection method: grep the sinks → trace each hit's parameter **back one function** → is the HTTP parameter user-controlled + unsanitized? → classify pre/post-auth. (This one-level-back traceback is what separates a real finding from a grep hit.)

Run these hunting tracks per target:

| Track | Look for |
|---|---|
| **CGI command injection** | `system(` / `popen(` / `execve(` / vendor wrappers (`doSystemCmd`, `qnap_exec`, etc.); IP-camera DDNS/PPPoE/NTP/timezone/MAC fields; unquoted `$1`/`$VAR` in `*.sh` |
| **Default / weak credentials** | `/etc/default/*.conf` (an empty-password account like `ACCOUNT_USER0='admin,'`), `/etc/passwd`+`/etc/shadow`, hardcoded `admin/1234`; factory-reset restores it |
| **Shipped SSH backdoor** | `authorized_keys*` / `*.pub` in rootfs + `PermitRootLogin yes`; a key comment like `root@kali` = dev/ODM leftover; the same key across ODM-shared SKUs = a whole-series backdoor |
| **Extended sinks** | `strcpy`/`strcat`/`sprintf`/`gets` (stack BOF); `telnetd`/`dropbear` in init.d; dual-dispatch auth flags (`AUTH_REQUIRED=0`) — a non-standard flag is a target list, decode it |
| **Vendor-ecosystem lateral** | fingerprint the model string (`var model="..."`) → list sibling SKUs → try known weak creds on each (shared credentials across a vendor's line is a force multiplier) |

**Firmware = a dev-environment snapshot**: after the first finding, grep wider — `known_hosts`, build paths, dev emails, expired TLS certs often ship alongside.

---

## Phase 3 — During-analysis QUALITY gates (every sink passes these)

Do not skip straight to a Finding:

- **Caller auth trace** — for each `system()`/`popen()` hit, trace the caller chain: reachable from an HTTP handler? is user input unsanitized to the arg? is there an auth check before the sink, and does that auth flag apply to *this* handler (traced, not assumed)? Anything unanswerable from static → mark `[needs dynamic confirmation]`, **not** exploitable.
- **Shared-lib false-positive filter** — the same `sprintf`/`strcpy`/`system` pattern in 3+ unrelated binaries (ftpd, telnetd, httpd) → likely a shared lib; one Finding for the lib, not N. Mark `[SAFE — shared lib]` or `[needs shared-lib origin check]`.
- **Double-quote ≠ mitigated** — `system("... \"%s\" ...", input)` is NOT safe. Mark `[needs two-stage bypass test]` (backtick / `$()` inside quotes; newline). Never write "double-quote wrapping prevents exploitation" without a dynamic test on the actual shell (sh/ash/bash differ).
- **Dedup by root cause** — the same sink pattern across 5 handlers = **1 Finding** with an Affected-Endpoints table, not 5. (Different param *classes* — ping/DNS/traceroute — may split.)

---

## Phase 4 — Output gates & grading (before writing the report)

Three things are mandatory (strings-only evidence = Grade C, not submittable): `strings -t x` offsets → `objdump`/Ghidra call chain → a local C PoC.

- **Conditional language** unless dynamically verified — "may allow … if exploitable", "static analysis indicates …", never "confirmed RCE" / "attacker can execute". Self-check: `grep -E "attacker can|allows .* to execute|confirmed RCE|is vulnerable to" report.md`.
- **Grade** — A = dynamic PoC on hardware/QEMU-chroot (execution, not just process start) → bounty/high-sev; B = full static call-chain traced, `verified_evidence: static` + `[audit:static]` → advisory/CERT standard; C = grep hit only → KB note, **do not submit**; D = shared-lib FP / unconfirmed double-quote bypass → do not submit.
- **Verification Boundary** section mandatory in advisory-style reports (binary + SHA-256, emulation environment or "static only", assumptions not verified).
- **Conditional CVSS** when reachability varies — dual score (AV:N internet-facing vs AV:A LAN-only) with explicit conditions; never silently pick the higher one.
- **Scrub** PoC URLs — no creds/tokens/session cookies/internal IPs (→ `<device-ip>`); **no internal Finding IDs** in the report body/title/CVSS.
- **Sibling-model report N** = copy report N-1, diff only model/version/hash/CVSS/endpoints (~80% time saved).

---

## Delegate the heavy binary pass to a subagent

Long, token-heavy work → an **isolated context** (the main conversation should ingest only the graded conclusion). Delegate to a subagent when:

- Disassembling/decompiling a monolithic httpd (>400 KB, hundreds of CGI branches) — Ghidra/objdump call-chain tracing.
- Bulk grep-and-triage across an entire rootfs or **multiple sibling SKUs** in one pass.
- QEMU/chroot bring-up + dynamic PoC attempts (unbounded debugging risk → time-box, own context).

**Inject into the subagent prompt** (it does NOT inherit your global conventions): the analysis-layer conventions — the Phase-3 quality gates (auth-trace, shared-lib filter, double-quote), the Grade rubric, dedup-by-root-cause, `[audit:static]` for static claims, and "return traced call chains + grades, not raw strings dumps."

---

## 100-turn stop-loss (ongoing)

If you're >100 turns in and the only conclusion is "binary is ELF / function X at addr Y" — declare stop-loss + a handoff note (the exact next-session QEMU/trace action). A 100-turn "ELF confirmed" session is net-negative. Do NOT open a Finding until the call chain is traced and the auth bypass is confirmed.

---

## Cross-reference

- `bb-version-cve-precheck` (Phase 0, runs first)
- `bb-surface-mapping` (map the firmware's surface: CGI handlers, init scripts, exposed services)
- `bb-dedup-finding` (Phase 3 dedup by root cause)
- `bb-evidence-readiness` / `bb-submission-readiness` (Phase 4)
- `09 - Knowledge Base/Lessons Learned.md` — firmware version/collision/shared-credential lessons
