---
type: wiki
category: tool
tool: burp-pro
status: active
last-updated: 2026-04-21
---

# Burp Pro Advanced Usage (2026 Edition)

> **Purpose:** Level up from "basic interception" to advanced workflows like Collaborator + Logger++ + BCheck + Turbo Intruder + Bambda. Mastering these = 10x hunting efficiency.

## 0. Basic Setup

```
Project options → TLS → auto-trust cert (for loopback)
Project options → Sessions → set up cookie jar
User options → Extender → load Jython / JRuby
User options → Connections → Upstream proxy (corporate proxy / tor)
Target scope → precisely set in-scope domains (avoid hitting OOS)
```

## 1. Collaborator (essential for OOB)

### 1.1 Basics

```
Burp → Collaborator → Copy to clipboard → get an FQDN
Insert it anywhere → DNS / HTTP requests will call back to Burp
```

### 1.2 Use cases

- **Blind XSS / SSTI / SSRF / XXE / RCE** verification
- **Log4Shell** DNS query
- **Blind SQLi** load_file UNC (Windows) / UTL_HTTP (Oracle)

### 1.3 Private instance

```
# Stand up a self-hosted collaborator (avoid public-IP rate limits)
burp-collaborator-server --config=config.yaml
# Configure a public domain / ACM cert / NS record pointing to your VPS
```

### 1.4 Burp Professional vs Community

Community edition's Collaborator is shared (rate-limited); Pro edition supports a private instance.

## 2. Intruder Modes

### 2.1 Sniper

```
Single-point attack; each position takes turns receiving payloads
```

### 2.2 Battering ram

```
All positions get the same payload simultaneously
(e.g. login username=password=admin)
```

### 2.3 Pitchfork

```
Multiple wordlists mapped 1:1 (same index)
```

### 2.4 Cluster bomb

```
Multiple wordlists, Cartesian product (username × password, all combinations)
```

### 2.5 Payload processing

```
Encoding / Hashing / Custom Jython script
```

## 3. Turbo Intruder (10x faster)

Burp extension capable of sending 10,000 requests per second.

### 3.1 Install

```
BApp Store → Turbo Intruder
```

### 3.2 Script template

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=100,
        pipeline=False
    )
    for word in open('/usr/share/wordlists/rockyou.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if req.status != 401:
        table.add(req)
```

### 3.3 Race condition

```python
engine.queue(target.req, gate='race1')
engine.queue(target.req, gate='race1')
engine.openGate('race1')    # fire simultaneously
```

### 3.4 Single-packet attack (HTTP/2)

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    engine=Engine.BURP2
)
# Pack multiple requests into a single TCP packet → microsecond-level simultaneous processing
```

See James Kettle's 2023 research: https://portswigger.net/research/smashing-the-state-machine

## 4. Logger++

```
BApp Store → Logger++
```

Features:

- Site-wide request/response logging
- Complex filters (regex / field / size)
- Export CSV / JSON
- Find "reflected XSS in historical requests"
- Find "a header that appeared before"

### 4.1 Filter syntax

```
Request.Body CONTAINS "password"
Response.Headers CONTAINS "X-Powered-By: PHP"
Request.Method IN ["POST","PUT","DELETE"]
Response.BodyLength > 5000 AND Response.MimeType == "JSON"
```

### 4.2 Colorize

Highlight specific patterns for quick visual identification.

## 5. BCheck (Burp custom scan rules)

New feature from 2023. Write rules in the BCheck DSL, feed them into Scanner → auto scan.

### 5.1 Template

```
metadata:
  language: v2-beta
  name: "Test for X-Debug header"
  description: "Check if X-Debug header leaks data"
  author: "me"
  tags: "debug,info-disclosure"

run for each:
  potential_header = "X-Debug"

given host then
  send request called check:
    method: "GET"
    path: {BaseRequest.path}
    headers:
      - {potential_header}: "1"
  
  if {check.response.body} matches "DEBUG MODE ON" then
    report issue:
      severity: medium
      confidence: firm
      detail: "X-Debug header activates debug mode"
```

### 5.2 Library

- https://github.com/PortSwigger/BChecks
- https://github.com/BC-Security/BChecks

## 6. Match & Replace (advanced)

```
User options → Connections → Match and Replace
```

### 6.1 Scenarios

```
Header: Origin:.* → Origin: attacker.com
Header: User-Agent:.* → User-Agent: <script>alert(1)</script>
Body regex: "role":"user" → "role":"admin"
Response: Content-Security-Policy: .* → (empty)
```

### 6.2 Restrict to a specific host

```
Type: Request body
Match: "userId":"\d+"
Replace: "userId":"999"
Comment: only in-scope
# Check "Only in-scope"
```

## 7. Session Handling Rules

```
Project options → Sessions → Session handling rules
```

### 7.1 Auto-refresh token

```
Rule: detect response containing "token expired" → re-run the login macro → get a new token → insert it into the Authorization header
```

### 7.2 Macro

```
Sessions → Macros → New → record login steps
Reference the macro from a rule
```

### 7.3 Automatic CSRF token replacement

```
Macro captures the CSRF token (regex)
Rule replaces the token in every POST with the latest value
```

## 8. Extender Add-ons

### 8.1 Must-haves

```
[ ] Autorize             — automated IDOR testing
[ ] AuthMatrix           — hierarchical authz testing
[ ] Param Miner          — hidden parameter / header discovery
[ ] Backslash Powered Scanner — advanced XSS/SQLi scanning
[ ] HTTP Request Smuggler    — smuggling detection
[ ] Stepper              — multi-step replay
[ ] Hackvertor           — quick encoding conversion
[ ] JWT Editor           — JWT testing
[ ] SAML Raider          — SAML XSW
[ ] Active Scan++        — extra scan rules
[ ] Logger++             — historical trace-back
[ ] Turbo Intruder       — race conditions / high-volume requests
[ ] BChecks              — custom rules
[ ] Software Vulnerability Scanner
[ ] Upload Scanner       — file upload testing
[ ] CO2                  — SSL/URL tooling
[ ] Collaborator Everywhere — inject a collaborator domain into every request
```

### 8.2 Installing Jython / JRuby

```
User options → Extender → Python Environment → Jython 2.7.x
                         → Ruby Environment → JRuby
```

## 9. Bambda (Burp 2023+ new filter DSL)

```java
// Proxy history → Filter → Bambda
return requestResponse.hasResponse() 
    && requestResponse.response().statusCode() == 500
    && requestResponse.response().bodyToString().contains("stack trace");
```

## 10. DOM Invader

```
Burp Browser → DOM Invader
```

Automatically finds DOM XSS / client-side prototype pollution / postMessage / client-side URL reflection.

Once enabled, multiple "DOM Invader" tabs appear in the browser's F12 devtools.

## 11. Quick Workflow

### 11.1 New target

```
1. Target → Scope → add to in-scope
2. Proxy → browse the entire site → build the site map
3. Scanner → Crawl + Audit in-scope
4. Extender → Param Miner → run headers/params discovery
5. Leave DOM Invader running automatically
```

### 11.2 Deep testing (per endpoint)

```
1. Repeater to establish a baseline
2. Change method (GET↔POST↔PUT↔DELETE)
3. Add debug headers (X-Original-URL, X-Rewrite-URL)
4. Intruder auth fuzzing (cookie, header, body)
5. Collaborator to probe SSRF / injection candidates
6. Autorize replay with another session
```

### 11.3 JWT / OAuth flow

```
1. JWT Editor to decode the token → check alg / claims
2. Try alg=none / kid injection
3. Macro to auto-refresh
4. Try bypassing OAuth redirect_uri (see §16)
```

## 12. Collaborator One-Click Integration

### 12.1 Collaborator Everywhere

Automatically adds common SSRF headers like `Referer: https://<collab>` and `X-Forwarded-Host: <collab>` to every request.

### 12.2 Copy to clipboard + quick insert

```
# In Repeater, place your cursor anywhere in the body → Ctrl+Shift+C (collab address) → paste
```

## 13. Keyboard Shortcuts

```
Ctrl+R       Send to Repeater
Ctrl+I       Send to Intruder
Ctrl+Shift+R New Repeater tab
Ctrl+B       Send selected value to Decoder
Ctrl+U       URL encode
Ctrl+Shift+U URL decode
Ctrl+F       Search history
Ctrl+Alt+O   Project options
```

## 14. Scanner Advanced

### 14.1 Audit checks

```
Active scan → Audit options → select insertion point (path, body, cookie...)
→ Scan → check Issues
```

### 14.2 Passive scan

```
Every proxied request is automatically passive-scanned
→ finds info leaks / missing headers / CSP / cookie flags
```

### 14.3 Scan definitions

```
Custom insertion points (e.g. nested JSON keys)
```

## 15. Practical Tips

- Use separate projects per engagement (File → New project)
- Save your project regularly (to avoid losing work on a crash)
- Use Burp Suite Enterprise to schedule scans across many targets (team edition)
- Integrate Burp API into CI: https://portswigger.net/burp/documentation/enterprise/api

## Related Documents

- [30-tool-burp-caido.md](30-tool-burp-caido.md) — Burp/Caido basics
- [31-jwt-attack-walkthrough.md](31-jwt-attack-walkthrough.md) — JWT attack walkthrough
- [83-saml-oidc-attacks.md](83-saml-oidc-attacks.md) — SAML Raider
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- BApp Store: https://portswigger.net/bappstore
- Turbo Intruder: https://github.com/PortSwigger/turbo-intruder
