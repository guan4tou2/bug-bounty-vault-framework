---
type: reference
title: Tool - JS-Tap (JavaScript Red Team Payload Framework)
tags: [red-team, javascript, xss, post-exploitation, credential-harvesting]
status: validated
last_updated: 2026-04-06
---

# JS-Tap: Weaponizing JavaScript for Red Teams

## Core Concept

JS-Tap is a **universal JavaScript payload framework** designed for red teams -- it can be deployed without prior knowledge of the target application, relying purely on client-side instrumentation to capture intelligence.

> Instead of attacking the server, it **hijacks user behavior inside the browser**.

---

## Two Operating Modes

### Trap Mode (iframe trap)
- Creates a full-page iframe, spoofing the address bar so the user doesn't notice
- Payload continues executing even after the user "closes the tab"
- Use cases: XSS injection, social engineering phishing pages

### Implant Mode (direct injection)
- Directly injected into a compromised server or JS file
- No iframe required; suitable when server access is already available
- More persistent

---

## Data Capture Capabilities

| Type | Description |
|------|-------------|
| System info | IP, OS, Browser |
| Keystrokes | Including login credentials (username/password) |
| Cookies | Non-httponly cookies |
| Storage | localStorage / sessionStorage |
| Page HTML | Full source code snapshot |
| Screenshots | Visual capture of browsed pages |
| API calls | XHR + Fetch request/response body |
| Auth headers | Bearer token, Authorization header |

---

## Technical Core: API Monkeypatching

```javascript
// Replace the underlying network implementation before legitimate code executes
const originalFetch = window.fetch;
window.fetch = function(...args) {
    // Intercept request, log headers / body
    logRequest(args);
    return originalFetch.apply(this, args);
};
```

Same technique applied to `XMLHttpRequest`:
- Override `open()`, `send()` methods
- Capture all API endpoints, methods, request bodies, response bodies
- **JWT/Bearer tokens extracted directly from headers**

---

## Practical Demonstrations

### WordPress Scenario
1. Capture admin login credentials as they are typed
2. Extract newly created account credentials from HTML source
3. Confirm httponly cookies cannot be read by JS (defense effective)

### SPA (Single Page Application) Scenario
1. Intercept JWT token stored in localStorage
2. Capture three types of API calls (XHR, Fetch, jQuery)
3. Record Authorization headers and response data
4. Delayed screenshots (page state after API response)

---

## Management Interface Features

- Real-time client session monitoring
- Chronological event visualization
- Event filtering and categorization
- HTML viewer + full-size screenshots
- Client notes
- Batch export of captured credentials

---

## Defense Bypass and Limitations

| Defense Mechanism | Effectiveness |
|-------------------|---------------|
| httponly cookie | Effective (JS cannot read) |
| CSP (Content-Security-Policy) | Can block iframe trap |
| X-Frame-Options | Can block iframe trap |
| JS framebusting | Can interfere with Trap mode |
| SPA storing tokens in memory | Harder to capture (but monkeypatching can still intercept API calls) |

---

## Bug Bounty Applications

### Applicable Scenarios
- Already have Stored XSS -> deploy JS-Tap as PoC to demonstrate real impact
- Escalate Self-XSS to Account Takeover (combined with iframe)
- Impact proof for DOM-based XSS

### Report Impact Description Template
```
Verified impact:
- Attacker can inject JS-Tap payload via XSS to capture all keystrokes from the victim on the target application
- This includes login credentials, API tokens (from Authorization header), and non-httponly cookies
- Full page screenshots can be captured as visual evidence

Potential impact (requires additional conditions):
- If target is SPA and JWT is stored in localStorage -> direct token theft -> Account Takeover
```

---

## Tool Information

| Field | Details |
|-------|---------|
| GitHub | https://github.com/trustedsec/js-tap |
| Author | Drew Kirkpatrick / TrustedSec |
| Language | JavaScript + Python (management interface) |
| Install | `git clone https://github.com/trustedsec/js-tap` |

---

## Related Notes

- [[Pattern - XSS Post-Exploitation]]
- [[Pattern - Source Map Exposure]]
- [[Skill - security-arsenal]]
