---
fileClass: Service
target: "[[]]"
kind: "web | api | graphql | websocket | mobile-app | desktop-app | firmware | iot | database | admin-panel | cdn | cloud-storage | auth-service | ci-cd | git | turn-stun | jitsi"
url: ""
ip: ""
tech_stack: []
status: "live | dead | auth-required | forbidden | redirect | staging | deprecated"
risk: "critical | high | medium | low | info | unknown"
in_scope: true
endpoints: []
credentials: []
findings_produced: []
parent: "[[]]"
first_seen: <% tp.date.now("YYYY-MM-DD") %>
last_verified: <% tp.date.now("YYYY-MM-DD") %>
tags:
  - service
---

# Service — {{TARGET}} — {{HOSTNAME}}

> Hub: `[[Target - {{TARGET}}]]`
> URL: `{{URL}}`

---

## 1. Snapshot

| Field | Value |
|---|---|
| Target | `[[]]` |
| Kind | |
| URL | |
| IP / CDN | |
| Tech Stack | |
| In Scope | |
| Status | |
| Risk | |

---

## 2. Endpoints / Paths

> Known paths, admin panel entry points, API endpoints, and URLs with interesting responses.

| Path | Method | Auth | Notes |
|---|---|---|---|
| `/` | GET | none | |
| | | | |

---

## 3. Tech Fingerprint

```
# nuclei tech-detection / wappalyzer / curl headers
```

- Server header:
- Powered-By:
- CSP:
- TLS:

---

## 4. Verified Weaknesses / Anomalies

> Link to Finding / Attempt notes with a one-line takeaway each.

- `[[Finding - ...]]` —
- `[[Attempt - ...]]` —

---

## 5. Credentials Discovered

> Link to Credential notes.

- `[[Credential - ...]]` —

---

## 6. Attack Surface Notes

- Endpoints to test:
- Angles to try when time allows:
- Sibling services from the same vendor:

---

## 7. References

- Target hub: `[[]]`
- Recon source: `[[Recon - ...]]`
