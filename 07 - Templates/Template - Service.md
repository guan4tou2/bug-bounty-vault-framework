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

| 欄位 | 值 |
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

> 已知 path、admin panel 入口、API endpoint、有趣 response 的 URL。

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

## 4. 已驗證的弱點 / 異常

> 連到 Finding / Attempt note，配上一行 takeaway。

- `[[Finding - ...]]` —
- `[[Attempt - ...]]` —

---

## 5. Credentials 挖出來的東西

> 連到 Credential note。

- `[[Credential - ...]]` —

---

## 6. 攻擊面備忘

- 待測 endpoint：
- 想嘗試但沒空的角度：
- 同 vendor 的 sibling service：

---

## 7. References

- Target hub: `[[]]`
- Recon source: `[[Recon - ...]]`
