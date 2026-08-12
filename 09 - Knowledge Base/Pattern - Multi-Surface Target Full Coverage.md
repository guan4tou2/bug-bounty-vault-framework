---
type: pattern
title: "Pattern - Multi-Surface Target Full Coverage"
tags: [pattern, methodology, attack-surface, decision-tree, electron, android, web, infra, bb-pattern]
status: verified
last_updated: 2026-05-18
severity: meta (methodology -- multiplier effect)
---

# Pattern - Multi-Surface Target Full Coverage

## TL;DR

When a target simultaneously has Desktop client, Mobile app, Web portal, and Infrastructure attack surfaces, **auditing in the correct order + cross-surface chaining** can combine individual P3 vulnerabilities into a P1 RCE chain, maximizing both finding volume and severity.

## Four Attack Surfaces and Audit Order

```
Priority (ROI ordering):

  1. Desktop Client    2. Mobile App     3. Web Portal    4. Infrastructure
  (Electron/CefSharp)  (Android/iOS)    (API/Auth)      (XMPP/DNS/Cloud)
  +----------------+  +----------------+ +------------+  +----------------+
  | ASAR static    |  | APK decompile  | | API enum   |  | subdomain      |
  | IPC bridge     |  | Manifest       | | Auth flow  |  | BOSH/XMPP      |
  | preload.js     |  | deep link      | | CAPTCHA    |  | GCS/S3         |
  | BrowserWindow  |  | FileProvider   | | user enum  |  | DNS records    |
  | localhost svc  |  | TrustManager   | | CSRF       |  | TLS config     |
  +-------+--------+  +-------+--------+ +-----+------+  +-------+--------+
          |                    |               |                  |
          +--------------------+---------------+------------------+
                               |
                     5. Cross-Surface Chain Design
                     (cross-surface chaining = severity multiplier)
```

### Why This Order?

| Order | Surface | Rationale |
|-------|---------|-----------|
| 1. Desktop | **Static analysis needs no account**, ASAR/binary locally auditable, finding IPC = direct path to RCE |
| 2. Mobile | APK decompilation similarly needs no account, FileProvider/deep link are high-frequency vulnerabilities |
| 3. Web | Needs an account to go deep, but test pre-auth endpoints first (enumeration oracle, CAPTCHA gaps) |
| 4. Infra | XMPP/DNS/Cloud bucket are "passive" surfaces, no interaction needed, batch curl scanning |
| 5. Chain | Findings from all four surfaces chain together -- this is where the highest severity comes from |

## Cross-Surface Chaining Mental Model

### Entry x Capability x Persistence (three dimensions)

Each attack chain = **Entry** + **Capability** + **Persistence**

```
Entry:
+-- Remote: Meet URL / deep link / email / malicious website
+-- Local: localhost service / IPC socket
+-- MITM: same WiFi / DNS hijack

Capability:
+-- File write: saveBase64toFile / FileProvider
+-- Command execution: shell.openExternal / WebView JS
+-- Information theft: token / chat DB / NTLM hash
+-- Identity impersonation: XMPP register / email spoof

Persistence:
+-- LaunchAgent (macOS) / Startup folder (Windows)
+-- Update hijack (supply chain)
+-- No persistence needed (one-time theft achieves goal)
```

### Chaining Formula

```
Chain severity = max(individual findings) + chain_bonus

chain_bonus rules:
- 2x P3 chained into exploitable chain -> P2
- P3 + P2 chained into RCE chain -> P1
- Cross-platform (macOS + Windows) same chain -> additional bonus
- Remote trigger > local trigger > MITM trigger
```

## Real-world Example: Multi-Surface Enterprise App (19 findings -> 9 chains)

### Individual Findings by Surface

| Surface | Findings | Severity Distribution |
|---------|----------|-----------------------|
| Desktop (Electron) | 7 | 3x P2 + 4x P3 |
| Mobile (Android) | 3 | 1x P2 + 2x P3 |
| Web (API/Auth) | 4 | 4x P3 |
| Infrastructure | 5 | 1x P2 + 3x P3 + 1x P4 |

Looking at individual findings alone: the highest is only P2.

### After Cross-Surface Chaining

| Chain | Surfaces | Chaining Logic | Result Severity |
|-------|----------|---------------|-----------------|
| Meet -> RCE | Desktop | Custom scheme -> preload injection -> shell exec | **P1 RCE** |
| Malicious link -> RCE | Desktop | XSS -> preload -> shell exec | **P1 RCE** |
| Android Kill Chain | Mobile | Deep link -> file write -> WebView JS exec | **P2 chain** |
| Update Hijack | Desktop+Infra | DNS + no signature + preload | **P1 RCE** |
| CORS XMPP Drive-by | Infra+Web | XMPP registration + CORS bypass | **P2 chain** |
| Email Spoof+SE | Infra+Web+Desktop | SPF fail + user enum + custom scheme | **P2 chain** |

**19 P2-P4 findings -> 3 P1 RCE chains + 3 P2 chains**

## Decision Tree: When to Apply Full Coverage?

```
Does the target have multiple attack surfaces?
+-- Web only -> Focus on Web (this pattern not needed)
+-- Desktop + Web -> Desktop ASAR first, then Web API
+-- Desktop + Mobile + Web -> Full coverage (this pattern)
+-- Desktop + Mobile + Web + Infra -> Highest ROI, prioritize this target
       |
       +-- Same vendor / same framework?
           +-- YES -> Multiplier effect (shared codebase)
           +-- NO -> Audit each surface independently, chain at the end
```

## When to Stop Expanding Attack Surfaces?

| Condition | Action |
|-----------|--------|
| No new findings on current surface for 2+ hours | Switch to next surface |
| Already have 3+ P3 findings not yet chained | Try chaining before continuing to dig |
| Already have RCE chain | Chain verification takes priority over new findings |
| All 4 surfaces scanned | Enter chain design phase |

## Anti-patterns

| Don't | Do |
|-------|----|
| Only dig Web and submit | First check if Desktop/Mobile client exists |
| Submit each finding independently | Try chaining first, then decide whether to split or combine submissions |
| Spend 3 days stuck on Web auth bypass | Switch to Desktop ASAR; 10 minutes may yield an IPC vulnerability |
| Ignore P4 DNS/email findings | P4 in a chain can be a critical linking point |

## Related

- [[Pattern - Electron contextIsolation Per-Window Variance]] -- Core pattern for the Desktop surface
- [[Pattern - CORS XMPP BOSH Drive-by Registration]] -- Infrastructure surface chain entry point
- [[Pattern - Supply Chain Analysis]] -- Same framework multiplier effect
