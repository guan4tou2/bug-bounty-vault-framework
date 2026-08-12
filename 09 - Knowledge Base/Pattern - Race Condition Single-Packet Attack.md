---
type: pattern
title: "Race Condition — Single-Packet Attack (HTTP/2 multiplexing)"
vuln_class: race-condition
status: active
last_updated: 2026-06-03
tags:
  - bb-pattern
  - sota-2024
---

# Pattern — Race Condition — Single-Packet Attack (HTTP/2 multiplexing)

> A technique published by James Kettle / PortSwigger in *Smashing the State Machine* (2023, Black Hat USA / DEF CON). It exploits HTTP/2's ability to multiplex 20–30 requests over a single TCP packet, sending the final frame of every request together so that network jitter drops from roughly 3 ms to roughly 0.3 ms — turning race conditions that looked "clearly unexploitable" into stable, reproducible limit-overrun bugs.

## Why This Is a Real Bug, Not Noise

Traditional race-condition testing uses last-byte sync (send headers first, hold back the final byte until the end), but on the public internet jitter still spans roughly 4 ms, while most application-layer race windows (DB transactions, auth checks, token consumption) are only 1–2 ms wide — producing a high false-negative rate.

The single-packet attack exploits HTTP/2 multiplexing: pre-send all request framing for every request, hold back the last byte (or withhold END_STREAM), then flush everything at once. The final byte of every stream lands in the same TCP segment on arrival at the server, shrinking the window to sub-millisecond and reopening endpoints previously dismissed as "not exploitable."

**Stop-loss check**: if the target doesn't support HTTP/2 (`curl -I --http2 https://target` returns HTTP/1.1), the single-packet attack doesn't apply — fall back to last-byte sync or H1 pipelining, and downgrade `verification_level` by at least one tier.

---

## Summary

Limit-overrun race conditions attack the TOCTOU gap between a "security check" and the "protected action" it gates. The single-packet attack uses HTTP/2 multiplexing to compress that gap's race window from millisecond-scale to sub-millisecond:

1. Find an endpoint with a "check-before-action / limit / one-time token" pattern (redemption, refund, email change, coupon consumption, CAPTCHA, MFA verify, addToCart)
2. Craft 20–30 identical requests and queue them all behind a Turbo Intruder gate
3. Release the gate simultaneously → the final byte of every request arrives in the same TCP packet
4. Observe the race window: did multiple requests pass the check (multiple refunds / redemptions / consumptions)?

**Why this scales**: the applicable surface is enormous — any "state change + preceding check" endpoint should be tested; the attack cost is low (one Turbo Intruder script + an HTTP/2 target); and Burp Repeater already ships a built-in "Send group in parallel (single-packet)" button, lowering the barrier to entry substantially.

---

## Detection Signals

| Signal | Tool | Meaning |
|--------|------|---------|
| Target supports HTTP/2 (`curl -I --http2 ...` returns `HTTP/2`) | curl | single-packet attack applicable |
| Endpoint has "one-time" semantics (redemption code, refund, invite acceptance, MFA verify) | manual exploration | high likelihood of limit-overrun |
| Concurrent requests from the same user to the same endpoint produce a non-monotonic change in response content (balance, count, status) | Turbo Intruder | race window hit |
| Response is "unexpectedly fast" (faster than server baseline) with a visible side effect | Turbo Intruder | async backend submission |
| Multiple requests all return 200, but business logic should only allow one | Turbo Intruder | confirmed limit overrun |
| Second-order effects (duplicate email sent, double points, credential collision) | business-side monitoring | confirmed |
| Endpoint uses `Authorization: Bearer` + short cache | header inspection | possible single-endpoint race |
| Multi-endpoint: A changes email + B confirms via token, with A racing ahead of B | logic analysis | hidden multi-step race |

---

## Test Methodology

### Step 0: Confirm HTTP/2 support

```bash
curl -sI --http2 https://target.example.com/api/redeem | head -1
# Expected: HTTP/2 200
# If it returns HTTP/1.1 → single-packet attack unavailable, use last-byte sync instead
```

### Step 1: Burp Repeater "Send group in parallel" (fastest to set up)

Built into Burp 2023.10+:

1. Right-click the request → `Send to Repeater`
2. Open several Repeater tabs (duplicates of the same request)
3. Right-click the tab group → `Send group in parallel` (single-packet mode is enabled automatically)
4. Compare all responses: did multiple return 200, and was the business state advanced more than once?

### Step 2: Turbo Intruder script (for quantitative testing)

Official example: [turbo-intruder/resources/examples/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)

```python
def queueRequests(target, wordlists):
    # HTTP/2 single-packet attack requires the BURP2 engine + a single connection
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2,
    )

    # Queue all requests behind the same gate
    for i in range(20):
        engine.queue(target.req, gate='race1')

    # Flush every final byte simultaneously
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Step 3: Interpreting Results

| Observation | Interpretation |
|------|------|
| All 20 requests return 200, but server-side state only changes once | Properly protected (correct DB transaction / lock) |
| All 20 requests return 200, state changes N times (N > 1) | **Limit-overrun vulnerability** |
| Some requests return 409 / 429, others 200 but state still changes > 1 time | Partial protection, still exploitable |
| A request returns "unexpectedly fast" with a side effect | async race — look for order-sensitive endpoints |

### Step 4: Evidence Preservation

- Screenshot the Repeater group response (showing multiple 200s)
- Screenshot business-side state (e.g. balance, redemption count) before/after the attack
- Save the Turbo Intruder log (response time + body diff)

---

## Variants / Common Bypass Techniques

| Variant | Description | Applicable Scenarios |
|------|------|---------|
| **Classic limit-overrun** | N concurrent requests to the same endpoint | gift card redemption, coupon, refund, MFA verify, CAPTCHA reuse |
| **Multi-endpoint race** | Endpoint A writes state, endpoint B reads/commits, with A racing ahead of B | password reset confirm + email change confirm; 2FA setup + verify |
| **Single-endpoint sub-state race** | Multiple sub-state conditions within one endpoint (e.g. cart update + checkout) | concurrent addToCart, then checkout to observe price |
| **Partial construction race** | Use a half-completed record to trigger a check skip | half-complete registration + login before email verification finishes |
| **Time-sensitive permissions** | Race a short-lived token before it expires | OAuth code consumption, JWT exchange, SSO ticket |
| **Connection warming** | Send one dummy request first to open the H2 connection + warm the TLS handshake, then race | necessary when TLS handshake jitter interferes (Kettle paper §4.2) |
| **Nagle on / TCP_NODELAY off** | Force the kernel to batch final frames into a single segment | ensures a true single-packet delivery |
| **H1 + last-byte fallback** | Fallback when HTTP/2 is unavailable | only effective when the window exceeds ~3 ms |

---

## Severity Guide

| Condition | Severity | Notes |
|------|----------|------|
| Verified multiple withdrawals / refunds / redemptions of a real asset (money, points, credit) | **P1 Critical** | direct monetary loss |
| MFA / CAPTCHA / rate-limit bypass via race (auth boundary defeated) | P1–P2 High | brute-force protection defeated |
| Repeated claim of a one-time reward / coupon (no direct monetary loss, but platform cost) | P2 High | scalable abuse |
| A single resource claimed by multiple parties / username-squatting race | P2–P3 | depends on business impact |
| Multi-step race (e.g. bypassing the password-reset + email-change sequence) | P1–P2 | depends on final impact (ATO-level = P1) |
| Race window hit but only produces duplicate log entries with no actual state change | P4 Low / Informational | TOCTOU residue with no real impact |
| Static reasoning that "a race should exist" without a dynamic Turbo Intruder verification | `verification_level: B` | don't submit as P1; flag as blocked |

**Anti-overclaim reminders**:

- Don't write up "Burp group send returned 20x 200" as "P1 RCE-level" without cross-verifying that **business state actually advanced N times** (balance over-debited / coupon over-redeemed / refund over-claimed)
- The bar for `verification_level: live` is: captured server response **and** business-side state diff as corroborating evidence; response 200 alone with no state diff is static/theoretical
- If HTTP/2 isn't enabled, the single-packet attack will necessarily fail — don't mistake "couldn't test it" for "no vulnerability"; confirm HTTP/2 first, otherwise fall back to last-byte sync or record it as not applicable

---

## Cross-reference

- [[Pattern - SaaS Marketplace OAuth Defaults]] — another example of a platform-level systemic vulnerability pattern
- [[Lessons Learned]] — run the full technique matrix per parameter; dynamic verification substantially raises credibility
- Source 1: PortSwigger's original research, [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine) (James Kettle, 2023)
- Source 2: Turbo Intruder official example, [race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
- Source 3: PortSwigger Web Security Academy, [Race conditions](https://portswigger.net/web-security/race-conditions) — interactive labs and detail

### Public Write-ups (unverified / supplementary)

| Write-up | Description | Verification status |
|---------|------|---------|
| Kettle, *Smashing the State Machine* (2023) | GitLab and Devise (Rails auth) case studies; the author notes missing out on roughly $5k by discovering a race chain too late | Verified (primary source) |
| Public bug bounty reports (refund duplication, coupon stacking, etc.) | Multiple H1 programs have public single-packet race reports, but specific bounty amounts aren't cited here | Unverified (avoiding fabricated figures) |
