---
type: pattern
title: Pattern - Account Enumeration Oracle
tags: [pattern, user-enumeration, account-enumeration, timing-attack, bb-pattern]
status: active
vuln_class: user-enumeration
last_updated: 2026-06-03
---

# Pattern: Account Enumeration Oracle

> Any endpoint that returns a distinguishable response for "account exists" versus "account does not exist" — whether the difference is in status code, message text, error code, timing, or a side effect such as an SMS being sent — is an enumeration oracle, no matter how subtle the difference is.

## Detection Signals

| Type | Signal | Confidence |
|------|--------|------------|
| Different HTTP status codes | exists → 200; does not exist → 404 / 422 | High |
| Different error codes | e.g. `-101` (wrong password) vs `-100` (account not found) | High |
| Different error message text | "incorrect password" vs "account not found" | High |
| Response-size difference | one branch returns more fields | Medium |
| Timing difference | bcrypt hashing only runs for existing accounts → existing-account responses are ~100ms+ slower | Medium |
| Side-effect oracle | an OTP SMS/email is only sent when the account exists | High |
| Four-state oracle | separate codes for exists-active / exists-disabled / exists-incomplete / not-exists | Highest confidence |

## Test Methodology

### Step 1 — Establish a Baseline (GET-first)

```bash
# Confirm the "exists" response using a known-existing account + wrong password
curl -s -X POST 'https://target/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"known_user","password":"wrong_password"}' | jq .

# Confirm the "does not exist" response using a clearly nonexistent account
curl -s -X POST 'https://target/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"aaabbbccc_definitely_not_real","password":"wrong_password"}' | jq .
```

### Step 2 — Compare the Difference

Fields to focus on:
- `.code` / `.error` / `.reason` / `.message`
- HTTP status code
- Response body size (`wc -c`)
- Response time (`curl -w "%{time_total}\n"`)

### Step 3 — Expand to Other Endpoints

Common high-value oracle endpoints:

```bash
# Login endpoints (most common)
POST /login, POST /v1/token, POST /auth/signin

# Password reset (often forgotten)
POST /forgot-password, POST /reset-password/request

# OTP / SMS send
POST /send-otp, POST /v1/sms/send, GET /otp/send?phone=...

# Registration (duplicate-account check)
POST /register, POST /signup

# Account lookup APIs (sometimes missing authn entirely)
GET /api/user?username=..., GET /api/account/check
```

### Step 4 — Automated Enumeration (after confirming the oracle exists)

```bash
# Enumerate using a wordlist of common account names
for account in alice bob charlie dave frank henry karen lily tim wayne; do
  resp=$(curl -s -X POST 'https://target/api/login' \
    -H 'Content-Type: application/json' \
    -d "{\"account\":\"$account\",\"password\":\"probe_$(date +%s)\"}")
  code=$(echo "$resp" | jq -r '.code // .error // empty')
  echo "$account → $code"
  sleep 0.2
done
```

### Step 5 — Confirm Rate Limiting

```bash
# Fire 10 requests quickly to check for throttling / IP ban
python3 -c "
import urllib.request, time, json
start = time.time()
for i in range(10):
    data = json.dumps({'account':f'test_{i}','password':'wrong'}).encode()
    req = urllib.request.Request('https://target/api/login',
          data=data, headers={'Content-Type':'application/json'})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f'[{i}] {e}')
print(f'10 requests in {time.time()-start:.2f}s')
"
```

## Real-World Case Studies

### Case A — Four-State Oracle

- **Endpoint**: `POST https://api.target.example/v1/token`
- **Oracle**:

| code | Meaning |
|------|------|
| `-100` | Account does not exist |
| `-101` | Account exists and is active (= attack target) |
| `-998` | Account exists but registration incomplete |
| `-999` | Account exists but disabled |

- Confirmed live enumeration of 11 accounts.
- Combined with a CAPTCHA-bypass finding for fully automated enumeration.
- Accounts in the `-101` state could be pushed into permanent deactivation via a separate denial-of-service finding.
- CVSS 6.5 / P3 (CWE-204 + CWE-203)

### Case B — SMS API Four-State Oracle

- **Endpoint**: `GET https://sms-api.target.example/API21/HTTP/getCredit.ashx?UID=<uid>&PWD=<pwd>`
- **Oracle**: same four-state code scheme as Case A (`-100/-101/-998/-999`)
- **Side-effect escalation**: the oracle had no rate limiting → brute force → SMS account takeover → billable SMS abuse
- Confirmed across all deployment nodes (production, alternate hostnames)
- CVSS 7.3 / P2, escalating to 8.0 once chained

## Variants

### Three-State Oracle (Common)

A login endpoint that returns only three states: account not found / exists+active (wrong password) / exists+disabled. More severe than a two-state oracle because it further discriminates the attack target.

### Timing Oracle (Subtle)

The backend runs a bcrypt/argon2 hash comparison for existing accounts, but rejects nonexistent accounts immediately. The response-time gap is typically 50–300ms. Hard to spot but measurable:

```bash
for account in real_user fake_user_xyz; do
  curl -s -o /dev/null -w "$account: %{time_total}s\n" \
    -X POST 'https://target/login' \
    -d "username=$account&password=probe"
done
```

### SMS / Email Side-Effect Oracle

Password-reset / OTP endpoints: an SMS or email is only sent when the account exists, and the request fails silently otherwise. An attacker can infer account existence purely by observing "did the SMS arrive?" without needing to inspect the HTTP response.

### Registration Collision Oracle

`POST /register` returns "account already in use" for an existing account, while a nonexistent account proceeds through the flow. Even if the message text is similar, the HTTP status code (400 vs 200) still leaks the signal.

## Severity Guide

| Scenario | Severity | Note |
|------|--------|------|
| Oracle + no rate limiting + chainable attack (ATO/DoS) | P2 High | Full attack chain established |
| Four-state oracle (including disabled/incomplete) | P2–P3 | Highest information content; precisely targets valid accounts |
| Standard three-state / two-state oracle | P3 Medium | Must articulate concrete post-enumeration impact |
| Timing oracle (≥100ms gap) | P3 Medium | Requires statistical significance across multiple samples |
| SMS side-effect oracle (with billing cost) | P2 High | Adds financial impact |
| Oracle only reachable after authentication | P4–P5 | Downgraded; attacker needs an existing account first |

The report must explain what the attacker can actually do after enumeration — not just "confirm the account exists."

## Pre-Submission Three-Question Check

1. **What can the attacker obtain?** — a confirmed account list (quantify it: `alice/-101`, `karen/-101`, etc.)
2. **Is this default/expected behavior?** — no (the industry standard is a unified error message)
3. **What remains once the theory is stripped away?** — directly reproducible differential responses (live screenshots / curl output)

## Cross-Reference

- [[Pattern - CAPTCHA Plaintext Disclosure]] — a common chaining path
- [[Lessons Learned]]

## Session-Mined Additions

- **HTTP 200 wrapper oracle**: even when the response body carries an error (`{"status":"error","message":"not found"}`), the HTTP status code itself may be 200 — status code alone cannot be used for dedup; the body must be compared.
- **Multi-tenant B2B SSO layered enumeration**: fleet code → account → password → OTP each have independent oracles, allowing an attacker to walk an entire org's user tree layer by layer.
- **Response-time oracle**: bcrypt lookups run roughly 100–500ms slower than PBKDF2; the existing-account path is usually slower than the nonexistent-account path (timing attack).
- **OTP leak oracle**: some systems return "OTP already sent" versus "account not found" — enumerable via that distinction alone.
