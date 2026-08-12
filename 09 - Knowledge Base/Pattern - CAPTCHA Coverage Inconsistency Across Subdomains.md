---
type: pattern
title: Pattern - CAPTCHA Coverage Inconsistency Across Subdomains
tags: [pattern, cwe-799, cwe-307, captcha, rate-limit, brute-force, subdomain, bb-pattern]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
severity: P3 Medium
---

# Pattern - CAPTCHA Coverage Inconsistency Across Subdomains

## TL;DR

Different subdomains or pages of the same app have inconsistent CAPTCHA/rate-limit coverage. One page has reCAPTCHA, but a functionally similar page doesn't — the attacker simply uses the one without CAPTCHA.

## Common Inconsistency Patterns

### Pattern A: Same Function, Different Subdomain

```
official.example.com/apply     ← has reCAPTCHA ✅
portalplus.example.com/apply   ← no CAPTCHA ❌   ← attacker uses this one
```

### Pattern B: Same Subdomain, Different Pages

```
console.example.com/site/signup              ← has reCAPTCHA ✅
console.example.com/site/login               ← no CAPTCHA ❌
console.example.com/site/request-password-reset  ← no CAPTCHA ❌
```

### Pattern C: Front-of-house vs. Back-office

```
www.example.com/login          ← has CAPTCHA + rate limit ✅
admin.example.com/login        ← no CAPTCHA ❌
api.example.com/auth/token     ← no rate limit ❌
```

## Detection Method

```bash
# 1. Enumerate login/signup/reset pages across all subdomains
for sub in www admin console portal api app; do
  for path in login signup register apply reset-password forgot-password; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}.target.com/${path}")
    [ "$code" != "000" ] && [ "$code" != "404" ] && echo "${sub}/${path}: ${code}"
  done
done

# 2. Check for a reCAPTCHA sitekey
for url in "https://portal.target.com/apply" "https://console.target.com/login"; do
  has_captcha=$(curl -s "$url" | grep -c "recaptcha\|hcaptcha\|turnstile\|captcha")
  echo "$url: captcha=$has_captcha"
done

# 3. Compare rate-limit headers
for url in ...; do
  curl -sD- "$url" -X POST -d "email=test@test.com" | grep -i "rate\|retry\|x-ratelimit"
done
```

## Why This Happens

| Cause | Explanation |
|------|------|
| Different teams | The portal and console are maintained by different teams with inconsistent security standards |
| CAPTCHA added later | The main domain was added CAPTCHA after an attack, but other subdomains were forgotten |
| Framework version drift | An older subdomain runs an older framework version that never integrated CAPTCHA |
| "Low-priority page" bias | Developers assumed a lower-traffic subdomain didn't need CAPTCHA |
| Staging leftovers | A staging/UAT subdomain was never hardened but shares a database with production |

## Case Study

### Same Function, Different CAPTCHA Coverage

| Aspect | Official domain | Alternate portal domain |
|------|----------------------|------------------------|
| Function | Enterprise account application | Enterprise account application (identical function) |
| CAPTCHA | ✅ Google reCAPTCHA v2 | ❌ None at all |
| Rate limit | ✅ | ❌ |
| Impact | Protected | Enables automated bulk enterprise-account applications |

### Login vs. Signup on the Same Subdomain

| Aspect | /site/signup | /site/login | /site/request-password-reset |
|------|------------|------------|------------------------------|
| CAPTCHA | ✅ reCAPTCHA | ❌ None | ❌ None |
| Impact | Prevents bot registration | **Brute-force feasible** | **Account enumeration + email bombing** |

## Report Framing

**Don't just report "CAPTCHA is missing" — compare it against another page in the same app that has CAPTCHA.**

✅ Correct:
> `portalplus.example.com/apply/submit` lacks CAPTCHA protection. By comparison, the functionally identical `official.example.com/operator-apply/submit` has Google reCAPTCHA v2 deployed. This indicates CAPTCHA protection was omitted during the portalplus subdomain's rollout.

❌ Wrong:
> CAPTCHA is missing. Recommend adding CAPTCHA.

The comparison lets the triager immediately recognize this as an omission rather than a deliberate design choice.

## Exploitation Chain

```
Missing CAPTCHA (this pattern)
  ├── + member-enumeration oracle → bulk account verification
  ├── + password-reset endpoint → email bombing / OTP brute force
  ├── + login endpoint → brute force (credential stuffing)
  └── + enterprise-application endpoint → bulk fake enterprise accounts
```

## Related

- [[Pattern - Account Enumeration Oracle]] — missing CAPTCHA plus an enumeration oracle amplifies exploitability
- [[Pattern - CAPTCHA Plaintext Disclosure]] — a related but distinct CAPTCHA weakness
