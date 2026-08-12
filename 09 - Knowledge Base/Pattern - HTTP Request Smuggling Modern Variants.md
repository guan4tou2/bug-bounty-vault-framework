---
type: pattern
title: "Pattern - HTTP Request Smuggling Modern Variants"
tags: [pattern, cwe-444, request-smuggling, http, reverse-proxy, sota-2024, sota-2025, bb-pattern]
status: verified
vuln_class: request-smuggling
severity_range: P1-P4
seen_in: [reverse-proxy, cdn, load-balancer]
prerequisites: ["keep-alive connection reuse", "program scope explicitly permits smuggling tests"]
last_updated: 2026-06-03
---

# Pattern - HTTP Request Smuggling Modern Variants (CL.0 / 0.CL / TE.0 / Expect)

> **TL;DR**: Classic CL.TE / TE.CL / TE.TE desync variants have largely been patched by mainstream reverse proxies. James Kettle's research arc from Browser-Powered Desync Attacks (2022) through HTTP/1.1 Must Die (2025) opened a new class of parser-discrepancy attacks — **CL.0**, **0.CL**, **TE.0**, and the **Expect header trick** — that no longer require a CL+TE conflict to exist simultaneously, letting them slip past most signature-based WAF rules built for the classic variants.

## Root Cause

HTTP/1.1's length semantics (`Content-Length` vs `Transfer-Encoding` vs "no body at all") are genuinely ambiguous at the RFC level. When a front-end proxy (CDN / WAF / load balancer) and the back-end origin disagree about whether a given request can carry a body, or whether a given header should be honored at all, the back-end ends up parsing the tail of one request as the start of the next.

What's new in this generation of variants:

1. **CL.0 / 0.CL don't require a TE conflict at all.** Classic mitigation logic ("reject any request with both CL and TE present") does nothing against them.
2. **The Expect header trick** opens new parser forks on links that previously had no desync at all — a plain `Expect: 100-continue` produced 0.CL on some front-ends (reported against T-Mobile, $12K bounty; against Akamai as CVE-2025-32094, $9K bounty).
3. **Early-response gadgets** (IIS reserved filenames `con`/`aux`/`nul`, static files, redirect endpoints) turn 0.CL from "hangs with a 400" into something weaponizable.

**Stop-loss judgment**: smuggling on a shared connection pool has very high blast radius for real users (response-queue poisoning, session hijacking, credential theft). Any unintended behavior — someone else's response landing on your socket, a long hang, a spike in 5xx — is an immediate stop signal; move to an authorized lab environment to reproduce further. Live testing must go through an isolated test path and strictly respect program rules — many programs explicitly forbid smuggling tests against production; check scope before touching this pattern.

## Summary

All modern variants reduce to the same detection framework:

| Variant | Front-end's view of body length | Back-end's view of body length | Result |
|---------|----------------------------------|----------------------------------|--------|
| **CL.0** | `Content-Length: N` | 0 (CL ignored) | Front-end forwards the trailing bytes down the same keep-alive socket → back-end treats them as the start of the next request |
| **0.CL** | 0 (CL hidden/obfuscated) | `Content-Length: N` | Back-end waits for N bytes; front-end has already forwarded the next legitimate request, which gets consumed as body |
| **TE.0** | Dechunked (sees the chunked body) | 0 (TE ignored / treated as no body) | Same effect as CL.0, triggered via chunked encoding instead |
| **Expect (vanilla)** | Front-end mishandles `Expect: 100-continue` and skips the body | Back-end still waits for the body | Produces 0.CL |
| **Expect (obfuscated)** | `Expect: y 100-continue` is ignored by the front-end | Back-end still understands it | Produces CL.0, and doubles as a WAF bypass |

The core mechanism is a **Visible-Hidden (V-H)** / **Hidden-Visible (H-V)** header discrepancy: obfuscation tricks (leading whitespace, unusual line breaks, casing, an `Expect` value prefix) make the same header resolve differently at each end of the chain.

## Detection Signals

| Signal | Tooling | Meaning |
|--------|---------|---------|
| HTTP Request Smuggler (Burp extension) reports "Probable" / "Confirmed" | Burp + extension | V-H / H-V parser discrepancy detected |
| A second GET on the same keep-alive connection returns an unexpected 404 / 405 / 500 | `curl --next` / raw `nc` | Back-end consumed the prior body as the start of a new request line |
| A POST with `Expect: 100-continue` gets a 200/400 from the front-end while the back-end access log (if visible) never sees it | Compare front-end response vs. back-end access log | Inconsistent Expect handling |
| Response headers show a duplicated `Content-Length` or two status lines | Hex dump | Residual response-splitting / queue poisoning |
| An unrelated request occasionally returns a response belonging to a different session/URL | Repeated load testing | Response-queue poisoning already occurring — **stop immediately** |
| `/con`, `/aux`, `/nul`, `/prn` (IIS reserved names) or similar return 200 with a body | `curl` | An early-response gadget exists — 0.CL can be weaponized |
| Multiple CDN/proxy layers in front of the origin (Akamai / Cloudflare / Fastly, chained) | Fingerprinting | More parsers in the chain = higher hit rate |

## Test Methodology

### Step 0 — Scope and safety gate

```
1. Confirm the program explicitly permits request-smuggling testing (most restrict it).
2. Test must reuse a single keep-alive TCP connection — curl does not do this by
   default; use an explicit raw-socket approach.
3. Avoid production peak-traffic windows; single-shot PoC only, never a scan.
4. Any of the following is a stop signal: someone else's response on your socket,
   a target hang, or a spike in 5xx responses.
```

### Step 1 — CL.0 baseline detection

PortSwigger Web Security Academy's canonical payload (single connection, two requests):

```http
POST /vulnerable-endpoint HTTP/1.1
Host: target.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: xGET / HTTP/1.1
Host: target.example.com
```

Interpretation: **the second response comes back 404** (instead of the homepage's 200) → the back-end treated the POST body as the start of a new request, meaning it resolved the effective Content-Length to 0.

```bash
# Open a raw connection with ncat / openssl s_client and paste the raw payload
ncat --ssl target.example.com 443 < payload.txt

# Or in Burp Repeater: turn OFF "Update Content-Length", use "Send group in sequence"
```

### Step 2 — 0.CL detection (vanilla Expect)

```http
POST /api/path HTTP/1.1
Host: target.example.com
Connection: keep-alive
Expect: 100-continue
Content-Length: 291
Content-Type: application/x-www-form-urlencoded

GET / HTTP/1.1
Host: target.example.com
X-Ignore: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Interpretation: the front-end returns a bare 400 while the back-end never received a body — a "mystery 400" is a 0.CL candidate. The next step is finding an early-response gadget to turn it into a weaponized CL.0 (double-desync).

### Step 3 — Obfuscated Expect (WAF bypass)

```http
POST /path HTTP/1.1
Host: target.example.com
Connection: keep-alive
Expect: y 100-continue
Content-Length: 50

GET /admin HTTP/1.1
X-Foo: bar
```

`Expect: y 100-continue` — a front-end regex that only matches the exact string `100-continue` lets this through unmodified, while a more permissive back-end parser still recognizes it → CL.0. This is the technique Kettle used to land CVE-2025-32094 against Akamai.

### Step 4 — TE.0 (chunked variant)

```http
POST /path HTTP/1.1
Host: target.example.com
Connection: keep-alive
Transfer-Encoding : chunked
Content-Length: 4

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0


```

Note the **trailing space** after `Transfer-Encoding` — a lenient front-end accepts it, while a strict back-end rejects the malformed header and falls back to treating the request as having no `Transfer-Encoding` (i.e., CL=0). This differentially tests how strictly a reverse proxy normalizes header names.

### Step 5 — Weaponizing via double-desync (0.CL → CL.0)

1. First POST: a vanilla Expect trigger produces 0.CL; an IIS-style early-response gadget (e.g. `/con`) makes the back-end respond immediately instead of hanging.
2. Second POST, same connection: send a CL.0 payload that prefixes the victim's next request.
3. The victim's next request on that connection gets consumed by the prefix (response-queue poisoning).

Full chain math and exact Content-Length accounting is covered in the source whitepapers referenced below.

## Bypass Techniques (Variant Catalog)

| Technique | Payload core idea | Applicable front-ends | Source |
|-----------|--------------------|------------------------|--------|
| CL.0 (vanilla) | `Content-Length: N` on a request/endpoint that shouldn't have a body | Reverse proxy + origin that doesn't ignore CL | PortSwigger Academy lab |
| 0.CL via Expect | `Expect: 100-continue` + large CL | Front-end mishandles Expect | Kettle 2025 (T-Mobile, $12K) |
| CL.0 via obfuscated Expect | `Expect: y 100-continue` | WAF regex only matches the exact value | Kettle 2025 (Akamai, CVE-2025-32094, $9K) |
| TE.0 (trailing space) | `Transfer-Encoding : chunked` | Lenient front-end + strict back-end | Kettle 2019 + 2025 |
| TE.0 (case / duplicate) | `transfer-Encoding: chunked\r\nTransfer-encoding: x` | Some proxies only read the first header instance | Kettle 2019 |
| Browser-powered desync (client-side) | Cross-origin fetch + connection-pool poisoning + connection-locked headers | Victim's browser becomes the delivery mechanism | Kettle 2022, DEF CON 30 |
| HTTP/2 → HTTP/1.1 downgrade smuggling | Front-end speaks H2, back-end speaks H1; header-casing discrepancies | H2 front-end + H1 origin | Kettle 2021 |
| Early-response gadget | `/con` / `/aux` / `/nul` (IIS) / large static file / redirect endpoint | Turns a hung 0.CL into a usable primitive | Kettle 2025 |

## Impact Assessment / Severity Guide

| Condition | Severity | Notes |
|-----------|----------|-------|
| End-to-end proof of hijacking another user's response / stealing a session cookie / Authorization header in production | **P1 Critical** | A genuine desync exploit; a viable entry point for account takeover chains |
| Confirmed CL.0 / 0.CL with prefix injection on an auth endpoint, capable of rewriting a victim's next request | **P1-P2** | Response-queue poisoning is directly achievable |
| CL.0 / TE.0 confirmed but limited to an isolated endpoint with no follow-on impact (e.g., only affects the attacker's own subsequent request) | **P3 Medium** | Parser discrepancy is verified, but there's no demonstrated victim impact |
| Expect-based parser discrepancy produces a hang/400 with no early-response gadget found | **P3-P4** | Still in the "mystery 400" / 0.CL stage; report should clearly label this as theoretical impact |
| Only an automated "Probable" from HTTP Request Smuggler with no manual reproduction | **P5 Informational** (unverified) | Do not submit; keep looking for a weaponizing gadget |

**Anti-overclaim reminders**:

- "The second request got a 404" is evidence of a parser discrepancy — it is not the same claim as "session theft is possible." Separate **verified parser discrepancy** from **theorized session-hijack chain** explicitly in the report.
- Don't paste a PortSwigger Academy lab payload directly into a production PoC. The real front-end/back-end combination will require different Content-Length arithmetic, line endings, and gadgets.
- If response-queue poisoning genuinely occurs, it affects real, uninvolved users. Describe the actual observed blast radius honestly — don't claim "all users are instantly compromised" when you observed a single cross-contaminated response.

## Stop-Loss

- If Steps 1-4 produce no observable discrepancy after a small, careful number of single-shot probes, do not escalate to repeated/scanning-style testing on production — stop and move on.
- If any test produces an unintended cross-user response, a target hang, or a spike in 5xx, stop immediately and switch to an authorized lab for further reproduction.

## References

- [[Pattern - CORS Misconfiguration]] — another platform-level default-configuration class of bug that benefits from testing the default/shared chain rather than each individual app
- James Kettle — Browser-Powered Desync Attacks (DEF CON 30 / 2022): <https://portswigger.net/research/browser-powered-desync-attacks>
- James Kettle — HTTP/1.1 Must Die: the desync endgame (2025): <https://portswigger.net/research/http1-must-die>
- PortSwigger Web Security Academy — CL.0 request smuggling: <https://portswigger.net/web-security/request-smuggling/browser/cl-0>
- PortSwigger Web Security Academy — HTTP request smuggling tutorial: <https://portswigger.net/web-security/request-smuggling>
