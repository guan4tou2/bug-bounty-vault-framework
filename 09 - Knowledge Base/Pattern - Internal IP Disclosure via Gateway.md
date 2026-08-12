---
type: pattern
title: "Pattern - Internal IP Disclosure via Gateway"
name: Internal IP Disclosure via Gateway Redirect/WADL
description: Public-facing reverse proxy leaks internal RFC 1918 IP + specific ports (including admin console port) via Location header or response body
last_updated: 2026-04-20
tags: [information-disclosure, cwe-200, jboss, wadl, redirect, lateral-movement, supply-chain, bb-pattern]
status: active
---

# Pattern -- Internal IP Disclosure via Gateway (Redirect / WADL / Error body)

## Core Concept

A public-facing reverse proxy / application gateway **directly exposes the internal backend host's private IP (RFC 1918) and port** in certain responses. This typically occurs via:

1. **Redirect Location header**: Public path -> backend redirect where the Location is not rewritten
2. **WADL / Swagger response body**: Auto-generated API schemas contain backend base URL
3. **Verbose error stack trace**: Exception messages contain internal hostname / file path
4. **Set-Cookie JSESSIONID suffix**: Java servlet session routing suffix contains internal pod names

## Example

### E-commerce Gateway (JBoss EAP 7 / Undertow 1 / Jersey 2.26)

**Host**: `epgateway.vendor-example.com`

| Leak Channel | Specific Content |
|---|---|
| `GET /console` Location header | `Location: http://10.32.34.199:9990/console` -- JBoss admin port |
| `OPTIONS /api` WADL body | `<resources base="http://10.32.34.199:8080/api/">` -- Jersey backend port |
| `Server` header | `JBoss-EAP/7` |
| `X-Powered-By` | `Undertow/1` |

Reveals 3 items of attacker value:
- Internal network segment `10.32.34.0/24`
- JBoss admin console port `9990` on that internal host
- Wildfly HTTP internal port `8080`

## Exploitability Assessment Flow (mandatory)

**First ask "Can we reach `10.x.x.x:9990` directly from the public internet?" -- usually not (RFC 1918 is not routable)**

But you must test and rule out the following pivot vectors to confirm "not directly exploitable":

| Vector | Test Command | Expected Block |
|---|---|---|
| Host header SSRF | `curl -H "Host: 10.x.x.x" https://gateway/` | 421 Misdirected Request (TLS SNI enforced) |
| URL override header | `curl -H "X-Original-URL: /management" https://gateway/` | 200 default landing (header ignored) |
| X-Forwarded-For / Host | Same as above | Usually forwarded but does not change backend path |
| Path proxy to admin | `curl https://gateway/management` | 404 |
| Path traversal | `curl https://gateway/console/../management` | 404 |
| Extra API paths | `curl https://gateway/api/<other>` | 404 |

If all are blocked -> severity is constrained to **supply-chain recon** rather than direct exploit.

## Severity Classification

| Scenario | Severity |
|---|---|
| Pure internal IP leak (no admin port info) | P5 info only |
| Internal IP + specific admin console port | **P4 Low-Medium** |
| Internal IP + admin port + supply chain correlation (known vendor network interconnectivity) | P3 Medium |
| + SSRF from public internet to that IP | P2-P1 (upgrades to full SSRF) |

## Program Acceptance

- Programs that do not explicitly exclude internal IP disclosure in their OOS policy
- OOS "Verbose messages/files/directory listings (no sensitive data)" -- counter with "Internal IP + admin port IS sensitive"
- OOS "Banner grabbing/Version disclosure" -- counter with "the core leak is in response body / Location header, not the Server header"
- Bugcrowd / HackerOne average severity for "Internal IP in error/redirect" is P4

## How to Report

Required elements:

1. **3 independent reproduction channels** (redirect + WADL + another) -- prevents the "transient debug artifact" argument
2. **Exploitability test records** (which pivot vectors were tested + results) -- proactively downgrading severity to P4 builds triager trust
3. **Supply chain argument**: Once an attacker gains supplier VPN access / employee device -> they directly know the target internal layout
4. **Remediation**:
   - Reverse proxy should rewrite Location header (use external URL or return 404)
   - Jersey: `jersey.config.server.wadl.disableWadl=true`
   - Block external access to `/console` and `/management`
   - Suppress Server / X-Powered-By headers

## Submission Template

```
Title: <host> -- <app-server> leaks internal IP <x.x.x.x> + admin port <N> via <redirect/WADL>

Severity: P4 Low
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

Severity note: RFC 1918 private, not directly reachable from internet.
Exploitation requires prerequisite internal foothold. Exploit paths tested
and blocked: (list). Value is supply-chain lateral-movement reconnaissance.

Not Line 62 (verbose messages): disclosed values are specific internal
network coordinates, not generic error text.
Not Line 81 (banner): core leak is in response body / Location header,
not Server banner.
```

## Related Patterns

- [[Pattern - Source Map Exposure]] -- Another info disclosure boundary
- [[Pattern - Hardcoded Credentials]] -- More severe info disclosure (directly usable)
