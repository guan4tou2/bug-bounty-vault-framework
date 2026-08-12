---
type: pattern
title: "Pattern - Mechanical False-Positive Gate"
category: triage
tags: [bb-pattern, false-positive, false-negative, spa-catch-all, header-fingerprint, public-by-design, severity-gate, dotenv, web-config, s3, metabase, promotion-gate, self-learning, transport-layer, http2, doh]
status: active
last_updated: 2026-07-05
---

# Pattern -- Mechanical False-Positive Gate (Pre-Finding Promotion Gate)

## Core Lesson

A review found that **9/9 signals in the findings layer were false positives**, all failing on the most basic live checks. LLM agent systems systematically treated "returns 200 / sees a login page / gets 403" as vulnerabilities, and self-review could not catch their own over-claims (producer bias).

## Mechanically Determinable False Positives (no LLM judgment needed, self-check before logging)

1. **SPA catch-all**: Fetch the target path + a random gibberish path (e.g., `/zqx9random404`). **Both return 200 with nearly identical size -> catch-all, not an exposed surface**. 5 out of 9 FPs were this type (random path byte count was exactly the same).
2. **403 = auth correctly rejecting** -> not a vulnerability.
3. **30x redirect to /login /signin /sso /oauth = auth working correctly** -> not a vulnerability (not "exposed admin panel").
4. **Basic Auth prompt** = protection in place -> not a vulnerability.
5. **WAF challenge 202 / empty body**: CloudFront + AWS WAF returns `202 + x-amzn-waf-action: challenge + content-length: 0` for unsolved challenges, creating a "site-wide 202" false impression -> not actuator exposure (check `x-amzn-waf-action` / `x-cache: Error from cloudfront`).

-> The `bb_log` function includes a built-in `_mechanical_false_positive()` auto-interceptor for types 1-4 before promoting to findings (routes to observation); type 5 and the "advanced SPA differentiation" below are currently manual checks / candidates for gate inclusion.

### Advanced SPA Catch-All Differentiation (three misjudgments the basic random-404 comparison misses)

The basic check (random path returns same 200 + same bytes) only catches the simplest catch-alls; these three patterns still slip through and are repeatedly encountered in practice:

1. **Header fingerprint, not just status/size**: S3-hosted SPA returns `server: AmazonS3` + `content-type: text/html` + same byte count for all paths; real backend returns `server: CloudFront` + `content-type: json` + different `etag`. When status/size match, **also compare headers**. Example: `/config/*` (6098B AmazonS3 = catch-all) vs `/api/` (401 CloudFront json = real backend).
2. **`/api/*` needs per-prefix verification**: Don't assume `/api/*` is also catch-all just because `/`, `/config`, `/auth`, `/random` all return SPA HTML -- frontend static serves `/`, backend API serves `/api/`. Example: `/api/catalog` -> 401 12B JSON, `/api/auth/providers` -> 400 JSON, but `/config/frontend/config` -> 6098B SPA HTML.
3. **JS bundle endpoints are not server-side exposure**: Endpoints extracted from bundles + token patterns may look medium-severity, but if those endpoints all return the same SPA HTML then there is no reachable backend -> observation. Before promoting, do `content-type + size + body` check on **every** endpoint.

## Mechanically Determinable False Negatives (probe-layer artifacts causing you to miss real findings -- the mirror image of false positives)

False positives are "probe returns a good-looking code, you mistake it for a vulnerability"; false negatives are **the other side of the same coin**: probe returns a bad-looking code (505 / cert error / empty body), and you mistake it for "nothing there" and **miss a real endpoint**. The root is identical -- **status code/response reflects the transport/framework layer, not application semantics**. A single status code is not trustworthy; re-verify with an orthogonal signal.

| Symptom | Misreading | Truth | Correct Action (re-probe with orthogonal signal) |
|---------|------------|-------|--------------------------------------------------|
| DoH probe returns `HTTP 505` | "No DoH" | Endpoint only accepts HTTP/2, urllib uses HTTP/1.1 | `curl --http2` to re-probe |
| Connecting via IP gives `IP address mismatch` | "TLS service doesn't exist" | Certificate was issued for hostname, not IP; default validation hides a usable endpoint | Use `CERT_NONE` for detection (equivalent to `curl -k`) |
| Login/SQLi POST returns `200` empty body | "Not injectable / no response" | Wrong field name, backend never entered processing logic = silent FN | First GET HTML to confirm actual field names |
| 403-bypass matrix hits near 0 | "Defense is solid, nothing to bypass" | SPA catch-all returns 200 for all paths, entire matrix is false | Random path body/hash comparison before testing |

-> The mechanical gate has **two faces**: block false positives before logging (don't mis-report), and block false negatives before dismissing/wrapping up (don't miss findings). For any conclusion of "tool reports nothing / probe failed," first ask "**is this a probe-layer artifact (HTTP version / cert hostname / field name / catch-all)?**" before closing.

## False Positives Requiring LLM Judgment (public-by-design, send to adversarial review)

- CA certificates / CRL, Sentry DSN (embedded in client SDK by design, publicly known), public SDK/protobuf/gRPC docs, Swagger/OpenAPI, developer platforms, health page version numbers.
- Only **private keys / secrets / PII / sessions / tokens / account or authorization boundary impact** constitute real vulnerabilities.

### Specific Downgrade Rules (successfully refuted in adversarial review; default downgrade unless upgrade conditions are met)

| Exposure | Default Judgment | Upgrade to Real Finding Condition | Why Default Downgrade |
|----------|-----------------|----------------------------------|----------------------|
| `.env` containing only `MIX_*` | info | File contains real credentials / API key / DB connection / PII / token | `MIX_*` is by design compiled into public JS build, not secret; exposure is hygiene only |
| `web.config` with no secrets | observation | appSettings credentials / connectionStrings / private key / token, or provable auth bypass | Only contains framework rewrite/filter/front-controller rules with no sensitive data |
| S3 bucket is listable | recon-only | Listed objects contain secrets/PII, bucket is writable, or chains to exploitable path | "Can list" by itself is not a vulnerability; needs exploitable content or write access |
| Metabase setup-token | unconfirmed | `/api/setup/status` is non-404 AND token can provably create admin | `/api/session/properties` after setup may still return a non-empty token; `POST /api/setup` returning 403 `"...can only be used to create the first user, however a user currently exists."` = token consumed, currently not exploitable (residual angle: during the exposure window it may have been abused; recommend vendor audit for unauthorized admin accounts, do not purely close as FP) |
| public-by-design artifact | observation (send to review) | Private key / secret / readable Sentry events / post-auth data / account boundary impact | CA/CRL, public SDK/protobuf/gRPC, Sentry DSN (ingestion only) are public/client-facing by purpose |

Minimal mechanical verification: `.env` grep `APP_KEY|DB_|AWS_|SECRET|_TOKEN|_KEY`; `web.config` grep `password|connectionString|PrivateKey|Bearer|ApiKey`; Metabase first `GET /api/setup/status` (404 = setup already complete = token likely invalid, do not POST `/api/setup`).

## Two-Layer Defense + Self-Learning

```
Recon SOUL content verification (source: returning 200 cannot be logged, must inspect actual content)
  -> Mechanical FP gate (intercept SPA/403/30x at log time, purely mechanical)
    -> Adversarial review (judgment-class FP; when demoting, --learn records generalizable lessons)
       -> Lessons enter learnings database, next agent query can find them
```

## Breadth/Depth Division of Labor

- VPS (cheap model) shallow probing generates noise -> deep leads (source audit/firmware/multi-step chain/authenticated state) use handoff to local high-tier model, don't force shallow models to go deep.

## Related

- [[Pattern - High-Yield Unauthenticated Web Hunting]]
