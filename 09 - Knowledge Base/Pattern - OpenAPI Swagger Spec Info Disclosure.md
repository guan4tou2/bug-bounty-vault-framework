---
type: pattern
title: "Pattern - OpenAPI Swagger Spec Info Disclosure"
category: information-disclosure
status: active
last_updated: 2026-06-04
tags: [openapi, swagger, info-disclosure, api-recon, cwe-200, bb-pattern]
---

# Pattern -- OpenAPI / Swagger Spec as Information Disclosure

> A publicly accessible OpenAPI/Swagger spec is itself an Information Disclosure finding (CWE-200), **regardless of whether the endpoints are actually reachable**.

## Trigger Conditions

During initial reconnaissance on any API endpoint, try the following paths:

```
/swagger.json
/openapi.json
/api-docs
/swagger/v1/swagger.json
/v2/api-docs
/v3/api-docs
```

## Core Content

- A public spec is itself a finding. Leaked items include:
  - Complete endpoint list
  - Request / response schemas
  - Auth model (Bearer / apiKey / OAuth scope)
  - Contact email, tenant ID, environment tag (staging / prod)
- `security: []` field = that endpoint is explicitly marked as requiring no auth -> test it first
- Report type: CWE-200 Information Disclosure; if auth scheme details are included, can be upgraded to security design issue

## SIT vs PROD Diff Attack

If the SIT spec has `/api/internal/admin` but the PROD spec does not:
1. Download both SIT and PROD specs
2. `diff` the endpoint lists
3. Endpoints that actually exist on PROD but are not documented in the PROD spec = undocumented endpoints -> test these first

## Anti-exaggeration

- Spec readable does not equal endpoints usable. Reports should only state what can be proven: "spec publicly leaks N endpoints + auth model."
- If claiming an undocumented endpoint is reachable, you must actually send a request to PROD and confirm a 200 / valid response.

## Related Patterns

- [[Pattern - Tech Stack Fingerprint to Probe Mapping]] -- SIT vs PROD OpenAPI diff flow
