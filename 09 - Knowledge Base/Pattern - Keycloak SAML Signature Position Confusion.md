---
type: pattern
title: "Pattern - Keycloak SAML Signature Position Confusion"
category: saml
status: active
last_updated: 2026-06-04
tags: [keycloak, saml, cve-2024-8698, signature-confusion, idp, bb-pattern]
---

# Pattern -- Keycloak SAML Signature Position Confusion (CVE-2024-8698)

> When Keycloak validates SAML assertions, it incorrectly determines the signature position (enveloped vs enveloping), allowing an attacker to replace the assertion content while retaining a valid signature, achieving SAML response forgery / arbitrary identity substitution. This can be directly referenced via the CVE without needing to rediscover the vulnerability.

## Trigger Conditions

Target uses Keycloak as a SAML IdP.

## CVE-2024-8698

When Keycloak validates SAML assertions, it incorrectly determines the signature position (enveloped vs enveloping), allowing an attacker to replace the assertion content while retaining a valid signature.

## Impact

SAML response forgery -> arbitrary identity substitution.

## Version Confirmation

- Affected: Keycloak < 22.0.10 / < 24.0.6 (confirm based on release date)
- Obtain version: `/auth/realms/master` returns `keycloak-version`

## Usage

- First confirm the Keycloak version (version precheck)
- Directly reference CVE-2024-8698; suitable for use with version-cve-precheck workflows

## Related Patterns

- [[Pattern - Custom OIDC Redirect URI Validation]]
