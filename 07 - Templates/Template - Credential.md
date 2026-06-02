---
fileClass: Credential
target: "[[]]"
service: "[[]]"
kind: "admin-password | user-password | api-key | oauth-secret | oauth-token | jwt | session-cookie | db-password | ssh-key | git-token | aws-key | gcp-key | firebase-key | maps-key | stripe-key | webhook-url | signed-url | turn-secret | private-key"
source: "git-leak | source-map | apk-decompile | ipa-decompile | firmware-extract | js-bundle | env-leak | config-file | http-response | graphql-introspection | password-spray | brute-force | default-creds | password-reuse"
source_location: ""
verified: "yes-live | yes-historical | rejected | rate-limited | untested | revoked"
privilege: "superadmin | admin | user | readonly | api-only | unknown"
redacted_value: ""
discovered_date: <% tp.date.now("YYYY-MM-DD") %>
rotated_date: ""
findings_produced: []
parent: "[[]]"
tags:
  - credential
  - sensitive
---

# Credential — {{TARGET}} — {{KIND}}

> ⚠️ Plaintext / actual value / hash goes only in the fenced code block below — **do not put it in frontmatter**.
> Hub: `[[Target - {{TARGET}}]]`
> Service: `[[]]`

---

## 1. Snapshot

| Field | Value |
|---|---|
| Target | `[[]]` |
| Service | `[[]]` |
| Kind | |
| Source | |
| Source location | |
| Verified | |
| Privilege | |
| Redacted | |
| Discovered | |
| Rotated | |

---

## 2. Actual Value (sensitive)

```
<!-- Put plaintext / hash / actual value here. Do not commit this block to a public repo. -->
```

---

## 3. How It Was Found

- Tool / command:
- Source path:
- Snippet:

```bash
# reproducible command
```

---

## 4. Verification PoC

```bash
# Prove the Credential is usable
curl -H "Authorization: Bearer ..." https://api.example.com/me
```

Expected response:
- HTTP code:
- Body summary:

---

## 5. Privilege / Blast Radius

- What can be done with this Credential:
- Other services / targets affected:
- Is this Credential reused in other environments?

---

## 6. Upgrade to Finding

- Corresponding Finding: `[[Finding - ...]]`
- VRT category:
- CVSS:

---

## 7. Disclosure

- Reported date:
- Rotation confirmed:
- Follow-up responsible disclosure:
