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

> ⚠️ 明文 / 真值 / hash 只放在下方的 fenced code block，**不要進 frontmatter**。
> Hub: `[[Target - {{TARGET}}]]`
> Service: `[[]]`

---

## 1. Snapshot

| 欄位 | 值 |
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

## 2. 真值（敏感）

```
<!-- 明文 / hash / 真值放這裡。不要 commit 這個 block 到 public repo。 -->
```

---

## 3. 怎麼挖到的

- Tool / command:
- Source path:
- Snippet:

```bash
# reproducible command
```

---

## 4. 驗證 PoC

```bash
# 證明憑證可用
curl -H "Authorization: Bearer ..." https://api.example.com/me
```

預期回應：
- HTTP code:
- Body 摘要:

---

## 5. Privilege / Blast Radius

- 拿到後可以做什麼：
- 影響到的其他 service / target：
- 這條憑證是否被 reuse 在別的環境？

---

## 6. 升級成 Finding

- 對應 Finding: `[[Finding - ...]]`
- VRT 分類：
- CVSS：

---

## 7. Disclosure

- 通報日期：
- Rotation 確認：
- 後續責任揭露：
