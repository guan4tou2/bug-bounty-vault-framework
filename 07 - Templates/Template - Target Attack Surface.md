---
type: target-subpage
subpage: attack-surface
target: "[[Target - {{name}}]]"
last_updated: "{{date}}"
apex_domains: 0
subdomains_total: 0
products: 0
---

# {{name}} — Attack Surface

> Complete attack surface inventory: apex domains, subdomains, product families, tech stack, exposed endpoints.
> Back to hub: [[Target - {{name}}]]

---

## 1. Product Families

| Product | Tier | Platforms | Deployment | Status |
|---|---|---|---|---|
| — | — | — | — | — |

---

## 2. Apex Domains

| Apex | Purpose | Primary IP | Hosting | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

---

## 3. Subdomain Inventory

> Sources: subfinder / chaos / crt.sh / subdomain enumeration
> Keep the full list in `workshop/<target>/subs.txt`; this page only lists **meaningful hits**

### 3.1 Production / Customer-facing

| Subdomain | Purpose | Technology | Attack Value |
|---|---|---|---|
| — | — | — | — |

### 3.2 R&D / Internal-facing

| Subdomain | Purpose | Technology | Attack Value |
|---|---|---|---|
| — | — | — | — |

### 3.3 Staging / Test / UAT

| Subdomain | Purpose | Technology | Attack Value |
|---|---|---|---|
| — | — | — | — |

---

## 4. Tech Stack (by platform)

### 4.1 Web

- —

### 4.2 Desktop

- —

### 4.3 Mobile (Android / iOS)

- —

### 4.4 Server / SaaS

- —

---

## 5. Exposed Endpoints

> Publicly reachable and enumerable API / portal / static assets.
> **Every endpoint must be tested!** Check off the OWASP column when tested. Unchecked = untested.

| Endpoint | Params | Auth | Method | A03 Injection | A06 CVE | A10 SSRF | WAF | Finding |
|---|---|---|---|---|---|---|---|---|
| — | — | — | — | ☐ | ☐ | ☐ | — | — |

**A03 Injection checklist** (run for every param): SQLi(boolean+time) / XSS(dialog) / LFI / CMDi / SSTI / XXE

**Endpoint → Kanban linkage**: each endpoint should also have a card in the Per-Target Kanban; move to Dead End or Candidate when tested.

---

## 6. Third-Party Dependencies (SBOM)

> **Every version number must be checked for CVEs** (`bb-version-cve-precheck`). Unchecked = ⬜, checked = ✅/❌.

| Component | Version | CVE Check | Known CVE | Exploitable? | Notes |
|---|---|---|---|---|---|
| — | — | ⬜ | — | — | — |

---

## 7. Related IPs / ASN

| ASN | IP Range | Service | Notes |
|---|---|---|---|
| — | — | — | — |

---

## Related

- Hub: [[Target - {{name}}]]
- Customers: [[{{name}} - Customers]]
- Recon Sessions: [[Recon/_index]]
- SCOPE: [[SCOPE]]
