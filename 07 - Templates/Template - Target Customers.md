---
type: target-subpage
subpage: customers
target: "[[Target - {{name}}]]"
last_updated: "{{date}}"
total_customers: 0
tier1_count: 0
---

# {{name}} — Customers

> Tier-1 customer list. **Used for impact analysis, advisory impact writing, and risk assessment.**
> Sources: CloudKey enumeration / public website / customer testimonials page / DNS reverse association / subdomain fixed patterns, etc.
> Back to hub: [[Target - {{name}}]]

---

## Summary

| Tier | Count | Criteria |
|---|---|---|
| **Tier-1** (verified + high sensitivity) | 0 | Financial / Government / Healthcare / Enterprise |
| **Tier-2** (publicly listed but not sensitive) | 0 | General business / Retail |
| **Suspected** (inferred, unverified) | 0 | DNS patterns / testimonials but unconfirmed |

---

## By Industry

### Financial / Regulated

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Government / Public Sector

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Healthcare

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Telecom / Network

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Retail / Consumer

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Manufacturing / Semiconductor

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

### Education / Other

| Customer | Tier | Source | Verification Method | Notes |
|---|---|---|---|---|
| — | — | — | — | — |

---

## Cross-border / International

> If there are cross-border customers (e.g., subsidiaries in other regions), cross-reference with program scope: are they in-scope or OOS.

| Customer | Region | Note |
|---|---|---|
| — | — | — |

---

## High-impact targets within customer base

> Which customers would amplify impact if the vulnerability were triggered (used for advisory Impact section).

- —

---

## Collection Methodology

```bash
# Example: CloudKey enumeration
curl -s 'https://<endpoint>?ASK=getServerSetting&CloudKey=test' | jq

# Example: crt.sh reverse certificate lookup
curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value' | sort -u
```

---

## Related

- Hub: [[Target - {{name}}]]
- Attack Surface: [[{{name}} - Attack Surface]]
- Submissions: [[Submissions/_index]]
