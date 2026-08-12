---
type: pattern
title: Pattern - Cross-System Credential Reuse (Enterprise Lateral Movement)
tags: [pattern, credential-reuse, lateral-movement, enterprise, sqli-chain, bb-pattern]
status: verified
vuln_class: credential-reuse, broken-access-control
severity: P1 Critical
first_seen: 2026-06-19
last_updated: 2026-06-19
precedents: "SQLi against an ERP system extracted an admin credential that was reused successfully against a separate internal warehouse-management system"
---

# Pattern: Cross-System Credential Reuse (Enterprise Lateral Movement)

> A credential extracted from one system (via SQLi dump, config leak, or a hardcoded value in JS) turns out to be valid on other systems within the same organization, because enterprise IT commonly reuses one password across multiple systems. Example: an ERP SQLi finding extracted an `admin:<company-name>` style credential, which was then found to log in directly to a separate warehouse-management system.

---

## Why Enterprise Environments Have High Password-Reuse Rates

| Reason | Explanation |
|------|------|
| Centralized IT management | One IT staffer manages every system and tends to reuse one password set |
| Unchanged factory defaults | Multiple systems from the same vendor ship with the same factory default (`admin:admin`, `admin:<company-name>`) |
| ERP/AD sync | Some systems are wired directly to AD/LDAP, syncing passwords |
| Naming-convention passwords | A company-name abbreviation used as a password (`acme`, `company123`) gets reused across systems |

---

## Trigger Conditions

Run cross-system testing immediately after any of the following, and only against systems covered by prior written authorization:

- [ ] SQLi successfully extracted a credential (plaintext, or a weak hash that was cracked)
- [ ] A config file / env leak contained a password
- [ ] A JS bundle had a hardcoded credential
- [ ] A known default credential was found (`admin/admin`, `admin/`)
- [ ] Vendor documentation lists a default credential

---

## Execution Flow

### Step 0: GET the login page first, confirm the actual form field names

```bash
# Don't assume the fields are named username/password
curl -sk http://TARGET/login.php | grep -oP 'name="[^"]+"'
# -> name="user", name="pass"  <- use these exact names
```

Wrong field names produce an HTTP 200 with an empty body, easily misread as "the vulnerability doesn't exist."

### Step 1: Build a Test Matrix

Enumerate the credentials already recovered and the in-scope login endpoints, then try each already-known credential against each in-scope endpoint using the endpoint's actual field names from Step 0. Rate-limit requests and record every attempt (success and failure) in the recon log — this is authorization-boundary testing using credentials you already legitimately possess, scoped strictly to systems covered by the engagement, not brute forcing.

### Step 2: Success-Indicator Identification (differs per system)

| Success indicator | Commonly seen in |
|---------|--------|
| HTTP 302 to a dashboard path | Traditional PHP web apps |
| JSON success field in the body | REST APIs |
| An explicit "login successful" flag/message | Legacy ASP.NET AJAX apps |
| Set-Cookie + 302 | Most session-based apps |
| HTTP 200 + rendered dashboard HTML | Direct server-side rendering |

### Step 3: Record the Operation

Log a simple table in the recon notes: timestamp, credential tried (redacted as needed), target endpoint, and result — for both successes and failures. This creates the evidence trail needed for the eventual report.

---

## Testing Priority Order

Within systems found under the same organization, test in this order:

1. **Other systems from the same vendor** (e.g. another deployment of the same ERP vendor's product)
2. **Admin interfaces with an unknown credential** (NVR / AP / firewall)
3. **Internal IT tools** (e.g. registry, monitoring, log dashboards)
4. **Business applications** (ERP / POS / access control)

---

## Distinguishing a Vendor Bug from a Deployment Misconfiguration (Important)

When an empty or default password is found, determine which category it falls into:

| Nature | Characteristics | Impact |
|------|------|------|
| **Vendor code bug** | The endpoint has no authentication at all (no configuration could fix it) / the product allows an empty password with no forced change | Every customer of the vendor is affected, file an independent vendor report |
| **Deployment misconfiguration** | The vendor provides a forced password-change mechanism but the operator skipped it | Only this one deployment is affected, file a customer-specific report |
| **Both** | An empty password is allowed by the vendor AND the customer never set one | File both reports |

> Example pattern: an unauthenticated internal API endpoint is a vendor bug (affects every customer using that product), while an admin account left with an empty password is a deployment issue (the vendor didn't force a change and the customer never set one) — shared responsibility, two separate findings.

---

## Attack-Chain Escalation Path

A credential obtained from any in-scope source, once tested against every known in-scope system, escalates in severity with the number of systems it works on: a single additional system (N=1) already justifies bumping to P2 High, since cross-system reuse itself is an escalation signal; three or more systems (N=3+) indicates a systemic password-management failure and justifies P1 Critical. Build a single Finding documenting the full chain: the original vulnerability that yielded the credential, followed by this reuse finding, with the attack chain clearly marked in the report.

---

## Tooling

- A batch credential-reuse tester script that tries every combination against in-scope endpoints only
- A centralized "known credentials" section in recon notes for extracted credentials
- Finding frontmatter fields like `chain: true` + `chain_from: [<original-finding-id>]` to mark the attack-chain relationship

## Cross-Reference

- [[Pattern - Account Enumeration Oracle]]
- [[Pattern - SQL Injection]]
- [[Pattern - Blind SQL Injection]]
