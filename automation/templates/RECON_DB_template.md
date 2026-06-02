# {{TARGET}} — Recon Database

> **Required reading at session start** (alongside FINDINGS_QUICK_REF.md). This file records all raw recon data: Credentials, paths, accounts, and infrastructure details.
> Append new findings as you go; commit to save.
> Last updated: {{DATE}}

---

## Status Overview

| Field | Value |
|-------|-------|
| Platform | |
| Program URL | |
| Last Recon Date | |
| Current Status | active / parked / closed |
| Known Findings | See FINDINGS_QUICK_REF.md |
| Key Attack Surface | — |

---

## ⏳ Deferred Actions (deployed, awaiting trigger)

> **Required reading at session start.** Actions that have been executed but not yet triggered. "Found an endpoint" does not equal "action deployed" — any deployed payload, written file, or chain step awaiting a callback must be recorded here with its current status, and reflected in memory.

_No deferred actions at this time._

<!--
Example row (fill in when a deferred action exists):

| Action Description | Target Host | Deployed At | Trigger Condition | Triggered | Callback / Response |
|--------------------|------------|-------------|-------------------|-----------|---------------------|
| /app/main.py payload write (#84) | api.example.com PROD | Session N | pod natural restart | ❌ | VPS :80/rce_proof |

SSRF capability boundaries (common misconceptions):
- "Service reachable (oracle confirmed)" ≠ "response readable" ≠ "exploitable"
- Blind SSRF: can only confirm connectivity; cannot read any response content
-->

---

## 🔑 Credentials & Keys

> ⚠️ Internal use only — must not appear in platform submissions or ZIP attachments.

| Type | User / Key | Value | Host / Service | Source | Status |
|------|-----------|-------|---------------|--------|--------|
| — | — | — | — | — | — |

---

## 🔍 Known Artifacts (confirmed to exist — do not re-investigate)

> **Each time you confirm a finding, immediately append all concrete identifiers (names, IPs, tokens, emails, extensions, versions, etc.) here.**
> The dedup pre-check script searches this section — this is your primary deduplication line of defense.
> Format: `| #NNN | <type> | <value 1>, <value 2>... | <notes> |`

| Report | Type | Concrete Identifiers | Notes |
|--------|------|----------------------|-------|
| — | — | — | — |

---

## 🛤 Discovered Paths & Endpoints

> Confidence: **TENTATIVE** (indirect hints) → **FIRM** (direct observation) → **CONFIRMED** (multi-source verified)

| URL / Path | Method | Auth? | Response | Confidence | Notes | Status |
|-----------|--------|-------|----------|-----------|-------|--------|
| — | — | — | — | — | — | — |

---

## 🖥 Internal Infrastructure

| Host / IP | Port | Role | Source |
|-----------|------|------|--------|
| — | — | — | — |

---

## 👤 Accounts & Usernames

| Account | Platform / System | Notes | Source |
|---------|------------------|-------|--------|
| — | — | — | — |

---

## 📦 Technology Stack

| Service / Framework | Version | Location | Notes |
|--------------------|---------|----------|-------|
| — | — | — | — |

---

## 🎯 Attack Surface (tested / untested)

| Endpoint / Feature | Status | Priority | Next Step | Attack Path Hint |
|-------------------|--------|----------|-----------|-----------------|
| — | untested | — | — | — |

---

## 🛡️ Pre-flight Checks (version + CVE check before analysis)

> **When to fill**: After obtaining a concrete target version or identifying a cloud target, before starting analysis — run the version and CVE pre-flight check and record results here.
> **Multi-version targets**: One entry per version (or per model); separate entries for each firmware model under the same vendor.
> **SaaS / Cloud**: Use the cloud target sub-table template; use the versioned target sub-table for targets with a version number.

_No entries yet. Add an entry the first time you run the pre-flight check._

---

## 📋 Operation Log

> **Log a row before sending any request (pre-execution logging).** Pre-fill the `Result` column with `pending`; update immediately after execution.
> Log: any POST/PUT/PATCH/DELETE, manual curl GET (endpoint probing), exploit/payload tests.
> Skip: automated scanner per-line output, background VPS scripts (poller/C2/exploit.sh), plain browser UI interactions.
>
> Get source IP: `curl -s https://ifconfig.me` (local) or `ssh <vps-user>@<vps-ip> "curl -s ifconfig.me"` (VPS)

| Time (local) | Time (UTC) | Source IP | Method | Target URL | Intent | Result |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

---

## 📝 Session Log (rolling append)

### {{DATE}} — Initialized

- RECON_DB created
