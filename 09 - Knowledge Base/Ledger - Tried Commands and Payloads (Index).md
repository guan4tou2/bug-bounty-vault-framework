---
fileClass: Ledger
type: ledger-index
title: Tried Commands and Payloads — Ledger Index
last_updated: 2026-07-08
tags: [ledger, payload, outcome-feedback, bb-ledger, index]
source: internal
---

# Ledger — Tried Commands and Payloads (Index)

> **In one line:** the only cross-target, durable, cumulative **output-side** record layer — it captures "which exact syntax / command / payload was tried, and what came back". It closes the feedback gap between the payload arsenal (which holds only INPUT) and the audit log (which holds syntax but is ephemeral).

---

## Why this layer exists (the confirmed gap)

None of the existing layers is a reusable, syntax-level record of what succeeded and what failed:

| Existing mechanism | Level | Why it does not close the gap |
|---|---|---|
| Payload arsenal (`security-arsenal` / `osint-arsenal` / `Pattern -`) | **INPUT only** | Tells you what to try, never how a target class actually responded |
| §6d Operation Log (`RECON_DB`) | action / disclosure | Auditable, per-target trail for the vendor; not abstracted, not cumulative across targets |
| §3b Discovery Log (Finding) | attack narrative | Bound to a single Finding; not a searchable syntax library |
| §6f Bash Audit Log | syntax-level | **Ephemeral** — git-ignored, rotated out, restore-only, and deliberately not meant to be read back for reuse |

**The ledger is the OUTCOME feedback loop**: it closes `arsenal (what to try) → actual result (how it responded) → next payload choice (pick what bypasses first)`. The goal is not disclosure and not single-case narrative — it lets the next session, before hunting a new target, see at a glance which syntaxes on a given vuln class are stably blocked, return 200, or bypass a given defense.

---

## File organization (per-vuln-class scheme)

One `Ledger - <class> Tried.md` per vuln class, mirroring the existing `Pattern -` / `Reference Card -` naming so Obsidian search and wikilinks work. Open a new class file once a class accumulates its 3rd reusable syntax; below that, keep rows in the tail of the nearest existing ledger.

---

## Row schema (uniform across every ledger)

```markdown
| payload/command | target class (sanitized) | result | date | source ref |
```

| Column | Meaning |
|---|---|
| **payload/command** | The **exact** syntax tried (including the key header / encoding / parameter). Copy-pasteable is the point; use `${VAR}` placeholders in place of real values |
| **target class (sanitized)** | A **class-level** description, e.g. `custom OIDC server`, `Spring Boot actuator (exposed)`, `Node URL-fetch backend`. **No** target name / hostname / IP |
| **result** | Normalized enum: `blocked` / `200` / `bypassed` / `error` / `filtered` / `WAF-403` / `no-effect`. A short note may be appended |
| **date** | `YYYY-MM-DD` (first observation) |
| **source ref** | Back-link to the source arsenal or `Pattern - <class>`, forming a two-way index |

---

## Sanitization rule (hard rule)

- **Class-level only**: the payload syntax may be concrete, but who it was fired at is always abstracted to a defense / technology class.
- **Forbidden**: target names, hostnames, IPs, internal case IDs, and any secret / token / cookie value → use `${TOKEN}`, `${HOST}`, `${REGISTERED_URI}` placeholders.
- Consistent with KB purity: a row enters the ledger only after it is abstracted. If a row cannot be sanitized to class level, it does not belong here — it stays in the per-target Operation Log.

---

## What goes in, what stays out

**In (reusable, syntax-level outcomes):**
- A payload that is **stably blocked** or **stably bypasses** a class of defense → record it so nobody retries blindly
- An encoding / header trick that flips a `WAF-403` into a `200`
- A probe syntax that is a reliable oracle for a technology class

**Out:**
- One-off operations bound to a specific target that cannot be abstracted (keep in §6d / §3b)
- Pure disclosure records (that is §6d's job)
- Any secret / PII / internal ID

---

## Skill hooks

| Trigger | Skill | Action on the ledger |
|---|---|---|
| A test / payload yields a negative / false-positive / blocked result | `bb-attempt-recorder` | Sanitize the `Exact syntax tried:` row and append it to the matching ledger (result = `blocked` / `error`) |
| Session-end knowledge reflux | `bb-knowledge-capture` | Scan this session's new ledger rows, decide whether any should be promoted to a `Pattern -`, and back-fill a pattern's key syntax into the ledger |
| Before hunting a new target / picking a payload | surface-mapping / arsenal lookup | **Read the matching ledger first** → prefer syntaxes that historically bypass, skip those that stably fail |

---

## Table template + illustrative row

Copy this into each new `Ledger - <class> Tried.md`. The row below is a fully generic placeholder — replace it with real (sanitized) entries; do not leave the example in a live ledger.

| payload/command | target class (sanitized) | result | date | source ref |
|---|---|---|---|---|
| `GET /${PATH} HTTP/1.1` + `Header: ${VALUE}` | example-class (`${HOST}` placeholder) | `blocked` | 2026-07-08 | `Pattern - <class>` |

---

## Maintenance

- Update `last_updated` on every new row.
- If the same payload against the same class already has a row → update its result (do not append a duplicate).
- A ledger past ~40 rows should be split by sub-technique.
