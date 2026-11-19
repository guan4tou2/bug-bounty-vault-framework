---
name: bb-cvss-score
description: Use when creating or reviewing a Finding and you need a CVSS 3.1 vector + base score. Stateless desc→vector transform for common BB vuln classes (IDOR, SSRF, XSS, SQLi, RCE, auth bypass, file upload, business logic, OAuth, GraphQL). Triggers include calculate CVSS, CVSS scoring, what severity.
---

# Bug Bounty — CVSS 3.1 Scoring

Given a vuln class, description, PoC/attack steps, and affected component + auth context, output a precise CVSS 3.1 vector and base score. Pure transform — no network, no state, no file writes; do it inline.

## Step 0 — every non-None impact metric needs one verified observation behind it (mandatory)

If C / I / A is anything other than `N`, you must be able to write **one line of an actually-observed result** supporting it. If you can't, downgrade.

| What the observation supports | Ceiling for that metric |
|---|---|
| Data already obtained / modification already made / outage already caused (request+response evidence) | `H` allowed |
| Request already accepted / feature reached / endpoint returns a business error (not 401) | **ceiling `L`** |
| "The attacker should be able to…" inferred from feature semantics | **`N`** — put it in a "potential impact" paragraph, not the vector |

> Why this gate exists (anonymized real case): a finding was first scored 9.1 (`C:H/I:H`) because the query and delete endpoints were **unauthenticated-reachable**. But C:H's substance is "the user list was obtained" (never happened — later proven to have no external retrieval path), and I:H's substance is "records were deleted" (only ever proven *reachable* with an invalid ID). On re-review both metrics were withdrawn → 6.5. **"Reachable" is not High, it's Low.**

Also write one reverse-check line:

> **"What is the minimum that the observation behind this metric requires to be true? Is there a more mundane explanation?"**
> e.g. an exit `code 0` plus a returned id minimally requires only "a statement was generated and an id returned" — it does **not** require "the query executed".

**Claim ladder** — six different claims, six different evidence bars, never interchangeable:
`reachable` → `accepted` → `statement/ticket generated` → `record created` → `executed` → `data obtained`

## Step 0.5 — prerequisite inventory: what must the attacker first know / have (mandatory for any H metric)

Step 0 asks "did you obtain it". This step asks "**what must be true for the attacker to even get there**".

Write out **every** prerequisite and mark each ✅verified / ⚠️unverified. **The first unverified prerequisite is the cutoff — no claim after it enters the vector.**

Commonly missed: **discoverability** (how does the attacker learn that ID / filename? is there an oracle?), **reachability** (is it actually open to unauth / low-priv?), **interaction** (`UI:R`, not `UI:N`), **the other half of a chain** (how far is the referenced Finding itself verified?), **scale** (how many requests does "enumerable" take? is there a rate limit? was it actually enumerated?).

Anonymized real cases that died here:
- A finding scored 6.5 → 4.3: the exploit needs to **know the filename first** — no listing path existed, and delete on a non-existent file also returned success (no existence oracle), so discoverability was never satisfied.
- A finding's "got what" was written "can read / can steal", when the actual observation was a single injected `"` — a capability assertion, not an obtained result.

### Answer standard for the three questions (they exist, but get filled in hypothetical voice)

| Question | Pass | Fail |
|---|---|---|
| What was done? | What you actually executed and observed (past tense) | "the attacker can…" |
| What was obtained? | Data actually landed + **quantity**; nothing obtained → write **0** | "can read…", "could steal…" |
| How is it exploited? | Step by step, each step ✅verified / ⚠️unverified | A full narrative with no verification marks |

Seeing "can / could / would be able to" + a verb with no matching "already did" means that cell is a **capability assertion**, not an obtained result.

> **Before giving any C/I/A an `H`, dispatch the `cvss-adversary` agent.** Its default stance is "this score is inflated"; it walks each prerequisite and demands one line of observed result per H metric. Scoring it yourself and then checking it yourself does not count — verification is not self-verification.

## Step 1 — determine each metric

**Attack Vector (AV)**: `N` network (remote) · `A` adjacent · `L` local · `P` physical
**Attack Complexity (AC)**: `L` no special conditions · `H` needs specific config / race / user-controlled prerequisite
**Privileges Required (PR)**: `N` none · `L` regular user · `H` admin/root
**User Interaction (UI)**: `N` none · `R` victim must act (click/visit)
**Scope (S)** — most commonly wrong, reason carefully: `U` only the vulnerable component · `C` other components affected (stored XSS in admin context, SSRF reaching internal services, SQLi on a shared DB host)
**Confidentiality / Integrity / Availability (C/I/A)**: `N` none · `L` limited · `H` full disclosure / full modification / complete DoS

## Step 2 — common vuln-class defaults (adjust to concrete target)

| Vuln Class | Typical Vector | Notes |
|---|---|---|
| RCE (unauth) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | S:C if code runs in container/shared host |
| RCE (auth) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | |
| SQLi (unauth, data leak) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | add I:H if write possible |
| IDOR (read other user) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | |
| IDOR (modify other user) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | |
| SSRF (internal reach) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N | S:C due to pivot |
| Stored XSS (admin panel) | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | raise C/I if ATO |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | |
| Auth Bypass | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | |
| Unauth File Upload (webshell) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | |
| Business Logic (payment bypass) | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | |
| OAuth token theft | AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N | AC:H due to redirect chain |

## Step 3 — base score ranges

9.0–10.0 Critical (AV:N, no auth, high C/I/A + S:C) · 7.0–8.9 High · 4.0–6.9 Medium (auth/limited) · 0.1–3.9 Low (local/minimal).

## Output

```text
CVSS 3.1 Vector: AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Base Score: X.X (Critical/High/Medium/Low)
Metric Reasoning:
- AV:_ — ...   (one line per metric)
```

Always flag Scope decisions and any low-confidence metric for human review — Scope is the most error-prone.

**If the Finding's frontmatter `risk:` is set higher than the CVSS band** (e.g. base 7.5 High but judged critical), record a `risk_escalation_reason:` in the frontmatter stating why — otherwise a finding-consistency check (band ↔ risk, and H metrics ↔ any counter-evidence sentence in the body) should flag it.

## Cross-References

- `bb-evidence-readiness` (Step 0's evidence bar shares its source with that skill's Adversarial Verification Gate)
- `cvss-adversary` agent (mandatory before any C/I/A = H)
