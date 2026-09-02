---
fileClass: ReferenceCard
type: reference-card
title: "Finding Discovery Verification Schema — Structured Discovery Reporting and Graph Integration"
---

# Reference Card — Finding Discovery Verification Schema

> Every finding must produce a structured **Discovery Verification Card** (embedded in the Finding template).
> Purpose: (1) rapid human review to catch hallucinations/false positives, (2) structured metadata for graph nodes, (3) enforced evidence-chain traceability.
> Template location: `07 - Templates/Template - Finding.md` → `## Discovery Verification Card`.

---

## 1. Why This Exists

| Problem | Root Cause | How This Schema Blocks It |
|---------|-----------|---------------------------|
| Model confirms a CVE but declares "not exploitable" after its own PoC fails | Did not search for public PoCs; self-designed failure ≠ not exploitable | `Public PoC Search` + `PoC Source` fields force documentation |
| Severity based on speculative data volume ("could affect millions of users") | Unverified claims in Impact | `Evidence Grade [D/I/H]` tagging; `[H]` = red flag |
| Theoretical attack chain written as established fact | No separation of verified vs. theoretical | `Verification Environment` + `Exploitability` + `Confidence Level` cross-validation |
| Human reviewer cannot tell "what the model actually did" | Discovery Log is scattered and unstructured | `Verification Trace` forces step-by-step documentation with evidence grades |
| Graph cannot extract structured relationships from a Finding | Prose has no schema | Table fields = graph node attributes; Trace steps = graph edges |

---

## 2. Evidence Grade Definitions ([D] / [I] / [H])

| Grade | Definition | Graph Confidence Weight | Human Review Action |
|-------|-----------|------------------------|---------------------|
| **[D] Direct** | First-hand observed evidence (HTTP response, source code line number, PoC output) | 1.0 | Trustworthy; spot-check |
| **[I] Inference** | Reasonable inference from direct evidence ("since LFI exists and DB config is at `/etc/`, infer that DB credentials are readable") | 0.6 | Must verify each step of the inference chain |
| **[H] Hypothesis** | Speculation with no direct evidence ("could affect all users", "theoretically RCE") | 0.2 | **Red flag** — must not serve as the primary basis for severity/impact |

### Upgrade Path

```
[H] → gather evidence → [I] → directly verify → [D]
[H] → cannot gather evidence → downgrade severity or mark as theoretical
```

> **Hard rule**: Any claim in the Impact section that depends on an `[H]`-graded Trace step must be labeled "Potential (requires further verification)" rather than "Verified."

---

## 3. Verification Trace Format

Each step follows this format:
```
Step N: [Action/Tool] → [Observation] → [D/I/H]
```

### Good Trace (traceable)

```
Step 1: curl GET /download.php?file=/etc/passwd → 200 OK, root:x:0:0 → [D]
Step 2: curl GET /download.php?file=/var/www/config.php → DB credentials visible → [D]
Step 3: mysql -h <host> -u <user> -p<pass> → connection successful, 64K rows → [D]
Conclusion: LFI → credential leak → remote DB access, full chain [D] confirmed
```

### Bad Trace (red flags)

```
Step 1: Discovered /api/users endpoint → [D]
Step 2: Speculate possible IDOR → [H]  ← speculation without testing
Step 3: Therefore assessed as High severity → [H] ← severity built on hypothesis
Conclusion: IDOR (but never actually tested) ← hallucination risk
```

---

## 4. Graph Integration

### Node Types

A Finding's Discovery Verification Card produces the following graph nodes and edges:

```
[Target] --has_finding--> [Finding]
[Finding] --verified_by--> [Evidence Step 1..N]
[Evidence Step] --confidence:{D=1.0,I=0.6,H=0.2}--> [Observation]
[Finding] --exploits--> [Vulnerability Class]
[Finding] --requires--> [Precondition]
[Finding] --impacts--> [Asset/Data]
```

### Graph Extraction Rules

Semantic extraction reads the Discovery Verification Card table fields:

| Field | → Graph Attribute |
|-------|-------------------|
| `Discovery Method` | `finding.discovery_method` |
| `CVE/Advisory` | `finding.cve` → links to CVE node |
| `Exploitability` | `finding.exploitability` |
| `Confidence Level` | `finding.confidence` → affects edge weight |
| `Preconditions` | `finding.precondition` → links to capability node |
| `Hallucination Risk Points` | `finding.hallucination_flags[]` → human review queue |

### Verification Trace → Attack Path Edges

Each Trace Step maps to one edge:

```yaml
edge:
  from: "state_before_step_N"
  to: "state_after_step_N"
  action: "Step N action"
  confidence: D=1.0 | I=0.6 | H=0.2
  evidence: "observation"
```

When multiple Findings' Traces intersect (same target, different findings), the graph automatically discovers shared intermediate states (e.g., two findings both used the same LFI as an entry point), forming an attack surface topology.

---

## 5. Human Review Checklist

Quick review flow when examining a Finding:

1. **Check `Confidence Level`**: `low` → focus review here
2. **Scan `Evidence Grade` column**: any `[H]` → that field is a red flag
3. **Check `Hallucination Risk Points`**: weak spots the model flagged itself
4. **Check `PoC Source` + `PoC Result`**:
   - `self_designed` + `failed` → highest risk: possible false negative
   - `self_designed` + `success` → medium risk: confirm PoC was actually executed
   - `public_poc` + `success` → low risk
5. **Check `Verification Trace`**:
   - Every step `[D]` → trustworthy
   - Any `[H]` step that the conclusion depends on → conclusion may not hold
   - Gaps between steps (Step 1 → Step 5 with no intermediate steps) → possibly omitted failed attempts

### Red-Flag Combinations (almost certainly problematic)

| Combination | What It Means |
|-------------|---------------|
| `Exploitability: confirmed` + `Confidence: low` | Contradiction — confirmed should mean high confidence |
| `PoC Result: failed` + `Exploitability: confirmed` | Contradiction — how is it confirmed if the PoC failed? |
| `Verification Environment: theoretical` + `Severity: P1` | Highest severity assigned without any verification |
| `Public PoC Search: not_found` + `CVE: CVE-20XX-XXXX` + `PoC Source: self_designed` + `PoC Result: failed` | Classic false-negative pattern |
| All Trace steps are `[I]` or `[H]` | No direct evidence whatsoever |
| `Exploitability: likely_exploitable [I]` + `Severity: ≥P2` | **Must run comparison test before submission** (see §5b) |

### 5b. Comparison Test Rule

> **Lesson learned**: A POST auth bypass was tested unauthenticated, but the authenticated baseline was never tested for comparison. The finding nearly shipped as P1 before an adversarial review discovered that the 500 response could simply be a route-not-found error rather than an authentication bypass.

**Rule**: When a Discovery Verification Card simultaneously meets both conditions below, **submission is blocked** until a comparison test is completed:

1. `Exploitability` ≥ `likely_exploitable` and graded as `[I]` (not `[D]`)
2. `Severity` ≥ P2

**Comparison tests by vulnerability class**:

| Vulnerability Class | What Must Be Compared | Pass Criteria (upgrade [I]→[D]) |
|---------------------|----------------------|--------------------------------|
| **Auth bypass** | Same endpoint, authenticated vs. unauthenticated with the same operation | Authenticated returns normal response (200/201) AND unauthenticated also returns normal response = true bypass |
| **IDOR** | Same endpoint, own account vs. another account (cross-account) | Other account's data is readable/writable |
| **Privilege escalation** | Same endpoint, low-privilege vs. high-privilege account | Low-privilege account can perform high-privilege operations |
| **SSRF** | Externally controlled URL vs. internal URL | Internal URL response differs from external (proves server-side fetch) |
| **Rate limiting bypass** | With rate limit vs. after bypass | After bypass, requests exceed the normal threshold |

> **Submitting without a comparison test** = submission-readiness gate **must block**. The Trace must contain at least one step like: "authenticated same operation → [normal response], compared with unauthenticated → [same normal response] = bypass confirmed [D]."

---

## 6. Relationship to Other Systems

| System | What This Schema Adds |
|--------|----------------------|
| Finding template `## Evidence` | Evidence holds raw curl output/payloads; this Card holds structured metadata and evidence chains |
| `bb-evidence-readiness` | Readiness gate judges ready/not ready; this Card's `[D/I/H]` grades are the basis for that judgment |
| `bb-exploit-chain` | Chain's 6 questions are brainstorming; this Card's Trace is verified steps |
| `bb-submission-readiness` | Submission gate can read this Card's `Confidence Level` + `Hallucination Risk Points` as pass/fail criteria |
| [[Reference Card - Orchestrator Architecture]] | Adversarial verification agent can read this Card to determine which `[H]` items need challenging |
| Capability Graph | This Card's fields = graph node attributes; Trace = graph edges |

---

## Quick Reference

1. Every Finding must include a Discovery Verification Card (above the Evidence section in the Finding template).
2. Every field must be tagged `[D]`/`[I]`/`[H]` — `[H]` = human review red flag.
3. Verification Trace must be step-by-step evidence chains, not prose.
4. Impact claims depending on `[H]` must be marked Potential.
5. `Self-designed PoC failed` ≠ `not exploitable` — search for public PoCs first.
6. Reviewers check: Confidence Level → [H] tags → Hallucination Risk Points → PoC Source + Result → Trace gaps.
7. `Exploitability [I]` + `Severity ≥ P2` → mandatory comparison test (§5b); must pass before submission.
