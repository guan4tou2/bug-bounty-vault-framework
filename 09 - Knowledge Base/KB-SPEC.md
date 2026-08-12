---
type: reference-card
title: KB Specification — Framework Knowledge Base Convention
tags: [meta, specification, kb]
status: verified
last_updated: 2026-08-08
---

# KB Specification

This document defines the rules for all files under `09 - Knowledge Base/`.
Every contributor (human or LLM agent) must follow these rules when creating, porting, or updating KB entries.

---

## 1. Types

Every KB file belongs to exactly one type. The type determines naming, frontmatter, and content structure.

| Type | Prefix | Purpose | Example |
|------|--------|---------|---------|
| **pattern** | `Pattern - ` | A reusable vulnerability pattern or attack technique | `Pattern - Race Condition Single-Packet Attack.md` |
| **checklist** | `Checklist - ` | A step-by-step verification or gate procedure | `Checklist - IDOR Test Coverage Matrix.md` |
| **playbook** | `Playbook - ` | An end-to-end workflow or methodology | `Playbook - IoT Firmware Analysis Session.md` |
| **reference-card** | `Reference Card - ` | Quick-reference summary, decision tree, or field guide | `Reference Card - GET-first Dangerous Ops.md` |
| **tool** | `Tool - ` | Documentation for a specific security tool | `Tool - Source Map Reverse Engineering.md` |
| **lesson** | `LL-<NNN>-` | A specific insight learned from real experience | `Lessons/LL-003-xss-value-is-not-alert.md` |
| **wiki** | `<NN>-` | Comprehensive deep-dive technique guide | `wiki/60-request-smuggling.md` |

### Naming rules

- **Top-level files**: `<Type Prefix><Title in Title Case>.md`
- **Lessons**: `Lessons/LL-<NNN>-<kebab-case-slug>.md` (English slug, max 60 chars)
- **Wiki**: `wiki/<NN>-<kebab-case-slug>.md` (two-digit category prefix)
- No target names, internal IDs, or private data in filenames
- English only (no CJK characters in filenames)

### Wiki category numbering

| Range | Domain |
|-------|--------|
| 00-09 | Meta / workflow |
| 10-19 | Recon / hunters / config |
| 20-29 | Tool references |
| 30-39 | Advanced tool techniques |
| 40-49 | Checklists (embedded) |
| 60-79 | Attack technique deep-dives |
| 80-89 | Specialized domains (AI/LLM, SAML, mobile, source review) |

---

## 2. Frontmatter Schema

Every KB file must start with a valid YAML frontmatter block. Required and optional fields per type:

### All types (required)

```yaml
---
type: pattern|checklist|playbook|reference-card|tool|lesson|wiki
title: "Human-readable title"
tags: [tag1, tag2]           # kebab-case, from controlled vocabulary
status: draft|verified|stale  # see §2.1
last_updated: YYYY-MM-DD
---
```

### Pattern (additional)

```yaml
vuln_class: ssrf|idor|xss|sqli|rce|auth-bypass|info-leak|race-condition|...
severity_range: P1-P2|P2-P3|P3-P4|P4-P5  # typical bounty tier
seen_in: []                                # generic tech stacks, never real targets
prerequisites: []                          # e.g. ["HTTP/2 support", "file upload endpoint"]
```

### Checklist (additional)

```yaml
category: gate|verification|coverage|pre-submit
gate_type: hard|soft        # hard = blocks next step; soft = advisory
```

### Playbook (additional)

```yaml
category: hunting|recon|reporting|maintenance|chain-analysis
estimated_time: "30-60 min"  # optional
```

### Lesson (additional)

```yaml
id: LL-<NNN>
summary: "One-line summary in English"
class: technique|decision|chain|stop-loss|pitfall|process
```

### Wiki (additional)

```yaml
category: attack|tool|checklist|workflow
```

### 2.1 Status lifecycle

```
draft → verified → stale
  ↑                  │
  └──────────────────┘  (refreshed)
```

- **draft**: New entry, not yet reviewed or tested
- **verified**: Content reviewed, techniques confirmed working
- **stale**: >6 months without update, or technique/tool deprecated

---

## 3. Content Structure

### 3.1 Pattern

```markdown
# Pattern - <Title>

> **TL;DR**: One paragraph summary.

## Trigger / When to look
When to suspect this pattern exists on a target.

## Detection
How to identify the vulnerability (safe GET-only probes).

## Verification
How to confirm it's real (minimal-impact PoC).

## Exploitation
How to demonstrate impact (safe, reversible).
Include code blocks with example commands.

## Impact Assessment
What an attacker gains. Separate verified vs theoretical.

## Stop-Loss
When to give up and move on. Specific failure signals.

## Bypass Techniques
Common defenses and how they're circumvented.

## References
- [[Related Pattern]]
- External writeups (URLs)
```

### 3.2 Checklist

```markdown
# Checklist - <Title>

> **TL;DR**: What this gate checks and why.

## Prerequisites
What must be true before running this checklist.

## Steps

1. **Step name** — description
   - Pass: expected good outcome
   - Fail: what to do on failure
2. ...

## Anti-patterns
| Don't | Do |
|-------|-----|
| ... | ... |

## Related
- [[Linked KB entries]]
```

### 3.3 Playbook

```markdown
# Playbook - <Title>

> **TL;DR**: One paragraph.

## Scope / When to use
Trigger conditions for this playbook.

## Phases

### Phase 1: <Name>
Steps, tools, expected outputs.

### Phase 2: <Name>
...

## Decision Points
Key branch conditions and how to choose.

## Expected Outputs
What artifacts this playbook produces.

## Related
- [[Linked KB entries]]
```

### 3.4 Reference Card

```markdown
# Reference Card - <Title>

> **TL;DR**: What this card covers.

## Quick Reference
Table, matrix, or field definitions.

## Details
Expanded explanations where needed.

## Related
- [[Linked KB entries]]
```

### 3.5 Tool

```markdown
# Tool - <Title>

> **TL;DR**: What the tool does and when to use it.

## Installation
```bash
# install commands
```

## Basic Usage
Common commands with examples.

## Advanced Flags
Less common but high-value options.

## Integration
How it fits into the hunting workflow.

## Pitfalls
Known gotchas and failure modes.

## Related
- [[Linked KB entries]]
```

### 3.6 Lesson

```markdown
# LL-<NNN>: <Title>

**Summary**: One sentence.

**Context**: What happened (no real target names).

**Insight**: What was learned.

**Application**: When to apply this lesson.
```

### 3.7 Wiki

Wiki entries are comprehensive deep-dive guides. They follow a looser structure but must include:

```markdown
# <Title>

> **Purpose**: One paragraph.

## Core Concept
How the technique works.

## Variants
Sub-techniques and variations.

## Detection & Exploitation
Step-by-step with tool commands.

## Tools
Relevant tools with usage examples.

## Bypass Techniques
Defenses and workarounds.

## References
External sources.
```

---

## 4. Inclusion Criteria

### What belongs in the framework KB (port from private vault)

- **Universal attack techniques** applicable to any target
- **Tool usage guides** for open-source security tools
- **Methodology procedures** (recon, hunting, reporting workflows)
- **Generic checklists** (coverage matrices, quality gates)
- **Lessons** that teach generalizable insights (no target-specific details)
- **Deep-dive technique guides** (wiki entries)

### What stays in the private vault (do NOT port)

| Category | Examples | Why |
|----------|----------|-----|
| Target-specific data | Findings, RECON_DB, submissions, screenshots | Contains private vulnerability data |
| Internal process docs | Vault maintenance, session management, Kanban | Specific to operator's workflow |
| Infrastructure docs | VPS setup, private-runtime agent config, Obsidian plugins | Specific to operator's infrastructure |
| Anti-fraud operations | Phishing takedown, IOC collection, LINE scam investigation | Region-specific, potentially sensitive |
| Competitive intelligence | Program-specific scoring rules, platform profiles | Operational advantage |
| Harness-specific meta | Agent skill matrix, audit policies, SOP review cadence | Internal harness governance |

### Grey area — port if sanitizable

- Patterns that reference real targets → replace with generic examples
- Lessons that embed target names → abstract the insight, strip the names
- Tool docs that reference private infra → replace VPS/IP references with placeholders

---

## 5. Sanitization Rules

Every file ported from a private vault MUST pass these checks before merging.

### 5.1 Forbidden strings (enforced by `test_public_skeleton.py`)

| Category | Forbidden | Replace with |
|----------|-----------|-------------|
| **Real target names** | Any private target/vendor name from the operator's vault | `acme-corp`, `vendor-app`, `target-host.example.com` |
| **Internal IDs** | Target-prefixed IDs (e.g. `XX-001`, `YY-002`) | `ACME-001`, `VENDOR-002`, or remove |
| **Private paths** | Operator home directory, vault directory name | Remove or use relative paths |
| **Private infra** | VPS hostnames, real IP addresses | `remote-vps`, `10.0.0.1` (RFC 5737) |
| **Personal data** | Operator usernames, student IDs | Remove |
| **Vault-specific refs** | Platform-specific skill names, platform report directories | `bb-form-writer`, `automation/` |

> See `tests/test_public_skeleton.py` for the canonical forbidden-string list.

### 5.2 Language

- **Filenames**: English only, no CJK characters
- **Content**: English only in the framework
  - Chinese-language source files must be translated, not just copied
  - Technical terms (CVE IDs, tool names, protocol names) remain as-is
  - Example outputs (HTTP responses, error messages) remain as-is

### 5.3 Links

- `[[Internal Link]]` Obsidian wikilinks are allowed (they work in both Obsidian and as plain text)
- External URLs must be to public resources (no internal dashboards, no private repos)
- No links to private vault paths

### 5.4 Code examples

- All example domains: `example.com`, `target.example.com`, `api.example.com`
- All example IPs: `10.0.0.1`, `192.168.1.1`, `203.0.113.0/24` (RFC 5737)
- Credentials in examples: `admin:password123`, `test:test`, never real values
- PoC commands must be clearly marked as examples, not live

---

## 6. Quality Gates

### 6.1 Pre-merge checklist

- [ ] Valid YAML frontmatter with all required fields
- [ ] Correct type prefix in filename
- [ ] English content (no untranslated CJK blocks)
- [ ] No forbidden strings (run: `python3 -m pytest tests/test_public_skeleton.py::test_no_private_or_target_specific_data`)
- [ ] At least a TL;DR section
- [ ] `status` field is `draft` for new entries (set to `verified` after review)
- [ ] No broken `[[wikilinks]]` to files that don't exist in framework
- [ ] Filename has no CJK characters

### 6.2 Automated enforcement

```bash
# Full test suite
python3 -m pytest tests/test_public_skeleton.py -v

# Quick forbidden-string check
python3 -m pytest tests/test_public_skeleton.py::test_no_private_or_target_specific_data -v

# Frontmatter validation
python3 -m pytest tests/test_public_skeleton.py::test_frontmatter_blocks_are_valid_yaml -v
```

### 6.3 Review rubric (for LLM agents porting files)

| Dimension | Pass | Fail |
|-----------|------|------|
| **Accuracy** | Technique description matches source | Translation errors or fabricated details |
| **Completeness** | All sections from §3 template present | Missing TL;DR, Stop-Loss, or References |
| **Sanitization** | Zero forbidden strings | Any private data remains |
| **Utility** | Entry teaches something actionable | Pure theory with no practical steps |

---

## 7. Cross-Referencing

### 7.1 Index files

- `Pattern Index.md` — master list of all patterns with one-line summaries
- `Lessons Learned.md` — master index of all lessons
- `wiki/README.md` — wiki table of contents

These index files must be updated when adding new entries.

### 7.2 Tagging vocabulary (controlled, extend as needed)

**Domain tags**: `web`, `mobile`, `firmware`, `electron`, `cloud`, `api`, `iot`, `ai-llm`, `saml-oidc`, `dns`

**Technique tags**: `ssrf`, `idor`, `xss`, `sqli`, `rce`, `auth-bypass`, `info-leak`, `race-condition`, `cors`, `csrf`, `deserialization`, `file-upload`, `path-traversal`, `prototype-pollution`, `cache-poisoning`, `request-smuggling`, `subdomain-takeover`, `oauth`, `graphql`, `websocket`, `command-injection`, `xxe`, `ssti`, `open-redirect`, `mfa-bypass`

**Workflow tags**: `recon`, `hunting`, `reporting`, `triage`, `chain-analysis`, `evidence`, `submission`

**Meta tags**: `bb-pattern`, `bb-checklist`, `bb-playbook`, `bb-lesson`, `sota-2024`, `sota-2025`, `sota-2026`

---

## 8. Porting Workflow (private vault → public framework)

### Step 1: Classify

Read the source file. Decide: **technical** (port) or **operational** (skip). See §4.

### Step 2: Translate

If the source is in Chinese, translate to English. Preserve technical accuracy. Do not add content that wasn't in the original.

### Step 3: Sanitize

Apply all rules from §5. Use find-and-replace for known forbidden strings.

### Step 4: Restructure

Ensure the file follows the content structure template from §3 for its type. Add missing sections (especially TL;DR and Stop-Loss for patterns).

### Step 5: Validate

```bash
python3 -m pytest tests/test_public_skeleton.py -v
```

### Step 6: Update indexes

Add the new entry to the relevant index file (Pattern Index, Lessons Learned, wiki/README).

---

## 9. Maintenance

- **Quarterly review**: Mark entries not updated in 6+ months as `stale`
- **After technique evolution**: Update patterns when new bypass or defense emerges
- **After tool updates**: Update tool docs when major versions ship
- **Lessons are append-only**: Never delete lessons; mark outdated ones as `stale` with a note explaining why
