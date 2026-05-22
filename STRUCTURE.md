# Workspace Structure Specification

> **Core philosophy: Vault (Obsidian) = Brain + Control Plane. Workspace = Process Artifacts. Target-Centric organization.**

---

## 1. Design Principles

1. **Target-Centric** -- finding everything about one target means opening one folder
2. **Workspace does not store canonical knowledge** -- raw recon, PoC binaries, scan logs are process artifacts
3. **Vault = single source of truth** -- everything you want to read across sessions lives in the Vault
4. **Every vulnerability is a structured record** -- time, commands, reasoning, results via mandatory frontmatter
5. **Leverage Obsidian plugins** -- Dataview, Templater, MetadataMenu, Kanban for dynamic views

**File placement rule:**
- "Will I come back to read this?" -> Yes -> Vault; No -> Workspace
- "Process artifact or synthesized knowledge?" -> Process -> Workspace; Synthesized -> Vault
- "Needs linking / querying / visualization?" -> Yes -> Vault; No -> Workspace

---

## 2. Canonical Directory Tree

### 2.1 Vault (Obsidian -- the Brain)

```
bug-bounty-vault/                      <- Obsidian Vault + Git repo + control plane
|
+-- 00 - Dashboard/                    <- Dataview dashboards + Kanban boards
|   +-- Dashboard.md                   <- Quick stats, priority queue, recent activity
|   +-- Kanban Board.md               <- Master workflow board
|
+-- 01 - Targets/                      <- One subfolder per target (see section 3)
|   +-- _INDEX.md                      <- Target listing (Dataview-generated)
|   +-- <target>/                      <- Target folder (see section 3 for structure)
|
+-- 01 - Dorks/                        <- Google dork collections and search queries
|
+-- 07 - Templates/                    <- Obsidian templates (Templater + QuickAdd)
|   +-- Template - Finding.md
|   +-- Template - Submission.md
|   +-- Template - Target.md
|   +-- Template - Recon Session.md
|   +-- Template - Attempt.md
|
+-- 09 - Knowledge Base/              <- Cross-target knowledge (Pattern/Playbook/etc.)
|   +-- Pattern - *.md                <- Reusable attack techniques
|   +-- Playbook - *.md               <- Step-by-step workflows
|   +-- Checklist - *.md              <- Verification checklists
|   +-- Tool - *.md                   <- Tool configuration and usage
|   +-- Resource - *.md               <- Resource lists
|   +-- Reference Card - *.md         <- Quick-reference cards
|   +-- Lessons Learned.md            <- Rolling log of what worked and what didn't
|   +-- References/                   <- External articles, PDFs, vendor docs
|   +-- graphify-out/                 <- Knowledge graph output
|
+-- 10 - Meta/                         <- Workspace meta notes
|
+-- automation/                        <- Session lifecycle scripts
|   +-- start_session.py
|   +-- end_session.py
|   +-- check_vault.py
|   +-- setup_workspace.sh
|
+-- _automation/                       <- Pre-commit hooks and linters
|   +-- lint_frontmatter.py
|
+-- .claude/skills/                    <- LLM workspace skills (source of truth)
+-- .claude/agents/                    <- LLM specialized agents
+-- .codex/skills/                     <- Codex CLI mirror (synced from .claude/)
+-- .gemini/skills/                    <- Gemini CLI mirror (synced from .claude/)
+-- tools/                            <- Scanner configs (Nuclei, Osmedeus, BBOT, bbflow)
+-- docs/                             <- Workflow documentation
+-- templates/                        <- Non-Obsidian templates (operation log, handoff)
+-- tests/                            <- Layout and workflow tests
```

### 2.2 Workspace (local scratch -- .gitignored)

```
workspace/                             <- .gitignored local scratch
|
+-- workshop/                          <- Per-target process artifacts
|   +-- _all/                          <- Cross-target shared: target lists, bbot output
|   +-- <target>/                      <- Per-target skeleton (see section 4)
|
+-- reports/                           <- Platform submission copies
|   +-- hitcon/
|   +-- hackerone/
|   +-- bugcrowd/
|   +-- twcert/
|   +-- intigriti/
|
+-- firmware_analysis/                 <- Firmware unpacking workspace
|   +-- <vendor>/                      <- Per-vendor analysis
|
+-- logs/                              <- Audit logs, session logs
+-- tmp/                               <- Temporary files
```

---

## 3. Target Folder Structure (Vault)

Each target in `01 - Targets/<target>/` follows this structure:

```
<target>/
+-- Target - <target>.md               <- Entity page (overview, status, platform links)
+-- Kanban.md                          <- Per-target workflow board (optional)
|
+-- Findings/                          <- Discovery notes
|   +-- Finding - <target> - <ID>.md
|
+-- Submissions/                       <- Platform-ready reports
|   +-- Submission - <target> - <ID> <title>.md
|   +-- Forms/                         <- Platform-specific formatted output
|       +-- FORM - <Platform> - <ID>.md
|
+-- Attempts/                          <- Tried but did not pan out
|   +-- Attempt - <target> - <description>.md
|
+-- Recon/                             <- Recon session notes
|   +-- Recon - <target> - <topic> - <date>.md
|
+-- Services/                          <- Per-service deep dives (optional)
|   +-- Service - <target> - <service>.md
|
+-- Attack Chains/                     <- Multi-vuln chain documentation (optional)
    +-- Chain - <target> - <description>.md
```

---

## 4. Workspace Target Skeleton

Each target in `workspace/workshop/<target>/` follows this structure:

```
<target>/
+-- SCOPE.md                           <- Program scope, URLs, credentials, rules
+-- RECON_DB.md                        <- Recon database (endpoints, infra, credentials)
+-- HANDOFF.md                         <- Session handoff context
+-- FINDINGS_QUICK_REF.md             <- Auto-generated finding/attempt/submission index
|
+-- poc/                               <- All PoC: payloads, test pages, exploit bundles
+-- scan_results/                      <- Tool raw output (nuclei, ffuf, amass, etc.)
+-- screenshots/                       <- Evidence screenshots
+-- hunters/                           <- bbflow hunter configurations
+-- rounds/                            <- Recon round logs
```

**Do not create alternative directories:**

| Purpose | Use | Do NOT create |
|---------|-----|---------------|
| PoC files | `poc/` | `poc_bundles/`, `pocs/`, `payloads/` |
| Scanner output | `scan_results/` | `scans/`, `nuclei_out/`, `*_out/` |
| Cross-target shared | `workshop/_all/` | Top-level loose files |
| External references | `09 - Knowledge Base/References/` | Top-level `raw/`, `articles/` |

---

## 5. Naming Conventions

### Finding

**Format:** `Finding - <Target> - <ID>.md`

| Element | Definition | Example |
|---------|-----------|---------|
| `<Target>` | Target name (matches folder name) | `acme-corp` |
| `<ID>` | Target prefix + 3-digit sequence number | `AC-001`, `AC-002` |

The filename carries only the stable identifier. Human-readable title goes in frontmatter `title:` and the document H1.

### Submission

**Format:** `Submission - <Target> - <ID> <title>.md`

| Element | Definition | Example |
|---------|-----------|---------|
| `<ID>` | Matches the Finding ID | `AC-001` |
| `<title>` | Short human-readable slug | `IDOR in User API` |

### FORM

**Format:** `FORM - <Platform> - <ID>.md`

| Element | Definition | Example |
|---------|-----------|---------|
| `<Platform>` | Submission platform | `HITCON`, `TWCERT`, `HackerOne`, `Bugcrowd` |
| `<ID>` | Matches the Finding ID | `AC-001` |

### Knowledge Base

| Prefix | Purpose | Location |
|--------|---------|----------|
| `Pattern - ` | Cross-target attack technique | `09 - Knowledge Base/` |
| `Playbook - ` | Attack surface / workflow manual | `09 - Knowledge Base/` |
| `Checklist - ` | Testing checklist | `09 - Knowledge Base/` |
| `Tool - ` | Tool configuration and usage | `09 - Knowledge Base/` |
| `Resource - ` | Resource lists | `09 - Knowledge Base/` |
| `Reference Card - ` | Quick-reference card | `09 - Knowledge Base/` |
| `Skill - ` | Skill documentation | `09 - Knowledge Base/` |

**Prohibited:** Inventing prefixes not listed above, or placing wiki-style `.md` files outside `09 - Knowledge Base/`.

### Other Vault Notes

| Type | Naming | Location |
|------|--------|----------|
| Target entity | `Target - <name>` | `01 - Targets/<name>/` |
| Attempt | `Attempt - <target> - <description>` | `01 - Targets/<target>/Attempts/` |
| Recon session | `Recon - <target> - <topic> - <date>` | `01 - Targets/<target>/Recon/` |
| Service | `Service - <target> - <service>` | `01 - Targets/<target>/Services/` |
| Attack chain | `Chain - <target> - <description>` | `01 - Targets/<target>/Attack Chains/` |

---

## 6. Frontmatter Schema

### Finding (required fields)

```yaml
---
fileClass: Finding
finding_id: "XX-001"
target: "[[Target - acme-corp]]"
severity: P2  # P1-P5
status: discovered  # discovered | verified | ready | submitted | withdrawn
verified_evidence: live  # live | source_code | static | theoretical
discovered_date: 2026-05-16
discovered_time: "14:32"
last_verified: 2026-05-16
title: "IDOR in User Profile API"
tags:
  - idor
  - api
---
```

**Status flow:** `discovered` -> `verified` -> `ready` -> `submitted` (or `withdrawn` at any point)

**verified_evidence enum:** `live` | `source_code` | `static` | `theoretical` (no other values accepted)

### Submission (required fields)

```yaml
---
fileClass: Submission
finding_id: "XX-001"
target: "[[Target - acme-corp]]"
platform: hackerone  # hackerone | bugcrowd | hitcon-zeroday | twcert | intigriti | yeswehack
status: draft  # draft | ready | submitted | accepted | na | dup | withdrawn
submitted_at: ""
bounty: ""
---
```

### FORM (required fields)

```yaml
---
fileClass: Form
finding_id: "XX-001"
target: "[[Target - acme-corp]]"
platform: hitcon-zeroday
status: ready  # ready | submitted
case_id: ""  # Platform-assigned ID (e.g., ZD-2026-XXXXX)
reported_date: 2026-05-16
submitted_date: ""
---
```

### Target (required fields)

```yaml
---
fileClass: Target
target_name: "acme-corp"
platform: hackerone
program_url: "https://hackerone.com/acme-corp"
status: active  # active | parked | closed
tags:
  - web
  - api
---
```

---

## 7. RECON_DB Sections

The workspace `RECON_DB.md` for each target should contain these sections:

```markdown
## Credentials & Accounts
## Tech Stack
## Endpoints
## Subdomains
## Pre-flight Checks
## Deferred Actions
## Operation Log
## Notes
```

### Endpoint Table Schema (6 columns)

```
| Path Pattern | Method | Auth | Status | Notes | Found By |
|---|---|---|---|---|---|
| /api/users/{id} | GET | cookie | 200 | returns PII | manual |
```

**One row = one path pattern** (not one specific URL). Group similar endpoints.

---

## 8. Workspace Layout Configuration

The workspace root is configured via `automation/workspace_layout.sh`:

```bash
# Get workspace paths
eval "$(bash automation/workspace_layout.sh --shell)"
echo "$WORKSPACE_ROOT"    # Vault root
echo "$WORKSHOP_ROOT"     # workspace/workshop/
```

This script resolves paths regardless of whether you are using the legacy layout or the preferred root-workspace layout.

---

## 9. Report Status Directories

Platform submission copies in `workspace/reports/<platform>/` use status-based subdirectories:

```
reports/<platform>/
+-- ready/                 <- Reports ready to submit
+-- submitted/             <- Reports that have been submitted
+-- fixed/                 <- Vendor confirmed fix
+-- withdrawn/             <- Withdrawn reports
+-- needs_revalidation/    <- Need fresh evidence before submitting
```

---

## 10. Obsidian Plugin Configuration

### Required Plugins

| Plugin | Purpose |
|--------|---------|
| **Dataview** | Dynamic queries, dashboards, Finding/Submission listing |
| **Templater** | Template engine for note creation |
| **QuickAdd** | Rapid note creation with templates |
| **Kanban** | Workflow boards (master + per-target) |
| **Metadata Menu** | Frontmatter management with fileClass |

### Recommended Plugins

| Plugin | Purpose |
|--------|---------|
| **Excalidraw** | Attack chain diagrams |
| **ExcaliBrain** | Relationship visualization |
| **Obsidian Git** | Auto-commit and sync |

---

## 11. Validation

```bash
# Vault health check
python3 automation/check_vault.py

# Frontmatter validation
python3 _automation/lint_frontmatter.py --all

# Workspace audit
bash automation/audit_workspace.sh
```

Pre-commit hooks automatically run frontmatter linting on staged files.
