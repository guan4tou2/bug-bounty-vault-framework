# Claude Code Workspace Guide

Claude must read these files in order when starting work:

1. [AGENTS_QUICK.md](AGENTS_QUICK.md) -- token-light session start/end/minimal audit path
2. This file -- Claude-specific supplements
3. Deep-read [AGENTS.md](AGENTS.md) / [STRUCTURE.md](STRUCTURE.md) sections as triggered by task context

---

## Workspace Skills (mandatory -- trigger fires, load immediately)

Skills live in `.claude/skills/<name>/SKILL.md`. When a trigger matches, load the skill using the Skill tool or Read the file, then follow its instructions strictly.

| Skill | Trigger | Path |
|-------|---------|------|
| **bb-version-cve-precheck** | Obtained firmware/binary/app; "start analyzing X"; "init target"; "download firmware" | `.claude/skills/bb-version-cve-precheck/SKILL.md` |
| **bb-dedup-finding** | Before new Finding/FORM; "wasn't this already found"; "same vulnerability" | `.claude/skills/bb-dedup-finding/SKILL.md` |
| **bb-cve-citation** | "Write CVE"; "NVD reference"; "prior disclosure" | `.claude/skills/bb-cve-citation/SKILL.md` |
| **bb-hitcon-form** | "Create HITCON FORM"; "ZD form" | `.claude/skills/bb-hitcon-form/SKILL.md` |
| **bb-context-handoff** | "Running out of context"; "handoff"; "takeover" | `.claude/skills/bb-context-handoff/SKILL.md` |
| **bb-triage-response** | "N/A"; "Duplicate"; "Triaged"; "Accepted"; "vendor replied" | `.claude/skills/bb-triage-response/SKILL.md` |
| **bb-incident-response** | "Service disruption"; "502/503 persistent"; "unintended impact" | `.claude/skills/bb-incident-response/SKILL.md` |

**Trigger matched -> immediately load skill -> strictly follow skill content.**

---

## Session Start

### Parallel Conflict Prevention + Dedup

```bash
bash automation/check_active_sessions.sh
bash automation/claim.sh <scope> [--eta-minutes=N]
```

Scope formats: `_meta` (rules/automation/workspace docs), `<target>`, `<target>/<sub-service>`, or finer sub-scope.

For any target work, also run:

```bash
bash automation/session_start_brief.sh <target> "<keyword>" "<host>"
```

`session_start_brief.sh` summarizes HANDOFF, FINDINGS_QUICK_REF, RECON_DB highlights. Only deep-read full files when the brief points to relevant sections.

New target: `bash automation/init_target.sh <target>`

Software/firmware/SaaS targets: run AGENTS.md section 0g version + CVE/advisory pre-flight before analysis.

### Session End

```bash
bash automation/session_end_brief.sh <scope>
# Then by scope:
#   _meta: bash automation/audit_workspace.sh meta && bash automation/release.sh _meta
#   target: bash automation/session_end_checklist.sh <target>
```

---

## Core Rules Pointer Table

| Rule | Location | One-liner |
|------|----------|-----------|
| **Version + CVE pre-flight** | AGENTS.md section 0g | Any software/firmware target: check latest stable + search CVE/advisory before analysis |
| GET-first principle | AGENTS.md section 6a + 6c | POST/PUT/PATCH/DELETE requires known consequence; uncertain = do not execute |
| Operation log | AGENTS.md section 6d | Log non-scan commands to RECON_DB Operation Log before executing |
| Unified Finding-style | AGENTS.md section 3e | Every vuln = Finding -> Submission -> FORM with matching IDs |
| Discovery Log 5 columns | AGENTS.md section 3b | Time, source IP, target IP, audit ref, action+result |
| KB lookup 3 triggers | AGENTS.md section 0c | Before research / during hunting / before reporting |
| KB backfill 6 types | AGENTS.md Knowledge Capture | technique / decision tree / chain / stop-loss / pitfall / checklist |
| Anti-exaggeration + severity | AGENTS.md sections 5 + 8 | Theoretical chains not written as facts; severity matches evidence |
| Triage response | AGENTS.md section 9 | Submission + Kanban + KB sync on vendor reply |
| Incident response | AGENTS.md section 6e | Stop testing, document, apologize, disclose |

---

## Subagent Convention Injection (mandatory)

Subagents **do not inherit** CLAUDE.md / AGENTS.md. When spawning a subagent, inject rules by task tier:

| Tier | Task Type | Must Inject |
|------|-----------|-------------|
| **Recon** | Scope pulling, subdomain enum, fingerprint, disclosed report research | GET-first principle, operation log format |
| **Analysis** | Vuln verification, PoC development, dynamic testing | + read FINDINGS_QUICK_REF before dedup, anti-exaggeration, dangerous ops via VPS |
| **Output** | Creating Finding / Submission / FORM | + unified Finding-style (Finding->Submission->FORM), Discovery Log 5 columns, severity rules, no internal IDs in reports |

### Quick Injection Template (analysis + output tier)

Paste at the end of subagent prompts:

```
## Rules (mandatory)
- Before creating Finding: read workshop/<target>/FINDINGS_QUICK_REF.md to avoid duplicates
- Theoretical attack chains must not be written as facts (anti-exaggeration)
- Finding format: Finding -> Submission -> FORM, see AGENTS.md section 3e
- Discovery Log 5 columns: time [IP->IP] [audit:ref] action->result
- POST/PUT/DELETE requires known consequence first (GET-first)
- Dangerous operations via VPS only
- No internal IDs (XX-001 etc.) in platform submissions
```

---

## Claude-Specific Supplements

1. Report body must not overwrite files in `09 - Knowledge Base/References/`
2. New submissions canonical in Vault `Submissions/Forms/`; `reports/` directory is historical archive
3. PoC/payload files go to `workspace/workshop/<target>/poc/`
4. Submission-ready versions: theoretical chains must not be written as accomplished facts
5. graphify subagents must use `model: "sonnet"` (parallel <= 4-5 chunks)

---

## After Any Changes

```bash
bash automation/check_vault.py
```

---

## Quick Pointer Table

| Topic | Location |
|-------|----------|
| Full workflow rules | [AGENTS.md](AGENTS.md) |
| Directory tree / naming / templates | [STRUCTURE.md](STRUCTURE.md) |
| Session lifecycle | [docs/session-lifecycle.md](docs/session-lifecycle.md) |
| Workspace audit | `bash automation/check_vault.py` |
