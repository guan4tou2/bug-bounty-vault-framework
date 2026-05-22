# Agents Quick Reference

Token-light entrypoint for Claude agents working in this vault. Read this first; dive into `AGENTS.md` only when a specific section is needed.

---

## Always Start

```bash
bash automation/check_active_sessions.sh      # prevent parallel conflicts
bash automation/claim.sh <scope> [--eta-minutes=N]  # claim your scope
```

Scope values: `_meta` (workspace files), `<target>`, `<target>/<sub-service>`.

## Portable Layout

```bash
source automation/workspace_layout.sh
```

This resolves `$WORKSPACE_ROOT`, `$WORKSHOP`, `$REPORTS`, and other path variables so scripts work regardless of where the repo is cloned.

## Target Start

New target:
```bash
bash automation/init_target.sh <target>
```

Resuming existing target:
```bash
bash automation/session_start_brief.sh <target> "<keyword>" "<host>"
```

This prints a summary of HANDOFF.md, FINDINGS_QUICK_REF.md, and RECON_DB.md high-signal sections. Only deep-read files the brief points you to.

## Pre-flight (Mandatory)

Before analyzing any software, firmware, or SaaS target:

1. Confirm the vendor's **latest stable version** -- do not analyze outdated versions
2. Search for **existing CVEs and advisories** for the target
3. If the version is old or CVEs already cover your findings, **stop and document why**

See AGENTS.md section 0g for the full protocol.

## During Work

- **Dedup gate**: Read `FINDINGS_QUICK_REF.md` before creating any new Finding
- **GET-first**: Never send POST/PUT/PATCH/DELETE without understanding the consequences; when unsure, document but do not trigger
- **KB lookup**: Query the Knowledge Base before researching a topic, during hunting, and before writing reports
- **VPS for risky ops**: Run bbflow, osmedeus, and any aggressive scanning on the VPS, not locally
- **Operation log**: Record manual curl/POST operations in RECON_DB.md under `## Operation Log`

## Session End

```bash
bash automation/session_end_brief.sh <scope>
bash automation/session_end_checklist.sh <target>   # for target work
bash automation/release.sh <scope>                  # release your claim
```

The checklist verifies: HANDOFF.md updated, FINDINGS_QUICK_REF.md current, KB capture gate reviewed, no uncommitted vault changes.

## Key Principles

- **Anti-exaggeration**: Theoretical attack chains must not be written as confirmed exploits
- **Finding pipeline**: Finding + Submission + FORM, linked by `finding_id`
- **No internal IDs in reports**: Strip internal references (e.g., ACME-001) from submission text
- **Discovery Log format**: `timestamp [src_IP > dst_IP] [audit:ref] action > result`
- **Subagent injection**: Subagents do not inherit CLAUDE.md; inject relevant conventions into their prompts based on task tier (recon / analysis / output)
