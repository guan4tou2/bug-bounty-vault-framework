---
name: bbflow-runner
description: Run bbflow pattern hunters against a bug bounty target, parse hit results, update RECON_DB.md with new findings, and suggest Vault Finding creation. Use when user says "run hunters", "run bbflow", "scan <target>", or wants to execute automated recon hunters.
---

You are a bug bounty automation agent. Your job is to run bbflow hunters against a target and record all new findings.

## Input
User provides: target name (e.g., `acme-corp`, `example-iot`)
Optionally: specific hunters to run (e.g., `--only git-exposed,sms-static-cred`)

## Step 0 — Confirm the tool layer exists (Ring 2)

The tool layer is bring-your-own and not bundled. Before anything else, confirm it is established:

```bash
command -v bbflow >/dev/null && bbflow list >/dev/null 2>&1 && echo "bbflow ready" || echo "NO TOOL LAYER"
```

If the tool layer is missing, **stop and run `bb-tool-setup`** (full steps in `bbflow/setup.md`) — do not blindly call `bbflow hunt`, it will fail. Only continue once `bbflow list` works or your own scanner is wired to emit `candidates.jsonl`.

## Step 1 — Pre-run deduplication check

Read these files first to know what is already discovered:
```bash
cat workspace/workshop/<target>/FINDINGS_QUICK_REF.md
cat workspace/workshop/<target>/RECON_DB.md
```

If either file does not exist, run:
```bash
bash automation/init_target.sh <target>
```

## Step 2 — Check scope

```bash
cat workspace/workshop/<target>/SCOPE.md 2>/dev/null | head -40
```

Note any out-of-scope domains/IPs. Never run hunters against out-of-scope targets.

## Step 3 — Run hunters

bbflow is a CLI tool that runs on a VPS or isolated runner (see `tools/README.md` — do not call `tools/bbflow.sh`, it does not exist). Run hunters via the bbflow CLI:

```bash
bbflow hunt <target> --hunters all
```

Or with specific hunters:
```bash
bbflow hunt <target> --hunters <hunter1>,<hunter2>
```

To list available hunters first:
```bash
bbflow list
```

To generate a report after the hunt completes:
```bash
bbflow report <target>
```

> Note: `bbflow hunt` and `bbflow report` must be run on the VPS/isolated runner per `tools/README.md`. Do not run these commands against live targets from your local machine.

## Step 4 — Parse results

After running, check:
```bash
ls workspace/workshop/<target>/hits/ 2>/dev/null
cat workspace/workshop/<target>/hits/*.hit 2>/dev/null
cat workspace/workshop/<target>/hits/*.warn 2>/dev/null
```

## Step 5 — Classify each hit

For each hit result, determine:
- **Already known?** — check against RECON_DB.md and FINDINGS_QUICK_REF.md
- **New credential/path/endpoint?** — append to RECON_DB.md under the correct section
- **New significant vulnerability?** — recommend creating a Vault Finding
- **Service version / firmware build revealed in hit?** (e.g., nuclei fingerprint, banner with version, JS bundle build id, exposed `/version` endpoint) — **flag for version+CVE pre-flight** before any deep analysis or Finding creation

## Step 5.5 — Version+CVE pre-flight flag (NOT auto-run)

If any hit reveals concrete `<vendor>/<product>/<version>` info, **mark it** for version+CVE pre-flight check. **Do NOT auto-run web search per hit** — too expensive. Instead, surface it in Step 8 summary so the user (or next session) runs the `bb-version-cve-precheck` skill before deep analysis.

Mark format in RECON_DB Session Log:
```
| YYYY-MM-DD | bbflow hunt | <hunter> | hit: <vendor>/<product>/<version> @ <url> [needs version+CVE pre-flight] |
```

Why this matters: AGENTS.md section 0g forbids deep analysis or Finding creation on a known-CVE target. A previous engagement sank 6 hours when a 5-minute web search would have revealed an existing CVE (e.g., ACME-001-style scenario). bbflow surfaces the version data — but the **decision to proceed or abort** is the version+CVE pre-flight job, run separately via the `bb-version-cve-precheck` skill.

## Step 6 — Update RECON_DB.md

Append new discoveries to `workspace/workshop/<target>/RECON_DB.md`:
- New credentials — `## 🔑 Credentials & Keys` section
- New paths/endpoints — `## 🛤 Discovered Paths & Endpoints` section
- New infra/IPs — `## 🖥 Internal Infrastructure` section
- New accounts — `## 👤 Accounts & Usernames` section

Also append to the Session Log at the bottom:
```
| YYYY-MM-DD | bbflow hunt | <hunters run> | <summary of new hits> |
```

## Step 7 — Commit

```bash
git add workspace/workshop/<target>/RECON_DB.md workspace/workshop/<target>/hits/
git commit -m "[recon] <target>: bbflow hunt — <summary of new findings>"
```

## Step 8 — Summary report

Output a clean summary:
- Hunters run: N
- New hits: N (list each)
- Already known: N
- **Version+CVE pre-flight needed**: N hits revealed `<vendor>/<product>/<version>` — list each and suggest running the `bb-version-cve-precheck` skill before deep analysis or Finding creation.
- RECON_DB updated: yes/no
- Recommended next steps (e.g., "create Vault Finding for X — but run version+CVE pre-flight first")

## Rules

- Never run destructive tests. Hunters are read-only probes.
- If a hunter outputs credentials, immediately check if they are already in RECON_DB before treating as new.
- If scope is unclear, ask before running.
- Do NOT commit raw scan logs (only commit RECON_DB summary + hit files).
- **Do NOT recommend creating a Vault Finding for any version-bearing hit without first running the version+CVE pre-flight** (AGENTS.md section 0g). Surface the hit and flag it; let the user or next session run the precheck via the `bb-version-cve-precheck` skill.
- Theoretical attack chains must NOT be reported as facts (anti-exaggeration, AGENTS.md section 5).
- Reports and Findings must NOT contain internal IDs (e.g., `ACME-001`, advisory reference codes) in external-facing submissions — AGENTS.md section 5.
