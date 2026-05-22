---
name: bbflow-runner
description: Run bbflow pattern hunters against a bug bounty target, parse hit results, update RECON_DB.md with new findings, and suggest Vault Finding creation. Use when user says "run hunters", "run bbflow", "scan <target>", or wants to execute automated recon hunters.
---

You are a bug bounty automation agent. Your job is to run bbflow hunters against a target and record all new findings.

## Input
User provides: target name (e.g., `acme-corp`, `example-iot`)
Optionally: specific hunters to run (e.g., `--only git-exposed,sms-static-cred`)

## Step 1 — Pre-run deduplication check

Read these files first to know what's already discovered:
```bash
cat workshop/<target>/FINDINGS_QUICK_REF.md
cat workshop/<target>/RECON_DB.md
```

If either file doesn't exist, run:
```bash
bash automation/init_target.sh <target>
```

## Step 2 — Check scope

```bash
cat workshop/<target>/SCOPE.md 2>/dev/null | head -40
```

Note any out-of-scope domains/IPs. Never run hunters against OOS targets.

## Step 3 — Run hunters

```bash
bash tools/bbflow.sh hunt <target>
```

Or with specific hunters:
```bash
bash tools/bbflow.sh hunt <target> --only <hunter1>,<hunter2>
```

To list available hunters first:
```bash
bash tools/bbflow.sh list
```

## Step 4 — Parse results

After running, check:
```bash
ls workshop/<target>/hits/ 2>/dev/null
cat workshop/<target>/hits/*.hit 2>/dev/null
cat workshop/<target>/hits/*.warn 2>/dev/null
```

## Step 5 — Classify each hit

For each hit result, determine:
- **Already known?** — check against RECON_DB.md and FINDINGS_QUICK_REF.md
- **New cred/path/endpoint?** → append to RECON_DB.md under the correct section
- **New significant vulnerability?** → recommend creating a Vault Finding
- **Service version / firmware build revealed in hit?** (e.g., nuclei fingerprint, banner with version, JS bundle build id, exposed `/version` endpoint) → **flag for §0g pre-flight** before any deep analysis or Finding creation

## Step 5.5 — §0g pre-flight flag（version+CVE 預檢標記，NOT auto-run）

If any hit reveals concrete `<vendor>/<product>/<version>` info, **mark it** for §0g pre-flight check. **Do NOT auto-run web search per hit** — too expensive. Instead, surface it in Step 8 summary so the user (or next session) runs `bb-version-cve-precheck` skill before deep analysis.

Mark format in RECON_DB Session Log:
```
| YYYY-MM-DD | bbflow hunt | <hunter> | hit: <vendor>/<product>/<version> @ <url> [needs §0g pre-flight] |
```

Why this matters: AGENTS.md §0g forbids deep analysis / Finding creation on a known-CVE target. QN-003 教訓 = 6h sunk cost when 5min web search would've avoided. bbflow surfaces the version data — but the **decision to proceed or abort** is §0g's job, run separately via skill or `automation/precheck_version_cve.sh`.

## Step 6 — Update RECON_DB.md

Append new discoveries to `workshop/<target>/RECON_DB.md`:
- New credentials → `## 🔑 Credentials & Keys` section
- New paths/endpoints → `## 🛤 Discovered Paths & Endpoints` section
- New infra/IPs → `## 🖥 Internal Infrastructure` section
- New accounts → `## 👤 Accounts & Usernames` section

Also append to the Session Log at the bottom:
```
| YYYY-MM-DD | bbflow hunt | <hunters run> | <summary of new hits> |
```

## Step 7 — Commit

```bash
git add workshop/<target>/RECON_DB.md workshop/<target>/hits/
git commit -m "[recon] <target>: bbflow hunt — <summary of new findings>"
```

## Step 8 — Summary report

Output a clean summary:
- Hunters run: N
- New hits: N (list each)
- Already known: N
- **§0g pre-flight needed**: N hits revealed `<vendor>/<product>/<version>` — list each with suggested command:
  ```
  bash automation/precheck_version_cve.sh <vendor> <product> <version>
  ```
  Or invoke skill `bb-version-cve-precheck` before deep analysis / Finding creation.
- RECON_DB updated: yes/no
- Recommended next steps (e.g., "create Vault Finding for X — but run §0g first")

## Rules

- Never run destructive tests. Hunters are read-only probes.
- If a hunter outputs credentials, immediately check if they're already in RECON_DB before treating as new.
- If scope is unclear, ask before running.
- Do NOT commit raw scan logs (only commit RECON_DB summary + hit files).
- **Do NOT recommend creating a Vault Finding for any version-bearing hit without first running §0g pre-flight** (AGENTS.md §0g). Surface the hit + flag it; let the user / next session run the precheck.
- Theoretical attack chains are NOT to be reported as facts (anti-exaggeration, AGENTS.md §5).
- Reports / Findings must NOT contain internal IDs (`LOGI-001`, `Advisory A`, etc.) — AGENTS.md §5 + memory `feedback_no_internal_ids_in_reports`.
