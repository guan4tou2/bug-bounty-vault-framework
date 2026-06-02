# Fresh Start

Use this repository as a starting point for a private operational vault.

## Bootstrap

1. Clone this public framework.
2. Create a separate private repository or local private vault.
3. Run `bash automation/setup_workspace.sh` to create ignored local runtime directories.
4. Run `bash automation/init_target.sh <target>` when starting the first private target.
5. Use the included `workspace/` scaffold for raw artifacts; it is ignored by default.
6. Keep this public framework free of operational data.

## After adoption

After adoption, the private vault and its ignored workspace are out of scope for this public repository.

This framework does not need to know about future targets, notes, evidence, reports, tool output, or private knowledge. Treat this repository as the reusable starter kit, not the place where execution data returns.

## Layout

The repo root **is** the Obsidian vault — you inherit this layout on clone (see [STRUCTURE.md](../STRUCTURE.md) for the full tree):

```text
<vault root>/                  # Obsidian vault root + git repo
  00 - Dashboard/              # Dataview dashboards + Kanban boards
  01 - Targets/                # One subfolder per target
  07 - Templates/              # Obsidian (Templater) templates
  09 - Knowledge Base/         # Patterns, Playbooks, Checklists, Lessons
  10 - Meta/                   # Meta notes
  .claude/ .codex/ .gemini/    # Optional LLM skills + agents
  automation/  _automation/    # Session lifecycle + lint
  docs/  bbflow/  tools/
  workspace/                   # gitignored runtime scratch
    workshop/<target>/         # SCOPE, RECON_DB, HANDOFF, poc/, scan_results/
    reports/  firmware_analysis/  logs/
```

Keep one clear split: canonical notes in the numbered vault folders, raw operational artifacts in the gitignored `workspace/`.

## Acceptance

- The public framework remains clean.
- Private data lives only in the private vault or its ignored workspace.
- The verifier passes before every public push.
