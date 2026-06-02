# Obsidian Setup

This repository **is** an Obsidian vault. Open the repo root directly as a vault — there is no separate "private vault" to build first. The bundled `.obsidian/` preset ships generic core settings, the recommended community-plugin ID list, graph defaults, and the template-folder config. It does **not** ship plugin binaries, workspace state, sync settings, or credentials.

## 1. Open the vault

In Obsidian: **Open folder as vault** → select the cloned repo root. The numbered folders (`00 - Dashboard/`, `01 - Targets/`, `07 - Templates/`, `09 - Knowledge Base/`, `10 - Meta/`) appear in the file explorer immediately.

## 2. Install the community plugins

The preset enables plugin **IDs** in `.obsidian/community-plugins.json`, but the binaries are not vendored. On first open, Obsidian will report "disabled" plugins — install them via **Settings → Community plugins → Browse**:

| Plugin | Priority | Role in this framework |
|---|---|---|
| **Dataview** | Required | Powers every dashboard query (`00 - Dashboard/Dashboard.md`, the Target hub views). Without it, dashboards show as code blocks. |
| **Templater** | Required | Renders the `<% tp.* %>` templates in `07 - Templates/`. Set Templater's template folder to `07 - Templates` (Settings → Templater). |
| **Kanban** | Required for boards | Renders `00 - Dashboard/Kanban Board.md` and per-target `Kanban - <target>.md` as draggable columns. |
| **MetadataMenu** | Recommended | Drives the `fileClass` property dropdowns (Finding/Submission/Attempt/Recon) that match the lint schema. |
| **QuickAdd** | Recommended | One-command capture: "new target", "new finding", "new recon note". |
| **Obsidian Git** | Recommended | Commit/push from inside Obsidian when no terminal is open. |
| **Omnisearch** | Optional | Better full-text search as the vault grows. |
| **Linter** | Optional | Normalizes Markdown/frontmatter formatting. |
| **Advanced Tables** | Optional | Easier editing of scope/triage/checklist tables. |
| **Excalidraw / ExcaliBrain** | Optional | Hand-drawn attack-chain diagrams and a relationship brain view. |

> The exact enabled list lives in `.obsidian/community-plugins.json`. You can disable any you don't want — only Dataview, Templater, and Kanban are needed for the bundled dashboards/boards/templates to render.

## 3. Core plugins

These built-ins are enabled by the preset (`.obsidian/core-plugins.json`) and need no install:

| Plugin | Role |
|---|---|
| Properties view | Edit frontmatter without opening raw YAML. |
| Backlinks / Outgoing links | Jump between a report and its supporting notes. |
| Graph view | See relationships between targets, findings, and KB patterns. |
| Quick switcher / Search | Move and search even with community plugins off. |
| Templates | Core fallback (the `<% %>` syntax needs Templater, above). |
| Canvas | Visual maps for attack chains and planning. |
| Bases | Optional database-like views over properties. |

## 4. Verify it works

After installing the required plugins:

1. Open `00 - Dashboard/Dashboard.md` — the tables should render and show the `_example` target's Finding/Submission.
2. Open `00 - Dashboard/Kanban Board.md` — should render as columns.
3. Open `01 - Targets/_example/Target - _example.md` — the embedded Dataview tables should list `ACME-001`.
4. Create a test note from `07 - Templates/Template - Finding.md` via Templater to confirm the template folder is wired.

If tables show as raw code blocks, Dataview isn't enabled. If `<% tp %>` appears literally, Templater isn't installed or its folder isn't set to `07 - Templates`.

## 5. Start your first target

```bash
bash automation/init_target.sh <target>
```

This creates `01 - Targets/<target>/` (with the full subfolder tree and a `Target - <target>.md` hub) plus the gitignored `workspace/workshop/<target>/` scratch area. Then follow [getting-started.md](getting-started.md) for the full recon → Finding → Submission walkthrough.

## Included preset files

| File | Purpose |
|---|---|
| `.obsidian/app.json` | Generic editor/file behavior. |
| `.obsidian/appearance.json` | Default theme, no custom snippets. |
| `.obsidian/core-plugins.json` | Core plugin enablement baseline. |
| `.obsidian/community-plugins.json` | Recommended community plugin IDs. |
| `.obsidian/templates.json` | Points the core Templates plugin at `07 - Templates`. |
| `.obsidian/graph.json` | Generic graph defaults. |
| `.obsidian/plugins/README.md` | Why plugin binaries are not committed. |

## Plugin safety rules

- Never sync `workspace/`, raw evidence, logs, exported archives, or credentials through Obsidian sync/plugins.
- Don't commit downloaded `.obsidian/plugins/<id>/` binaries, plugin cache, API keys, or `workspace.json` into a public fork.
- Keep public examples generic — use `example.com` and `<target>` placeholders.
- The Markdown files are the source of truth; plugin automation is convenience only.

## Suggested dashboard views

The bundled `00 - Dashboard/Dashboard.md` already includes these; extend as needed:

| View | Backing data |
|---|---|
| Active Targets | `fileClass: Target` where `status != closed` |
| Findings by Severity | `fileClass: Finding`, sorted P1→P5 |
| Open Findings Needing Action | `fileClass: Finding` where `status` is `verified`/`ready` |
| Submissions by Status | `fileClass: Submission` grouped by `status` |
| Recent Findings | `fileClass: Finding` where `discovered_date` within 7 days |
