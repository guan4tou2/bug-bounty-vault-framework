# Obsidian Setup

This framework treats Obsidian as the human-facing interface for the private vault. The public repository includes a minimal `.obsidian/` preset with generic core plugin settings, community plugin IDs, graph defaults, and template folder configuration.

The preset does not include downloaded plugin code, workspace state, sync settings, credentials, or personal UI history.

## Recommended Core Plugins

Recommended core plugins are the built-in features that make the vault useful before any community plugin is installed.

Enable these from Obsidian Settings -> Core plugins:

| Plugin | Role in this framework |
|---|---|
| Bases | Database-like views over Markdown properties for targets, findings, reviews, and learning queues. |
| Canvas | Visual maps for attack chains, workflow diagrams, and high-level program planning. |
| Graph view | Relationship checks between targets, findings, patterns, playbooks, and reference notes. |
| Backlinks | Fast context recovery when moving from a report back to supporting notes. |
| Properties view | Frontmatter inspection and cleanup without opening raw YAML every time. |
| Templates | Lightweight fallback for inserting simple template text. |
| Quick switcher | Fast movement across target, workflow, and knowledge notes. |
| Search | Baseline search that works even when community plugins are disabled. |

## Recommended Community Plugins

Recommended community plugins add automation, dashboards, and search once the private vault structure is stable.

The community plugin IDs are committed in `.obsidian/community-plugins.json`, but the plugin binaries are not vendored. Install community plugins through Obsidian's Community Plugins browser after opening your private vault.

| Plugin | Priority | Role in this framework |
|---|---:|---|
| Dataview | Required for dashboard-style vaults | Query Markdown properties and generate live indexes for targets, findings, reviews, and knowledge notes. |
| Templater | Required for structured capture | Create notes from templates with dates, generated IDs, and consistent frontmatter. |
| QuickAdd | Recommended | Turn common actions into commands, such as "new target", "new recon note", or "new finding". |
| Git | Recommended | Commit and push vault changes from inside Obsidian when a CLI is not open. |
| Tasks | Optional | Track review, validation, and learning tasks across notes. |
| Omnisearch | Optional | Improve full-text search when the vault grows. |
| Linter | Optional | Normalize Markdown formatting and frontmatter style. |
| Advanced Tables | Optional | Improve editing for scope tables, triage tables, and report checklists. |

## Minimal Private Vault Layout

```text
private-vault/
├── 00-dashboard/
├── 01-targets/
├── 07-templates/
├── 09-knowledge/
└── workspace/          # ignored scratch space, outside public sync
```

This layout is intentionally generic. Rename folders to match your own conventions, but keep one clear split: canonical notes in the vault, raw operational artifacts in the ignored workspace.

## Setup Order

1. Open the private vault folder in Obsidian.
2. Enable core plugins first.
3. Install only the community plugins you need.
4. Copy files from `templates/` into the private vault's template folder.
5. Create a first placeholder target using `templates/target.md`.
6. Create one recon note and one finding draft to test properties, backlinks, and dashboard queries.
7. Commit the private vault only after confirming no raw artifacts or secrets are present.

## Included Preset Files

| File | Purpose |
|---|---|
| `.obsidian/app.json` | Generic editor and file behavior. |
| `.obsidian/appearance.json` | Default theme and no custom snippets. |
| `.obsidian/core-plugins.json` | Core plugin enablement baseline. |
| `.obsidian/community-plugins.json` | Recommended community plugin IDs. |
| `.obsidian/templates.json` | Points Obsidian's Templates core plugin at `templates/`. |
| `.obsidian/graph.json` | Generic graph defaults for target and knowledge folders. |
| `.obsidian/plugins/README.md` | Explains why plugin binaries are not committed. |

## Plugin Safety Rules

- Do not sync `workspace/`, raw evidence, logs, exported archives, or credential material through Obsidian plugins.
- Avoid publishing `.obsidian/plugins/` unless you intentionally maintain a shared team preset.
- Prefer documenting plugin names and roles over committing personal plugin settings.
- Keep public examples generic. Use placeholder domains such as `example.com`.
- Treat plugin automation as convenience only. The Markdown files remain the source of truth.

## Suggested Dashboard Views

Start with these views before adding complex dashboards:

| View | Backing data |
|---|---|
| Active Targets | Target notes with `status: active` |
| Findings Queue | Finding notes grouped by `status` and `severity` |
| Review Queue | Review notes grouped by `status` and `risk` |
| Knowledge Capture | Recon notes where lessons or patterns still need extraction |
| Review Aging | Findings or reviews older than your review threshold |
