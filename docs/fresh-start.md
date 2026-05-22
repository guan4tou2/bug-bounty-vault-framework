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

## Suggested Private Layout

```text
private-vault/                 # Obsidian vault root
  docs/
  templates/
  prompts/
  agents/
  skills/
  hooks/
  bbflow/
  workspace/                  # ignored runtime workspace
    workshop/
    tools/
    reports/
    logs/
  targets/
  wiki/
  dashboard/
```

## Acceptance

- The public framework remains clean.
- Private data lives only in the private vault or its ignored workspace.
- The verifier passes before every public push.
