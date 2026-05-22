# Fresh Start

Use this repository as a starting point for a private operational vault.

## Bootstrap

1. Clone this public framework.
2. Create a separate private repository or local private vault.
3. Run `python3 scripts/bootstrap_private_vault.py <private-vault-path>` or copy the framework files manually.
4. Use the included `workspace/` scaffold for raw artifacts; it is ignored by default.
5. Keep this public framework free of operational data.

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
