# Fresh Start

Use this repository as a starting point for a private operational vault.

## Bootstrap

1. Clone this public framework.
2. Create a separate private repository or local private vault.
3. Copy the templates into the private vault.
4. Create an external ignored workspace for raw artifacts.
5. Keep this public framework free of operational data.

## After adoption

After adoption, the private vault and external workspace are out of scope for this public repository.

This framework does not need to know about future targets, notes, evidence, reports, tool output, or private knowledge. Treat this repository as the reusable starter kit, not the place where execution data returns.

## Suggested Private Layout

```text
private-vault/
  targets/
  wiki/
  dashboard/
  automation/
  templates/

external-workspace/
  raw/
  scans/
  poc/
  logs/
  evidence/
```

## Acceptance

- The public framework remains clean.
- Private data lives only in the private vault or external workspace.
- The verifier passes before every public push.
