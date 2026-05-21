# bbflow Framework Layer

This directory is a framework-only placeholder for connecting an optional automation runtime to the vault workflow.

It is intentionally bring your own tools. It defines the shape of the workflow, the scope guard, the expected output contract, and the knowledge capture hook.

## What Is Included

- A simple flow model.
- A scope example.
- A machine-readable output contract.
- A knowledge capture hook.
- A public safety boundary.

## What Is Not Included

- no hunters.
- no payloads.
- no bundled scanners.
- no target-specific templates.
- no evasion guidance.
- no private findings or lessons.

## Intended Use

1. Copy this framework into a private automation project.
2. Replace the examples with your own allowed scope and tools.
3. Keep raw output in an ignored workspace.
4. Promote only reviewed, sanitized lessons back to the vault.
