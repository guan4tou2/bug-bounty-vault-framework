# bbflow Framework Layer

> **Not the bbflow tool.** This directory is the *generic workflow spec* (gates / scope guard / output contract) — architecture-only, no hunters or templates. The actual runnable toolchain (47 hunters, BBOT/Osmedeus, real nuclei templates, zero-LLM CLI) is the separate repo [`guan4tou2/bbflow`](https://github.com/guan4tou2/bbflow), created earlier (2026-04). This framework abstracts the flow that any private toolchain — including that tool — can implement.

This directory is a framework-only placeholder for connecting an optional automation runtime to the vault workflow.

It defines the shape of the workflow, the scope guard, the expected output contract, and the knowledge capture hook. The contract is intentionally open — but the framework's **default implementation is the standalone `guan4tou2/bbflow` CLI** (`bb-tool-setup` / `setup.md`). An alternative scanner is a fallback only if it conforms to this contract.

## What Is Included

- A simple flow model.
- A scope example.
- A machine-readable output contract.
- A knowledge capture hook.
- A public safety boundary.
- Example configuration shapes for Nuclei, Osmedeus, and BBOT.
- `TOOLS.md` — a sanitized inventory (names + purposes, no payloads) of the bbflow toolchain that implements this flow.

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

See `configs/` for public-safe examples. They describe how to connect tools to the workflow without shipping scanners, hunters, payloads, evasion logic, or target-specific rules.
