# Session Lifecycle

This public-safe lifecycle describes how an adopted private vault can track work without copying private runtime data into the public seed.

The lifecycle is intentionally abstract. It gives users the same operating rhythm as the framework without shipping private lock files, live target data, scanning logic, or platform-specific workflows.

## Lifecycle

```
Claim -> Work -> Handoff -> Closeout -> Knowledge Capture -> Check
```

## Claim

Claim means declaring the target, program, scope source, and intended work before creating notes or running automation.
Authorized scope must be explicit before active work starts.

Minimum claim record:

- target name
- program or owner
- scope file or scope note
- safety level
- session status
- planned next action

Use:

```bash
python3 scripts/start_session.py --target <target> --program <program> --scope-file bbflow/scope.example.yaml
```

The script creates a target workspace folder under `workspace/workshop/<target>/` and writes:

- `HANDOFF.md`
- `OPERATION_LOG.md`
- `SESSION_STATE.json`

## Handoff

Handoff means recording enough state for a later operator or LLM agent to continue without reading raw logs.

The handoff should contain:

- current status
- scope source
- active questions
- next action
- blockers
- links to review-ready notes

Do not paste raw scan output, secrets, tokens, screenshots, or private report bodies into the handoff.

## Closeout

Closeout means ending a session by writing a concise summary and deciding whether any reusable lesson should enter the LLM Wiki.

Use:

```bash
python3 scripts/end_session.py --target <target> --summary "<what changed>" --knowledge-capture "<generic lesson or none>"
```

Closeout updates `SESSION_STATE.json`, appends `OPERATION_LOG.md`, and marks `HANDOFF.md` as closed.

## Knowledge Capture

Knowledge Capture is the only path from runtime work back into durable process knowledge.

Allowed promoted forms:

- Pattern
- Playbook
- Checklist
- Reference Card

Do not promote target names, account data, raw output, copied responses, or platform text.

## Check

Use `check_vault.py` before publishing or sharing a framework copy:

```bash
python3 scripts/check_vault.py
```

This delegates to the public verifier and confirms the public skeleton still has only scaffold files under `workspace/`.

## Public Boundary

The public repository may include lifecycle docs, templates, and minimal scripts. It must not include:

- real session state
- active target queues
- private lock files
- raw tool output
- credentials
- platform-specific disclosure material
