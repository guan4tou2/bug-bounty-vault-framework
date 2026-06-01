# Workflow

The generic lifecycle is:

```text
Target -> Recon -> Finding -> Review -> Knowledge Capture
```

## Gates

Each gate can be performed manually or via the corresponding LLM skill.

### Safety gate (`bb-scope-safety-check`)

Confirm authorization, scope, and testing constraints before any active work.

### Dedupe gate (`bb-dedup-finding`)

Check whether the same host, feature, primitive, or root cause has already been investigated.

### Chain review gate (`bb-attack-chain-review`)

Assess whether a candidate can chain into higher impact before finalizing a Finding.

### Evidence gate (`bb-evidence-readiness`)

Do not promote a candidate into a Finding until the evidence is reproducible, scoped, and minimally documented.

### Submission gate (`bb-submission-readiness`)

Final check before creating a Submission or FORM: dedupe, scope, evidence, severity, platform fit, and report hygiene.

### Knowledge capture gate (`bb-knowledge-capture`)

Capture what can be reused: decision points, false-positive filters, stop conditions, and workflow lessons.

### Attempt recording (`bb-attempt-recorder`)

When a candidate fails any gate, record the negative result to prevent repeated effort.

## Lifecycle

1. Create or select a target placeholder.
2. Confirm scope and allowed testing behavior.
3. Run recon in an external workspace.
4. Record a recon note with tools, scope, decisions, and outputs.
5. Promote validated issues into findings.
6. Review findings for evidence quality, risk, and duplicate likelihood.
7. Record the review decision in a review note.
8. Optionally create a platform-neutral submission or form bundle for private downstream use.
9. Feed reusable lessons back into the LLM Wiki.

## Close-Out

Before ending work:

- Release any active ownership lock if your private implementation uses one.
- Record what was done and what remains.
- Move raw artifacts out of the public Vault boundary.
- Update reusable generic lessons only after sanitization.
