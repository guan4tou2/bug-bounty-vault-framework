# Workflow

The generic lifecycle is:

```text
Target -> Recon -> Finding -> Submission -> Triage -> Knowledge Capture
```

## Gates

### Safety gate

Confirm authorization, scope, and testing constraints before any active work.

### Dedupe gate

Check whether the same host, feature, primitive, or root cause has already been investigated.

### Evidence gate

Do not promote a candidate into a Finding until the evidence is reproducible, scoped, and minimally documented.

### Knowledge capture gate

Capture what can be reused: decision points, false-positive filters, stop conditions, and report lessons.

## Lifecycle

1. Create or select a target placeholder.
2. Confirm scope and allowed testing behavior.
3. Run recon in an external workspace.
4. Record a recon note with tools, scope, decisions, and outputs.
5. Promote validated issues into findings.
6. Convert report-ready findings into submissions or platform forms.
7. Update triage status after platform or owner response.
8. Feed reusable lessons back into the LLM Wiki.

## Close-Out

Before ending work:

- Release any active ownership lock if your private implementation uses one.
- Record what was done and what remains.
- Move raw artifacts out of the public Vault boundary.
- Update reusable generic lessons only after sanitization.
