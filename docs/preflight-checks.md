# Preflight Checks

This public-safe preflight model helps an adopted private vault stop early when work is not authorized, stale, duplicated, or already known.

It is a decision gate, not a scanner and not a vulnerability feed.

## Inputs

- Authorized scope note or scope file.
- Target or asset name.
- Version or release channel when applicable.
- Public advisory sources chosen by the private operator.
- Existing private vault notes, findings, and reviews.

## Gate Order

1. Authorized scope check.
2. Duplicate check against private notes.
3. Version and release status check.
4. CVE, advisory, and known issue search.
5. Safety-level decision.
6. Work decision: proceed, park, or stop.

## Version

When a target has a product, component, package, application, firmware, or service version, record:

- observed version
- latest stable or supported branch
- release source
- version gap
- support status

If there is no stable version concept, record the review date and the relevant public advisory window instead.

## CVE, Advisory, And Known Issue Review

Use public authoritative sources selected by the private operator. Record enough citation detail in the private vault to explain why a candidate is new, duplicate, stale, or already known.

The preflight can mark a candidate as:

- no known overlap found
- likely duplicate
- known issue
- patched upstream but still present in an observed environment
- unsupported or out of scope

## Stop conditions

Stop before active work when:

- Authorized scope is missing or expired.
- The requested action exceeds the declared safety level.
- The issue is already covered by an existing private finding.
- The issue is a known issue and the program does not accept it.
- The target version is unsupported and no authorized reason exists to continue.
- Evidence would require collecting unrelated sensitive data.

## Output

Write a short private preflight note or a section in the session handoff:

```text
Preflight:
- Scope: <scope file or note>
- Version: <version or not applicable>
- Advisory review: <summary>
- Decision: <proceed | park | stop>
- Reason: <short reason>
```

## Knowledge Capture

Promote only generic lessons:

- useful advisory search pattern
- version decision rule
- duplicate decision rule
- stop condition that should become a checklist item

Do not promote target names, raw evidence, account details, or copied advisory text into public material.
