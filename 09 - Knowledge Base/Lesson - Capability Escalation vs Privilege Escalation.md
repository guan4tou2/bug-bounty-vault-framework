---
type: lesson
title: "Lesson - Capability Escalation vs Privilege Escalation"
tags: [lesson, pitfall-avoidance, report-writing, terminology, electron, localhost, capability-escalation]
status: active
first_seen: 2026-05-18
last_updated: 2026-05-18
category: pitfall-avoidance
precedents: an Electron desktop app case — unauthenticated localhost IPC service allowing borrowed capabilities
---

# Lesson - Capability Escalation vs Privilege Escalation

## TL;DR

When a vulnerability gives a low-privilege process access to **additional capabilities** (file write, shell execution, camera) without changing the **OS user context**, call it **capability escalation** — NOT privilege escalation (LPE). Misusing "privilege escalation" when root/admin isn't involved weakens your report and invites triage pushback.

## The distinction

| Term | What changes | Example |
|------|-------------|---------|
| **Privilege escalation (LPE)** | OS user context: user → root/admin | Kernel exploit, sudo bypass, SUID abuse |
| **Capability escalation** | Available operations expand, **same user** | A localhost service grants file write + shell exec |

## Why it matters for reports

1. **Triage accuracy**: reviewers who see "privilege escalation" will check whether you gained root. If you didn't, credibility drops.
2. **CVSS scoring**: the AV/AC/PR/UI vector changes. "Privileges Required" stays the same (Low→Low), but the **Scope** may change if the vulnerable component's authorization boundary is crossed.
3. **Severity framing**: capability escalation is still serious — a browser tab gaining an arbitrary-file-write primitive plus a shell-execution primitive is functionally RCE at user level. Frame it as "any local process can borrow the application's IPC bridge to achieve arbitrary code execution **as the current user**."

## Real-world example: an Electron desktop app localhost IPC case

**Wrong framing** (first draft):
> "An unauthenticated localhost service = a local privilege escalation stepping stone."

**Correct framing** (after review):
> "An unauthenticated localhost service = capability escalation — any local process can borrow the Electron app's IPC bridge to achieve arbitrary file write + command execution (at the same user's privilege level)."

The attacker **stays the same OS user** but gains:
- An arbitrary-file-write primitive exposed via IPC
- An arbitrary-command-execution primitive exposed via IPC (e.g. via a "shell open external" style API)
- Camera/microphone entitlements already granted to the app

These are **borrowed capabilities** from the Electron app's IPC bridge, not OS-level privilege escalation.

## Checklist: which term to use?

```
Does the exploit change the OS user context?
  ├── YES (user → root/admin/SYSTEM) → Privilege Escalation (LPE)
  └── NO (same user, more capabilities) → Capability Escalation
        ├── Crosses process boundary? → Capability Escalation
        ├── Crosses sandbox boundary? → Sandbox Escape + Capability Escalation
        └── Only within same process? → Likely just a bug, not escalation
```

## Report writing template

```markdown
### Impact

Any local process (including low-privilege browser JavaScript via localhost)
can connect to `localhost:PORT` without authentication and invoke the
application's IPC bridge to:

1. Write arbitrary files
2. Execute arbitrary commands
3. Access camera/microphone (via inherited entitlements)

This constitutes **capability escalation**: while the attacker remains
at the same OS user privilege level, they gain the full operational
capabilities of the Electron application's main process.
```

## Related patterns

- Pattern - Localhost WebSocket Session-Bounded Unauth — localhost services without auth
- Pattern - Electron contextIsolation Per-Window Variance — per-window security variance
- Pattern - IPC Socket Hijack — IPC boundary crossing
