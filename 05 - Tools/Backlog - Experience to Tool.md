---
fileClass: Note
type: tool-backlog
title: Backlog — Experience → Tool (living scanner)
last_updated: 2026-09-07
tags: [tool, backlog, nuclei, scanner, crystallization]
---

# Backlog — Experience → Tool (living scanner)

> **Purpose:** crystallize the *rule-detectable* patterns you learn while hunting into **re-runnable
> detections**, so your scanner grows from a frozen check set into one continuously fed by your own
> experience.
> This is the **executable-tool track** of [[Reference Card - Promotion Ladder]] (parallel to the
> T1–T7 knowledge ladder). Feed point = the `tool crystallization` field at the end of
> [[bb-knowledge-capture]].

## The split (which way a learning goes)

| Nature of the learning | Destination |
|---|---|
| **A rule can catch it** (header combo / exposed endpoint / version fingerprint / magic bytes / hardcoded pattern) | → **tool** (this backlog → authored + deployed as a template/hunter/script) |
| **It needs judgment** (is this IDOR worth it, is this chain sound, should it be reported) | → **KB / DT** ([[Reference Card - Decision Trees]]), NOT a hunter |

> Only mechanizable, portable, testable patterns become scanner checks. Forcing a "needs-judgment"
> lesson into a hunter floods the scanner with false positives and rots it.

## Format taxonomy (pick the format by domain)

| Domain / signal shape | Crystallizes into | Run with |
|---|---|---|
| web req/resp pattern (header, exposed endpoint, misconfig, version) | **nuclei template** | `nuclei -t …` |
| multi-step recon / enumeration logic | **hunter script** | your runner |
| firmware/binary signature (magic bytes, function pattern, hardcoded cred) | **grep-signature / binwalk rule / RE script** | script under `05 - Tools/` |
| mobile (APK) static rule | **jadx-grep / static rule** | manual / script |
| infra/cloud (bucket, actuator, metadata) | **hunter / nuclei** | your runner |

> nuclei is the preferred authoring format for web patterns (portable, testable). RE/pentest patterns
> crystallize into a script under `05 - Tools/` plus a `Tool - <name>.md` note.
> **No infra coupling:** templates/hunters/scripts are portable artifacts that run locally; *where*
> they run is an execution detail, not a design concern.

## Backlog (the queue)

> On session wrap-up, append one row for each new *rule-detectable* pattern. status: `idea` (just
> logged) → `authored` (written, locally validated) → `deployed` (in your hunter set, runs daily).

| id | Catches (pattern) | domain | mechanizable signal | target format | source | status |
|---|---|---|---|---|---|---|
| _(example)_ | Spring actuator `/env` unauth exposure | web/infra | GET `/actuator/env` → 200 + JSON with `systemProperties` | nuclei template | LL-xxx / FINDING | idea |

## Drain (a template lifecycle — don't shortcut to "deployed")

status flows through a lifecycle: `idea → draft → validate → null-case → canary → FP-review → promoted`.
**Only `promoted` enters the default auto-run set** (never auto-run an un-canaried template against real targets).

1. Pick the top backlog entries (high-reuse, clearly-ruled ones first).
2. **draft** — author into the matching format (web → nuclei template; RE → a script). **Sanitize**
   ([[bb-knowledge-capture]] hard rule). **Dedup first** — don't duplicate an existing template.
3. **validate** — `nuclei -validate -t <file>`.
4. **null-case** — run against `example.com` / a harmless host; must yield NO hit (no obvious false positive).
5. **canary** — only on an authorized target, low rate-limit, single template.
6. **FP-review → promote** — only after it passes: move into the default set, note it in your scanner's
   CHANGELOG, flip status to `promoted`, and back-link the source Pattern.

> The `build-hunters` workflow automates **draft→validate→null-case** (output is a DRAFT); **canary +
> FP-review + promote need a live target and stay manual**. This backlog makes "experience → an
> ever-growing scanner" visible, trackable, and drainable, instead of rotting as prose notes.
