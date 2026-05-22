# Bug Bounty Workflow Specification

> Full workflow reference. Quick path: [AGENTS_QUICK.md](AGENTS_QUICK.md). Structure: [STRUCTURE.md](STRUCTURE.md).

---

## §0 Session Protocol

### §0a Session Start

```bash
bash automation/check_active_sessions.sh    # list active locks
bash automation/claim.sh <scope>            # acquire scope lock
# or
python3 automation/start_session.py <scope>
```

Scopes: `_meta` (docs/automation), `<target>`, `<target>/<sub-service>`, `<target>/<sub-service>/<vuln-class>`.

### §0b New Target

```bash
bash automation/init_target.sh <target>
```

Then fill: `SCOPE.md` (program boundaries) + `Target - <target>.md` (vault hub page).

### §0c Knowledge Base Lookup

Query the KB at three moments:
1. **Before research** — is there a Pattern for this tech stack?
2. **During hunting** — has this technique been documented?
3. **Before reporting** — check Lessons Learned for triage calibration

### §0d Session End

```bash
python3 automation/end_session.py <scope>
```

### §0g Version + CVE Pre-flight

**Before any software/firmware/SaaS analysis:**

1. Check vendor's latest stable version
2. Search NVD / GHSA / vendor advisories for the target version
3. Check recent disclosed reports on the platform
4. Write results to `RECON_DB.md ## Pre-flight Checks`

**Stop-loss:** If the target runs an old version with known CVEs, document and move on.

---

## §1 Target Structure

Every target gets:
- **Vault:** `01 - Targets/<target>/` with Findings, Submissions, Forms, Attempts, Recon, Services, Attack Chains, Screenshots
- **Workspace:** `workshop/<target>/` with SCOPE.md, RECON_DB.md, HANDOFF.md, FINDINGS_QUICK_REF.md, poc/, scan_results/

**Rule:** Vault stores canonical knowledge. Workspace stores process artifacts.

---

## §3 Finding Pipeline

### §3a Finding Creation

> **Principle: Finding first, auto-create.** Every confirmed vuln gets a Finding immediately. Don't wait, don't batch.

- **Finding** — auto-create on discovery
- **Submission** — propose to user for approval
- **FORM** — user explicitly triggers

### §3b Discovery Log Format

Five columns, mandatory in every Finding:

```
- `YYYY-MM-DD HH:MM` `[source IP → target IP]` `[audit:ref]` action → result
```

### §3e Pipeline Chain

```
Finding → Submission → FORM
```

All three share the same ID. No Submission-only workflow — every Submission must have a parent Finding.

### §3f Dedup Rules

**Same Finding:** Same root cause, same endpoint, same parameter.
**Different Findings:** Same vuln type but different parameters/resources = separate Findings.

Check before creating: `FINDINGS_QUICK_REF.md` + `RECON_DB.md` Known Artifacts.

---

## §5 Anti-Exaggeration

- Theoretical attack chains must not be written as accomplished facts
- "If X then Y" is acceptable; "attacker gains Z" requires PoC
- Severity must match verified evidence, not theoretical maximum

---

## §6 Operation Safety

### §6a GET-first Principle

| HTTP Method | Policy |
|-------------|--------|
| `GET` / `HEAD` / `OPTIONS` | Execute freely |
| `POST` (read-only query) | Confirm no side effects first |
| `POST` (write) / `PUT` / `PATCH` | Confirm consequences; use VPS |
| `DELETE` (not self-created) | **Never execute** |

### §6b Never-Execute List

- `stop` / `destroy` / `shutdown` / `kill` / `restart` operations
- Bulk delete / truncate / drop
- Endpoints that trigger Email / SMS notifications

### §6c VPS Boundary

**VPS only:** bbflow, nuclei, ffuf, sqlmap, osmedeus, bbot, any automated scanning.
**Local OK:** single GET, reading tool output, writing reports.

### §6d Operation Log

Record in `RECON_DB.md ## Operation Log` **before** executing:

| Local Time | UTC Time | Source IP | Method | Target URL | Intent | Result |
|---|---|---|---|---|---|---|

Update `Result` immediately after.

---

## §8 Severity Calibration

| Level | Criteria |
|-------|----------|
| P1 Critical | RCE, full admin takeover, mass data breach |
| P2 High | Significant data access, auth bypass, stored XSS in admin |
| P3 Medium | Limited data access, requires conditions |
| P4 Low | Info disclosure, requires chaining |
| P5 Info | Best practice violation, no direct impact |

**Rules:** Severity must match `verified_evidence` field. `live` supports full claim. `static`/`theoretical` caps at P3.

---

## §9 Triage Response

When vendor responds:
1. Update Submission status
2. Update Kanban
3. Capture lessons
4. If Duplicate: record, don't rationalize. Move on.

---

## Knowledge Capture Gate

| Type | When to Create |
|------|---------------|
| Attack technique (Pattern) | New vuln class or novel method |
| Decision tree (Playbook) | Repeatable multi-step process |
| Attack chain | Multi-vuln chain amplifying impact |
| Stop-loss (Lesson) | Spent >2h on abandoned direction |
| Pitfall (Lesson) | Preventable error |
| Checklist | Reusable verification steps |

---

## Subagent Convention Injection

| Tier | Task Type | Must Inject |
|------|-----------|-------------|
| Recon | Scope, subdomain enum, fingerprint | GET-first, operation log |
| Analysis | Vuln verification, PoC | + dedup, anti-exaggeration, VPS |
| Output | Finding / Submission / FORM | + pipeline, discovery log, severity, no internal IDs |
