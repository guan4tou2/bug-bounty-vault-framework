# Getting Started

A complete walkthrough of one target, from clone to a ready submission. It uses the bundled `_example` target as a reference; substitute your own target name where you see `<target>`.

## 0. Prerequisites

- **Git** and **Python 3.10+** (for the automation scripts and tests).
- **Obsidian** (optional but recommended) — open the repo root as a vault.
- After opening in Obsidian, install the **Templater** and **Dataview** community plugins (Settings → Community plugins). They power the templates and the dashboards. See [post-clone-checklist.md](post-clone-checklist.md).
- An **LLM CLI (Claude Code / Codex / Gemini) is the intended way to operate the vault** — it loads each skill when its trigger fires and enforces the gates. The flow also works by hand in plain Markdown as a fallback.
- **Tool layer:** establish it once with `bb-tool-setup` ([../bbflow/setup.md](../bbflow/setup.md)) — install the standalone bbflow CLI (or a contract-conforming scanner). It is a separate dependency, not bundled.

## 1. Clone and scaffold

```bash
git clone https://github.com/guan4tou2/bug-bounty-vault-framework.git
cd bug-bounty-vault-framework
bash automation/setup_workspace.sh          # creates the .gitignored workspace/ scratch area
```

## 2. Start a target

```bash
bash automation/init_target.sh <target>
```

This creates:

- **Vault side** — `01 - Targets/<target>/` with `Findings/`, `Submissions/`, `Recon/`, `Attempts/`, `Services/`, `Attack Chains/`, `Credentials/`, `Screenshots/`, and a `Target - <target>.md` hub note.
- **Workspace side** (gitignored) — `workspace/workshop/<target>/` with `SCOPE.md`, `RECON_DB.md`, `HANDOFF.md`, `FINDINGS_QUICK_REF.md`.

Fill in `SCOPE.md` first: program URL, in-scope and out-of-scope assets, and testing rules. **Everything downstream depends on scope being correct.**

## 3. Claim the session (optional, for parallel work)

```bash
python3 automation/start_session.py <target>
```

This prints a brief from `HANDOFF.md` / `RECON_DB.md` and claims a scope lock so a second session (human or LLM) does not collide with you.

## 4. Recon

Follow the [[Playbook - Recon]] note: subdomain enumeration → live hosts → content discovery → JS analysis → tech fingerprinting. Record everything reusable in `workspace/workshop/<target>/RECON_DB.md`:

- Credentials and tokens
- Discovered paths and endpoints (with the Attack Surface table)
- Tech stack and infrastructure

> **Safety:** run aggressive scans on an isolated runner/VPS, keep to GET-first, and log manual write requests in the Operation Log before sending them. See [[Reference Card - Testing Safety Rules]].

## 4b. Map the surface, then test (the front gate)

Before you trust any scanner output, **map the attack surface vuln-agnostically** (`bb-surface-mapping`): one row per endpoint/parameter/role/trust-boundary/etc. in the `RECON_DB.md` Attack Surface Map, each with a "how could this break?" hypothesis. Jumping straight to a scanner is the streetlight effect — you only find the vuln classes your patterns already know.

Then test with full coverage (`bb-web-vuln-scan`): OWASP Top 10, the injection matrix per parameter, version→CVE, WAF bypass. A scanner/bbflow hit is a **lead**, not a Finding — it still gets cross-checked against the map. See [architecture-closed-loop.md](architecture-closed-loop.md).

## 5. From candidate to Finding

When something looks exploitable, run the candidate lifecycle gates (AGENTS.md §3e.1). The short version:

1. **Dedup** — is this already a Finding? (`bash automation/vault_precheck.sh <target> "<keyword>" "<host>"`)
2. **Scope + safety** — is the next step in scope and safe?
3. **Exploit chain** — run the 6-question chain (`bb-exploit-chain`); escalate the finding before moving to the next system.
4. **Chain review** — can this primitive chain into higher impact?
5. **Evidence readiness** — is it reproducible with request + response captured?

If it clears the gates, create a Finding from the template:

- In Obsidian: `01 - Targets/<target>/Findings/` → new note → Templater → **Template - Finding**.
- The frontmatter is schema-validated (`severity` P1-P5, `verification_level` A-D, `verified_evidence`, `status`, `discovered_date`/`discovered_time`). See [[Finding - _example - ACME-001]] for a filled-in example.

Keep the **verified vs potential** boundary explicit — prove impact, never assert it.

## 6. Finding → Submission → FORM

Every confirmed vuln follows the same chain, all sharing one `finding_id`:

```
Finding → Submission → FORM
```

- **Submission** — a platform-neutral report draft (see [[Submission - _example - ACME-001]]).
- **FORM** — the platform-specific output, generated at submission time.

Before writing the Submission, run the [[Checklist - Pre-Submission Validation]] note: dedup, scope, evidence completeness, anti-exaggeration, severity sanity, no internal IDs in the report body.

## 7. After triage

When the vendor/platform replies, sync the result everywhere (Submission frontmatter, Kanban, Target hub, Dashboard, Lessons Learned) so state does not drift. The `bb-triage-response` skill enforces this if you use an LLM CLI; otherwise do it by hand.

## 8. Capture what you learned

Promote anything reusable to `09 - Knowledge Base/`:

- A repeatable technique → a new `Pattern - *.md`
- A decision/pitfall/stop-condition → an entry in `Lessons Learned.md`
- A multi-step workflow → a `Playbook - *.md`

## 9. End the session

```bash
python3 automation/end_session.py <target>     # runs the closeout checklist + releases the lock
```

Update `HANDOFF.md` with the next concrete action so the next session starts informed.

## Where things live

| You want… | Look at |
|-----------|---------|
| The full ruleset | [AGENTS.md](../AGENTS.md) |
| Directory tree, naming, frontmatter schema | [STRUCTURE.md](../STRUCTURE.md) |
| Token-light quick reference | [AGENTS_QUICK.md](../AGENTS_QUICK.md) |
| Dashboards | `00 - Dashboard/Dashboard.md` |
| Reusable knowledge | `09 - Knowledge Base/` |
| Session protocol | [session-lifecycle.md](session-lifecycle.md) |
