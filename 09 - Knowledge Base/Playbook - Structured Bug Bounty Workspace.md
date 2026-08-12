---
type: playbook
title: "Structured Bug Bounty Workspace"
tags: [playbook, workspace, organization, methodology, bb-playbook]
category: recon
status: draft
last_updated: 2026-08-12
sources:
  - https://medium.com/@baler3ion/stop-hunting-blind-build-a-structured-bug-bounty-workflow-620b16887368
---

# Playbook - Structured Bug Bounty Workspace

> **TL;DR**: "Taking notes is an underrated competency in bug bounty." Hunting without structure means repeated work, forgotten leads, and missed chances to chain vulnerabilities. This playbook defines a per-target workspace convention — a folder tree, a set of rolling notes files, a bootstrap script, and a recon pipeline that feeds it — so that every observation, question, and half-formed attack idea has a place to live and can later be turned into a chained, submission-ready finding.

## Scope / When to use

Use this at the start of any new target engagement, before serious testing begins, to set up a consistent workspace. It applies to manual bug bounty hunting in general — it is not tied to any specific target, program, or platform. Re-apply it whenever you pick up a new target so that notes, recon output, and test results stay isolated and comparable across targets.

## Phases

### Phase 1: Workspace directory structure

Create one dedicated, fully isolated folder per target:

```
{target-name}/
├── notes.md            ← main rolling observation log
├── questions.md        ← open questions to answer
├── whitepaper.md       ← attack ideas, payload drafts
├── info/
│   ├── scope.md        ← in-scope / out-of-scope rules
│   └── accounts.md     ← test accounts, tokens, JWTs, sessions
├── recon/
│   ├── subdomains/     ← subfinder/amass/assetfinder output
│   └── urls/           ← waybackurls/gau output
├── analysis/
│   ├── javascript/
│   │   └── notes.md    ← JS analysis: API keys, hidden endpoints, logic
│   └── api-endpoints/
│       └── notes.md    ← endpoint list still to test
├── testing/            ← one file per vulnerability class
│   ├── xss.md
│   ├── idor.md
│   ├── sqli.md
│   └── ...
└── reports/            ← final, submission-ready reports
```

### Phase 2: What each file is for

**`notes.md` — main observation log**

Capture everything you notice while exploring:
- Interesting functionality (how are users identified? how is data stored?)
- Leads on potential vulnerabilities (not yet confirmed)
- Endpoints worth revisiting

```markdown
## 2026-04-11

- /api/v1/user returns full PII including SSN → test for IDOR
- After login, the JWT includes role: "user" → try changing it to "admin"
- /debug path exists but returns 403 → try a method-bypass
```

**`questions.md` — open questions**

Force yourself to "think like a developer":

```markdown
- How does this app identify a user? (JWT? session cookie? API key?)
- How are roles designed? (user / admin / moderator)
- Where is data stored? (DB? S3? Redis?)
- Any history of disclosed vulnerabilities? (search HackerOne disclosed reports)
- Has this feature changed over time? (Wayback Machine)
- Is every step of the payment flow validated?
```

**`whitepaper.md` — attack idea drafts**

Jot down attack vectors you haven't tested yet:

```markdown
## Untested ideas

- The /api/admin/users endpoint referenced in account.js — does it actually require the admin role?
- GraphQL's nodes() resolver — try substituting the Relay ID
- Checkout flow — can you jump straight from step 3 to step 5?
- Password-reset token — is it predictable? does it expire?
```

**`info/scope.md`**

```markdown
# Scope

## In-Scope
- *.example.com
- api.example.com
- Android app (com.example.app)

## Out-of-Scope
- vendor.example.com
- third-party integrations
- Rate limiting / DoS
- Email spoofing

## Bounty Range
- P1: $5,000 - $10,000
- P2: $1,000 - $5,000
- P3: $200 - $1,000
- P4: $50 - $200

## Program URL
https://bugcrowd.com/engagements/example
```

**`info/accounts.md`**

```markdown
# Test Accounts

## Account A (primary test account)
- Email: attacker@bugcrowdninja.com
- Password: TestPass2026!
- Role: user
- customerNo: abc-123
- Bearer: eyJhbGci...
- Refresh: eyJhbGci...

## Account B (for cross-account verification)
- Email: victim@bugcrowdninja.com
- Password: TestPass2026!
- Role: user
- Resource IDs: basket=xyz, address=abc

## Admin Account (if available)
- Email: admin@example.com (test environment)
```

**`testing/idor.md`**

One test log per vulnerability class:

```markdown
# IDOR Testing

## /api/orders/{id}

### Baseline (own ID: 78452)
GET /api/orders/78452
→ 200 + {"orderId": 78452, "email": "attacker@...", ...}

### IDOR probe (sequential: 78453)
GET /api/orders/78453
→ 200 + {"orderId": 78453, "email": "victim@...", ...}  ← IDOR!

### Auth probe (no token)
GET /api/orders/78452
→ 401 Unauthorized

**Status: CONFIRMED IDOR — P2**
**Evidence: responses saved in reports/idor-orders.md**
```

### Phase 3: Bootstrap script (workspace.sh)

A one-command script that scaffolds the whole tree for a new target:

```bash
#!/bin/bash
# workspace.sh — bootstrap a bug bounty workspace in one command
# Usage: bash workspace.sh target-name

TARGET="${1:-new-target}"
BASE="$HOME/bugbounty/targets/$TARGET"

mkdir -p "$BASE"/{info,recon/{subdomains,urls},analysis/{javascript,api-endpoints},testing,reports}

# Seed initial files
cat > "$BASE/notes.md" << EOF
# $TARGET — Notes

## $(date +%Y-%m-%d)

-
EOF

cat > "$BASE/questions.md" << EOF
# $TARGET — Questions

- How does this app identify a user?
- How are roles designed?
- Where is data stored?
- Any history of disclosed vulnerabilities?
- What does the payment flow look like?
-
EOF

cat > "$BASE/whitepaper.md" << EOF
# $TARGET — Attack Ideas

## Untested ideas

-
EOF

cat > "$BASE/info/scope.md" << EOF
# Scope

## In-Scope

## Out-of-Scope

## Bounty Range

## Program URL

EOF

cat > "$BASE/info/accounts.md" << EOF
# Test Accounts

## Account A
- Email:
- Password:
- Role:
- Bearer:

## Account B (for cross-account verification)
- Email:
- Password:
- Resource IDs:
EOF

cat > "$BASE/analysis/javascript/notes.md" << EOF
# JavaScript Analysis

## Endpoints Found

## API Keys / Secrets

## Interesting Logic

EOF

cat > "$BASE/analysis/api-endpoints/notes.md" << EOF
# API Endpoints to Test

## High Priority

## Medium Priority

## Tested (results)

EOF

echo "Workspace created: $BASE"
ls -la "$BASE"
```

**Install:**
```bash
cp workspace.sh ~/bugbounty/automation/
chmod +x ~/bugbounty/automation/workspace.sh
# Usage
bash ~/bugbounty/automation/workspace.sh example-target
```

### Phase 4: Core working philosophy

**1. Think like a developer, not just a tester**

Don't just ask "does this endpoint have a bug" — ask "why did the developer design it this way?":
- What is this endpoint's business logic actually doing?
- Where might the developer have *assumed* the user is honest?
- Which steps can be skipped or reordered?

**2. Bug chaining needs notes**

An endpoint found while testing a Low + a token leaked from a Medium + an IDOR on a third endpoint can add up to a P1. That combination is only visible if all three observations were written down in `notes.md` — the chain then gets assembled in `whitepaper.md`.

**3. Reports are your portfolio**

Every report in `reports/` should be complete enough that "you, three months from now" can still follow it:
- Full reproduction steps
- Screenshots or captured responses
- Tool commands (copy-pasteable and runnable as-is)
- Paths you tried that failed

### Phase 5: Integrated recon flow

Feed the `recon/` folders directly from your recon tooling so notes and raw output stay in the same place:

```bash
TARGET="example.com"
BASE="$HOME/bugbounty/targets/$TARGET"

# Subdomains → recon/subdomains/
subfinder -d $TARGET -all -silent > $BASE/recon/subdomains/subfinder.txt
amass enum -passive -d $TARGET > $BASE/recon/subdomains/amass.txt
cat $BASE/recon/subdomains/*.txt | sort -u > $BASE/recon/subdomains/all.txt

# URLs → recon/urls/
echo $TARGET | waybackurls > $BASE/recon/urls/wayback.txt
gau --subs $TARGET >> $BASE/recon/urls/gau.txt
cat $BASE/recon/urls/*.txt | sort -u > $BASE/recon/urls/all.txt

# Live check
cat $BASE/recon/subdomains/all.txt | httpx -silent -mc 200,403 \
  > $BASE/recon/subdomains/live.txt
```

## Decision Points

- **When does an observation in `notes.md` graduate to `testing/<class>.md`?** Once you have a concrete, reproducible probe to run against it (not just a hunch).
- **When does a `testing/` entry graduate to `reports/`?** Once the vulnerability is confirmed (baseline + probe + evidence), not while it's still a hypothesis.
- **When does a lone finding become a chain?** Whenever `whitepaper.md` shows two or more independently-recorded observations (from `notes.md` or `testing/`) that can be combined for higher impact — see the chaining principle in Phase 4.
- **`analysis/api-endpoints/notes.md` priority buckets exist to force triage** — don't let "Tested" grow without "High Priority" shrinking; if everything sits in one bucket, the workspace isn't doing its job.

## Expected Outputs

- One isolated, consistently-structured folder per target (`{target-name}/`).
- A running observation log (`notes.md`) and open-questions list (`questions.md`) that make it possible to resume work after a break without re-deriving context.
- Per-vulnerability-class testing logs (`testing/*.md`) with baseline/probe/evidence structure, ready to promote into a report.
- Raw recon output (`recon/subdomains/`, `recon/urls/`) kept alongside the notes that reference it.
- Submission-ready reports in `reports/` with full reproduction steps and tool commands.

## Related

- [[Playbook - Wayback URL Mining]] — detailed URL collection and filtering process
- [[Playbook - Recon Methodology]] — full reconnaissance workflow
- [[Pattern - IDOR Response Differential]] — IDOR testing methodology
