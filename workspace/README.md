# workspace/ — Local Working Directory

This directory is **`.gitignored`** and exists only on your local machine. It holds all operational data that should never be committed: scan results, raw recon output, PoC files, logs, and per-target working notes.

## Directory Layout

```
workspace/
  workshop/
    <target>/              # One directory per target
      SCOPE.md             # Program scope, rules, URLs, domains
      RECON_DB.md          # Recon findings, tech stack, endpoints, operation log
      HANDOFF.md           # Context for resuming work in a new session
      FINDINGS_QUICK_REF.md  # One-line summary of every finding (dedup gate)
      poc/                 # Proof-of-concept scripts and payloads
      scan_results/        # Nuclei, bbot, osmedeus output
      screenshots/         # Evidence screenshots
    _all/
      targets/             # Cross-target index files
  reports/
    hitcon/                # HITCON ZeroDay submissions
    h1/                    # HackerOne submissions
    bugcrowd/              # Bugcrowd submissions
    intigriti/             # Intigriti submissions
    twcert/                # TWCERT submissions
  firmware_analysis/
    <vendor>/              # Firmware binaries, extracted filesystems, analysis notes
  logs/                    # Session logs, audit logs
  tmp/                     # Scratch space, auto-cleaned
```

## Setup

Run the scaffold script to create all directories:

```bash
bash automation/setup_workspace.sh
```

This creates the full directory tree and a `.workspace_root` marker file in the repo root.

## Key Rules

- **Never commit workspace/ contents.** It is in `.gitignore`.
- **FINDINGS_QUICK_REF.md** must be read before creating any new Finding to prevent duplicate work.
- **RECON_DB.md** is the single source of truth for recon data per target.
- **HANDOFF.md** is written at session end so the next session can resume without re-reading everything.
- **poc/** scripts must not contain hardcoded credentials or target-specific secrets.
