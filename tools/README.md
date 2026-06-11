# Tool Integration

This directory contains starter configurations for bug bounty automation tools. These integrate with the vault's session lifecycle — recon output feeds into `RECON_DB.md`, findings feed into the Finding pipeline.

## bbflow

[bbflow](https://github.com/guan4tou2/bbflow) is a pattern-based vulnerability hunter with 47+ hunters. It runs independently of the vault and LLM — results are imported into vault findings.

### Install

```bash
pip install bbflow
# or
pipx install bbflow
```

### Usage with Vault

```bash
# Initialize target (creates workspace/workshop/<target>/SCOPE.md — fill it in)
bbflow init <target>

# Run hunters (on VPS — noisy scanning is VPS-only); scope file is mandatory.
# All hunters is the default; add --only h1,h2 for a subset.
ssh your-vps "bbflow hunt <target> --scope-file workspace/workshop/<target>/SCOPE.md"

# Generate a human report (machine-readable candidates.jsonl is emitted automatically)
bbflow report <target>
```

> Flags match the bbflow tool at time of writing — confirm with `bbflow --help`.

### Vault Integration Points

| bbflow Output | Vault Destination |
|---|---|
| `bbflow report` | `workspace/workshop/<target>/hunters/` |
| Hit results | Review → Finding (if confirmed) |
| Scope data | `workspace/workshop/<target>/SCOPE.md` |

**Rule:** bbflow runs on VPS. Local machine only reads results and writes reports.

---

## Nuclei

[Nuclei](https://github.com/projectdiscovery/nuclei) is a vulnerability scanner with template-based detection.

### Starter Templates

```
tools/nuclei/templates/
├── info-disclosure.yaml      # Common info disclosure checks
├── misconfig-headers.yaml    # Security header misconfigurations
└── oauth-misconfig.yaml      # OAuth flow misconfigurations
```

### Usage with Vault

```bash
# Run on VPS
ssh your-vps "nuclei -t tools/nuclei/templates/ -l targets.txt -o results.json -jsonl"

# Copy results back
scp your-vps:results.json workspace/workshop/<target>/scan_results/nuclei_deep.json
```

### Custom Templates

Add your templates to `tools/nuclei/templates/`. Follow the [Nuclei template guide](https://docs.projectdiscovery.io/templates/introduction).

---

## Osmedeus

[Osmedeus](https://github.com/j3ssie/osmedeus) is a recon automation framework.

### Starter Profiles

```
tools/osmedeus/profiles/
├── light-recon.yaml          # Quick subdomain + port scan
└── full-recon.yaml           # Full recon chain (subdomain + port + tech + vuln)
```

### Usage with Vault

```bash
# Run on VPS
ssh your-vps "osmedeus scan -f tools/osmedeus/profiles/light-recon.yaml -t target.com"

# Results land in osmedeus output dir — copy relevant findings
```

---

## BBOT

[BBOT](https://github.com/blacklanternsecurity/bbot) is a recursive recon tool.

### Starter Presets

```
tools/bbot/presets/
├── subdomain-enum.yml        # Subdomain enumeration
└── web-audit.yml             # Web application audit
```

### Usage with Vault

```bash
# Run on VPS
ssh your-vps "bbot -t target.com -p tools/bbot/presets/subdomain-enum.yml -o workspace/workshop/<target>/scan_results/"
```

---

## General Rules

1. **All automated scanning runs on VPS** — never from local machine
2. **GET-first:** manual exploratory requests are OK locally; automated/write operations go to VPS
3. **Record operations:** log manual requests in `RECON_DB.md ## Operation Log` before executing
4. **Import, don't symlink:** copy tool results into workspace, don't create symlinks back to tool output directories
5. **Review before Finding:** tool output is raw data; confirm each hit before creating a vault Finding
