# hunters/ — detections crystallized from experience

> The **drain destination** of [[Backlog - Experience to Tool]]. Rule-detectable patterns, once
> crystallized, land here as **portable, runnable** artifacts — the body of your living scanner.
> No infra coupling: local `nuclei` / a script is enough.

## Structure

```
hunters/
├── nuclei/          # web pattern → nuclei v3 template (.yaml)
│   └── <slug>.yaml
├── re/              # firmware/binary/mobile static detection → script (.sh/.py) + notes
│   └── <slug>.<ext>
└── README.md
```

## Naming convention

- slug = kebab-case, tied to the source pattern, e.g. `apereo-cas-execution-stacktrace`.
- Each artifact's `metadata.source-pattern` (nuclei) or header comment (script) points back to the
  `09 - Knowledge Base/Pattern - …` it was crystallized from, so it stays traceable.

## Lifecycle gate (before promoting into the auto-run set)

A template flows `draft → validate → null-case → canary → FP-review → promoted`. Only `promoted`
templates join the default auto-run set — never auto-run an un-canaried template against real targets.

1. **Sanitize:** no target-specific host / token / customer name.
2. **Validate + null-case:** `nuclei -validate -t nuclei/<slug>.yaml` passes AND a run against
   `example.com` yields no hit. (`build-hunters` automates up to here — output is a DRAFT.)
3. **Canary + FP-review:** run on one authorized target, low rate-limit, review for false positives — manual.
4. **Dedup:** one artifact per root-cause pattern; don't duplicate a template nuclei already ships.
5. **Split rule:** only rule-detectable patterns belong here; judgment-needed ones stay in KB/DT.

## Running

```bash
# a single template
nuclei -t "05 - Tools/hunters/nuclei/<slug>.yaml" -u https://target

# the whole set (your scanner)
nuclei -t "05 - Tools/hunters/nuclei/" -l hosts.txt
```

> Each hunting round → a few more backlog rows → drained here → your scanner's coverage becomes your
> accumulated hunting experience.
