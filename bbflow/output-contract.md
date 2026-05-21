# Output Contract

Private automation can emit any files it needs, but this framework recommends two stable handoff artifacts.

## `run_manifest.json`

```json
{
  "schema version": 1,
  "run_id": "<run id>",
  "started_at": "<ISO-8601>",
  "scope_file": "<scope file>",
  "safety_level": "<passive | low | active>",
  "tool_profile": "<private tool profile>",
  "output_dir": "<ignored workspace path>",
  "summary": {
    "candidate_count": 0,
    "blocked_count": 0,
    "error_count": 0
  }
}
```

## `candidates.jsonl`

One JSON object per line:

```json
{
  "schema version": 1,
  "candidate_id": "<id>",
  "asset": "<asset placeholder>",
  "category": "<generic category>",
  "evidence_ref": "<ignored workspace path or hash>",
  "review_status": "<new | duplicate_likely | needs_evidence | rejected | promote>",
  "knowledge_capture": "<none | pattern | playbook | checklist | reference>"
}
```

## Contract Rules

- Use placeholders in public examples.
- Store raw output outside the vault.
- Keep candidates review-oriented, not exploit-oriented.
- Promote only reviewed items into vault notes.
