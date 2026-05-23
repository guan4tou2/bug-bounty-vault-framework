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
  "candidate_type": "<info_leak | idor | cors | ssrf | debug_endpoint | known_cve | takeover | unknown>",
  "evidence_hint": "<http_response | screenshot | raw_artifact | needs_repro | needs_manual_validation>",
  "chain_potential": "<none | low | medium | high>",
  "requires_scope_safety": false,
  "suggested_skill": "<bb-scope-safety-check | bb-attack-chain-review | bb-evidence-readiness | bb-attempt-recorder | bb-knowledge-capture>",
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
- Use lifecycle routing fields to help the private vault decide which skill should review the candidate next.
