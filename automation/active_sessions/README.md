# Active Sessions Lock Registry

**Purpose:** Coordination mechanism for parallel sessions (human or LLM). Lock files are the source of truth.

## Schema

Each lock is `<safe_scope>.lock`, containing JSON:

```json
{
  "session_id": "uuid-prefix",
  "owner": "claude",
  "scope": "target/sub-service",
  "target": "target",
  "claimed_at": "2026-01-01T09:00:00Z",
  "last_heartbeat": "2026-01-01T09:15:00Z",
  "expected_release": "2026-01-01T11:00:00Z",
  "host": "machine-name"
}
```

## Scope Hierarchy

| Scope | Meaning |
|-------|---------|
| `_meta` | Non-target work (docs, automation) |
| `target` | Entire target locked |
| `target/sub-service` | Sub-service lock |
| `target/sub-service/vuln-class` | Narrow vuln-class lock |

## Conflict Rules

1. **Exact match** → conflict
2. **New is prefix of existing** (claim parent, child locked) → conflict
3. **Existing is prefix of new** (claim child, parent locked) → conflict
4. **Different branches** → no conflict

## Files

- `*.lock` — active session locks (.gitignored)
- `_expired/*.lock.*` — released/expired locks (.gitignored)
