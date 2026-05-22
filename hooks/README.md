# Hook Skeletons

These are hook skeletons for private implementations. They define where automated guardrails can be attached, but they contain no runtime commands.

Use them as design references when adapting this public seed into a private vault.

## Included Hooks

| Hook | Purpose |
|---|---|
| `preflight-scope-guard.md` | Stop work before scope is confirmed. |
| `post-run-knowledge-capture.md` | Remind the workflow to capture reusable lessons after a run. |
| `pre-public-sync.md` | Check that only sanitized framework updates move back toward a public seed. |

## Boundary

Public hooks describe intent, inputs, stop conditions, and output. A private implementation can bind them to local tools, editor hooks, CI, or agent runtime events.
