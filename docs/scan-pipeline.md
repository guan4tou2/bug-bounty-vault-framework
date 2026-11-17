# Evidence-driven research pipeline

The existing ASG ledger connects hypotheses, tool attempts, saved observations, advisory candidate analysis and independent verification. Product behavior belongs to the flow model; research conclusions belong to ASG. No second orchestrator, database or full external service is installed.

Install the public test dependencies in your own environment with `python3 -m pip install -r requirements-dev.txt`.

- [Native scan import](scan-import.md): Nmap XML observations and Nuclei JSONL candidates, exact XPath/line locators, content hashes, parser versions and actor-specific identity. Import never executes a scanner or creates a verified Finding.
- [Obstruction handling](blocked-research.md): diagnose, establish normal CONTROL, select a bounded alternative, execute through existing gates, validate the result contract, persist evidence and project the next work card.
- [Flow models](flow-model.md): product roles/states/transitions, declarative conditions, separate actual/reproduced traces, optional GraphWalker planning and Attack Flow export.
- [Evaluation](harness-evaluation.md): synthetic offline fixtures and an explicitly invoked, bounded live-model runner. Fixture scores do not establish real vulnerability detection quality.

`hunt_integration.execute_command` retains intent, heartbeat, raw output and terminal status. Cancel/timeout handles the owned local process group; disconnected SSH clients do not prove the remote job stopped. Unknown effects require an explicit acknowledgement with pinned evidence before retry. Command summaries avoid storing argument values in ordinary telemetry.

Evidence integrity and applicability are separate. Bind observations to explicit target version, role, settings, environment and observation time; optional expiry is explicit. Changed, expired or unknown bindings require revalidation. Old records remain readable without inventing missing conditions. New evidence and analysis versions preserve history.

The public seed includes code, schemas, licenses and synthetic tests only. Store raw outputs, model transcripts, browser captures and target-specific ledgers in your private workspace. Do not synchronize operational data back into this repository.

Rollback is opt-in adoption rollback: stop using the new adapters, retain existing readers and raw evidence, and leave historical Finding records intact. The adapters do not provide a universal GUI executor, universal tool-result interpreter, semantic cross-tool deduplication, or remote-stop acknowledgement service.
