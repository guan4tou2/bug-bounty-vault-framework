"""Offline bbflow ingestion and read-only projections over the hunt-loop ledger.

No scanners are launched. Imported candidates remain unverified hypotheses.
This single-process adapter does not replace host compaction or existing Vault gates.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from hunt_loop import HuntLoop


def import_bbflow(loop, directory):
    root = Path(directory).resolve()
    manifest = json.loads((root / 'run_manifest.json').read_text())
    for key in ('run_id', 'target', 'started_at', 'tool_versions', 'scope_contract', 'scan_level'):
        if key not in manifest:
            raise ValueError(f'missing manifest field: {key}')
    rows = [json.loads(line) for line in (root / 'candidates.jsonl').read_text().splitlines() if line.strip()]
    staged = []
    known = {e['import_key']: e for e in loop.events if e['kind'] == 'bbflow_candidate'}
    for row in rows:
        # bbflow output-contract core (bbflow/output-contract.md). Candidates are
        # review-oriented LEADS, never findings; the rest of the contract fields
        # (category/candidate_type/chain_potential/suggested_skill/review_status/
        # knowledge_capture) ride along in `row` for routing.
        for key in ('candidate_id', 'asset', 'candidate_type'):
            if key not in row:
                raise ValueError(f'missing candidate field: {key}')
        identity = json.dumps([manifest['target'], manifest['run_id'], row['candidate_id']])
        digest = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
        if identity in known:
            if known[identity]['digest'] != digest:
                raise ValueError('same candidate identity has different content')
            continue
        # evidence_ref (contract: single; may be a workspace path OR a hash — raw
        # output is stored outside the vault). Hash it when it resolves to a real
        # file inside the run dir; otherwise keep the reference pointer verbatim.
        refs = []
        ev = row.get('evidence_ref')
        if ev:
            if '..' in Path(str(ev)).parts:
                raise ValueError('evidence_ref must not use path traversal')
            artifact = (root / ev).resolve()
            if artifact.is_relative_to(root) and artifact.is_file():
                refs.append({'path': str(artifact), 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
            else:
                refs.append({'ref': str(ev)})
        event = dict(import_key=identity, digest=digest, candidate=row,
                     manifest=manifest, artifacts=refs)
        staged.append(event)
        known[identity] = event
    # Validate the complete batch before mutating canonical state.
    for event in staged:
        hid = 'bbflow:' + hashlib.sha256(event['import_key'].encode()).hexdigest()[:24]
        loop.append('bbflow_candidate', hyp_id=hid, **event)
        loop.add_hypothesis(hid)
        loop.add_surface(str(event['candidate']['asset']))
    return len(staged)


def record_lesson(loop, lesson_id, tags, rule, evidence_ref, *, trigger=None,
                  hypotheses=None, discriminator=None, rationale=None,
                  transferable_scope=None, reopen_when=None, source=None):
    """Record a reusable LESSON. `rule`+`tags`+`evidence` are the minimum; the
    optional fields are the DECISION-RECORD contract (Reflexion-shaped) that lets a
    later agent act on it, not just read it:
      trigger        — what situation/architecture should make you retrieve this
      hypotheses     — the competing explanations that were in play
      discriminator  — the test that told them apart
      rationale      — why that test was chosen first / what would flip the plan
      transferable_scope — where it applies, and where it does NOT
      reopen_when    — when a previously-dead path is worth re-trying
      source         — link back to the originating execution/evidence
    Stored as an auditable decision SUMMARY, not verbatim model reasoning."""
    evidence = Path(evidence_ref).resolve()
    if not evidence.is_file() or not rule.strip() or not tags:
        raise ValueError('lesson requires a rule, applicability tags and existing evidence')
    loop.append('lesson', lesson_id=lesson_id, tags=sorted(set(tags)), rule=rule,
                evidence_ref=str(evidence), sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
                trigger=trigger, hypotheses=hypotheses or [], discriminator=discriminator,
                rationale=rationale, transferable_scope=transferable_scope,
                reopen_when=reopen_when, source=source)


def retrieve_lessons(loop, hyp_id, tags):
    if hyp_id not in {e.get('hyp_id') for e in loop.events if e['kind'] == 'hypothesis'}:
        raise ValueError('unknown hypothesis')
    latest = {e['lesson_id']: e for e in loop.events if e['kind'] == 'lesson'}
    matched = [e for e in latest.values() if set(e['tags']) & set(tags)]
    loop.append('lesson_retrieval', hyp_id=hyp_id, lesson_ids=sorted(e['lesson_id'] for e in matched))
    return matched


def execute_command(loop, ledger, hyp_id, action_id, argv, output, timeout=30):
    """Persist intent before execution. An interrupted action is never auto-retried.

    Caller owns scope authorization. This adapter accepts an argv list, never a
    shell string; it does not authorize live scanning or bypass Vault gates.
    """
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError('argv must be a nonempty list of strings')
    if any(e.get('action_id') == action_id for e in loop.events):
        raise ValueError('action already recorded; reconcile before a new action')
    if hyp_id not in loop.capsule()['ready_hypotheses']:
        raise ValueError('hypothesis is not ready')
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('refusing to overwrite evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    loop.append('action_started', action_id=action_id, hyp_id=hyp_id,
                argv=argv, output_ref=str(output))
    loop.save(ledger)
    try:
        with output.open('xb') as stream:
            result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
        exit_ok, error = result.returncode == 0, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        exit_ok, error = False, type(exc).__name__
    loop.append('action_finished', action_id=action_id, hyp_id=hyp_id,
                exit_ok=exit_ok, error=error, output_ref=str(output),
                sha256=hashlib.sha256(output.read_bytes()).hexdigest() if output.is_file() else None)
    # Output is observation only; a separate, explicit oracle must judge it.
    loop.save(ledger)
    return exit_ok


import re as _re
_HOST_RE = _re.compile(r'^[A-Za-z0-9._-]+$')


def remote_argv(host, argv):
    """Build a safe argv to run `argv` on `host` over ssh (no shell string; the
    remote command is passed as separate args after `--`). vault-97 gap #3:
    real hunts run via VPS (e.g. host 'vps-host'), not local subprocess."""
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise ValueError('host must be a simple hostname/alias (no shell metacharacters)')
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError('argv must be a nonempty list of strings')
    return ['ssh', host, '--', *argv]


def remote_execute_command(loop, ledger, hyp_id, action_id, host, argv, output, timeout=30):
    """execute_command over ssh to `host`. Reuses all of execute_command's intent-
    persist / no-blind-retry / evidence-hashing safety; only the transport differs.
    Scope/authorization is the caller's responsibility (GET-first VPS policy)."""
    return execute_command(loop, ledger, hyp_id, action_id, remote_argv(host, argv), output, timeout)


def graph_views(loop):
    """Read-only capability graph and decision records; no parallel state files.

    This is not a complete ASG or a hard-precedence Work DAG scheduler.
    """
    hypotheses = [e for e in loop.events if e['kind'] == 'hypothesis']
    state = loop.capsule()
    return {'cg': {'requires': [{'hypothesis': e['hyp_id'], 'capability': c}
                               for e in hypotheses for c in e['requires']],
                   'provides': [{'hypothesis': h, 'capability': c}
                                for h, cs in state['confirmed'].items() for c in cs]},
            'decisions': [e for e in loop.events if e['kind'] == 'verdict']}


def handoff(loop):
    state = loop.capsule()
    artifacts = [a for e in loop.events if e['kind'] == 'bbflow_candidate' for a in e['artifacts']]
    artifacts += [{'path': e['output_ref'], 'sha256': e['sha256']} for e in loop.events
                  if e['kind'] == 'action_finished' and e.get('sha256')]
    finished = {e['action_id'] for e in loop.events if e['kind'] == 'action_finished'}
    in_flight = [e for e in loop.events if e['kind'] == 'action_started' and e['action_id'] not in finished]
    problems = [a['path'] for a in artifacts if not Path(a['path']).is_file()
                or hashlib.sha256(Path(a['path']).read_bytes()).hexdigest() != a['sha256']]
    return {'priority': {'run_state': loop.run_state().value,
                         'ready': state['ready_hypotheses'],
                         'in_flight_requires_reconciliation': in_flight,
                         'blocked': state['blocked_hypotheses'],
                         'disputed': state['disputed'], 'evidence_problems': problems},
            'canonical_state': state,
            'lesson_retrievals': [e for e in loop.events if e['kind'] == 'lesson_retrieval'],
            'evidence': artifacts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ledger', type=Path)
    parser.add_argument('--import-bbflow', type=Path)
    args = parser.parse_args()
    loop = HuntLoop.load(args.ledger)
    if args.import_bbflow:
        import_bbflow(loop, args.import_bbflow)
        loop.save(args.ledger)
    print(json.dumps(handoff(loop), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
