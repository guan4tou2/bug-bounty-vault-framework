"""Offline bbflow ingestion and read-only projections over the hunt-loop ledger.

No scanners are launched. Imported candidates remain unverified hypotheses.
This single-process adapter does not replace host compaction or existing Vault gates.
"""
import argparse
import hashlib
import io
import json
import os
import shlex
import socket
import subprocess
import time
from pathlib import Path

from hunt_loop import HuntLoop
from command_lifecycle import command_summary, drain_output, group_alive, owner_gone, stop_process, timestamp, unresolved_actions


def import_bbflow(loop, directory):
    root = Path(directory).resolve()
    manifest = json.loads((root / 'run_manifest.json').read_text())
    for key in ('run_id', 'target', 'started_at', 'tool_versions', 'scope_contract', 'scan_level'):
        if key not in manifest:
            raise ValueError(f'missing manifest field: {key}')
    rows = [json.loads(line) for line in (root / 'candidates.jsonl').read_text().splitlines() if line.strip()]
    staged = []
    known = {e['import_key']: e for e in loop.events if e['type'] == 'bbflow_candidate'}
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
    if hyp_id not in {e.get('id') for e in loop.events if e['type'] == 'hypothesis'}:
        raise ValueError('unknown hypothesis')
    latest = {e['lesson_id']: e for e in loop.events if e['type'] == 'lesson'}
    matched = [e for e in latest.values() if set(e['tags']) & set(tags)]
    loop.append('lesson_retrieval', hyp_id=hyp_id, lesson_ids=sorted(e['lesson_id'] for e in matched))
    return matched


def execute_command(loop, ledger, hyp_id, action_id, argv, output, timeout=30, *,
                    cancel_requested=None, scope_ref=None, tool_version=None,
                    command_ref=None, heartbeat_interval=10, _remote=False, _secret_env=None, credential=None):
    """Persist intent before execution. An interrupted action is never auto-retried.

    Caller owns scope authorization; the existing machine-readable program gate
    is also checked here so direct Python and SSH callers cannot skip that gate.
    Cancellation is cooperative through a no-argument callback. A retry requires
    a new action ID; previous evidence and attempts are never overwritten.
    The caller must serialize access to its in-memory loop and ledger.
    """
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) and '\x00' not in a for a in argv):
        raise ValueError('argv must be a nonempty list of strings')
    if not argv[0] or not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout < float('inf'):
        raise ValueError('executable and finite positive timeout are required')
    if (not isinstance(heartbeat_interval, (int, float)) or isinstance(heartbeat_interval, bool)
            or not 0 < heartbeat_interval < float('inf')):
        raise ValueError('heartbeat interval must be finite and positive')
    if credential:
        from credentials import inject
        _secret_env = inject(loop, credential, argv)
    secret_env = _secret_env or {}
    if (not isinstance(secret_env, dict) or any(k != 'VAULT_CREDENTIAL' or not isinstance(v, str) or not v
            or '\x00' in v or len(v.encode()) > 8192 for k, v in secret_env.items())):
        raise ValueError('bounded credential environment injection required')
    if any(value in argument for value in secret_env.values() for argument in argv):
        raise ValueError('credential values cannot appear in argv')
    _remote = _remote or Path(argv[0]).name == 'ssh'
    import program_rules_gate
    # judge() strips shell comments. In an argv API a literal '#' is data, so do
    # not let a header/URL fragment hide subsequent target arguments from it.
    gate_command = shlex.join(argv).replace('#', ' ')
    reason = program_rules_gate.judge(gate_command, program_rules_gate.load_programs(Path(__file__).resolve().parents[1]))
    if reason:
        raise PermissionError(f'program rules gate blocked action: {reason}')
    if any(e.get('action_id') == action_id for e in loop.events):
        raise ValueError('action already recorded; reconcile before a new action')
    if unresolved_actions(loop.events, hyp_id):
        raise ValueError('prior execution or side effects require evidence-backed reconciliation before retry')
    if hyp_id not in loop.capsule()['ready_hypotheses']:
        raise ValueError('hypothesis is not ready')
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('refusing to overwrite evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    if credential:
        loop.append('credential_used', credential_ref=credential['credential_ref'], action_id=action_id,
                    hyp_id=hyp_id, permission=credential['permission'])
    loop.append('action_started', action_id=action_id, hyp_id=hyp_id,
                argv=command_summary(argv), output_ref=str(output),
                status='starting', started_at=timestamp(), owner_pid=os.getpid(),
                owner_host=socket.gethostname(), scope_ref=scope_ref,
                tool_version=tool_version, command_ref=command_ref,
                heartbeat_interval=heartbeat_interval,
                transport='ssh' if _remote else 'local')
    loop.save(ledger)
    process = None
    output_created = False
    status, error, stop_confirmed, returncode = 'failed', None, False, None
    interrupted = None
    try:
        from credential_output import protected_output
        with protected_output(output, secret_env.values()) as stream:
            output_created = True
            if cancel_requested and cancel_requested():
                status, stop_confirmed = 'cancelled', True
            else:
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           start_new_session=os.name == 'posix',
                                           env={**os.environ, **secret_env} if secret_env else None)
                os.set_blocking(process.stdout.fileno(), False)
                loop.append('action_running', action_id=action_id, hyp_id=hyp_id,
                            status='running', pid=process.pid, at=timestamp())
                loop.save(ledger)
                deadline = time.monotonic() + timeout
                last_heartbeat = time.monotonic()
                leader_done_at = None
                while True:
                    eof = drain_output(process, stream)
                    if time.monotonic() - last_heartbeat >= heartbeat_interval:
                        loop.append('action_heartbeat', action_id=action_id, at=timestamp(), pid=process.pid)
                        loop.save(ledger)
                        last_heartbeat = time.monotonic()
                    if cancel_requested and cancel_requested():
                        status = 'cancelled'
                        stop_confirmed = stop_process(process)
                        stop_confirmed = drain_output(process, stream) and stop_confirmed
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status, error = 'timed_out', 'TimeoutExpired'
                        stop_confirmed = stop_process(process)
                        stop_confirmed = drain_output(process, stream) and stop_confirmed
                        break
                    returncode = process.poll()
                    if returncode is not None:
                        leader_done_at = leader_done_at or time.monotonic()
                        if eof and not group_alive(process.pid):
                            status = 'completed' if returncode == 0 else 'failed'
                            stop_confirmed = True
                            break
                        if group_alive(process.pid) or time.monotonic() - leader_done_at >= 0.3:
                            # A successful leader exit is not successful tool
                            # completion while inherited output/owned children remain.
                            status, error = 'failed', 'DescendantsOutlivedTool'
                            stop_confirmed = stop_process(process)
                            stop_confirmed = drain_output(process, stream) and stop_confirmed
                            break
                        time.sleep(min(0.01, remaining))
                        continue
                    try:
                        process.wait(timeout=min(0.1, remaining))
                    except subprocess.TimeoutExpired:
                        continue
    except BaseException as exc:
        error = type(exc).__name__
        status = 'interrupted' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'failed'
        if process is not None:
            stop_confirmed = stop_process(process)
            stop_confirmed = drain_output(process, io.BytesIO()) and stop_confirmed
        else:
            stop_confirmed = True
        if not isinstance(exc, OSError):
            interrupted = exc
    if process is not None:
        returncode = process.returncode
        process.stdout.close()
    exit_ok = status == 'completed'
    # Killing an SSH client is not acknowledgement that its remote job stopped.
    remote_stop = _remote and status != 'completed' and process is not None
    loop.append('action_finished', action_id=action_id, hyp_id=hyp_id,
                exit_ok=exit_ok, error=error, output_ref=str(output),
                status=status, finished_at=timestamp(), returncode=returncode,
                execution_stop_confirmed=stop_confirmed and not remote_stop,
                remote_stop_requires_reconciliation=remote_stop,
                sha256=hashlib.sha256(output.read_bytes()).hexdigest() if output_created and output.is_file() else None)
    # Output is observation only; a separate, explicit oracle must judge it.
    loop.save(ledger)
    if interrupted is not None:
        raise interrupted
    if credential and exit_ok and output.is_file() and output.stat().st_size <= 1024 * 1024:
        try:
            response = json.loads(output.read_text())
        except (ValueError, OSError, UnicodeError):
            response = {}
        if isinstance(response, dict) and response.get('auth_status') in {'unauthenticated', 'invalid', 'expired', 'rate_limited', 'locked'}:
            from credentials import status as credential_status
            state = response['auth_status'] if response['auth_status'] in {'rate_limited', 'locked'} else 'invalid'
            credential_status(loop, credential['credential_ref'], state, reason='adapter reported authentication failure or stop signal')
            loop.save(ledger)
            return False
    return exit_ok


def reconcile_actions(loop, ledger):
    """Close orphaned local-owner intents honestly, without replaying or killing PIDs.

    A lost controller does not prove its child stopped. Unknown/remote/legacy owners
    remain explicitly unresolved. Recovery never fabricates an exit code or evidence hash.
    """
    finished = {e['action_id'] for e in loop.events if e['type'] == 'action_finished'}
    from command_lifecycle import reconciled_actions
    finished |= reconciled_actions(loop.events)
    recovered, unresolved = [], []
    for event in list(loop.events):
        if event['type'] != 'action_started' or event['action_id'] in finished:
            continue
        aid = event['action_id']
        if not owner_gone(event):
            unresolved.append(aid)
            continue
        loop.append('action_finished', action_id=aid, hyp_id=event.get('hyp_id'),
                    status='interrupted', exit_ok=False, error='ControllerLost',
                    finished_at=timestamp(), output_ref=event.get('output_ref'),
                    sha256=None, returncode=None, execution_stop_confirmed=False,
                    remote_stop_requires_reconciliation=event.get('transport') == 'ssh')
        recovered.append(aid)
        finished.add(aid)
    if recovered:
        loop.save(ledger)
    return {'interrupted': recovered, 'requires_reconciliation': unresolved}


def acknowledge_action(loop, ledger, action_id, evidence_ref, effect_status):
    """Record an operator/executor acknowledgement; never infer it from a timeout.

    The caller must inspect the execution end and any writes before producing
    this artifact. Its hash binds that acknowledgement; it is not a verdict.
    """
    if action_id not in unresolved_actions(loop.events):
        raise ValueError('action does not require reconciliation')
    if effect_status not in {'not-executed', 'effects-checked'}:
        raise ValueError('side effects must be explicitly reconciled')
    artifact = Path(evidence_ref).resolve()
    if not artifact.is_file() or not artifact.stat().st_size:
        raise ValueError('reconciliation requires existing nonempty evidence')
    loop.append('action_reconciled', action_id=action_id, execution_stopped=True,
                effect_status=effect_status, at=timestamp(),
                artifact={'path': str(artifact), 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
    loop.save(ledger)


def record_poc_claim(loop, hyp_id, *, poc_kind, result, evidence_ref=None,
                     known_cve=None, existing_poc_search_ref=None,
                     negative_control_ref=None, note=""):
    """Record a PoC claim with the minimum anti-hallucination metadata.

    A PoC event is still an observation; it does not confirm/refute a hypothesis by
    itself. The gate is deliberately mechanical:
      * known CVE work must first cite the search/advisory/PoC lookup that was done;
      * generated/custom PoC success must carry a negative control;
      * failed generated PoC is not a refutation.
    """
    if poc_kind not in {"existing", "generated", "manual"}:
        raise ValueError("poc_kind must be existing, generated or manual")
    if result not in {"success", "failure", "inconclusive"}:
        raise ValueError("result must be success, failure or inconclusive")
    if known_cve and not existing_poc_search_ref:
        raise ValueError("known CVE PoC work requires existing_poc_search_ref")
    if poc_kind == "generated" and result == "success" and not negative_control_ref:
        raise ValueError("generated PoC success requires negative_control_ref")
    loop.append("poc_claim", hyp_id=hyp_id, poc_kind=poc_kind, result=result,
                evidence_ref=evidence_ref, known_cve=known_cve,
                existing_poc_search_ref=existing_poc_search_ref,
                negative_control_ref=negative_control_ref, note=note)


def poc_gate_report(loop):
    """Return PoC hygiene issues. Empty `issues` means the observed PoC events have
    the required provenance; it does not mean the vulnerability is confirmed."""
    issues = []
    for e in loop.events:
        if e.get("type") != "poc_claim":
            continue
        hid = e.get("hyp_id")
        if e.get("known_cve") and not e.get("existing_poc_search_ref"):
            issues.append({"hypothesis": hid, "issue": "known_cve_without_existing_poc_search"})
        if (e.get("poc_kind") == "generated" and e.get("result") == "success"
                and not e.get("negative_control_ref")):
            issues.append({"hypothesis": hid, "issue": "generated_success_without_negative_control"})
        if e.get("poc_kind") == "generated" and e.get("result") == "failure":
            issues.append({"hypothesis": hid, "issue": "generated_failure_is_not_refutation"})
    return {"issues": issues}


import re as _re
_HOST_RE = _re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')


def remote_argv(host, argv):
    """Quote a POSIX remote command: ssh concatenates command arguments with spaces.

    This protects argument boundaries, and does not grant authorization or guarantee
    cancellation of a remote process after the SSH client disconnects.
    """
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise ValueError('host must be a simple hostname/alias (no shell metacharacters)')
    if not isinstance(argv, (list, tuple)) or not argv or not argv[0] or not all(isinstance(a, str) and '\x00' not in a for a in argv):
        raise ValueError('argv must be a nonempty list of strings')
    return ['ssh', '--', host, shlex.join(argv)]


def remote_execute_command(loop, ledger, hyp_id, action_id, host, argv, output, timeout=30, **kwargs):
    """execute_command over ssh to `host`. Reuses all of execute_command's intent-
    persist / no-blind-retry / evidence-hashing safety; only the transport differs.
    Scope/authorization is the caller's responsibility (GET-first VPS policy)."""
    return execute_command(loop, ledger, hyp_id, action_id, remote_argv(host, argv), output, timeout,
                           _remote=True, **kwargs)


def graph_views(loop):
    """Read-only projections over the single ASG ledger; no parallel state files.

    CG/DAG/DT/coverage/dead-path/PoC-gate are all computed views of the same event
    log. Callers should consume these projections instead of maintaining separate
    DAG/CG/DT documents by hand.
    """
    hypotheses = list({e['id']: e for e in loop.events if e['type'] == 'hypothesis'}.values())
    state = loop.capsule()
    terminal = set(state['confirmed']) | set(state['refuted']) | set(state['disputed'])
    terminal.update(e.get('hyp_id') for e in loop.events if e.get('type') == 'dead_end')
    surfaces = {}
    swept = set()
    for e in loop.events:
        if e.get('type') == 'surface':
            surfaces[e['name']] = e.get('untested', True)
        elif e.get('type') == 'surface_swept':
            swept.update(e.get('surfaces', []))

    dead = {}
    for e in loop.events:
        if e.get('type') == 'dead_end':
            dead[e['hyp_id']] = dict(e)
    actionable_ready = [h for h in state['ready_hypotheses'] if h not in dead]

    decisions = [e for e in loop.events
                 if e['type'] in ('verdict', 'logic_verdict', 'kb_consulted',
                                  'lesson_retrieval', 'lesson_influence',
                                  'lesson_effect', 'knowledge_retrieval',
                                  'poc_claim')]
    return {
        'cg': {
            'requires': [{'hypothesis': e['id'], 'capability': c}
                         for e in hypotheses for c in e.get('requires', [])],
            'provides': [{'hypothesis': h, 'capability': c}
                         for h, cs in state['confirmed'].items() for c in cs],
            'capabilities': state['capabilities'],
        },
        'dag': {
            'ready': actionable_ready,
            'blocked': state['blocked_hypotheses'],
            'invalidated': state.get('invalidated_hypotheses', []),
            'disputed': state['disputed'],
            'dead': sorted(dead),
        },
        'dt': {
            'decisions': decisions,
            'next': ('resolve_dispute' if state['disputed'] else
                     'run_ready' if actionable_ready else
                     'map_surface' if state['untested_surface'] else
                     'unblock' if state['blocked_hypotheses'] else
                     loop.run_state().value),
        },
        'coverage': {
            'surface_total': len(surfaces),
            'surface_untested': len(state['untested_surface']),
            'surface_swept_clean': len(swept),
            'hypothesis_total': len(hypotheses),
            'hypothesis_terminal': len([h for h in {e['id'] for e in hypotheses} if h in terminal]),
        },
        'dead_paths': [dead[k] for k in sorted(dead)],
        'poc_gate': poc_gate_report(loop),
    }


def handoff(loop):
    from blocked_research import project as blocked_project
    state = loop.capsule()
    views = graph_views(loop)
    from candidate_analysis import analysis_view
    from scan_import import evidence_valid
    analysis = analysis_view(loop)
    from evidence_review import project as evidence_review
    from flow_model import summary as flow_summary
    artifacts = [a for e in loop.events if e['type'] == 'bbflow_candidate' for a in e['artifacts']]
    scan_artifacts = [a for e in loop.events if e['type'] in {'scan_import', 'scan_candidate', 'scan_observation'}
                      for a in e['artifacts']]
    artifacts += [{'path': e['output_ref'], 'sha256': e['sha256']} for e in loop.events
                  if e['type'] == 'action_finished' and e.get('sha256')]
    finished = {e['action_id'] for e in loop.events if e['type'] == 'action_finished'}
    in_flight = [e for e in loop.events if e['type'] == 'action_started' and e['action_id'] not in finished
                 and e['action_id'] in unresolved_actions(loop.events)]
    stop_unknown = [e for e in loop.events if e['type'] == 'action_finished'
                    and e.get('execution_stop_confirmed') is False
                    and e.get('action_id') in unresolved_actions(loop.events)]
    from asg_command_runs import artifact_status
    problems = [str(a.get('path') or a.get('ref') or 'missing artifact reference')
                for a in artifacts if artifact_status(a.get('path'), a.get('sha256')) != 'valid']
    problems += [a['path'] for a in scan_artifacts if not evidence_valid(a)]
    artifacts += scan_artifacts
    return {'priority': {'run_state': loop.run_state().value,
                         'ready': state['ready_hypotheses'],
                         'actionable_ready': views['dag']['ready'],
                         'in_flight_requires_reconciliation': in_flight,
                         'execution_stop_requires_reconciliation': stop_unknown,
                         'blocked': state['blocked_hypotheses'],
                         'disputed': state['disputed'],
                         'dead': views['dag']['dead'],
                         'poc_gate_issues': views['poc_gate']['issues'],
                         'evidence_problems': sorted(set(problems)),
                         'evidence_revalidation': [r for r in evidence_review(loop.events)
                                                   if r['bound'] and r['requires_revalidation']],
                         'flow_model': flow_summary(loop.events, loop.base_path),
                         'blocked_research': blocked_project(loop.events, loop.base_path),
                         'work_dispatch': __import__('work_dispatch').jobs(loop.events),
                         'reassessments': __import__('reassessment').view(loop),
                         'dependency_impact': __import__('research_dependencies').project(loop),
                         'evidence_gaps': __import__('evidence_gaps').project(loop),
                         'research_metrics': __import__('research_progress').metrics(loop),
                         'credentials': __import__('credentials').project(loop.events, loop.base_path),
                         'research_sources': __import__('research_sources').project(loop),
                         'candidate_analysis': [{k: j.get(k) for k in
                             ('job_id', 'candidate_id', 'status', 'stale', 'evidence_problems', 'failure_class', 'recovery')}
                             for j in analysis]},
            'research_delivery': __import__('research_delivery').project(loop.events),
            'canonical_state': state,
            'asg_views': views,
            'lesson_retrievals': [e for e in loop.events if e['type'] == 'lesson_retrieval'],
            'evidence': artifacts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ledger', type=Path)
    parser.add_argument('--import-bbflow', type=Path)
    parser.add_argument('--reconcile-actions', action='store_true',
                        help='mark lost-controller actions interrupted; never replay or kill unknown processes')
    parser.add_argument('--ack-action', help='record an inspected execution-stop/side-effect acknowledgement')
    parser.add_argument('--stop-evidence', type=Path)
    parser.add_argument('--effect-status', choices=['not-executed', 'effects-checked'])
    args = parser.parse_args()
    from hunt_lock import acquire, release
    token = acquire(args.ledger, 'hunt-integration') if args.import_bbflow or args.reconcile_actions or args.ack_action else None
    try:
        loop = HuntLoop.load(args.ledger)
        if args.import_bbflow:
            import_bbflow(loop, args.import_bbflow)
            loop.save(args.ledger)
        if args.reconcile_actions:
            reconcile_actions(loop, args.ledger)
        if args.ack_action:
            if not args.stop_evidence or not args.effect_status:
                parser.error('--ack-action requires --stop-evidence and --effect-status')
            acknowledge_action(loop, args.ledger, args.ack_action, args.stop_evidence, args.effect_status)
        print(json.dumps(handoff(loop), ensure_ascii=False, indent=2))
    finally:
        if token is not None:
            release(args.ledger, token)


if __name__ == '__main__':
    main()
