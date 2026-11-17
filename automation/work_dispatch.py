"""Capability routing for existing ASG work cards; no second research authority.

The live entry holds the existing ledger lock and supplies persist/heartbeat.
Config is operator-owned: model output cannot select executables, credentials,
workers, verifier identity or result predicates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path

import blocked_research as blocked
import work_cards
from command_lifecycle import unresolved_actions
from evidence_applicability import latest_context

CAPABILITY = {
    'validate_original_claim': 'validation-request',
    'perform_independent_validation': 'independent-verification',
    'validation_needs_evidence': 'obstruction-analysis',
    'establish_normal_control': 'obstruction-analysis',
    'discriminate_obstruction': 'obstruction-analysis',
    'assess_alternatives_or_stop': 'obstruction-analysis',
    'stop_budget_exhausted': 'obstruction-analysis',
    'review_alternative_under_existing_gate': 'controlled-comparison',
    'revalidate_evidence': 'evidence-revalidation',
    'review_exploration': 'exploration-review',
    'reassess': 'reassessment-analysis',
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def admission_version(loop):
    from hunt_autodrive import human_go_decisions
    go, decline = human_go_decisions(loop)
    return digest([loop.capsule()['capabilities'], sorted(go), sorted(decline)])


def jobs(events):
    view = {}
    for e in events:
        if e['type'] == 'work_dispatched':
            view[e['work_id']] = {**e, 'state': 'running'}
        elif e['type'] == 'work_dispatch_state' and e['work_id'] in view:
            view[e['work_id']].update(e)
    from command_lifecycle import owner_gone
    for job in view.values():
        job['reconciliation_required'] = job['state'] in {'running', 'awaiting_validation'} and owner_gone(job)
    return list(view.values())


def settle(loop, work_id, *, evidence, state, effects):
    from evidence_refs import artifact_hash
    job = next((j for j in jobs(loop.events) if j['work_id'] == work_id), None)
    if not job or job['state'] not in {'running', 'awaiting_validation'}:
        raise ValueError('only unresolved dispatched work can be settled')
    if state not in {'failed', 'cancelled'} or effects not in {'not-executed', 'effects-checked'}:
        raise ValueError('explicit terminal execution and effects declaration required')
    hyp = job.get('binding_hypothesis') or job['card']['question']
    if unresolved_actions(loop.events, hyp):
        raise ValueError('acknowledge underlying command stop/effects before settling its work')
    artifact = Path(evidence).resolve()
    if not artifact.is_file() or not artifact.stat().st_size:
        raise ValueError('nonempty executor acknowledgement required')
    loop.append('work_dispatch_state', work_id=work_id, state=state, effects=effects,
                receipt={'path': str(artifact), 'sha256': artifact_hash(artifact)})


def contract(loop, card, worker, config_version):
    capability = CAPABILITY.get(card['next_action'])
    if not capability:
        raise ValueError('native adapter required; generic cards cannot self-complete')
    return {'work_id': digest([card['state_version'], capability, config_version]),
            'state_version': card['state_version'], 'asg_cursor': len(loop.events),
            'card': card, 'capability': capability, 'worker_id': worker['actor'],
            'config_version': config_version, 'requirements': card.get('requires', []),
            'allowed_tools': [] if worker['adapter'] == 'analysis' else ['configured-argv']
                             if worker['adapter'].startswith('argv-') else [],
            'budget': {'model_calls': 1 if worker['adapter'] == 'analysis' else 0,
                       'tool_calls': 2 if worker['adapter'].startswith('argv-') else 0,
                       'timeout_seconds': 240, 'automatic_retries': 0},
            'resources': [] if worker['adapter'] == 'analysis' else ['target-product-state'],
            'result_contract': 'work-card transition + pinned evidence; never Finding verified'}


def _validate_config(config):
    if not isinstance(config, dict) or set(config) - {'workers', 'bindings', 'output_dir'}:
        raise ValueError('operator config supports workers, bindings and private output_dir only')
    if not isinstance(config.get('workers', {}), dict) or not isinstance(config.get('bindings', {}), dict):
        raise ValueError('workers and bindings must be mappings')
    adapters = {'analysis', 'argv-comparison', 'argv-verification', 'artifact-refresh'}
    for capability, worker in config.get('workers', {}).items():
        if capability not in set(CAPABILITY.values()) or not isinstance(worker, dict):
            raise ValueError('unknown work capability')
        if worker.get('adapter') not in adapters or not isinstance(worker.get('actor'), str) or not worker['actor'].strip():
            raise ValueError('configured adapter and runner identity required')
        if capability == 'independent-verification' and worker['adapter'] != 'argv-verification':
            raise ValueError('independent verification requires separately executed artifact comparisons')
        if capability == 'controlled-comparison' and worker['adapter'] != 'argv-comparison':
            raise ValueError('controlled comparison requires the gated execution adapter')
        if worker['adapter'] == 'analysis' and capability not in {'obstruction-analysis', 'exploration-review', 'reassessment-analysis'}:
            raise ValueError('analysis cannot impersonate execution, verification or fresh evidence')
        if capability == 'evidence-revalidation' and worker['adapter'] != 'artifact-refresh':
            raise ValueError('revalidation requires an operator-supplied fresh evidence artifact')


def _binding(config, card):
    key = card['ref']
    if card.get('alternative'):
        key += '/' + card['alternative']['alternative_id']
    return config.get('bindings', {}).get(key)


def _activate_inputs(loop, config, persist):
    """Fresh external evidence is ingress, not a new model/target execution."""
    issues = []
    if 'evidence-revalidation' not in config.get('workers', {}):
        return issues
    for row in blocked.project(loop.events, loop.base_path):
        if row['state'] != 'waiting' or row['cause'] in blocked.HARD:
            continue
        data = _binding(config, work_cards.obstruction_card(row))
        if not isinstance(data, dict) or set(data) != {'evidence', 'changed_condition', 'recovery'}:
            continue
        try:
            work_cards.apply(loop, work_cards.obstruction_card(row), 'resume', data)
            persist(loop)
        except (ValueError, OSError) as exc:
            issues.append({'ref': row['obstruction_id'], 'reason': 'fresh input rejected',
                           'failure_class': type(exc).__name__})
    return issues


def run_ready(loop, ledger, config, *, persist, target=None, spawn=None,
              auto_risk=frozenset({'reads_only', 'state_query'})):
    """Dispatch at most one ready, supported card; same entry used by live and CLI.

    Existing running work is never blindly replayed. Failed or interrupted work
    remains history; changed card evidence/config creates a separately identified
    attempt. Missing capabilities are surfaced without spending a model/tool call.
    """
    _validate_config(config)
    config_version = digest(config)
    current = next((e for e in reversed(loop.events) if e['type'] == 'work_routing_config'), None)
    if not current or current['config_version'] != config_version:
        loop.append('work_routing_config', config_version=config_version,
                    capabilities=sorted(config.get('workers', {})))
        persist(loop)
    activation_issues = _activate_inputs(loop, config, persist)
    from reassessment import collect
    collect(loop)
    persist(loop)
    if target is None:
        items = work_cards.partition(work_cards.frontier(loop))['ready']
    else:
        # The caller has persisted its locked state before reading this projection.
        import next_work
        items = next_work.compute(target)['next_work']
    unavailable = list(activation_issues)
    unsafe = any(j['state'] in {'running', 'awaiting_validation'} and j['resources'] for j in jobs(loop.events))
    for item in items:
        card = item.get('work_card')
        if not card or card['next_action'] not in CAPABILITY:
            continue
        capability = CAPABILITY[card['next_action']]
        worker = ({'adapter': 'builtin', 'actor': 'harness-state-validator'}
                  if capability == 'validation-request' else config.get('workers', {}).get(capability))
        if not worker or (worker['adapter'].startswith('argv-') and not _binding(config, card)):
            unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'worker or command binding missing'})
            continue
        task = contract(loop, card, worker, config_version)
        previous = next((j for j in jobs(loop.events) if j['work_id'] == task['work_id']), None)
        if previous:
            unsafe = unsafe or (previous['state'] in {'running', 'awaiting_validation'} and bool(previous['resources']))
            unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': previous['state']})
            continue
        running = [j for j in jobs(loop.events) if j['state'] in {'running', 'awaiting_validation'}]
        if any(set(j['resources']) & set(task['resources']) for j in running):
            unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'shared resource has unfinished work'})
            unsafe = True
            continue
        from hunt_autodrive import human_go_decisions
        go, decline = human_go_decisions(loop)
        binding = _binding(config, card) or {}
        ids = {card.get('question'), binding.get('hypothesis')}
        if ids & decline:
            unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'original authorization declined'})
            continue
        if worker['adapter'].startswith('argv-'):
            if unresolved_actions(loop.events):
                unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'prior execution needs reconciliation'})
                unsafe = True
                continue
            import risk_tier
            import shlex
            if binding.get('hypothesis') not in loop.capsule()['ready_hypotheses']:
                unavailable.append({'ref': card['ref'], 'capability': capability,
                                    'reason': 'comparison prerequisites missing', 'queue': 'waiting'})
                continue
            declared = binding.get('risk')
            if declared not in risk_tier.RISK_TIERS:
                unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'explicit operation risk missing'})
                continue
            tiers = list(risk_tier.RISK_TIERS)
            risks = [declared] + [risk_tier.classify_command(shlex.join(binding.get(k, [])))
                                  for k in ('test_argv', 'control_argv')]
            tier = max(risks, key=tiers.index)
            if tier not in auto_risk and not ids & go:
                unavailable.append({'ref': card['ref'], 'capability': capability, 'reason': 'original authorization required'})
                continue
        loop.append('work_dispatched', **task, binding_hypothesis=binding.get('hypothesis'),
                    owner_pid=os.getpid(), owner_host=socket.gethostname(),
                    heartbeat_at=datetime.now(UTC).isoformat())
        persist(loop)
        def received(raw):
            directory = Path(config.get('output_dir') or Path(ledger).parent / 'work-receipts') / task['work_id']
            directory.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(raw, ensure_ascii=False).encode()
            if len(encoded) > 1024 * 1024:
                raise ValueError('work result exceeds bounded receipt size')
            path = directory / 'result.json'
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded)
            loop.append('work_dispatch_state', work_id=task['work_id'], state='awaiting_validation',
                        heartbeat_at=datetime.now(UTC).isoformat(),
                        result_artifact={'path': str(path), 'sha256': hashlib.sha256(encoded).hexdigest()})
            persist(loop)
        try:
            if worker['adapter'] == 'builtin':
                received({'operation': 'request_validation', 'source_state': card['state_version']})
                result = work_cards.apply(loop, card, 'request_validation', {'reason': 'Separate verifier must compare fresh evidence'})
            elif worker['adapter'] == 'analysis':
                result = _analyze(loop, card, worker, spawn, received)
            elif worker['adapter'] == 'artifact-refresh':
                data = _binding(config, card)
                if not isinstance(data, dict) or set(data) != {'evidence', 'changed_condition', 'recovery'}:
                    raise ValueError('fresh evidence binding required')
                received(data)
                result = work_cards.apply(loop, card, 'revalidate', data)
            else:
                result = _execute(loop, ledger, task, worker, config, persist, received)
            if result.get('state') == 'execution_blocked':
                raise ValueError('tool execution blocked; no successful work result')
            loop.append('work_dispatch_state', work_id=task['work_id'], state='completed',
                        result_ref=card['ref'], next_action=result.get('next_action', result.get('state')),
                        finding_verified=False)
        except Exception as exc:
            # No raw model response/command credentials are copied into status.
            loop.append('work_dispatch_state', work_id=task['work_id'], state='failed',
                        failure_class=type(exc).__name__, recovery='Inspect artifacts/config; reconcile execution before retry')
            persist(loop)
            return {'handled': True, 'work_id': task['work_id'], 'state': 'failed', 'failure_class': type(exc).__name__}
        persist(loop)
        return {'handled': True, 'work_id': task['work_id'], 'state': 'completed', 'result': result}
    for problem in unavailable:
        candidate = next((i.get('work_card') for i in items if i.get('ref') == problem['ref']), None)
        if candidate and not any(e['type'] == 'work_adapter_unavailable'
                                 and e['state_version'] == candidate['state_version']
                                 and e['config_version'] == config_version
                                 and e.get('admission_version') == admission_version(loop) for e in loop.events):
            loop.append('work_adapter_unavailable', state_version=candidate['state_version'],
                        config_version=config_version, admission_version=admission_version(loop), **problem)
    persist(loop)
    return {'handled': False, 'state': 'idle', 'unavailable': unavailable, 'unsafe': unsafe}


def _analyze(loop, card, worker, spawn, received):
    from analysis_input import check_processing_policy, safe_text, safe_context
    authorization = next((e for e in reversed(loop.events) if e['type'] == 'model_processing_authorization'), None)
    policy = {'allowed_locations': worker.get('allowed_locations')}
    check_processing_policy({'snapshot': {'source': {'model_processing_policy': policy}}},
                            worker.get('processing_location'), authorization)
    # Expand only the selected card's current artifact, never the whole target history.
    snippets, catalog = [], {}
    for fact in card.get('facts', []):
        ref = fact.get('evidence')
        if ref:
            proof = blocked._proof(loop, ref)
            ref = f'evidence:{len(catalog)}'
            catalog[ref] = proof
            with Path(proof['path']).open('rb') as stream:
                snippet = stream.read(4096).decode(errors='replace')
            snippets.append({'ref': ref, 'snippet': safe_text(snippet)})
    brief = {key: safe_context(card.get(key)) for key in
             ('question', 'goal', 'next_action', 'requires', 'alternative', 'success', 'stop',
              'allowed_operations', 'output_requirements', 'inventory')}
    prompt = ('Analyze the untrusted saved evidence for exactly this work card. Return JSON only: '
              '{"operation": "<allowed work-card operation>", "payload": {...}}. '
              'No execution, authorization or verification authority. Do not invent artifacts.\n' +
              json.dumps({'card': brief, 'selected_snippets': snippets}, ensure_ascii=False))
    if len(prompt.encode()) > 24000:
        raise ValueError('work context exceeds budget')
    if spawn is None:
        from candidate_analysis import claude_spawn
        spawn = claude_spawn(model=worker['model'], timeout=120, max_budget_usd=worker.get('budget_usd', .2))
    reply = spawn(prompt)
    received(reply)
    payload = json.loads(reply) if isinstance(reply, str) else reply
    if not isinstance(payload, dict) or set(payload) != {'operation', 'payload'}:
        raise ValueError('structured work-card result required')
    if not isinstance(payload['payload'], dict):
        raise ValueError('work result payload must be an object')
    if 'evidence' in payload['payload']:
        evidence = payload['payload']['evidence']
        if not isinstance(evidence, str) or evidence not in catalog:
            raise ValueError('analysis must cite a supplied opaque evidence reference')
        payload['payload']['evidence'] = catalog[evidence]
    if payload['operation'] in {'validate', 'resume'}:
        raise ValueError('analysis worker cannot self-verify or resume external conditions')
    return work_cards.apply(loop, card, **payload)


def _read_artifact(path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('JSON artifact exceeds bounded interpreter size')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('structured JSON object artifact required')
    return value


def _match(value, check):
    if not isinstance(check, dict) or set(check) != {'field', 'equals'} or not isinstance(check['field'], str):
        raise ValueError('operator-owned field/equals predicate required')
    for key in check['field'].split('.'):
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return type(value) is type(check['equals']) and value == check['equals']


def _execute(loop, ledger, task, worker, config, persist, received):
    from hunt_integration import execute_command
    card = task['card']
    binding = _binding(config, card)
    if not isinstance(binding, dict) or set(binding) != {'hypothesis', 'scope_ref', 'risk', 'test_argv', 'control_argv', 'checks'}:
        raise ValueError('explicit command binding and artifact predicates required')
    checks = binding['checks']
    if not isinstance(checks, dict) or not {'normal', 'behavior', 'impact'}.issubset(checks):
        raise ValueError('normal, protected behavior and impact predicates required')
    output = Path(config['output_dir']).resolve() / task['work_id']
    def interpret(test, control):
        a, b = _read_artifact(test), _read_artifact(control)
        return {'observation': 'Saved JSON artifacts compared against operator-owned predicates',
                'excluded': 'A response status alone is insufficient', 'recovery': 'Independent evidence or new discriminating condition',
                'normal_succeeds': _match(b, checks['normal']), 'behavior_observed': _match(a, checks['behavior']),
                'impact_observed': _match(a, checks['impact'])}
    if worker['adapter'] == 'argv-comparison':
        return work_cards.execute_alternative(loop, ledger, card, comparison_hyp_id=binding['hypothesis'],
            test_argv=binding['test_argv'], control_argv=binding['control_argv'], output_dir=output,
            scope_ref=binding['scope_ref'], interpret=interpret, producer_id=worker['actor'], on_result=received)
    row = next(r for r in blocked.project(loop.events, loop.base_path) if r['obstruction_id'] == card['ref'])
    if any(a.get('attempt', {}).get('producer_id') == worker['actor'] for a in row['alternatives']):
        raise ValueError('verifier must use a different configured runner from the source producer')
    if unresolved_actions(loop.events, binding['hypothesis']):
        raise ValueError('prior verifier execution requires reconciliation')
    paths = {branch: output / (branch + '.json') for branch in ('control', 'test')}
    for branch in ('control', 'test'):
        if not execute_command(loop, ledger, binding['hypothesis'], task['work_id'] + ':' + branch,
                               binding[branch + '_argv'], paths[branch], timeout=120, scope_ref=binding['scope_ref']):
            raise ValueError('independent comparison execution failed; preserve uncertainty')
        persist(loop)
    observed = interpret(paths['test'], paths['control'])
    outcome = ('supported' if all(observed[k] for k in ('normal_succeeds', 'behavior_observed', 'impact_observed')) else
               'not_supported' if observed['normal_succeeds'] and 'rejection' in checks
               and _match(_read_artifact(paths['test']), checks['rejection']) else 'needs_evidence')
    context = {**(latest_context(loop.events) or {}), 'observed_at': datetime.now(UTC).isoformat()}
    result = {'request_id': row['validation_request']['request_id'], 'outcome': outcome, 'verifier_id': worker['actor'],
              'reason': observed['observation'], 'recovery': observed['recovery'],
              **{branch + '_evidence': {'kind': 'artifact', 'path': str(path), 'applicability': context}
                 for branch, path in paths.items()}}
    received(result)
    return work_cards.apply(loop, card, 'validate', result)


def main():
    import asg
    from hunt_lock import acquire, guarded_save, heartbeat, release
    from hunt_loop import HuntLoop
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--settle-work')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--effects', choices=['not-executed', 'effects-checked'])
    parser.add_argument('--state', choices=['failed', 'cancelled'], default='failed')
    args = parser.parse_args()
    if not args.settle_work and not args.config:
        parser.error('--config or --settle-work required')
    if args.settle_work and (not args.receipt or not args.effects):
        parser.error('settlement requires --receipt and --effects')
    ledger = asg.ledger_path(args.target)
    token = acquire(ledger, 'work-dispatch')
    try:
        loop = HuntLoop.load(ledger)
        def persist(lp):
            heartbeat(ledger, token)
            guarded_save(lp, ledger, token)
        if args.settle_work:
            settle(loop, args.settle_work, evidence=args.receipt, state=args.state, effects=args.effects)
            result = {'state': args.state, 'work_id': args.settle_work}
        else:
            result = run_ready(loop, ledger, json.loads(args.config.read_text()), persist=persist, target=args.target)
        persist(loop)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        release(ledger, token)


if __name__ == '__main__':
    main()
