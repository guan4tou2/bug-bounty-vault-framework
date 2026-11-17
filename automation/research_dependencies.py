"""Scoped change impact over canonical ASG records; no second state authority.

Edges point from a source to its dependent. Explicit links pin source revisions;
artifact integrity/applicability changes seed a cycle-safe downstream traversal.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque

from evidence_applicability import assess_artifact
from evidence_refs import evidence_resolves, finding_records


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def project(loop):
    nodes, edges = {}, set()

    def node(ref, value):
        material = {k: v for k, v in value.items() if k not in {'at', 'ts', 'sid'}}
        nodes[ref] = {'ref': ref, 'revision': digest(material), 'reasons': []}

    def proof(value, dependent):
        if not isinstance(value, dict):
            return
        if value.get('kind') == 'comparison':
            proof(value.get('test'), dependent)
            proof(value.get('control'), dependent)
        elif value.get('kind') in {None, 'artifact', 'observation'} and (value.get('path') or value.get('text')):
            if value.get('path') and value.get('kind') is None:
                value = {**value, 'kind': 'artifact'}
            ref = 'evidence:' + digest(value)[:24]
            node(ref, value)
            if not evidence_resolves(value, loop.base_path, loop.events):
                nodes[ref]['reasons'].append('original evidence missing, changed or inapplicable')
            if 'applicability' in value:
                assessment = assess_artifact(value, loop.events)
                if assessment['requires_revalidation']:
                    nodes[ref]['reasons'].extend(assessment['reasons'])
            edges.add((ref, dependent))

    def proofs(value, dependent):
        if isinstance(value, list):
            for item in value:
                proofs(item, dependent)
        elif isinstance(value, dict):
            proof(value, dependent)
            for key in ('evidence', 'artifacts', 'evidence_ref', 'test_evidence', 'control_evidence',
                        'steps', 'actual', 'pre', 'action', 'post', 'finding_document', 'review_evidence', 'attachments'):
                if key in value:
                    proofs(value[key], dependent)

    # Only the latest canonical revision contributes active evidence dependencies.
    records = {}
    for event in loop.events:
        kind = event['type']
        if kind == 'hypothesis':
            records['hypothesis:' + event['id']] = event
        elif kind in {'logic_hypothesis', 'logic_verdict'}:
            ref = 'hypothesis:' + event['hyp_id']
            records[ref] = {**records.get(ref, {}), **event}
        elif kind == 'verdict':
            ref = 'hypothesis:' + event['hypothesis']
            records[ref] = {**records.get(ref, {}), **event}
        elif kind in {'scan_candidate', 'scan_observation'}:
            records['hypothesis:' + event['candidate_id']] = event
        elif kind == 'flow_definition':
            records['flow:' + event['flow_id']] = event
        elif kind == 'flow_case':
            records['case:' + event['case_id']] = event
            edges.add(('flow:' + event['flow_id'], 'case:' + event['case_id']))
        elif kind == 'flow_trace_started':
            records['trace:' + event['trace_id']] = {**event, 'steps': []}
            edges.add(('case:' + event['case_id'], 'trace:' + event['trace_id']))
        elif kind == 'flow_trace_step':
            trace = records.get('trace:' + event['trace_id'])
            if trace is not None:
                trace['steps'].append(event)
        elif kind == 'flow_reproduction':
            records['reproduction:' + event['reproduction_id']] = event
            for trace_id in event['trace_ids']:
                edges.add(('trace:' + trace_id, 'reproduction:' + event['reproduction_id']))
        elif kind == 'flow_case_binding':
            edges.add(('case:' + event['case_id'], 'hypothesis:' + event['hyp_id']))
        elif kind == 'credential_used':
            edges.add((event['credential_ref'], 'hypothesis:' + event['hyp_id']))
    for identifier, finding in finding_records(loop.events).items():
        records['finding:' + identifier] = finding
    from asg_research import project as research
    graph = research(loop.events, loop.base_path, cap=loop.capsule())
    for row in graph['nodes']:
        records.setdefault(row['ref'], row)
    for edge in graph['edges']:
        # These relations express use/derivation, not mere membership or chronology.
        if edge['rel'] in {'derived_from', 'depends_on', 'yields', 'proves'}:
            edges.add((edge['src'], edge['dst']))
    from research_delivery import records as delivery_records
    for kind, rows in delivery_records(loop.events).items():
        for identifier, row in rows.items():
            ref, value = 'delivery:' + kind + ':' + identifier, row['data']
            records[ref] = value
            for trace_id in value.get('research_binding', {}).get('trace_ids', []):
                edges.add(('trace:' + trace_id, ref))
            for field, prefix in (('flow_id', 'delivery:flow:'), ('trace_id', 'delivery:trace:'),
                                  ('instance_id', 'delivery:instance:'), ('finding_id', 'finding:')):
                if value.get(field):
                    edges.add((prefix + value[field], ref))
    for ref, value in records.items():
        node(ref, value)
        proofs(value, ref)
    from credentials import project as credential_rows
    for row in credential_rows(loop.events, loop.base_path):
        ref = row['credential_ref']
        node(ref, row)
        if row['state'] != 'valid':
            nodes[ref]['reasons'].append('credential is ' + row['state'])
        for subject, record in records.items():
            if any(r.startswith(ref + ':permission:') for r in record.get('requires', [])):
                edges.add((ref, subject))
    for ref, value in records.items():
        if ref.startswith('case:'):
            definition = records.get('flow:' + value['flow_id'])
            if definition and value['definition_version'] != definition['version']:
                nodes[ref]['reasons'].append('flow definition revision changed')
    from blocked_research import project as obstructions
    for row in obstructions(loop.events, loop.base_path):
        owner = 'hypothesis:' + row['hyp_id']
        proofs(row, owner)
        for alternative in row['alternatives']:
            proofs(alternative, owner)
            if alternative.get('attempt'):
                proofs(alternative['attempt'], owner)
        if row.get('validations'):
            proofs(row['validations'][-1], owner)
    explicit = {}
    for event in loop.events:
        if event['type'] == 'research_dependency':
            explicit[(event['source'], event['dependent'])] = event
    for (source, dependent), event in explicit.items():
        edges.add((source, dependent))
        if dependent not in nodes:
            continue
        if source not in nodes or nodes[source]['revision'] != event['source_revision']:
            nodes[dependent]['reasons'].append('pinned dependency revision changed: ' + source)
    downstream = defaultdict(set)
    for source, dependent in edges:
        if source in nodes and dependent in nodes:
            downstream[source].add(dependent)
    affected = {ref: {ref} for ref, row in nodes.items() if row['reasons']}
    pending = deque(affected)
    while pending:
        source = pending.popleft()
        for dependent in downstream[source]:
            old = affected.get(dependent, set())
            new = old | affected[source]
            if new != old:
                affected[dependent] = new
                pending.append(dependent)
    return {'nodes': list(nodes.values()), 'edges': [{'source': a, 'dependent': b} for a, b in sorted(edges)],
            'affected': [{'ref': ref, 'causes': sorted(causes)} for ref, causes in sorted(affected.items())],
            'limit': 'Only recorded dependencies are traversed; no inferred target-wide invalidation or automatic rerun.'}


def link(loop, source, dependent, *, reason):
    graph = project(loop)
    nodes = {n['ref']: n for n in graph['nodes']}
    if source == dependent or source not in nodes or dependent not in nodes or not isinstance(reason, str) or not reason.strip():
        raise ValueError('distinct existing source/dependent references and a reason required')
    value = dict(source=source, dependent=dependent, source_revision=nodes[source]['revision'], reason=reason)
    prior = next((e for e in reversed(loop.events) if e['type'] == 'research_dependency'
                  and e['source'] == source and e['dependent'] == dependent), None)
    if not prior or any(prior[k] != value[k] for k in ('source_revision', 'reason')):
        loop.append('research_dependency', **value)
    return value


def main():
    import argparse
    from pathlib import Path
    import asg
    from hunt_loop import HuntLoop
    from hunt_lock import acquire, guarded_save, release
    from evidence_gaps import declare, project as gaps
    from research_progress import metrics
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('view')
    add = sub.add_parser('link'); add.add_argument('source'); add.add_argument('dependent'); add.add_argument('--reason', required=True)
    gap = sub.add_parser('gap'); gap.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    if args.command == 'view':
        loop = HuntLoop.load(ledger)
    else:
        token = acquire(ledger, 'research-planning')
        try:
            loop = HuntLoop.load(ledger)
            if args.command == 'link':
                link(loop, args.source, args.dependent, reason=args.reason)
            else:
                declare(loop, **json.loads(args.input.read_text()))
            guarded_save(loop, ledger, token)
        finally:
            release(ledger, token)
    print(json.dumps({'impact': project(loop), 'evidence_gaps': gaps(loop), 'metrics': metrics(loop)}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
