#!/usr/bin/env python3
"""Read-only ASG gates over the canonical read model; Markdown is not an input
when a ledger exists. Coverage, modelling, and effective proof are separate facts.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import sys
import yaml
import asg
from ledger_reader import LedgerReadError

INVENTORY = re.compile(r'disclosure|discovery|reconnaissance|assessment|scan|research|version detection|threat|missing security|misconfiguration|infrastructure|api exposure|service|enumeration', re.I)
INITIAL = {'P:net=external', 'P:auth=anonymous', 'P:net=on-path', 'P:net=lan-adjacent'}
STEPPING = re.compile(r'^P:(cred|secret|token|key|apim-token|enum|auth-bypass|source|impersonate|oracle|login-csrf|session)=')
VERIFIED = {'verified', 'ready', 'submitted', 'accepted', 'validated', 'confirmed'}


def finding_docs(target):
    result = {}
    for path in sorted((asg.target_dir(target) / 'Findings').glob('*.md')):
        text = path.read_text(encoding='utf-8-sig').replace('\r\n', '\n')
        if not text.startswith('---\n'):
            continue
        end = text.find('\n---', 4)
        if end < 0:
            raise ValueError(f'incomplete frontmatter: {path.name}')
        try:
            data = yaml.safe_load(text[4:end])
        except yaml.YAMLError as exc:
            raise ValueError(f'invalid frontmatter: {path.name}') from exc
        if not isinstance(data, dict) or not data.get('finding_id'):
            continue
        fid = str(data['finding_id'])
        if fid in result:
            raise ValueError(f'duplicate finding_id: {fid}')
        result[fid] = {**data, 'doc': path.relative_to(asg.target_dir(target)).as_posix()}
    return result


def coverage(target, *, state=None):
    state = state if state is not None else asg.read_state(target)
    docs = finding_docs(target)
    graph = {str(f['id']): f for f in state['findings'] if isinstance(f, dict) and f.get('id')}
    nodes = {str(n.get(k)) for n in state['nodes'] if isinstance(n, dict)
             for k in ('id', 'name', 'identifier', 'label') if n.get(k)}
    capable, inventory, exempt, missing, unmodelled, proof_pending = [], [], [], [], [], []
    paths = {p['name']: p for p in state['paths'] if p.get('name')}
    for fid, doc in docs.items():
        if doc.get('asg_exempt') and doc.get('asg_exempt_reason'):
            exempt.append(fid)
            continue
        kind = graph.get(fid, {}).get('finding_kind') or doc.get('finding_kind') or None
        if kind not in (None, 'vulnerability', 'inventory', 'signal', 'context'):
            raise ValueError(f'invalid finding_kind: {fid}')
        if kind in ('inventory', 'context'):
            inventory.append(fid)
            continue
        declared = doc.get('provides') or graph.get(fid, {}).get('declared_provides') or graph.get(fid, {}).get('provides')
        if kind is None and not declared and INVENTORY.search(str(doc.get('vuln_class') or '')):
            inventory.append(fid)
            continue
        capable.append(fid)
        finding = graph.get(fid)
        if finding is None:
            missing.append(fid)
            continue
        links = finding.get('resolves') or ([finding['on_node']] if finding.get('on_node') else [])
        prov = finding.get('declared_provides', finding.get('provides')) or []
        path = paths.get(f'finding:{fid}', paths.get(fid, {}))
        if not prov or not any(str(n) in nodes for n in links) or not ('requires' in path or 'requires' in finding):
            unmodelled.append(fid)
        effective = path.get('status') == 'confirmed' if state['source'] == 'ledger' else finding.get('status') in VERIFIED
        if doc.get('status') in VERIFIED and not effective:
            proof_pending.append(fid)
    represented = len(capable) - len(missing)
    return {'target': state['target'], 'source': state['source'], 'event_cursor': state['event_cursor'],
            'eligible': len(capable), 'represented': represented,
            'coverage_percent': represented * 100 // len(capable) if capable else 100,
            'inventory': inventory, 'exempt': exempt, 'missing_findings': missing,
            'unmodelled_findings': unmodelled, 'proof_pending': proof_pending}


def chains(target, *, state=None):
    state = state if state is not None else asg.read_state(target)
    if state['source'] == 'ledger':
        chain = asg.auto_chain(target, state=state)
        confirmed = chain['total_confirmed']
        edges = chain['chain_edges']
    else:
        finds = [f for f in state['findings'] if f.get('status') in VERIFIED]
        edges = [{'from': a['id'], 'to': b['id'], 'capability': c}
                 for a in finds for b in finds if a['id'] != b['id']
                 for c in a.get('provides') or [] if c in (b.get('requires') or []) and c not in INITIAL]
        confirmed = len(finds)  # legacy declarations, not a new evidence verdict
    return {'target': state['target'], 'source': state['source'], 'event_cursor': state['event_cursor'],
            'confirmed_hypotheses': confirmed, 'chain_edges': edges,
            'pending_hypotheses': [p['name'] for p in state['paths'] if p.get('status') not in
                                   {'confirmed', 'dead_end', 'withdrawn', 'not_applicable', 'fixed_upstream'}],
            'note': 'effective ledger chains' if state['source'] == 'ledger' else 'legacy declarations; not live verification'}


def capabilities(target, *, state=None):
    state = state if state is not None else asg.read_state(target)
    declarations = state['paths'] if state['source'] == 'ledger' else state['findings']
    providers = {c for p in declarations for c in p.get('provides') or []}
    # Ledger hypotheses may declare provides on verdicts instead of hypothesis.
    if state['source'] == 'ledger':
        providers |= {c for e in state['loop'].events if e['type'] == 'verdict' for c in e.get('provides') or []}
    requirements = {c for p in declarations for c in p.get('requires') or []}
    effective = {c['cap'] for c in state['capability_state'] if c.get('state', 'confirmed') == 'confirmed'}
    return {'target': state['target'], 'source': state['source'], 'event_cursor': state['event_cursor'],
            'dangling_requires': sorted(requirements - providers - effective - INITIAL),
            'blocked_requires': sorted((requirements & providers) - effective - INITIAL),
            'unused_stepping_stones': sorted(c for c in effective - requirements if STEPPING.search(c))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('coverage', 'chains', 'capabilities'))
    parser.add_argument('target', nargs='?')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    root = asg.vault_root() / asg.TARGETS_DIRNAME
    targets = [args.target] if args.target else sorted(p.name for p in root.iterdir() if p.is_dir() and
              ((p / f'Target - {p.name}.md').exists() or (p / '.state/asg-events.jsonl').exists()))
    reports, errors = [], []
    for target in targets:
        try:
            reports.append(globals()[args.mode](target))
        except (LedgerReadError, OSError, ValueError) as exc:
            errors.append({'target': target, 'error': str(exc)})
    if args.json:
        print(json.dumps({'reports': reports, 'errors': errors}, ensure_ascii=False, indent=2))
    else:
        for r in reports:
            print(f"{r['target']} — source={r['source']} events={r['event_cursor']}")
            if args.mode == 'coverage':
                print(f"  能力承載型入帳 {r['coverage_percent']}% ({r['represented']}/{r['eligible']}); inventory={len(r['inventory'])} exempt={len(r['exempt'])}")
                for key, label in [('missing_findings', '未入帳'), ('unmodelled_findings', '缺 surface／provides／requires 建模'), ('proof_pending', '文件已驗證但 ledger proof 尚未確認')]:
                    print(f"  {label}: {len(r[key])}" + (f" — {', '.join(r[key][:12])}" if r[key] else ''))
            elif args.mode == 'chains':
                print(f"  {r['note']}: confirmed={r['confirmed_hypotheses']} edges={len(r['chain_edges'])} pending={len(r['pending_hypotheses'])}")
                for e in r['chain_edges'][:12]:
                    print(f"  {e['from']} → {e['to']} [{e['capability']}]")
            else:
                for key in ('dangling_requires', 'blocked_requires', 'unused_stepping_stones'):
                    print(f"  {key}: {len(r[key])}" + (f" — {', '.join(r[key][:12])}" if r[key] else ''))
        for error in errors:
            print(f"ERROR {error['target']}: {error['error']}", file=sys.stderr)
    if errors:
        return 2
    if args.mode == 'coverage':
        threshold = int(os.environ.get('ASG_MIN_MISSING', '3'))
        return int(any(len(r['missing_findings']) >= threshold or r['unmodelled_findings'] or r['proof_pending'] for r in reports))
    if args.mode == 'capabilities':
        return int(any(r['dangling_requires'] for r in reports))
    return 0  # no chain is an observation, not proof that a chain should exist


if __name__ == '__main__':
    raise SystemExit(main())
