#!/usr/bin/env python3
"""Same-ledger flow/trace/report contracts. No target execution or verdict promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

KINDS = {'flow', 'trace', 'instance', 'retest', 'task', 'group', 'report'}
TASKS = {'verify', 'evidence', 'reply', 'retest', 'research'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def require(data, *keys):
    for key in keys:
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f'missing text: {key}')


def rows(data, key):
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f'{key} must be a list')
    return value


def records(events):
    out = {k: {} for k in KINDS}
    for e in events:
        if e.get('type') == 'delivery_record' and e.get('record_kind') in KINDS:
            out[e['record_kind']][e['data']['id']] = e
    return out


def pin_files(refs, base):
    if not isinstance(refs, list) or not refs:
        raise ValueError('evidence requires at least one file reference')
    result = []
    for ref in refs:
        if not isinstance(ref, dict):
            raise ValueError('evidence reference must have path and locator')
        require(ref, 'path', 'locator')
        path = Path(ref['path'])
        path = path if path.is_absolute() else base / path
        if not path.is_file():
            raise ValueError(f'missing evidence: {path}')
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if ref.get('sha256') and ref['sha256'] != sha:
            raise ValueError('evidence hash mismatch')
        result.append({**ref, 'path': str(path.resolve()), 'sha256': sha})
    return result


def files_current(refs):
    try:
        return bool(refs) and all(Path(r['path']).is_file() and
            hashlib.sha256(Path(r['path']).read_bytes()).hexdigest() == r['sha256'] for r in refs)
    except (KeyError, OSError, TypeError):
        return False


def normalize(data, loop):
    """Called inside ASG's single-writer transaction, before append/save."""
    kind = data.get('record_kind')
    if kind not in KINDS or not isinstance(data.get('data'), dict):
        raise ValueError('invalid delivery kind/data')
    d = json.loads(json.dumps(data['data']))
    require(d, 'id')
    state = records(loop.events)
    previous = state[kind].get(d['id'])
    if previous:
        if previous['data'] == d:
            raise ValueError('record already exists; no duplicate append needed')
        if kind in {'trace', 'retest'}:
            raise ValueError(f'{kind} is immutable; create a new id')
        if data.get('previous_revision') != previous['revision']:
            raise ValueError('amend requires current previous_revision')
    base = loop.base_path or Path.cwd()
    # HuntLoop.load sets base_path to the target dir; keep all relative evidence anchored there.
    def reference(k, field):
        require(d, field)
        if d[field] not in state[k]:
            raise ValueError(f'unknown {k}: {d[field]}')
        e = state[k][d[field]]
        d[field + '_revision'] = e['revision']
        return e['data']

    if kind == 'flow':
        require(d, 'entry', 'initial_state', 'invariant', 'rule_source')
        states = rows(d, 'states')
        if not states or len(set(states)) != len(states) or d['initial_state'] not in states:
            raise ValueError('invalid flow states')
        ids = set()
        for t in rows(d, 'transitions'):
            require(t, 'id', 'from', 'to', 'action', 'guard', 'expected')
            if t['id'] in ids or t['from'] not in states or t['to'] not in states:
                raise ValueError('invalid transition identity/state')
            ids.add(t['id'])
        if not ids:
            raise ValueError('flow requires transitions')
        d['evidence'] = pin_files(d.get('evidence'), base)
    elif kind == 'trace':
        flow = reference('flow', 'flow_id')
        require(d, 'finding_id', 'actor', 'environment', 'preconditions', 'data_origin',
                'expected', 'actual', 'impact', 'limitations', 'producer')
        if d.get('mode') not in {'ui', 'api', 'cli', 'sdk', 'native'}:
            raise ValueError('invalid interaction mode')
        finding_exists(loop.events, d['finding_id'])
        transitions = {t['id']: t for t in flow['transitions']}
        current = flow['initial_state']
        steps = rows(d, 'steps')
        phases = set()
        if not steps:
            raise ValueError('empty trace')
        for step in steps:
            require(step, 'transition_id', 'action', 'observed', 'phase')
            if step['phase'] not in {'setup', 'control', 'trigger', 'observe'}:
                raise ValueError('invalid trace phase')
            phases.add(step['phase'])
            transition = transitions.get(step['transition_id'])
            if not transition or transition['from'] != current:
                raise ValueError('trace does not follow flow state order')
            current = transition['to']
            step['evidence'] = pin_files(step.get('evidence'), base)
        if not {'setup', 'control', 'trigger', 'observe'} <= phases:
            raise ValueError('trace needs setup, control, trigger and observe')
        # Stored as an observation only; never grants confirmed/verified/capabilities.
    elif kind == 'instance':
        require(d, 'finding_id', 'asset', 'version', 'role', 'relation', 'confirmation')
        finding_exists(loop.events, d['finding_id'])
        if d['confirmation'] not in {'unknown', 'observed', 'independently-verified', 'refuted', 'blocked'}:
            raise ValueError('invalid instance confirmation')
        if d['confirmation'] not in {'unknown', 'blocked'}:
            d['evidence'] = pin_files(d.get('evidence'), base)
    elif kind == 'retest':
        instance = reference('instance', 'instance_id')
        require(d, 'occurred_at', 'conditions', 'result', 'event_kind')
        from datetime import datetime
        datetime.fromisoformat(d['occurred_at'].replace('Z', '+00:00'))
        allowed = {'vendor-claim': {'claimed-fixed'}, 'retest':
                   {'still-vulnerable', 'not-reproduced', 'inconclusive', 'recurrence'}}
        if d['result'] not in allowed.get(d['event_kind'], set()):
            raise ValueError('vendor claim and observed retest must remain separate')
        if d['result'] == 'recurrence':
            prior = reference('retest', 'previous_retest_id')
            if prior['instance_id'] != d['instance_id'] or prior['result'] != 'not-reproduced':
                raise ValueError('recurrence needs a prior successful same-instance retest')
            if not files_current(prior['evidence']):
                raise ValueError('prior retest evidence is stale')
        d['finding_id'] = instance['finding_id']
        d['evidence'] = pin_files(d.get('evidence'), base)
    elif kind == 'task':
        require(d, 'finding_id', 'reason')
        finding_exists(loop.events, d['finding_id'])
        if d.get('kind') not in TASKS or d.get('state') not in {'open', 'blocked', 'done', 'cancelled'}:
            raise ValueError('invalid work kind/state')
        if d.get('state') == 'done':
            d['evidence'] = pin_files(d.get('evidence'), base)
    elif kind == 'group':
        require(d, 'basis', 'reason')
        if d['basis'] not in {'similarity', 'same-cve', 'suspected-root-cause', 'confirmed-root-cause'}:
            raise ValueError('invalid group basis')
        if not rows(d, 'members'):
            raise ValueError('group needs members')
        for member in d['members']:
            if not isinstance(member, str) or not member.strip():
                raise ValueError('group members require explicit references')
        if d['basis'] == 'confirmed-root-cause':
            d['evidence'] = pin_files(d.get('evidence'), base)
    elif kind == 'report':
        trace = reference('trace', 'trace_id')
        require(d, 'title', 'summary', 'remediation', 'finding_id')
        if d['finding_id'] != trace['finding_id']:
            raise ValueError('report/finding mismatch')
        finding_exists(loop.events, d['finding_id'])
        # Actual finding document is pinned, so later changes require explicit report amendment.
        d['finding_document'] = pin_files(d.get('finding_document'), base)
        d['attachments'] = pin_files(d.get('attachments'), base)
        filenames = set()
        for attachment in d['attachments']:
            require(attachment, 'label', 'filename')
            name = attachment['filename']
            import re
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or name in filenames:
                raise ValueError('attachment filenames must be unique safe basenames')
            filenames.add(name)
        from evidence_refs import finding_records
        d['finding_revision'] = digest(finding_records(loop.events)[d['finding_id']])
        d['content_revision'] = digest({k: d[k] for k in ('title', 'summary', 'remediation',
            'finding_id', 'finding_revision', 'finding_document', 'trace_id', 'trace_id_revision', 'attachments')})
        require(d, 'reviewer', 'review_result')
        if d['review_result'] not in {'pending', 'passed', 'needs-evidence'}:
            raise ValueError('invalid review result')
        if d['review_result'] == 'passed':
            if d['reviewer'] == trace['producer']:
                raise ValueError('independent review cannot be self review')
            d['review_evidence'] = pin_files(d.get('review_evidence'), base)
            receipt = json.loads(Path(d['review_evidence'][0]['path']).read_text())
            if not isinstance(receipt, dict) or any(receipt.get(k) != v for k, v in {
                'report_id': d['id'], 'content_revision': d['content_revision'],
                'reviewer': d['reviewer'], 'result': 'passed', 'reproduction_checked': True}.items()):
                raise ValueError('review receipt does not attest this report content and reproduction')
        else:
            d.pop('review_evidence', None)
        d['status'] = 'draft'
    return {**data, 'record_kind': kind, 'data': d, 'revision': digest(d)}


def finding_exists(events, fid):
    if not any(e.get('type') == 'finding' and e.get('finding_id') == fid for e in events):
        raise ValueError('Finding must be recorded in ASG first')


def project(events):
    state = records(events)
    def evidence_current(refs):
        from evidence_applicability import assess_artifact
        return files_current(refs) and all(
            not assess_artifact(ref, events)['requires_revalidation']
            for ref in refs if 'applicability' in ref)
    def stale(kind, record, seen=None):
        seen = set() if seen is None else seen
        key = (kind, record['data']['id'])
        if key in seen:
            return True
        seen = seen | {key}
        d = record['data']
        if kind == 'report':
            from evidence_refs import finding_records
            finding = finding_records(events).get(d['finding_id'])
            if not finding or digest(finding) != d.get('finding_revision'):
                return True
        for field in ('evidence', 'finding_document', 'review_evidence', 'attachments'):
            if field in d and not evidence_current(d[field]):
                return True
        for step in d.get('steps', []):
            if not evidence_current(step.get('evidence')):
                return True
        for field, target_kind in (('flow_id','flow'), ('trace_id','trace'),
                                  ('instance_id','instance'), ('previous_retest_id','retest')):
            if field + '_revision' in d:
                other = state[target_kind].get(d[field])
                if not other or other['revision'] != d[field + '_revision'] or stale(target_kind, other, seen):
                    return True
        return False
    result = {k: [{**v['data'], 'revision': v['revision'], 'stale': stale(k, v)}
                  for v in state[k].values()] for k in sorted(KINDS)}
    from research_dependencies import project as change_impact
    affected = {r['ref'] for r in change_impact(__import__('hunt_loop').HuntLoop(events))['affected']}
    for kind in KINDS:
        for row in result[kind]:
            row['stale'] = row['stale'] or 'delivery:' + kind + ':' + row['id'] in affected
    result['queue'] = [t for t in result['task'] if t['state'] in {'open','blocked'}]
    result['repair'] = [{'kind': k, 'id': r['id']} for k in sorted(KINDS) for r in result[k] if r['stale']]
    return result


def render(events, report_id, *, ready=False):
    view = project(events)
    report = next((r for r in view['report'] if r['id'] == report_id), None)
    if not report:
        raise ValueError('unknown report')
    if report['stale']:
        raise ValueError('stale report/trace/evidence; repair before rendering')
    if ready and report['review_result'] != 'passed':
        raise ValueError('independent review required for ready check')
    trace = next(t for t in view['trace'] if t['id'] == report['trace_id'])
    lines = [f"# {report['title']}", '', '## 問題與影響', '', report['summary'], '',
             '## 測試前提', '', trace['preconditions'], '', f"操作身分：{trace['actor']}",
             f"測試環境：{trace['environment']}", f"必要資料取得方式：{trace['data_origin']}", '',
             '## 復現步驟', '']
    for n, step in enumerate(trace['steps'], 1):
        lines += [f"{n}. {step['action']}（觀察：{step['observed']}）"]
    lines += ['', '## 預期與實際結果', '', f"預期：{trace['expected']}",
              f"實際：{trace['actual']}"]
    for a in report['attachments']:
        lines.append(f"- [{a['label']}]({attachment_dir(report_id)}/{a['filename']})")
    lines += ['', '## 修補建議', '', report['remediation'],
              '', '## 驗證限制', '', trace['limitations'], '']
    # Only explicitly public prose is rendered; internal refs, jobs and raw credentials are not copied.
    return '\n'.join(lines)


def attachment_dir(report_id):
    return 'evidence-' + digest(report_id)[:16]


def export_document(events, target, report_id, output):
    """Bundle only explicitly selected public attachments; never copy raw refs automatically."""
    import shutil
    output = Path(output)
    text = render_document(events, target, report_id)
    report = records(events)['report'][report_id]['data']
    folder = output.parent / attachment_dir(report_id)
    if output.exists() or folder.exists():
        raise ValueError('output or attachment directory exists; choose a fresh directory')
    folder.mkdir()
    try:
        for a in report['attachments']:
            destination = folder / a['filename']
            shutil.copyfile(a['path'], destination)
            if hashlib.sha256(destination.read_bytes()).hexdigest() != a['sha256']:
                raise ValueError('attachment changed during export')
        with output.open('x', encoding='utf-8') as stream:
            stream.write(text)
    except Exception:
        shutil.rmtree(folder)
        raise


def render_document(events, target, report_id, *, ready=False):
    import yaml
    report = records(events)['report'].get(report_id)
    body = render(events, report_id, ready=ready)
    metadata = {'fileClass': 'Submission', 'status': 'draft', 'report_contract_version': 1,
                'delivery_target': str(target), 'delivery_report_id': report_id,
                'finding_id': report['data']['finding_id'], 'delivery_revision': report['revision']}
    return '---\n' + yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False) + '---\n\n' + body


def plan_paths(events, flow_id, max_steps=12):
    """Bounded transition-covering plans only; never executes or claims coverage."""
    if not 1 <= max_steps <= 100:
        raise ValueError('max_steps must be between 1 and 100')
    flow = next((r for r in project(events)['flow'] if r['id'] == flow_id), None)
    if flow is None or flow['stale']:
        raise ValueError('unknown or stale flow')
    from collections import deque
    frontier = deque([(flow['initial_state'], [])])
    visited = {flow['initial_state']}
    plans = []
    while frontier:
        source, path = frontier.popleft()
        if len(path) >= max_steps:
            continue
        for t in flow['transitions']:
            if t['from'] != source:
                continue
            sequence = path + [t['id']]
            plans.append({'flow_id': flow_id, 'flow_revision': flow['revision'], 'status': 'planned',
                          'transitions': sequence, 'condition_to_check': t['guard'],
                          'expected': t['expected']})
            if t['to'] not in visited:
                visited.add(t['to']); frontier.append((t['to'], sequence))
    covered = {x for p in plans for x in p['transitions']}
    return {'plans': plans, 'unreached': [t['id'] for t in flow['transitions'] if t['id'] not in covered],
            'limitation': 'structural paths only; guards, roles, feasibility and negative cases require research review'}


def check_document(path):
    """Opt-in check; legacy wrappers remain on existing report gates."""
    import yaml
    import asg
    from hunt_loop import HuntLoop
    text = Path(path).read_text(encoding='utf-8')
    parts = text.split('---', 2) if text.startswith('---\n') else []
    fm = yaml.safe_load(parts[1]) if len(parts) == 3 else {}
    if not isinstance(fm, dict) or fm.get('report_contract_version') != 1:
        return 'LEGACY: no delivery contract; existing checks and manual journey review still required'
    require(fm, 'delivery_target', 'delivery_report_id', 'delivery_revision')
    events = HuntLoop.load(asg.ledger_path(fm['delivery_target'])).events
    expected = render_document(events, fm['delivery_target'], fm['delivery_report_id'], ready=True)
    if text != expected:
        raise ValueError('report text or metadata differs from current reviewed source; amend and review')
    report = records(events)['report'][fm['delivery_report_id']]['data']
    for a in report['attachments']:
        copied = Path(path).parent / attachment_dir(fm['delivery_report_id']) / a['filename']
        if not copied.is_file() or hashlib.sha256(copied.read_bytes()).hexdigest() != a['sha256']:
            raise ValueError('exported attachment missing or modified')
    return 'PASS: report matches current ASG source and recorded review; semantic review remains human responsibility'


def main():
    import asg
    from hunt_loop import HuntLoop
    ap = argparse.ArgumentParser(description=__doc__)
    import sys
    if sys.argv[1:2] == ['check-file']:
        if len(sys.argv) != 3:
            raise ValueError('usage: research_delivery.py check-file REPORT.md')
        print(check_document(Path(sys.argv[2])))
        return
    ap.add_argument('target')
    sub = ap.add_subparsers(dest='command', required=True)
    add = sub.add_parser('record'); add.add_argument('kind', choices=sorted(KINDS))
    add.add_argument('file', type=Path); add.add_argument('--previous-revision')
    sub.add_parser('status')
    plan = sub.add_parser('plan'); plan.add_argument('flow_id'); plan.add_argument('--max-steps', type=int, default=12)
    for name in ('render', 'check'):
        p = sub.add_parser(name); p.add_argument('report_id')
        if name == 'render':
            p.add_argument('--output', required=True, type=Path)
        else:
            p.add_argument('--body', type=Path)
    args = ap.parse_args()
    if args.command == 'record':
        triggers = [('reassessment_trigger', {'reason': 'pre_delivery', 'scope': 'target'})] if args.kind == 'report' else []
        asg.append_events(args.target, triggers + [('delivery_record', {'record_kind': args.kind,
                         'data': json.loads(args.file.read_text()), 'previous_revision': args.previous_revision})])
        asg.write_snapshot(args.target)
    events = HuntLoop.load(asg.ledger_path(args.target)).events
    if args.command == 'plan':
        print(json.dumps(plan_paths(events, args.flow_id, args.max_steps), ensure_ascii=False, indent=2))
    elif args.command in {'record', 'status'}:
        print(json.dumps(project(events), ensure_ascii=False, indent=2))
    else:
        body = render_document(events, args.target, args.report_id, ready=args.command == 'check')
        if args.command == 'render':
            export_document(events, args.target, args.report_id, args.output)
            # Existing outputs are never overwritten; check compares against current source.
            print(f'draft: {args.output}; independent semantic review still required')
        elif args.body:
            if args.body.read_text(encoding='utf-8') != body:
                raise ValueError('report body does not match the requested target and report')
            print(check_document(args.body))
        else:
            print('PASS: current provenance and recorded independent review; no automatic vulnerability verification')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(f'FAIL: {exc}')
