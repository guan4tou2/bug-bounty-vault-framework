"""Gap-driven local retrieval, public-query provider and checked source review.

External retrieval is an operator-configured adapter. Private questions/evidence
never become its query. Sources remain source-claimed methods, not target facts.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from blocked_research import _proof, _required
from evidence_applicability import _time, latest_context
from evidence_refs import artifact_hash, evidence_resolves


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _profile_value(event):
    return {k: event[k] for k in ('public_terms', 'version', 'allowed_domains')} if event else None


def profile(loop, *, public_terms, version, allowed_domains):
    if not isinstance(public_terms, list) or not 1 <= len(public_terms) <= 12:
        raise ValueError('bounded explicitly public product/technical terms required')
    for term in [*public_terms, version]:
        if not isinstance(term, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._+-]{0,79}', term) or re.search(r'[A-Za-z0-9_-]{32,}', term):
            raise ValueError('queries must not contain addresses, URLs, opaque values or credentials')
        try:
            ipaddress.ip_address(term)
        except ValueError:
            pass
        else:
            raise ValueError('IP addresses are not public research terms')
    if not isinstance(allowed_domains, list) or not 1 <= len(allowed_domains) <= 12 or any(
            not isinstance(d, str) or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', d) for d in allowed_domains):
        raise ValueError('explicit primary-source domain allowlist required')
    for domain in allowed_domains:
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            if domain.endswith(('.local', '.internal', '.localhost')):
                raise ValueError('primary sources must use declared public domains')
        else:
            raise ValueError('source IP addresses are not accepted as public domains')
    value = dict(public_terms=public_terms, version=version, allowed_domains=allowed_domains)
    if _profile_value(next((e for e in reversed(loop.events) if e['type'] == 'research_search_profile'), None)) != value:
        loop.append('research_search_profile', **value)
        loop.append('reassessment_trigger', reason='conditions_changed', scope='target')


def request(loop, *, question, decision, excluded, evidence, refresh_hours=24):
    _required(question, decision)
    if not isinstance(excluded, list) or any(not isinstance(e, str) or len(e) > 512 for e in excluded):
        raise ValueError('bounded excluded explanations required')
    if type(refresh_hours) is not int or not 1 <= refresh_hours <= 168:
        raise ValueError('refresh horizon must be 1..168 hours')
    search = next((e for e in reversed(loop.events) if e['type'] == 'research_search_profile'), None)
    if not search:
        raise ValueError('explicit public search profile required before external lookup')
    search = _profile_value(search)
    proof = _proof(loop, evidence)
    signature = digest([question, decision, excluded, search, latest_context(loop.events), proof])
    prior = next((r for r in project(loop) if r['signature'] == signature), None)
    if prior and not prior['stale'] and datetime.now(UTC) < _time(prior['refresh_at']):
        return prior['request_id']
    rid = digest([signature, prior['request_id'] if prior else None])
    loop.append('research_source_requested', request_id=rid, signature=signature, question=question,
                decision=decision, excluded=excluded, evidence=proof, profile=search, requested_at=datetime.now(UTC).isoformat(),
                refresh_at=(datetime.now(UTC) + timedelta(hours=refresh_hours)).isoformat(),
                public_query=' '.join([*search['public_terms'], search['version'], 'documentation prerequisites limitations']),
                budget={'provider_calls': 1, 'review_calls': 1, 'sources': 3})
    return rid


def collect(loop):
    """Existing reassessments trigger supplemental research only with a public profile."""
    if not any(e['type'] == 'research_search_profile' for e in loop.events):
        return
    for event in tuple(loop.events):
        if event['type'] != 'reassessment_requested' or event['reason'] not in {
                'obstruction', 'evidence_conflict', 'evidence_changed', 'conditions_changed', 'no_information_gain', 'queue_exhausted'}:
            continue
        proof = next((p['proof'] for p in event['inventory']['evidence'] if p['integrity'] and p['applicability'] == 'applicable'), None)
        if proof:
            try:
                request(loop, question='Find a different discriminator for ' + event['reason'] + ' in ' + event['scope'],
                        decision='Decide a bounded next test or retain the unresolved gap',
                        excluded=[p.get('cause', '') for p in event['inventory'].get('dead_paths', [])], evidence=proof)
            except ValueError:
                continue  # historical trigger evidence cannot authorize a fresh request


def project(loop):
    rows = {}
    for event in loop.events:
        rid = event.get('request_id')
        if event['type'] == 'research_source_requested':
            rows[rid] = {**event, 'state': 'retrieve', 'sources': []}
        elif rid in rows and event['type'] == 'research_sources_retrieved':
            rows[rid].update(state='review' if event['sources'] else 'insufficient', **{k: event[k] for k in ('sources', 'local_hits')})
        elif rid in rows and event['type'] == 'research_source_reviewed':
            rows[rid].update(state='reviewed', review=event)
    latest = {r['signature']: r['request_id'] for r in rows.values()}
    for row in rows.values():
        current_profile = _profile_value(next((e for e in reversed(loop.events) if e['type'] == 'research_search_profile'), None))
        row['stale'] = current_profile != row['profile'] or not evidence_resolves(row['evidence'], loop.base_path, loop.events) or any(
            not evidence_resolves(s['evidence'], loop.base_path, loop.events) for s in row['sources'])
        row['expired'] = datetime.now(UTC) >= _time(row['refresh_at'])
        row['superseded'] = latest[row['signature']] != row['request_id']
        row['state_version'] = digest([row['request_id'], row['state'], row['sources'], row['stale'], row['expired']])
    return list(rows.values())


def card(row):
    return {'schema': 1, 'kind': 'research-source', 'ref': row['request_id'], 'question': row['question'],
            'goal': row['decision'], 'excluded': row['excluded'], 'public_query': row['public_query'],
            'next_action': 'retrieve_research_sources' if row['state'] == 'retrieve' else 'review_research_sources',
            'facts': [{'evidence': s['evidence'], 'source_ref': s['id']} for s in row['sources']],
            'research_sources': [{k: s[k] for k in ('id', 'url', 'version', 'prerequisites', 'limitations', 'checked_at')}
                                 for s in row['sources']], 'requires': [],
            'allowed_operations': ['review'], 'output_requirements': {'decision': 'adopt/reject/insufficient',
                'source_ids': 'supplied full-source IDs', 'reason': 'applicability and counterevidence',
                'question': 'next discriminating test when adopting', 'requires': 'required capabilities'},
            'success': 'Evidence-linked method decision and a reviewable test proposal, never target verification',
            'stop': ['one provider and review call', 'three full sources', 'no private external query data'],
            'state_version': row['state_version']}


def retrieve(loop, ledger, work_card, binding, output, *, lookup=None):
    row = next((r for r in project(loop) if r['request_id'] == work_card['ref']), None)
    if not row or row['state'] != 'retrieve' or row['stale'] or row['expired'] or work_card != card(row):
        raise ValueError('current research retrieval card required')
    local_hits = []
    kb = loop.base_path.parents[1] / '09 - Knowledge Base' if loop.base_path and len(loop.base_path.parents) > 1 else None
    if lookup is not None or kb and kb.is_dir():
        if lookup is None:
            from kb_retrieval import search
            lookup = lambda terms: search(terms=terms, limit=3, root=kb)
        local_hits = lookup(row['profile']['public_terms'])[:3]
    argv = binding.get('provider_argv')
    if not isinstance(argv, list) or argv.count('{public_query}') != 1:
        raise ValueError('operator provider argv must contain one public_query argument')
    directory = Path(output).resolve().parent
    directory.mkdir(parents=True, exist_ok=True)
    argv = [row['public_query'] if arg == '{public_query}' else str(directory) if arg == '{artifact_dir}' else arg for arg in argv]
    from hunt_integration import execute_command
    if not execute_command(loop, ledger, binding['hypothesis'], 'research:' + row['request_id'], argv, output,
                           timeout=60, scope_ref=binding['scope_ref']):
        raise ValueError('retrieval failed; absence of methods is not established')
    if Path(output).stat().st_size > 1024 * 1024:
        raise ValueError('bounded source bundle required')
    bundle = json.loads(Path(output).read_text())
    sources = bundle.get('sources')
    if bundle.get('query') != row['public_query'] or not isinstance(sources, list) or len(sources) > 3:
        raise ValueError('source bundle must bind the public query and source budget')
    checked = []
    for source in sources:
        _required(*(source.get(k) for k in ('id', 'url', 'version', 'prerequisites', 'limitations', 'checked_at')))
        url = urlsplit(source['url'])
        if source.get('retrieval_kind') != 'full_source' or url.scheme != 'https' or url.hostname not in row['profile']['allowed_domains'] or url.username or url.password:
            raise ValueError('read primary source receipts required, not search snippets')
        if not _time(row['requested_at']) <= _time(source['checked_at']) <= datetime.now(UTC) or not isinstance(source.get('path'), str):
            raise ValueError('actual source read time and local artifact required')
        path = Path(source['path'])
        if not path.resolve().is_relative_to(directory):
            raise ValueError('source artifacts must be inside this retrieval work directory')
        if not path.is_file() or not path.stat().st_size or path.stat().st_size > 2 * 1024 * 1024 or artifact_hash(path) != source.get('sha256'):
            raise ValueError('source bytes must match their read receipt')
        proof = _proof(loop, {'kind': 'artifact', 'path': str(path), 'sha256': source['sha256'],
            'applicability': {**(latest_context(loop.events) or {}), 'observed_at': source['checked_at']}})
        checked.append({**{k: source[k] for k in ('id', 'url', 'version', 'prerequisites', 'limitations', 'checked_at')}, 'evidence': proof})
    loop.append('research_sources_retrieved', request_id=row['request_id'], sources=checked, local_hits=local_hits)
    return {'next_action': 'review_research_sources' if checked else 'research_sources_insufficient', 'finding_verified': False}


def apply(loop, work_card, operation, payload):
    row = next((r for r in project(loop) if r['request_id'] == work_card.get('ref')), None)
    if not row or row['state'] != 'review' or row['stale'] or row['expired'] or work_card != card(row) or operation != 'review':
        raise ValueError('current full-source review card required')
    if set(payload) != {'decision', 'source_ids', 'reason', 'question', 'requires'} or payload['decision'] not in {'adopt', 'reject', 'insufficient'}:
        raise ValueError('structured applicability decision required')
    _required(payload['reason'])
    selected = [s for s in row['sources'] if s['id'] in payload['source_ids']]
    if not selected or set(payload['source_ids']) != {s['id'] for s in selected}:
        raise ValueError('existing read sources must support the decision')
    proposal = None
    if payload['decision'] == 'adopt':
        applicable = next((s for s in selected if s['version'] == row['profile']['version']), None)
        if not applicable:
            raise ValueError('applicable version evidence required before method adoption')
        from work_cards import propose_exploration
        proposal = propose_exploration(loop, question=payload['question'], reason=payload['reason'],
                                       evidence=applicable['evidence'], requires=payload['requires'])
    loop.append('research_source_reviewed', request_id=row['request_id'], **payload, proposal_id=proposal, basis='source-claimed')
    return {'next_action': 'review_exploration' if proposal else 'research_method_' + payload['decision'], 'finding_verified': False}


def main():
    import argparse
    import asg
    from hunt_loop import HuntLoop
    from hunt_lock import acquire, guarded_save, release
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('view')
    for name in ('profile', 'request'):
        command = sub.add_parser(name); command.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    if args.command == 'view':
        loop = HuntLoop.load(ledger)
    else:
        token = acquire(ledger, 'research-sources')
        try:
            loop = HuntLoop.load(ledger)
            data = json.loads(args.input.read_text())
            profile(loop, **data) if args.command == 'profile' else request(loop, **data)
            collect(loop)
            guarded_save(loop, ledger, token)
        finally:
            release(ledger, token)
    print(json.dumps(project(loop), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
