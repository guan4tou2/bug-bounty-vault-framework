"""Supplemental research uses public-only queries and read-source receipts."""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import research_sources as sources
import work_cards as wc
import work_dispatch as wd
from tests import test_blocked_research as fixture


def setup(tmp_path, *, version='1.0', profile_version='1.0', retrieval_kind='full_source', empty=False):
    loop, proof = fixture.setup(tmp_path)
    sources.profile(loop, public_terms=['ExampleProduct', 'access control'], version=profile_version, allowed_domains=['docs.example.org'])
    rid = sources.request(loop, question='Which method distinguishes private customer conditions?',
                          decision='select the next comparison', excluded=['same condition already failed'], evidence=proof)
    page = tmp_path / 'source.txt'; page.write_text('Official fixture: sharing can be cached; use a new server request. Applies to release ' + version)
    source = {'id': 'official', 'url': 'https://docs.example.org/sharing', 'version': version,
              'prerequisites': 'owned fixture and two roles', 'limitations': 'cache does not establish new server access',
              'retrieval_kind': retrieval_kind, 'path': str(page), 'sha256': hashlib.sha256(page.read_bytes()).hexdigest()}
    script = ('import json,sys; from datetime import datetime,UTC; from pathlib import Path; source=' + repr(source) +
              '; p=Path(sys.argv[2])/"source.txt"; p.write_bytes(Path(source["path"]).read_bytes()); source["path"]=str(p)' +
              '; source["checked_at"]=datetime.now(UTC).isoformat(); print(json.dumps({"sources":' +
              ('[]' if empty else '[source]') + ',"query":sys.argv[1]}))')
    config = {'workers': {'research-retrieval': {'adapter': 'argv-research', 'actor': 'source-provider'},
              'research-source-analysis': {'adapter': 'analysis', 'actor': 'source-reader', 'model': 'fixture',
                 'processing_location': 'fixture', 'allowed_locations': ['fixture']}},
              'bindings': {rid: {'hypothesis': 'h', 'scope_ref': 'owned:public-docs', 'risk': 'reads_only',
                  'provider_argv': [sys.executable, '-c', script, '{public_query}', '{artifact_dir}']}}, 'output_dir': str(tmp_path / 'results')}
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    return loop, rid, config


def test_provider_then_read_source_review_creates_a_test_proposal(tmp_path):
    loop, rid, config = setup(tmp_path)
    save = lambda lp: lp.save(tmp_path / 'ledger')
    assert wd.run_ready(loop, tmp_path / 'ledger', config, persist=save)['state'] == 'completed'
    def review(prompt):
        assert 'official' in prompt and 'prerequisites' in prompt
        return {'operation': 'review', 'payload': {'decision': 'adopt', 'source_ids': ['official'],
                'reason': 'same release; fresh request separates cache from authorization',
                'question': 'Does the server return new protected content after revocation?', 'requires': []}}
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=save, spawn=review)
    assert result['state'] == 'completed' and result['result']['next_action'] == 'review_exploration'
    row = next(r for r in sources.project(loop) if r['request_id'] == rid)
    assert row['state'] == 'reviewed' and row['review']['basis'] == 'source-claimed'
    assert any(i['kind'] == 'exploration-review' for i in wc.frontier(loop))
    assert loop.capsule()['confirmed'] == {}
    request = next(e for e in loop.events if e['type'] == 'research_source_requested' and e['request_id'] == rid)
    assert 'customer' not in request['public_query'] and 'ExampleProduct' in request['public_query']
    assert sources.request(loop, question=request['question'], decision=request['decision'], excluded=request['excluded'], evidence=request['evidence']) == rid


@pytest.mark.parametrize('kind', ['search_snippet', 'model_summary'])
def test_search_snippet_is_not_an_accepted_read_source(tmp_path, kind):
    loop, rid, config = setup(tmp_path, retrieval_kind=kind)
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert result['state'] == 'failed'
    assert next(r for r in sources.project(loop) if r['request_id'] == rid)['state'] == 'retrieve'
    assert loop.capsule()['confirmed'] == {}


def test_no_sources_preserves_gap_and_wrong_version_cannot_be_adopted(tmp_path):
    loop, rid, config = setup(tmp_path, empty=True)
    wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))
    assert next(r for r in sources.project(loop) if r['request_id'] == rid)['state'] == 'insufficient'
    other = tmp_path / 'other'; other.mkdir()
    loop, rid, config = setup(other, version='0.9')
    wd.run_ready(loop, other / 'ledger', config, persist=lambda lp: lp.save(other / 'ledger'))
    row = next(r for r in sources.project(loop) if r['request_id'] == rid)
    with pytest.raises(ValueError, match='version'):
        wc.apply(loop, sources.card(row), 'review', {'decision': 'adopt', 'source_ids': ['official'],
                  'reason': 'old conditions differ', 'question': 'new test', 'requires': []})


def test_query_rejects_addresses_credentials_and_profile_change_stales_work(tmp_path):
    loop, rid, _ = setup(tmp_path)
    for term in ('https://private.invalid', '192.0.2.1', 'Bearer secret', 'a' * 40):
        if term == 'Bearer secret':
            term = 'token=synthetic-value'
        with pytest.raises(ValueError):
            sources.profile(loop, public_terms=[term], version='1.0', allowed_domains=['docs.example.org'])
    sources.profile(loop, public_terms=['ExampleProduct'], version='2.0', allowed_domains=['docs.example.org'])
    assert next(r for r in sources.project(loop) if r['request_id'] == rid)['stale']


def test_unknown_version_can_be_researched_but_cannot_support_adoption(tmp_path):
    loop, rid, config = setup(tmp_path, version='unknown', profile_version='unknown')
    assert wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'))['state'] == 'completed'
    row = next(r for r in sources.project(loop) if r['request_id'] == rid)
    with pytest.raises(ValueError, match='known applicable version'):
        wc.apply(loop, sources.card(row), 'review', {'decision': 'adopt', 'source_ids': ['official'],
                  'reason': 'unknown is not a version confirmation', 'question': 'test after identifying version', 'requires': []})
