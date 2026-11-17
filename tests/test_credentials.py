"""Synthetic credentials only; fake protected store and real local child processes."""
import io
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import credentials as credentials
import work_dispatch as wd
from credential_output import SecretWriter
from hunt_integration import execute_command
from research_dependencies import project as impact
from tests import test_blocked_research as fixture

CONTEXT = {'service': 'https://fixture.invalid', 'account_ref': 'account:owned', 'role': 'member',
           'tenant': 'tenant:owned', 'scope_ref': 'owned:fixture'}
SECRET = 'synthetic-value-for-isolated-tests'


class Store:
    def __init__(self):
        self.values = {}
    def put(self, reference, value):
        self.values[reference] = value
    def get(self, reference):
        return self.values.get(reference)


def setup(tmp_path):
    loop, _ = fixture.setup(tmp_path)
    store = Store()
    source = tmp_path / 'private-source.json'; source.write_text(json.dumps({'access_token': SECRET})); source.chmod(0o600)
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    ref = credentials.capture(loop, source, '/access_token', context=CONTEXT, kind='bearer', expires_at=expires, store=store)
    loop.save(tmp_path / 'ledger')
    return loop, store, ref


def argv(status='authenticated', permission='read:own', role='member'):
    identity = {k: v for k, v in CONTEXT.items() if k != 'scope_ref'}; identity['role'] = role
    script = 'import os,json; print(json.dumps({"auth_status":' + repr(status) + ',"identity":' + repr(identity) + ',"permissions":[' + repr(permission) + '],"echo":os.environ["VAULT_CREDENTIAL"]}))'
    return [sys.executable, '-c', script, CONTEXT['service'] + '/identity']


def validate(loop, store, ref, tmp_path, **overrides):
    return credentials.validate(loop, tmp_path / 'ledger', ref, CONTEXT, hyp_id='h', argv=argv(**overrides),
        output=tmp_path / ('validation-' + str(len(loop.events)) + '.json'), permissions=['read:own'],
        scope_ref=CONTEXT['scope_ref'], store=store)


def test_discovery_deduplicates_without_leaking_or_granting_permission(tmp_path):
    loop, store, ref = setup(tmp_path)
    assert SECRET not in json.dumps(loop.events) and store.get(ref) == SECRET
    assert loop.capsule()['capabilities'] == [] and loop.capsule()['confirmed'] == {}
    duplicate = credentials.discover(loop, value=SECRET, context=CONTEXT, kind='bearer',
        evidence=credentials.project(loop.events, loop.base_path)[0]['evidence'],
        expires_at=(datetime.now(UTC) + timedelta(hours=2)).isoformat(), store=store)
    assert duplicate == ref and len(store.values) == 1


def test_actual_child_validation_unlocks_work_then_reuses_without_login(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    cap = ref + ':permission:read:own'
    loop.add_hypothesis('consumer', requires=[cap])
    assert 'consumer' in loop.capsule()['blocked_hypotheses']
    assert validate(loop, store, ref, tmp_path)
    assert 'consumer' in loop.capsule()['ready_hypotheses'] and loop.capsule()['confirmed'] == {}
    row = credentials.project(loop.events, loop.base_path)[0]
    assert SECRET not in Path(row['validation_evidence']['path']).read_text()
    assert Path(row['validation_evidence']['path']).stat().st_mode & 0o077 == 0
    monkeypatch.setattr(credentials, 'KeyringStore', lambda: store)
    declaration = {'credential_ref': ref, 'context': CONTEXT, 'permission': 'read:own'}
    assert execute_command(loop, tmp_path / 'ledger', 'consumer', 'reuse', argv(), tmp_path / 'reuse.json',
                           scope_ref=CONTEXT['scope_ref'], credential=declaration)
    assert credentials.project(loop.events, loop.base_path)[0]['attempts'] == 1
    assert SECRET not in (tmp_path / 'ledger').read_text() and SECRET not in (tmp_path / 'reuse.json').read_text()
    credentials.status(loop, ref, 'revoked', reason='controlled revocation fixture')
    assert cap not in loop.capsule()['capabilities'] and 'consumer' in loop.capsule()['blocked_hypotheses']
    assert 'hypothesis:consumer' in {r['ref'] for r in impact(loop)['affected']}
    with pytest.raises(ValueError):
        execute_command(loop, tmp_path / 'ledger', 'consumer', 'rejected-reuse', argv(), tmp_path / 'forbidden', credential=declaration)


@pytest.mark.parametrize('change', [{'status': 'redirect'}, {'role': 'admin'}, {'permission': 'unproven'}])
def test_status_or_role_or_permission_mismatch_never_grants_capability(tmp_path, change):
    loop, store, ref = setup(tmp_path)
    assert not validate(loop, store, ref, tmp_path, **change)
    assert loop.capsule()['capabilities'] == []


def test_lock_and_attempt_limit_stop_new_validation_and_expiry_withdraws_capability(tmp_path):
    loop, store, ref = setup(tmp_path)
    assert not validate(loop, store, ref, tmp_path, status='locked')
    with pytest.raises(ValueError):
        validate(loop, store, ref, tmp_path)
    unlock = tmp_path / 'unlock.txt'; unlock.write_text('external fixture unlock acknowledged')
    credentials.recover(loop, ref, evidence=fixture.artifact(unlock), changed_condition='explicit fixture unlock')
    assert not validate(loop, store, ref, tmp_path, role='wrong')
    with pytest.raises(ValueError):
        validate(loop, store, ref, tmp_path)


def test_expiry_withdraws_permission_without_modifying_verdicts(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    assert validate(loop, store, ref, tmp_path)
    future = datetime.now(UTC) + timedelta(hours=2)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future
    monkeypatch.setattr(credentials, 'datetime', Clock)
    assert credentials.project(loop.events, loop.base_path)[0]['state'] == 'expired'
    assert loop.capsule()['capabilities'] == [] and loop.capsule()['confirmed'] == {}
    assert credentials.project(loop.events, loop.base_path, now=datetime.now(UTC) + timedelta(days=1))[0]['state'] == 'expired'


def test_destination_and_tenant_mismatch_rejected_before_execution(tmp_path):
    loop, store, ref = setup(tmp_path)
    with pytest.raises(ValueError, match='mismatch'):
        credentials.select(loop, ref, {**CONTEXT, 'tenant': 'tenant:other'}, validation=True)
    with pytest.raises(ValueError, match='destination'):
        credentials.check_destination(['client', 'https://other.invalid/identity'], CONTEXT)
    assert not any(e['type'] == 'action_started' for e in loop.events)


def test_stream_redaction_covers_every_chunk_boundary():
    for split in range(len(SECRET) + 1):
        stream = io.BytesIO(); writer = SecretWriter(stream, [SECRET])
        writer.write(b'prefix ' + SECRET[:split].encode()); writer.flush()
        writer.write(SECRET[split:].encode() + b' suffix'); writer.write(b'', final=True)
        assert stream.getvalue() == b'prefix [credential redacted] suffix'


def test_dispatcher_consumes_credential_validation_card_without_model(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    monkeypatch.setattr(credentials, 'KeyringStore', lambda: store)
    config = {'workers': {'credential-validation': {'adapter': 'credential-validation', 'actor': 'identity-adapter'}},
              'bindings': {ref: {'hypothesis': 'h', 'scope_ref': CONTEXT['scope_ref'], 'risk': 'state_query',
                                 'argv': argv(), 'permissions': ['read:own']}}, 'output_dir': str(tmp_path / 'receipts')}
    result = wd.run_ready(loop, tmp_path / 'ledger', config, persist=lambda lp: lp.save(tmp_path / 'ledger'),
                          spawn=lambda _: pytest.fail('identity validation is a deterministic adapter'))
    assert result['state'] == 'completed' and result['result']['next_action'] == 'credential_ready'
    assert loop.capsule()['capabilities'] == [ref + ':permission:read:own']
    assert SECRET not in json.dumps(loop.events)


def test_reuse_failure_withdraws_capability_and_requires_matching_permission(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    assert validate(loop, store, ref, tmp_path)
    monkeypatch.setattr(credentials, 'KeyringStore', lambda: store)
    with pytest.raises(ValueError, match='permission'):
        credentials.resolve(loop, ref, CONTEXT, permission='admin:all', store=store)
    assert credentials.choose(loop, CONTEXT, permission='read:own') == ref
    declaration = {'credential_ref': ref, 'context': CONTEXT, 'permission': 'read:own'}
    assert not execute_command(loop, tmp_path / 'ledger', 'h', 'failed-reuse', argv(status='expired'),
                               tmp_path / 'failed-reuse.json', scope_ref=CONTEXT['scope_ref'], credential=declaration)
    assert loop.capsule()['capabilities'] == []
    assert 'hypothesis:h' in {r['ref'] for r in impact(loop)['affected']}


def test_tool_failure_is_blocked_validation_not_invalid_credentials(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    import hunt_integration
    def denied(*args, **kwargs):
        raise PermissionError('synthetic authorization stop')
    monkeypatch.setattr(hunt_integration, 'execute_command', denied)
    assert not validate(loop, store, ref, tmp_path)
    assert credentials.project(loop.events, loop.base_path)[0]['state'] == 'validation_blocked'
    recovery = tmp_path / 'recovery'; recovery.write_text('new fixture permission precondition')
    credentials.recover(loop, ref, evidence=fixture.artifact(recovery), changed_condition='original operation permission restored')
    assert credentials.project(loop.events, loop.base_path)[0]['attempts'] == 1


def test_model_uses_opaque_requirements_and_never_reads_credential_source(tmp_path):
    from dataclasses import asdict
    import work_cards as wc
    from logic_vuln_loop import Env, LogicHypothesis
    loop, store, ref = setup(tmp_path)
    loop.append('model_processing_authorization', allowed_locations=['fixture'], policy_ref='owned:fixture')
    required = ref + ':permission:read:own'
    source = dict(credentials.project(loop.events, loop.base_path)[0]['evidence'])
    copied = tmp_path / 'copied-source.json'; copied.write_bytes(Path(source['path']).read_bytes())
    source['path'] = str(copied)
    wc.propose_exploration(loop, question='Investigate after a scoped capability is acquired', reason='bounded fixture gap',
                           evidence=source, requires=[required])
    card = next(i['work_card'] for i in wc.frontier(loop) if i['kind'] == 'exploration-review')
    hyp = LogicHypothesis('followup', 'state', 'fixture invariant', Env('fixture-v1', 'member', 'fixture'),
                           'owned object', 'owner succeeds', 'read alternate', 'read owner', 'protected',
                           requires=['requirement:0'])
    def model(prompt):
        assert SECRET not in prompt and ref not in prompt and 'source withheld' in prompt
        return {'operation': 'review', 'payload': {'decision': 'adopt', 'reason': 'test after the original prerequisite',
                'evidence': 'evidence:0', 'hypothesis': asdict(hyp)}}
    wd._analyze(loop, card, {'model': 'fixture', 'processing_location': 'fixture', 'allowed_locations': ['fixture']}, model, lambda _: None)
    assert wc.adopted_hypothesis(loop, 'followup').requires == [required]
    assert 'followup' in loop.capsule()['blocked_hypotheses']


def test_new_reference_cannot_reset_same_account_attempt_budget(tmp_path):
    loop, store, ref = setup(tmp_path)
    assert not validate(loop, store, ref, tmp_path, role='wrong')
    assert not validate(loop, store, ref, tmp_path, role='wrong')
    row = credentials.project(loop.events, loop.base_path)[0]
    other = credentials.discover(loop, value='different-synthetic-fixture-value', context=CONTEXT, kind='bearer',
        evidence=row['evidence'], expires_at=row['expires_at'], store=store)
    with pytest.raises(ValueError, match='account validation budget'):
        validate(loop, store, other, tmp_path)
    assert sum(e['type'] == 'action_started' for e in loop.events) == 2


def test_unknown_credential_identity_is_not_a_validation_target(tmp_path):
    loop, store, ref = setup(tmp_path)
    with pytest.raises(ValueError, match='unknown'):
        credentials.select(loop, ref, {**CONTEXT, 'role': 'unknown'}, validation=True)


def test_unknown_owner_is_saved_then_bound_before_any_validation(tmp_path):
    loop, store, ref = setup(tmp_path)
    source = credentials.project(loop.events, loop.base_path)[0]['evidence']
    pending = credentials.discover(loop, value='unattributed-synthetic-fixture-value',
        context={**CONTEXT, 'service': 'unknown', 'account_ref': 'unknown', 'role': 'unknown'}, kind='bearer',
        evidence=source, expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(), store=store)
    assert store.get(pending) and not loop.capsule()['capabilities']
    with pytest.raises(ValueError):
        credentials.select(loop, pending, CONTEXT, validation=True)
    credentials.bind_context(loop, pending, context=CONTEXT, evidence=source, reason='owned fixture issuer and identity context')
    assert credentials.select(loop, pending, CONTEXT, validation=True)['attempts'] == 0
    with pytest.raises(ValueError, match='redirect'):
        credentials.bind_context(loop, pending, context={**CONTEXT, 'tenant': 'other'}, evidence=source, reason='incorrect new tenant')


def test_account_stop_survives_token_expiry_and_can_be_cleared_without_reviving_token(tmp_path, monkeypatch):
    loop, store, ref = setup(tmp_path)
    assert not validate(loop, store, ref, tmp_path, status='locked')
    future = datetime.now(UTC) + timedelta(hours=2)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future
    monkeypatch.setattr(credentials, 'datetime', Clock)
    row = credentials.project(loop.events, loop.base_path)[0]
    other = credentials.discover(loop, value='new-isolated-synthetic-value', context=CONTEXT, kind='bearer',
        evidence=row['evidence'], expires_at=(future + timedelta(hours=1)).isoformat(), store=store)
    with pytest.raises(ValueError, match='lock signal'):
        credentials.select(loop, other, CONTEXT, validation=True)
    proof = tmp_path / 'external-unlock'; proof.write_text('fresh fixture account unlock evidence')
    credentials.recover(loop, ref, evidence=fixture.artifact(proof), changed_condition='external account unlock')
    assert credentials.select(loop, other, CONTEXT, validation=True)['state'] == 'unvalidated'
    assert next(r for r in credentials.project(loop.events, loop.base_path) if r['credential_ref'] == ref)['state'] == 'expired'
