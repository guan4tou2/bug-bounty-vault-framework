"""Credential references and bounded validation; raw values stay in an OS keyring.

No default passwords, cross-service guesses, redirect-success inference or Finding
promotion. Caller holds the canonical ledger lock and original operation authority.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from blocked_research import _proof, _required
from evidence_applicability import _time, latest_context
from evidence_refs import evidence_resolves

SERVICE = 'vault.research.credentials.v1'
MATCH = ('service', 'account_ref', 'role', 'tenant', 'scope_ref')


class KeyringStore:
    """Only explicitly supported OS-protected backends; no plaintext/null fallback."""
    def __init__(self):
        try:
            import keyring
            backend = keyring.get_keyring()
            name = type(backend).__module__ + '.' + type(backend).__name__
            if name not in {'keyring.backends.macOS.Keyring', 'keyring.backends.Windows.WinVaultKeyring',
                            'keyring.backends.SecretService.Keyring', 'keyring.backends.kwallet.DBusKeyring'}:
                raise ValueError('OS-protected keyring backend required')
            self.backend = backend
        except Exception:
            raise ValueError('supported OS keyring unavailable; no fallback storage') from None

    def put(self, reference, value):
        try:
            self.backend.set_password(SERVICE, reference, value)
        except Exception:
            raise ValueError('protected secret storage failed') from None

    def get(self, reference):
        try:
            return self.backend.get_password(SERVICE, reference)
        except Exception:
            raise ValueError('protected secret retrieval failed') from None


def _context(context):
    if not isinstance(context, dict) or set(context) != set(MATCH):
        raise ValueError('exact service/account/role/tenant/scope references required')
    _required(*(context[k] for k in MATCH))
    url = urlsplit(context['service'])
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in {'', '/'}:
        raise ValueError('credential service must be an explicit origin without userinfo or wildcards')
    if '*' in json.dumps(context):
        raise ValueError('wildcard credential reuse is prohibited')
    return dict(context)


def discover(loop, *, value, context, kind, evidence, expires_at, store=None):
    """Explicit structured discovery ingress; value is never appended or hashed alone."""
    context = _context(context)
    if kind not in {'bearer', 'api_key', 'password', 'session'} or not isinstance(value, str) or not 1 <= len(value.encode()) <= 8192 or '\x00' in value:
        raise ValueError('bounded supported credential value required')
    if _time(expires_at) <= datetime.now(UTC):
        raise ValueError('explicit future expiry required')
    proof = _proof(loop, evidence)
    secret_store = store or KeyringStore()
    for existing in project(loop.events, loop.base_path):
        if existing['context'] == context and existing['kind'] == kind and secret_store.get(existing['credential_ref']) == value:
            return existing['credential_ref']
    reference = 'credential:' + uuid.uuid4().hex
    secret_store.put(reference, value)
    loop.append('credential_discovered', credential_ref=reference, context=context, credential_kind=kind,
                evidence=proof, expires_at=expires_at, validation_limit=2)
    return reference


def capture(loop, artifact, pointer, *, context, kind, expires_at, store=None):
    """Opt-in JSON pointer extraction for parser/adapter ingress; never scans a wordlist."""
    path = Path(artifact)
    if not path.is_file() or path.stat().st_size > 1024 * 1024 or path.stat().st_mode & 0o077:
        raise ValueError('bounded private source artifact (0600) required')
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise ValueError('explicit JSON pointer required')
    value = json.loads(path.read_text())
    for part in pointer[1:].split('/'):
        key = part.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if isinstance(value, list) else value[key]
    return discover(loop, value=value, context=context, kind=kind, expires_at=expires_at,
                    evidence={'kind': 'artifact', 'path': str(path), 'applicability': {
                        **(latest_context(loop.events) or {}), 'observed_at': datetime.now(UTC).isoformat()}}, store=store)


def project(events, base=None, now=None):
    rows = {}
    for event in events:
        reference = event.get('credential_ref')
        if event['type'] == 'credential_discovered':
            rows[reference] = {**event, 'kind': event['credential_kind'], 'state': 'unvalidated', 'attempts': 0, 'permissions': []}
        elif reference in rows:
            if event['type'] == 'credential_validation_started':
                rows[reference].update(state='validating', attempts=rows[reference]['attempts'] + 1)
            elif event['type'] == 'credential_validated':
                rows[reference].update(state='valid', permissions=event['permissions'], validation_evidence=event['evidence'])
            elif event['type'] == 'credential_status':
                rows[reference].update(state=event['state'], permissions=[])
            elif event['type'] == 'credential_recovered':
                rows[reference].update(state='unvalidated', permissions=[], evidence=event['evidence'])
            elif event['type'] == 'credential_validation_failed':
                rows[reference].update(state='validation_blocked', permissions=[])
    instant = _time(now) if now else datetime.now(UTC)
    for row in rows.values():
        if instant >= _time(row['expires_at']):
            row.update(state='expired', permissions=[])
        if row['state'] == 'valid' and (not evidence_resolves(row.get('validation_evidence'), base, events)
                                      or not evidence_resolves(row['evidence'], base, events)):
            row.update(state='stale', permissions=[])
    return list(rows.values())


def select(loop, reference, context, *, validation=False):
    context = _context(context)
    row = next((r for r in project(loop.events, loop.base_path) if r['credential_ref'] == reference), None)
    if not row or row['context'] != context:
        raise ValueError('credential service/account/role/tenant/scope mismatch')
    allowed = {'unvalidated', 'invalid'} if validation else {'valid'}
    if row['state'] not in allowed or (validation and row['attempts'] >= row['validation_limit']):
        raise ValueError('credential is not eligible for this operation or validation budget is exhausted')
    if validation and any(r['context']['service'] == context['service'] and r['context']['account_ref'] == context['account_ref']
                          and r['state'] in {'rate_limited', 'locked'} for r in project(loop.events, loop.base_path)):
        raise ValueError('account validation stopped by rate-limit or lock signal')
    return row


def status(loop, reference, state, *, reason):
    if state not in {'revoked', 'invalid', 'rate_limited', 'locked'}:
        raise ValueError('explicit credential failure/revocation state required')
    _required(reason)
    row = next((r for r in project(loop.events, loop.base_path) if r['credential_ref'] == reference), None)
    if not row:
        raise ValueError('unknown credential reference')
    if row['state'] in {'revoked', 'expired'} and state != 'revoked':
        raise ValueError('revoked/expired credential cannot be revived')
    if row['state'] in {'locked', 'rate_limited'} and state == 'invalid':
        raise ValueError('fresh recovery evidence required after lock or rate limit')
    loop.append('credential_status', credential_ref=reference, state=state, reason=reason)
    loop.append('reassessment_trigger', reason='conditions_changed', scope='target')


def recover(loop, reference, *, evidence, changed_condition):
    row = next((r for r in project(loop.events, loop.base_path) if r['credential_ref'] == reference), None)
    _required(changed_condition)
    if not row or row['state'] not in {'locked', 'rate_limited', 'invalid', 'stale', 'validation_blocked', 'validating'} or row['attempts'] >= row['validation_limit']:
        raise ValueError('recoverable credential and remaining original validation budget required')
    from command_lifecycle import unresolved_actions
    if any(a.startswith(reference + ':') for a in unresolved_actions(loop.events)):
        raise ValueError('reconcile credential validation execution before recovery')
    proof = _proof(loop, evidence)
    if proof == row['evidence'] or proof == row.get('validation_evidence'):
        raise ValueError('new recovery evidence required')
    loop.append('credential_recovered', credential_ref=reference, evidence=proof, changed_condition=changed_condition)
    loop.append('reassessment_trigger', reason='conditions_changed', scope='target')


def validate(loop, ledger, reference, context, *, hyp_id, argv, output, permissions, scope_ref, store=None):
    """Run one operator-configured identity/permission adapter under existing gates."""
    row = select(loop, reference, context, validation=True)
    if scope_ref != context['scope_ref'] or row['kind'] == 'password':
        raise ValueError('matching scope and a session/token validation adapter required')
    if not isinstance(permissions, list) or not permissions or any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', p) for p in permissions):
        raise ValueError('explicit bounded permission checks required')
    check_destination(argv, context)
    secret = (store or KeyringStore()).get(reference)
    if not secret:
        raise ValueError('credential value unavailable')
    loop.append('credential_validation_started', credential_ref=reference)
    loop.save(ledger)
    from hunt_integration import execute_command
    action_id = reference + ':validate:' + str(row['attempts'] + 1)
    try:
        ok = execute_command(loop, ledger, hyp_id, action_id, argv, output, timeout=30, scope_ref=scope_ref,
                             _secret_env={'VAULT_CREDENTIAL': secret})
    except Exception as exc:
        loop.append('credential_validation_failed', credential_ref=reference, failure_class=type(exc).__name__)
        loop.save(ledger)
        return False
    if not ok:
        loop.append('credential_validation_failed', credential_ref=reference, failure_class='ExecutionFailed')
        loop.save(ledger)
        return False
    try:
        if not ok:
            raise ValueError('validation execution failed')
        observed = json.loads(Path(output).read_text())
        if observed.get('auth_status') in {'rate_limited', 'locked'}:
            status(loop, reference, observed['auth_status'], reason='validation adapter reported stop signal')
            return False
        if observed.get('auth_status') != 'authenticated' or observed.get('identity') != {k: context[k] for k in MATCH if k != 'scope_ref'}:
            raise ValueError('identity not established')
        if not set(permissions) <= set(observed.get('permissions', [])):
            raise ValueError('actual requested permissions not established')
        proof = _proof(loop, {'kind': 'artifact', 'path': str(output), 'applicability': {
            **(latest_context(loop.events) or {}), 'observed_at': datetime.now(UTC).isoformat()}})
        loop.append('credential_validated', credential_ref=reference, permissions=sorted(set(permissions)), evidence=proof)
        loop.append('reassessment_trigger', reason='capability_changed', scope='target')
        return True
    except (ValueError, OSError, TypeError):
        status(loop, reference, 'invalid', reason='identity/permission validation failed; no capability granted')
        return False
    finally:
        loop.save(ledger)


def capabilities(events, base=None):
    return {r['credential_ref'] + ':permission:' + p for r in project(events, base) if r['state'] == 'valid'
            for p in r['permissions']}


def resolve(loop, reference, context, *, permission, store=None):
    row = select(loop, reference, context)
    if permission not in row['permissions']:
        raise ValueError('requested permission was not established')
    value = (store or KeyringStore()).get(reference)
    if not value:
        raise ValueError('credential value unavailable')
    return value


def choose(loop, context, *, permission):
    context = _context(context)
    matches = [r['credential_ref'] for r in project(loop.events, loop.base_path)
               if r['state'] == 'valid' and r['context'] == context and permission in r['permissions']]
    if len(matches) != 1:
        raise ValueError('one unambiguous matching valid credential required')
    return matches[0]


def check_destination(argv, context):
    """Adapters must declare an explicit destination; program/egress gates also apply."""
    urls = [urlsplit(arg) for arg in argv if isinstance(arg, str) and arg.startswith(('https://', 'http://'))]
    service = urlsplit(_context(context)['service'])
    if not urls or any((u.scheme, u.hostname, u.port) != (service.scheme, service.hostname, service.port) or u.username or u.password for u in urls):
        raise ValueError('credential adapter destination must match the declared service exactly')


def inject(loop, declaration, argv, *, store=None):
    if not isinstance(declaration, dict) or set(declaration) != {'credential_ref', 'context', 'permission'}:
        raise ValueError('credential reference/context/permission declaration required')
    check_destination(argv, declaration['context'])
    secret = resolve(loop, declaration['credential_ref'], declaration['context'], permission=declaration['permission'], store=store)
    return {'VAULT_CREDENTIAL': secret}


def card(row):
    return {'schema': 1, 'kind': 'credential-validation', 'ref': row['credential_ref'],
            'credential_ref': row['credential_ref'], 'question': 'Verify credential identity and explicit permissions',
            'goal': 'Establish a scoped resource without creating a vulnerability verdict', 'context': row['context'],
            'next_action': 'validate_credential', 'facts': [], 'requires': [],
            'success': 'Saved identity and permission checks match the declared service/account/role/tenant',
            'stop': ['expiry', 'two validation attempts', 'rate limit or locked account', 'original authorization gates'],
            'budget_remaining': row['validation_limit'] - row['attempts'],
            'state_version': __import__('hashlib').sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()}


def main():
    import argparse
    import getpass
    import asg
    from hunt_loop import HuntLoop
    from hunt_lock import acquire, guarded_save, release
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('view')
    for name in ('capture', 'validate', 'discover', 'recover'):
        command = sub.add_parser(name); command.add_argument('--input', type=Path, required=True)
    revoke = sub.add_parser('status'); revoke.add_argument('credential_ref')
    revoke.add_argument('state', choices=['revoked', 'invalid', 'rate_limited', 'locked']); revoke.add_argument('--reason', required=True)
    args = parser.parse_args()
    ledger = asg.ledger_path(args.target)
    if args.command == 'view':
        loop = HuntLoop.load(ledger)
    else:
        token = acquire(ledger, 'credential-lifecycle')
        try:
            loop = HuntLoop.load(ledger)
            if args.command == 'status':
                status(loop, args.credential_ref, args.state, reason=args.reason)
            else:
                data = json.loads(args.input.read_text())
                if 'value' in data:
                    raise ValueError('raw values must use protected prompt or private capture, never metadata JSON')
                if args.command == 'discover':
                    discover(loop, value=getpass.getpass('Credential (stored in OS keyring): '), **data)
                elif args.command == 'capture':
                    capture(loop, **data)
                elif args.command == 'recover':
                    recover(loop, **data)
                else:
                    validate(loop, ledger, **data)
            guarded_save(loop, ledger, token)
        finally:
            release(ledger, token)
    print(json.dumps(project(loop.events, loop.base_path), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
