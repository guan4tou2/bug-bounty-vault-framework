"""`record-finding --amend` must be able to write every field delivery_gate demands.

Regression for a deadlock observed in practice:

  delivery_gate.inspect() reads `meta = {**doc, **record}` — the ledger record
  overrides the Finding file's frontmatter. It then requires `impact_result`
  and `verification_environment` for a `runtime-impact` claim. But the amend
  flag table carried neither field, and the Finding document itself is blocked
  for editing by delivery_ready_hook. Both write paths were closed, so the
  finding could never reach ready=true by any legal route.

These tests pin the write channel open. They assert the fields LAND, not that
any particular value passes — value ranges stay delivery_gate's job.
"""
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import asg  # noqa: E402

# Every field delivery_gate.py reads off `record` for a vulnerability report.
# Adding a requirement there without adding it here reopens the deadlock.
DELIVERY_FIELDS = {
    'impact-result': ('impact_result', 'achieved'),
    'verification-environment': ('verification_environment', 'stock_target'),
    'environment-equivalence-ref': ('environment_equivalence_ref', 'Notes/equiv.md'),
    'claim-scope': ('claim_scope', 'runtime-impact'),
    'finding-kind': ('finding_kind', 'vulnerability'),
    'observation-kind': ('observation_kind', 'data_access'),
}


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, 'vault_root', lambda: tmp_path)
    td = asg.target_dir('fixture')
    (td / 'Findings').mkdir(parents=True)
    (td / 'Findings/F-1.md').write_text(
        '---\nfinding_id: F-1\nstatus: verified\n---\n# Controlled fixture')
    return td


def _amend(target, *args):
    env = {**os.environ, 'VAULT_ROOT': str(target.parent.parent)}
    return subprocess.run(
        [sys.executable, str(Path(asg.__file__)), 'record-finding', 'fixture',
         'F-1', '--amend', *args],
        env=env, capture_output=True, text=True)


def _record(target):
    """Read the finding exactly the way delivery_gate.inspect() does."""
    state = asg.read_state('fixture')
    return next((f for f in state['findings'] if f.get('id') == 'F-1'), {})


@pytest.mark.parametrize('flag', sorted(DELIVERY_FIELDS))
def test_amend_writes_each_field_delivery_gate_reads(target, flag):
    """A field the gate requires must have at least one writable path."""
    asg.append_events('fixture', [('finding', {'finding_id': 'F-1'})])
    field, value = DELIVERY_FIELDS[flag]
    result = _amend(target, f'--{flag}', value)
    assert result.returncode == 0, result.stderr + result.stdout
    assert _record(target).get(field) == value, (
        f'--{flag} did not land as {field}; the delivery deadlock is back')


def test_amend_writes_the_whole_runtime_impact_set_in_one_call(target):
    """The real recovery path: one amend closing every runtime-impact gap."""
    asg.append_events('fixture', [('finding', {'finding_id': 'F-1'})])
    result = _amend(target,
                    '--claim-scope', 'runtime-impact',
                    '--finding-kind', 'vulnerability',
                    '--impact-result', 'achieved',
                    '--verification-environment', 'stock_target')
    assert result.returncode == 0, result.stderr + result.stdout
    record = _record(target)
    assert record.get('claim_scope') == 'runtime-impact'
    assert record.get('finding_kind') == 'vulnerability'
    assert record.get('impact_result') == 'achieved'
    assert record.get('verification_environment') == 'stock_target'


def test_amend_does_not_invent_fields_that_were_not_passed(target):
    """Negative fixture: opening the channel must not backfill anything."""
    asg.append_events('fixture', [('finding', {'finding_id': 'F-1'})])
    result = _amend(target, '--impact-result', 'achieved')
    assert result.returncode == 0, result.stderr + result.stdout
    record = _record(target)
    assert record.get('impact_result') == 'achieved'
    # The gate must still complain about the environment — amending one field
    # cannot silently satisfy the other, or the gate stops gating.
    assert 'verification_environment' not in record


def test_amend_preserves_finding_state(target):
    """Amending delivery fields must not reset the state machine."""
    asg.append_events('fixture', [('finding', {'finding_id': 'F-1'}),
                                  ('finding_state', {'finding_id': 'F-1', 'to': 'tested'})])
    result = _amend(target, '--impact-result', 'achieved')
    assert result.returncode == 0, result.stderr + result.stdout
    assert asg.finding_state('fixture', 'F-1') == 'tested'
