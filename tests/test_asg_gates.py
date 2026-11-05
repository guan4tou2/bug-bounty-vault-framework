"""Gates must distinguish membership, modelling, proof, and projection freshness."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import asg
import asg_checks
import capability_view
import check_asg_drift
from ledger_reader import LedgerReadError

@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(asg, 'vault_root', lambda: tmp_path)
    td = asg.target_dir('fixture')
    (td / 'Findings').mkdir(parents=True)
    (td / 'Findings/F-1.md').write_text('---\nfinding_id: F-1\nstatus: verified\nvuln_class: Access Control\nprovides: [read]\n---\n# Controlled fixture')
    return td


def model(target, confirmed=True):
    events=[('surface', {'name':'endpoint','untested':False}),
            ('finding', {'finding_id':'F-1','resolves':['endpoint'],'provides':['read']}),
            ('hypothesis', {'id':'finding:F-1','requires':[]})]
    if confirmed:
        events.append(('verdict', {'hypothesis':'finding:F-1','status':'confirmed',
                                 'evidence':{'kind':'observation','text':'controlled fixture private record'},'provides':['read']}))
    asg.append_events('fixture',events)


def test_ledger_only_gate_does_not_need_yaml_or_markdown(target):
    model(target)
    result=asg_checks.coverage('fixture')
    assert result['represented']==1 and result['coverage_percent']==100
    assert result['missing_findings']==result['unmodelled_findings']==result['proof_pending']==[]
    assert result['source']=='ledger'


def test_stub_is_present_but_not_modelled_or_confirmed(target, capsys):
    asg.append_event('fixture','finding',finding_id='F-1')
    result=asg_checks.coverage('fixture')
    assert result['missing_findings']==[] and result['represented']==1
    assert result['unmodelled_findings']==result['proof_pending']==['F-1']
    state=asg.read_state('fixture')
    capability_view.mode_chains([],[],state['findings'],False)
    output=capsys.readouterr().out
    assert '入口點（requires 僅初始能力）：0' in output
    assert '尚無有效 confirmed' in output


def test_stale_yaml_cannot_hide_missing_ledger_entry(target):
    asg.append_event('fixture','surface',name='endpoint')
    asg.markdown_path('fixture').write_text('```yaml\nfindings:\n- id: F-1\n  status: validated\n  provides: [read]\n```\n')
    assert asg_checks.coverage('fixture')['missing_findings']==['F-1']
    assert check_asg_drift.drift('fixture')['missing_findings']==['F-1']


def test_legacy_gate_remains_readable_and_does_not_create_ledger(target):
    asg.markdown_path('fixture').write_text('```yaml\nnodes:\n- id: endpoint\n  identifier: /fixture\nfindings:\n- id: F-1\n  on_node: endpoint\n  status: validated\n  provides: [read]\n  requires: []\n```\n')
    result=asg_checks.coverage('fixture')
    assert result['source']=='legacy' and not result['unmodelled_findings']
    assert not asg.ledger_path('fixture').exists()


def test_chain_gate_uses_effective_edges_without_chain_document(target):
    model(target)
    asg.append_events('fixture', [('hypothesis',{'id':'dependent','requires':['read']}),
                                 ('verdict',{'hypothesis':'dependent','status':'confirmed','provides':['write'],
                                             'evidence':{'kind':'observation','text':'controlled fixture dependent write'}})])
    assert len(asg_checks.chains('fixture')['chain_edges'])==1
    asg.append_event('fixture','revoke',cap='read',reason='fixture rotation')
    assert asg_checks.chains('fixture')['chain_edges']==[]
    assert asg_checks.capabilities('fixture')['blocked_requires']==['read']


def test_drift_ignores_stale_yaml_but_detects_current_projection(target):
    model(target)
    asg.markdown_path('fixture').write_text('```yaml\nfindings:\n- id: STALE-1\n```\n')
    result=check_asg_drift.drift('fixture')
    assert result['missing_findings']==[] and len(result['stale_projections'])==2
    asg.project_markdown('fixture');asg.write_snapshot('fixture')
    assert check_asg_drift.drift('fixture')['stale_projections']==[]
    asg.append_event('fixture','hypothesis',id='new-pending',requires=[])
    assert len(check_asg_drift.drift('fixture')['stale_projections'])==2


def test_all_gates_fail_closed_on_corrupt_ledger(target):
    led=asg.ledger_path('fixture');led.parent.mkdir()
    led.write_text('{bad json}\n')
    for read in (asg_checks.coverage, asg_checks.chains, asg_checks.capabilities, check_asg_drift.drift):
        with pytest.raises(LedgerReadError):read('fixture')
    env={**os.environ,'VAULT_ROOT':str(target.parent.parent)}
    scripts=[('check_asg_coverage.sh','bash'),('check_chain_assembly.sh','bash'),
             ('check_capability_integrity.sh','bash'),('check_asg_drift.py',sys.executable),
             ('check_asg_status_consistency.py',sys.executable),('check_path_integrity.py',sys.executable)]
    for script,runner in scripts:
        result=subprocess.run([runner,str(Path(asg.__file__).parent/script),'fixture'],env=env,capture_output=True,text=True)
        assert result.returncode!=0,script


def test_finding_amendment_preserves_canonical_query_state(target):
    asg.append_events('fixture',[('finding',{'finding_id':'F-1'}),('finding_state',{'finding_id':'F-1','to':'tested'}),
                                 ('finding',{'finding_id':'F-1','severity':'P2'})])
    assert asg.finding_state('fixture','F-1')=='tested'


def test_chains_cli_handles_an_existing_ledger(target):
    model(target)
    env={**os.environ,'VAULT_ROOT':str(target.parent.parent)}
    result=subprocess.run([sys.executable,str(Path(asg.__file__)),'chains','fixture'],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert isinstance(json.loads(result.stdout),dict)


@pytest.mark.parametrize('stage',['hypothesis','tested','adversary-verified','confirmed'])
def test_status_sensor_distinguishes_workflow_progress_from_contradiction(target,stage):
    model(target)
    asg.append_event('fixture','finding_state',finding_id='F-1',to=stage)
    env={**os.environ,'VAULT_ROOT':str(target.parent.parent)}
    result=subprocess.run([sys.executable,str(Path(asg.__file__).parent/'check_asg_status_consistency.py'),'fixture'],env=env,capture_output=True,text=True)
    assert result.returncode==0,result.stderr+result.stdout
    assert '真矛盾 0 筆' in result.stdout


def test_consistency_matches_file_by_doc_link_not_only_id(target):
    """A ledger finding whose id differs from the file's finding_id (e.g. a migration
    slug-id) but which links to the file via `doc` must be matched through the link, not
    reported as a phantom/contradiction. 2026-10-09: this blind spot (id-only match) made
    one target's slug-id findings look like drift and drove a duplicate「fix」."""
    env = {**os.environ, 'VAULT_ROOT': str(target.parent.parent)}
    cons = Path(asg.__file__).parent / 'check_asg_status_consistency.py'
    # slug-id finding, no id match, linked to the verified F-1.md via doc, at tested
    asg.append_events('fixture', [
        ('finding', {'finding_id': 'svc-slug-x', 'doc': 'Findings/F-1.md'}),
        ('finding_state', {'finding_id': 'svc-slug-x', 'to': 'tested'})])
    r = subprocess.run([sys.executable, str(cons), 'fixture'], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
    assert '真矛盾 0 筆' in r.stdout                      # tentative vs confirmed = 圖落後, not contradiction
    assert 'svc-slug-x' in r.stdout                       # matched via doc-link (not dropped as phantom)
    # a withdrawn slug-finding linked to the same verified file asserts nothing → skipped
    asg.append_events('fixture', [
        ('finding', {'finding_id': 'svc-slug-y', 'doc': 'Findings/F-1.md'}),
        ('finding_state', {'finding_id': 'svc-slug-y', 'to': 'withdrawn'})])
    r = subprocess.run([sys.executable, str(cons), 'fixture'], env=env, capture_output=True, text=True)
    assert '真矛盾 0 筆' in r.stdout and 'svc-slug-y' not in r.stdout


def test_imported_finding_hypothesis_counts_as_membership_but_not_proof(target):
    asg.append_events('fixture',[('hypothesis',{'id':'finding:F-1','requires':[]}),
                                 ('verdict',{'hypothesis':'finding:F-1','status':'confirmed','evidence':'F-1','provides':['read']})])
    result=asg_checks.coverage('fixture')
    assert result['missing_findings']==[] and result['proof_pending']==['F-1']
    assert asg.read_state('fixture')['capsule']['capabilities']==[]
