"""Real ASG persistence, evidence changes, UI trace and concise report integration."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'automation'))
import asg
import next_work
from hunt_loop import HuntLoop
from hunt_integration import handoff
from research_delivery import project, render, render_document, check_document, export_document, plan_paths


def test_cli_check_binds_requested_report(env, monkeypatch, tmp_path):
    import research_delivery
    seed(env)
    output = tmp_path / 'export' / 'report.md'
    output.parent.mkdir()
    export_document(events(env), str(env[0]), 'report1', output)
    monkeypatch.setattr(sys, 'argv', ['research_delivery.py', str(env[0]), 'check', 'report1', '--body', str(output)])
    research_delivery.main()
    output.write_text(output.read_text().replace('撤銷分享後仍能下載私人文件', '未經審查的主張'))
    with pytest.raises(ValueError, match='requested target and report'):
        research_delivery.main()


@pytest.fixture
def env(tmp_path, monkeypatch):
    td = tmp_path / '01 - Targets' / 'demo'
    td.mkdir(parents=True)
    monkeypatch.setattr(asg, 'vault_root', lambda: tmp_path)
    monkeypatch.setattr(next_work, 'TARGETS', td.parent)
    asg.append_event(td, 'genesis', profile='web')
    asg.append_event(td, 'finding', finding_id='demo-find')
    evidence = td / 'observation.txt'
    evidence.write_text('Owned fixture only: A revokes B; B downloads a new server response.')
    finding = td / 'finding.md'
    finding.write_text('Fixture finding: known document ID; only two isolated test accounts.')
    proof = [{'path': str(evidence), 'locator': 'line 1'}]
    def record(kind, data, revision=None):
        asg.append_events(td, [('delivery_record', {'record_kind': kind, 'data': data,
                                                  'previous_revision': revision})])
    return td, evidence, finding, proof, record


def seed(env):
    td, evidence, finding, proof, record = env
    states = ['start', 'created', 'shared', 'revoked', 'checked']
    actions = ['A 從文件頁建立測試文件', 'A 分享給 B，B 正常開啟', 'A 撤銷 B 的分享', 'B 重新開啟文件']
    flow = {'id':'flow1', 'entry':'文件頁', 'initial_state':'start', 'states':states,
            'invariant':'撤銷後 B 不能重新取得文件', 'rule_source':'產品說明與正常對照',
            'evidence':proof, 'transitions':[{'id':f't{i}', 'from':states[i], 'to':states[i+1],
            'action':action, 'guard':'授權測試帳號', 'expected':'符合權限規則'} for i, action in enumerate(actions)]}
    record('flow', flow)
    trace = {'id':'trace1', 'flow_id':'flow1', 'finding_id':'demo-find', 'mode':'ui',
             'actor':'獨立測試帳號 A 與 B', 'environment':'隔離 fixture v1',
             'preconditions':'建立兩個互不共享組織權限的帳號', 'data_origin':'A 建立文件後取得連結；已知 ID 是前提',
             'expected':'B 被拒絕重新下載', 'actual':'撤銷後 B 仍取得新的文件回應',
             'impact':'一般成員仍可讀取已撤銷分享的私人文件', 'limitations':'只驗證兩個測試帳號，不宣稱可枚舉其他 ID',
             'producer':'executor-A', 'steps':[{'transition_id':f't{i}', 'action':a,
             'observed':f'fixture step {i}', 'phase':p, 'evidence':proof}
             for i,(a,p) in enumerate(zip(actions,['setup','control','trigger','observe']))]}
    record('trace', trace)
    report = {'id':'report1', 'trace_id':'trace1', 'finding_id':'demo-find',
              'title':'撤銷分享後仍能下載私人文件', 'summary':trace['impact'],
              'remediation':'下載時重新檢查目前分享權限。',
              'finding_document':[{'path':str(finding), 'locator':'whole fixture'}],
              'attachments':[{'path':str(evidence), 'locator':'line 1', 'label':'受控測試結果', 'filename':'result.txt'}],
              'reviewer':'independent-B', 'review_result':'pending'}
    record('report', report)
    pending = project(events(env))['report'][0]
    review = td / 'review.json'
    review.write_text(json.dumps({'report_id':'report1','content_revision':pending['content_revision'],
        'reviewer':'independent-B','result':'passed','reproduction_checked':True}))
    report.update(review_result='passed',review_evidence=[{'path':str(review),'locator':'whole receipt'}])
    record('report', report, pending['revision'])
    return flow, trace, report


def events(env):
    return HuntLoop.load(asg.ledger_path(env[0])).events


def test_round_trip_snapshot_handoff_report_and_no_promotion(env):
    seed(env)
    body = render(events(env), 'report1', ready=True)
    assert body.startswith('# 撤銷分享後仍能下載私人文件\n\n## 問題與影響')
    assert body.count('\n## ') == 6
    assert '1. A 從文件頁建立' in body and '必要資料取得方式' in body
    assert str(env[1]) not in body and 'demo-find' not in body
    assert not any(e['type'] in {'verdict','finding_state'} for e in events(env))
    assert len(json.loads(asg.write_snapshot(env[0]).read_text())['research_delivery']['trace']) == 1
    assert 'Finding management and report provenance' in asg.project_markdown(env[0]).read_text()
    assert len(handoff(HuntLoop.load(asg.ledger_path(env[0])))['research_delivery']['report']) == 1


def test_stale_evidence_blocks_render_and_surfaces_work(env):
    seed(env)
    env[1].write_text('changed')
    with pytest.raises(ValueError, match='stale'):
        render(events(env), 'report1')
    assert any(w['kind'] == 'delivery-evidence' for w in next_work.compute('demo')['next_work'])


def test_finding_change_invalidates_report(env):
    seed(env)
    env[2].write_text('claim changed')
    with pytest.raises(ValueError, match='stale'):
        render(events(env), 'report1', ready=True)


def test_invalid_order_missing_origin_and_no_control_rejected(env):
    _, trace, _ = seed(env)
    for change in ('order','origin','control'):
        data = copy.deepcopy(trace); data['id'] = change
        if change == 'order': data['steps'].reverse()
        if change == 'origin': data['data_origin'] = ''
        if change == 'control': data['steps'][1]['phase'] = 'setup'
        before = len(events(env))
        with pytest.raises(ValueError): env[4]('trace', data)
        assert len(events(env)) == before


def test_review_required_no_self_review_and_concurrent_amend_guard(env):
    _, _, report = seed(env)
    data = dict(report, id='pending', review_result='pending')
    env[4]('report', data)
    render(events(env), 'pending')
    with pytest.raises(ValueError, match='independent review required'):
        render(events(env), 'pending', ready=True)
    with pytest.raises(ValueError, match='self review'):
        env[4]('report', dict(report, id='self', reviewer='executor-A'))
    with pytest.raises(ValueError, match='previous_revision'):
        env[4]('report', dict(report, title='changed'))


def test_groups_instances_retests_and_work_are_separate(env):
    seed(env)
    record = env[4]; proof = env[3]
    for i, role in [('I1','member'),('I2','admin')]:
        record('instance', {'id':i,'finding_id':'demo-find','asset':'fixture', 'version':'1',
                            'role':role,'relation':'cross-tenant','confirmation':'observed','evidence':proof})
    record('group', {'id':'G1','basis':'similarity','reason':'same feature','members':['finding:demo-find','candidate:x']})
    record('retest', {'id':'R1','instance_id':'I1','event_kind':'vendor-claim', 'occurred_at':'2026-11-16',
                      'result':'claimed-fixed','conditions':'vendor statement only','evidence':proof})
    bad = {'id':'R2','instance_id':'I1','event_kind':'retest','occurred_at':'2026-11-16',
           'result':'recurrence','conditions':'same environment','evidence':proof,'previous_retest_id':'R1'}
    with pytest.raises(ValueError, match='prior successful'): record('retest', bad)
    record('retest', dict(bad, result='inconclusive'))
    with pytest.raises(ValueError, match='immutable'): record('retest', dict(bad, result='still-vulnerable'))
    work = {'id':'W1','finding_id':'demo-find','kind':'retest','state':'open','reason':'Verify vendor claim'}
    record('task',work)
    assert any(w['kind'] == 'finding-work' for w in next_work.compute('demo')['next_work'])
    view = project(events(env)); rev = view['task'][0]['revision']
    record('task', dict(work,state='done',evidence=proof),rev)
    view = project(events(env))
    assert len(view['instance']) == 2 and len(view['retest']) == 2 and not view['queue']


def test_flow_amend_invalidates_old_trace(env):
    flow, _, _ = seed(env)
    rev = project(events(env))['flow'][0]['revision']
    env[4]('flow', dict(flow,invariant='changed requirement'),rev)
    with pytest.raises(ValueError, match='stale'): render(events(env),'report1')


def test_public_document_gate_detects_edits_and_canonical_finding_changes(env):
    seed(env)
    out = env[0] / 'report.md'
    export_document(events(env), 'demo', 'report1', out)
    assert check_document(out).startswith('PASS')
    original = out.read_text()
    out.write_text(original.replace('一般成員仍可讀取', '所有人都可以讀取'))
    with pytest.raises(ValueError, match='differs'): check_document(out)
    out.write_text(original)
    asg.append_event(env[0], 'finding_state', finding_id='demo-find', to='withdrawn')
    with pytest.raises(ValueError, match='stale'): check_document(out)


def test_legacy_report_not_misrepresented_as_verified(env):
    out = env[0] / 'old.md'; out.write_text('# Old wrapper')
    assert check_document(out).startswith('LEGACY')


def test_plans_are_not_execution_and_export_preserves_files(env):
    seed(env)
    planned = plan_paths(events(env), 'flow1', 2)
    assert len(planned['plans']) == 2 and len(planned['unreached']) == 2
    assert all(p['status'] == 'planned' for p in planned['plans'])
    out = env[0] / 'draft.md'
    export_document(events(env), 'demo', 'report1', out)
    original = out.read_text()
    with pytest.raises(ValueError, match='exists'): export_document(events(env), 'demo','report1',out)
    assert out.read_text() == original
    next(env[0].glob('evidence-*/result.txt')).unlink()
    with pytest.raises(ValueError, match='attachment'): check_document(out)


def test_old_review_cannot_authorize_new_wording(env):
    _, _, report = seed(env)
    old = project(events(env))['report'][0]
    with pytest.raises(ValueError, match='does not attest'):
        env[4]('report',dict(report,summary='different impact'),old['revision'])
