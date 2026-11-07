"""Management uses signed original risks; the SQL index is never a write authority."""
import json
import shutil
import subprocess
from pathlib import Path
import pytest
from test_development_risks import sample, scanner, observation
from security_runtime import dashboard_catalog, dashboard_records, risk_dashboard, user_config
from security_runtime.risk_management import revision
from security_runtime.project_identity import describe


@pytest.fixture
def managed(sample, monkeypatch, tmp_path):
    root, service, ref, risks = sample
    scanner(sample, monkeypatch)
    risk = risks.submit([observation(risks, same_issue_as='s1')], 1)['risks'][0]
    state = tmp_path/'global'
    wd = state/'global-workspaces'/describe(root)['workspace_id']
    shutil.copytree(service.hooks.directory, wd/'hooks')
    monkeypatch.setattr(risk_dashboard, 'STATE', state)
    identifier = ':'.join(('codex', wd.name, ref, risk['id']))
    return identifier, risks, root


def command(risk, action, key='request-0001', **extra):
    return dict(action=action, request_id=key, expected_revision=revision(risk), reason='User explanation', **extra)


def test_web_mutations_preserve_judgment_and_retry_once(managed):
    identifier, _, _ = managed
    _, row, rid = dashboard_records.locate(identifier)
    original = row['risks'][rid]
    request = command(original, 'EXCLUDE')
    first = dashboard_records.mutate(identifier, request)
    second = dashboard_records.mutate(identifier, request)
    assert first['saved'] and not first['repeated'] and second['repeated']
    _, saved, _ = dashboard_records.locate(identifier)
    risk = saved['risks'][rid]
    assert risk['decision'] == original['decision'] == 'CONFIRMED'
    assert risk['assessments'] == original['assessments'] and risk['finding'] == original['finding']
    assert risk['disposition'] == 'EXCLUDE' and len(risk['management']['history']) == 1
    with pytest.raises(ValueError, match='CONFLICT'):
        dashboard_records.mutate(identifier, command(original,'DEFER', key='request-0002'))
    dashboard_records.mutate(identifier, command(risk,'RESTORE',key='request-0003'))
    _, saved, _ = dashboard_records.locate(identifier)
    assert saved['risks'][rid]['disposition'] == 'ACTIVE'


def test_manual_and_archived_records_round_trip_without_losing_evidence(managed):
    identifier, _, _ = managed
    data = dict(anchor_id=identifier, request_id='manual-0001', finding=dict(title='Manual',
        file_path='query.py',line_start=2,line_end=2,severity='HIGH',category='manual',description='Supplied evidence'))
    result = dashboard_records.create(data)
    assert dashboard_records.create(data) == result
    _, row, rid = dashboard_records.locate(result['id'])
    dashboard_records.mutate(result['id'], command(row['risks'][rid],'ARCHIVE'))
    records = risk_dashboard.records()
    item = next(r for r in records['risks'] if r['id'] == result['id'])
    assert item['archived'] and item['decision'] is None and item['description'] == 'Supplied evidence'
    with pytest.raises(ValueError):
        dashboard_records.create(dict(data,finding=dict(data['finding'], file_path='../outside.py')))


def test_config_conflict_and_validation_preserve_last_saved(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG',str(tmp_path/'config.toml'))
    before = user_config.read_config()
    values = before['values']
    values['agent']['review_scanner_findings'] = False
    saved = user_config.save_config(values, before['revision'])
    assert saved['effective'] == 'NEXT_BATCH' and not user_config.read_config()['values']['agent']['review_scanner_findings']
    with pytest.raises(ValueError, match='CONFLICT'):
        user_config.save_config(values,before['revision'])
    values['scan']['discovery']['max_files'] = -1
    with pytest.raises(ValueError):
        user_config.save_config(values,saved['revision'])
    assert user_config.read_config()['revision'] == saved['revision']


def test_worktrees_group_project_keep_workspace_and_accept_old_links(tmp_path):
    root, work = tmp_path/'repo', tmp_path/'work'
    subprocess.run(['git','init','-q',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.email=test@example.invalid','-c','user.name=Test','commit','--allow-empty','-qm','initial'],check=True)
    subprocess.run(['git','-C',str(root),'worktree','add','-qb','fixture',str(work)],check=True)
    assert describe(root)['project_id'] == describe(work)['project_id']
    assert describe(root)['workspace_id'] != describe(work)['workspace_id']


def test_index_pagination_and_totals_share_identical_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_catalog, 'directory',lambda: tmp_path)
    catalog = dashboard_catalog.Catalog()
    rows = [dict(id=str(i),editor='codex',project='fixture',project_id='project',workspace_id='work',
        session_id='one' if i%2 else 'two',check_id='check',category='sql',severity='高',status='待处理',archived=False)
        for i in range(10000)]
    catalog.replace(dict(risks=rows,partial=False,note='Fixture'))
    result = catalog.query(dict(session='one',offset='50',limit='50'))
    assert result['total'] == 5000 and len(result['risks']) == 50 and result['next_offset'] == 100
    assert result['statistics']['status'] == {'待处理':5000}
    assert all(r['session_id']=='one' for r in result['risks'])
    assert catalog.query(dict(project='work'))['total']==10000
    assert catalog.query(dict(workspace='other'))['total']==0
    with pytest.raises(ValueError):
        catalog.query({'limit':'10000'})


def test_repair_selection_is_single_and_targets_original_owner(managed):
    from security_runtime.repair_notifications import offer
    from security_runtime.hook_state import HookStateStore
    identifier, _, root = managed
    wd,row,rid = dashboard_records.locate(identifier)
    request=command(row['risks'][rid],'REPAIR',fields={'target_host':'codex'})
    dashboard_records.mutate(identifier,request)
    dashboard_records.mutate(identifier,request)
    _,saved,_=dashboard_records.locate(identifier)
    assert saved['risks'][rid]['management']['repair_request']['status']=='AWAITING_HOST'
    hooks=HookStateStore(wd/'hooks')
    assert offer(hooks,root,dict(host='codex',session='b'*64)) is None
    message=offer(hooks,root,row['owner'])
    assert rid in message and 'prepare_development_risk_fix' in message
    assert 'get_development_risks(view="full")' in message
    assert 'get_development_risks(view="batch")' not in message
    assert offer(hooks,root,row['owner']) is None


def test_exports_preserve_locations_and_neutralize_csv_formulas(managed):
    from security_runtime.dashboard_export import render
    result=dict(risk_dashboard.records(),status='AVAILABLE')
    sarif=json.loads(render(result,'sarif')[1])
    assert sarif['version']=='2.1.0'
    assert sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']==2
    result['risks'][0]['title']='=HYPERLINK("https://foreign.invalid")'
    assert "'=HYPERLINK" in render(result,'csv')[1].decode()
    assert json.loads(render(result,'json')[1])['schema']=='ai-security-risks-v1'
    with pytest.raises(ValueError,match='INCOMPLETE'):
        render(dict(result,partial=True),'sarif')


def test_source_change_restores_web_disposition_for_reassessment(sample,monkeypatch):
    root,_,_,risks=sample
    scanner(sample,monkeypatch)
    item=risks.submit([observation(risks,same_issue_as='s1')],1)['risks'][0]
    rid=item['id']
    risks.manage(rid,command(risks.load()['risks'][rid],'EXCLUDE'))
    risks.sync_scanner()
    assert risks.load()['risks'][rid]['disposition']=='EXCLUDE'
    (root/'query.py').write_text('changed = True\n')
    risks.sync_scanner()
    risk=risks.load()['risks'][rid]
    assert risk['disposition']=='ACTIVE' and risk['management']['disposition_review_required']
    assert len(risk['management']['history'])==1
