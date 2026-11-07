"""Regression through the raw MCP boundary, signed ledger and real HTTP reader."""
import asyncio
import json
import time
import pytest
from test_task_audit_startup import audit_pool, installed, projects, start
from test_global_integration import structured
from test_development_risks import sample, scanner, observation
from test_dashboard_management import managed
from security_runtime.business_audit import operate, status
from security_runtime.development_risks import review_input_failure
from security_runtime.development_stop import native_closeout, closeout_message
from security_runtime.development_views import closeout_page
from security_runtime.dashboard_detail import detail
from security_runtime.dashboard_records import locate
from security_runtime.risk_management import revision


def test_grouped_audit_submission_first_save_before_scan_and_retry(audit_pool, projects, tmp_path, monkeypatch):
    config=tmp_path/'audit.toml';config.write_text('[agent]\naudit_business_logic=true\n')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG',str(config))
    pool, server, _ = audit_pool; root=projects[0]
    token=start(server,root,'flow-audit')['task_session_ref']
    from security_runtime.storage import SQLiteStore
    hooks=pool.children[root][1].store
    pool.children[root][1].runtime.store=SQLiteStore(hooks.directory.parent/'scans.db')
    (root/'sample.py').write_text('def legacy(orders, key, user):\n    return orders.get(key)\n')
    from security_runtime.mcp_tool_groups import ROUTES
    args=dict(workspace_path=str(root),session_ref=token)
    def call(name, **extra):
        result=asyncio.run(server.call_tool(ROUTES[name],dict(operation=name,arguments=dict(args,**extra))))
        data=structured(result)
        assert not getattr(result,'isError',False),data
        assert data.get('reason_code') is None,data
        return data
    ref=call('begin_development_check',task_key='flow-audit')['check_ref'];args['check_ref']=ref
    call('record_development_changes',paths=['sample.py'])
    job=call('manage_development_audit',action='prepare')
    call('manage_development_audit',action='started',audit_id=job['audit_id'],agent_ref='actual-fixture-child')
    value=dict(issue_key='ownership',file_path='sample.py',line_start=2,line_end=2,category='authorization',
        title='Missing ownership check',description='User ignored',impact='Other orders readable',fix_advice='Check owner',
        severity='HIGH',decision='CONFIRMED',rationale='Return ignores user',evidence_refs=job['evidence_refs'],
        report_text='**Missing ownership check**\n**问题** User ignored\n**可能影响** Read orders\n**建议修复** Check owner\n**尚未确认** Deployment')
    submission=dict(expected_seq=job['dirty_seq'],audit_id=job['audit_id'],observations=[value],
        business_reviews=[dict(file_path='sample.py',rationale='Checked paths',evidence_refs=job['evidence_refs'],limitations=[])],
        return_risks=True,response_view='final_report')
    assert review_input_failure(dict(args,**submission)) is None
    first=call('submit_development_review',**submission)
    assert first['review_saved'] and first['delivery_status']=='WAITING_FOR_STATIC_SCAN'
    assert 'report_text' not in first
    again=call('submit_development_review',**submission)
    assert first['review_progress']==again['review_progress']
    saved=call('get_development_risks',view='full')
    assert saved['total']==1 and saved['risks'][0]['assessment_count']==1
    assert saved['review_version_count']==1
    assert call('manage_development_audit',action='status')['status']=='COMPLETE'
    bad=review_input_failure(dict(args,**dict(submission,audit_id=123)))
    assert bad['field_errors'][0]['field']=='audit_id'
    assert 'observations' in bad['message']
    # No worker was launched by this development-time save.
    assert not first['scanner_run']


def test_partial_audit_preserves_finding_and_report_after_scan(sample,monkeypatch,tmp_path):
    root,service,ref,risks=sample
    from security_runtime import dashboard_service
    monkeypatch.setattr(dashboard_service,'directory',lambda:tmp_path/'dashboard')
    dashboard_service.save_endpoint(40000,'a'*32)
    job=operate(risks,'prepare');operate(risks,'started',job['audit_id'],'child')
    value=observation(risks,report_text='**Known risk**\n**问题** Detail\n**可能影响** Impact\n**建议修复** Bind\n**尚未确认** Deployment')
    risks.submit([value],1,audit_id=job['audit_id'],business_reviews=[dict(file_path='query.py',rationale='Audited',evidence_refs=job['evidence_refs'],limitations=['Deployment unknown'])])
    assert status(risks.current_check())['status']=='PARTIAL'
    scanner(sample,monkeypatch);risks.sync_scanner()
    monkeypatch.setattr('security_runtime.mcp_tools.presentation._agent_result',lambda *a,**kw:{'scan_id':'scan-1'})
    # Independently mark scanner review off to isolate business-only reporting.
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref);row['effective_config']['values']['agent']['review_scanner_findings']=False
        row.update(state='RESULTS_READY',finish_requested=True);service.store(root)._put(db,ref,row)
    page=risks.get(batch_version=(1,'scan-1'))
    assert 'Known risk' in page['report_text'] and '覆盖限制' in page['report_text'] and '本会话风险管理' in page['report_text']
    assert page['review_progress']['business_review']=='PENDING'
    result=native_closeout(service,root,risks.current_check(),time.monotonic()+1,set(),None)
    assert result['decision']=='block' and result['reason']==closeout_message(ref)
    delivered=closeout_page(risks,0,20)
    assert delivered['closeout_mode']=='REPORT' and 'Known risk' in delivered['report_text']
    assert delivered['session_url'] in delivered['report_text']
    assert native_closeout(service,root,risks.current_check(),time.monotonic()+1,set(),None) is None


def test_scanner_only_notice_is_bounded_without_faking_delivery(sample,monkeypatch):
    root,service,ref,risks=sample;scanner(sample,monkeypatch);risks.sync_scanner()
    monkeypatch.setattr('security_runtime.mcp_tools.presentation._agent_result',lambda *a,**kw:{'scan_id':'scan-1'})
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref);row['effective_config']['values']['agent']=dict(review_scanner_findings=False,audit_business_logic=False)
        row.update(state='RESULTS_READY',finish_requested=True);service.store(root)._put(db,ref,row)
    result=native_closeout(service,root,risks.current_check(),time.monotonic()+1,set(),None)
    assert result['decision']=='block' and result['reason']==closeout_message(ref)
    delivered=closeout_page(risks,0,20)
    assert delivered['closeout_mode']=='REPORT' and delivered['report_text']
    assert native_closeout(service,root,risks.current_check(),time.monotonic()+1,set(),None) is None
    assert not risks.load()['reviews'] and not risks.current_check().get('host_report_submitted')


def test_detail_preserves_code_identity_and_rejects_stale_request(managed):
    identifier,_,root=managed;_,row,rid=locate(identifier);rev=revision(row['risks'][rid])
    value=detail(identifier,rev)
    assert value['current']['matches_record'] and value['function']=='query'
    assert value['current']['lines'][1]['highlight'] and 'conn.execute' in value['current']['lines'][1]['text']
    (root/'query.py').write_text('password = "private-value"\ndef query():\n    return 1\n')
    value=detail(identifier,rev)
    assert not value['current']['matches_record'] and 'private-value' not in json.dumps(value)
    with pytest.raises(ValueError,match='VERSION_CONFLICT'):detail(identifier,'stale')
    with pytest.raises(ValueError):detail(identifier,rev,context=100)
    (root/'query.py').unlink();(root/'query.py').symlink_to('/etc/passwd')
    assert detail(identifier,rev)['current'] is None


def test_detail_http_auth_and_no_extra_path_parameter(managed):
    from test_dashboard_service import running,request
    from urllib.parse import urlencode
    identifier,_,_=managed;_,row,rid=locate(identifier)
    url='/api/detail?'+urlencode(dict(id=identifier,revision=revision(row['risks'][rid])))
    with running() as server:
        assert request(server,url)[0]==403
        headers={'Cookie':'dashboard='+server.token}
        assert request(server,url,headers)[0]==200
        assert request(server,url+'&path=/etc/passwd',headers)[0]==400


def test_detail_redacts_multiline_before_slicing_and_bounds_long_code(managed):
    identifier,_,root=managed;_,row,rid=locate(identifier);rev=revision(row['risks'][rid])
    (root/'query.py').write_text('private_key = """-----BEGIN PRIVATE KEY-----\nprivate-middle\n-----END PRIVATE KEY-----"""\npassword = "tiny"\nhtml = "<script>alert(1)</script>"\n'+'x'*900+'\n')
    result=detail(identifier,rev,context=0)
    assert 'private-middle' not in json.dumps(result)
    assert result['current']['lines'][0]['number']==2
    result=detail(identifier,rev,context=20)
    serialized=json.dumps(result)
    assert 'tiny' not in serialized and 'private-middle' not in serialized
    assert '<script>' in serialized  # JSON code is rendered through textContent.
    assert result['current']['lines'][-1]['truncated']
    assert max(len(v['text']) for v in result['current']['lines'])<=600


def test_deleted_resource_detail_is_inaccessible_until_restored(managed,monkeypatch,tmp_path):
    from security_runtime import dashboard_catalog, dashboard_entities, risk_dashboard
    identifier,_,_=managed;_,row,rid=locate(identifier);rev=revision(row['risks'][rid])
    monkeypatch.setattr(dashboard_catalog,'directory',lambda:tmp_path/'catalog')
    catalog=dashboard_catalog.Catalog();catalog.replace(risk_dashboard.records())
    target=dashboard_entities.listing(catalog,'project')['items'][0]
    request=dict(action='delete',kind='project',id=target['id'],expected_revision=target['revision'],request_id='delete-project')
    dashboard_entities.change(catalog,request)
    with pytest.raises(ValueError,match='NOT_VISIBLE'):detail(identifier,rev,catalog=catalog)
    trash=dashboard_entities.listing(catalog,'trash')['items'][0]
    dashboard_entities.change(catalog,dict(action='restore',kind='trash',id=trash['id'],expected_revision=trash['revision'],request_id='restore-project'))
    assert detail(identifier,rev,catalog=catalog)['current']['matches_record']


from test_development_check import check, execute


def test_large_project_only_scans_observed_file_and_zero_stop_is_silent(check,monkeypatch):
    root,service,_,counts=check
    historical=root/'historical';historical.mkdir()
    for index in range(3000):
        (historical/f'module{index}.ts').write_text('export const preserved = 1;\n')
    ref=service.begin(root,'large-normal-doc-change')['check_ref']
    service.record(root,ref,['app.ts'])
    execute(check,monkeypatch)
    assert counts['inputs']==[('app.ts',)] and counts['calls']==1
    result=service.get(root,ref)
    assert result['scope']['paths']==['app.ts']
    assert not result['development_result']['risks']
    # The single native test provider declares limited engine coverage. Keep
    # that real gap for this scope assertion, then isolate the zero-gap Stop.
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        row['result']['gaps']=[]
        service.store(root)._put(db,ref,row)
    assert native_closeout(service,root,service.store(root).load(ref,service.owner),time.monotonic()+1,set(),None) is None
    assert counts['calls']==1


def test_partial_audit_retry_preserves_one_judgment_and_releases_lease(sample,monkeypatch,tmp_path):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'private-lease'))
    _,_,_,risks=sample;job=operate(risks,'prepare')
    values=[observation(risks)]
    coverage=[dict(file_path='query.py',rationale='Only local source checked',evidence_refs=job['evidence_refs'],limitations=['Deployment'])]
    risks.submit(values,1,audit_id=job['audit_id'],business_reviews=coverage)
    risks.submit(values,1,audit_id=job['audit_id'],business_reviews=coverage)
    row=risks.load()
    assert len(row['reviews'])==1 and len(next(iter(row['risks'].values()))['assessments'])==1
    assert status(risks.current_check())['status']=='PARTIAL'
    from security_runtime.audit_leases import reserve
    reserve(tmp_path,{'host':'codex','session':'2'*64},'independent-1')
    reserve(tmp_path,{'host':'codex','session':'3'*64},'independent-2')


def test_parallel_child_turn_preserves_parent_stop_scope(check,monkeypatch):
    from security_runtime.development_check import record_hook
    from security_runtime.development_stop import fallback
    from test_development_check import OWNER
    root,service,_,counts=check
    ref=record_hook(service.hooks,root,OWNER,['app.ts'],event_id='parent-edit',turn_id='parent',scope_unknown=False,scan_path=service.scan_path(),launcher=lambda *a:None)['check_ref']
    record_hook(service.hooks,root,OWNER,[],prepare_only=True,turn_id='child',scope_unknown=False)
    # A child with no new edits cannot scan its parent's dirty files.
    assert fallback(service.hooks,root,OWNER,service=service,turn_id='child',automatic=True) is None
    # The parent's earlier pending turn survives the child's Stop.
    execute(check,monkeypatch)
    result=fallback(service.hooks,root,OWNER,service=service,turn_id='parent',automatic=True)
    assert result['status']=='STOP_RESULT_NOTICE'  # Single provider coverage gap.
    assert counts['calls']==1
    assert fallback(service.hooks,root,OWNER,service=service,turn_id='parent',automatic=True) is None
    # A later read-only turn cannot inherit that old eligibility.
    record_hook(service.hooks,root,OWNER,[],prepare_only=True,turn_id='later',scope_unknown=False)
    assert fallback(service.hooks,root,OWNER,service=service,turn_id='later',automatic=True) is None
    assert counts['calls']==1


def test_returning_parent_preserves_original_base_before_more_readonly_work():
    from security_runtime.development_check import note_activity
    row=note_activity(dict(dirty_seq=0),'parent');row['dirty_seq']=1
    row=note_activity(row,'child');assert row['stop_activity']['base_seq']==1
    row=note_activity(row,'parent');assert row['stop_activity']['base_seq']==0
    assert row['stop_activity_previous'][0]['base_seq']==1


def test_pending_scan_still_delivers_saved_business_once(sample, monkeypatch):
    root,service,ref,risks=sample
    job=operate(risks,'prepare');operate(risks,'started',job['audit_id'],'child')
    risks.submit([observation(risks,report_text='Saved full report')],1,audit_id=job['audit_id'],
        business_reviews=[dict(file_path='query.py',rationale='Checked',evidence_refs=job['evidence_refs'],limitations=[])])
    state=dict(status='RUNNING',dirty_seq=1,scanned_seq=0)
    monkeypatch.setattr(service,'finish',lambda *a:state)
    async def pending(*a,**kw):return state
    monkeypatch.setattr(service,'wait_saved',pending)
    result=native_closeout(service,root,risks.current_check(),time.monotonic(),set(),None)
    assert result['decision']=='block' and result['reason']==closeout_message(ref)
    delivered=closeout_page(risks,0,20)
    assert delivered['closeout_mode']=='INCOMPLETE'
    assert 'Saved full report' in delivered['report_text'] and '未取得' in delivered['report_text']
    assert delivered['next_action'] is None
    assert native_closeout(service,root,risks.current_check(),time.monotonic(),set(),None) is None
