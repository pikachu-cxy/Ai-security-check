"""Short notices route saved batches without launching or waiting for scans."""
import time
import pytest
from test_development_risks import sample,scanner,observation
from security_runtime.development_stop import native_closeout,incomplete_notice,closeout_message
from security_runtime.development_views import closeout_page
from security_runtime.development_risks import DevelopmentRiskError


def ready(sample,monkeypatch,review=True):
    root,service,ref,risks=sample
    scanner(sample,monkeypatch);risks.sync_scanner()
    monkeypatch.setattr('security_runtime.mcp_tools.presentation._agent_result',lambda *a,**kw:{'scan_id':'scan-1'})
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        row['effective_config']['values']['agent']=dict(review_scanner_findings=review,audit_business_logic=False)
        service.store(root)._put(db,ref,dict(row,state='RESULTS_READY',finish_requested=True))


@pytest.mark.parametrize('review',[True,False])
def test_identical_notice_and_correct_internal_mode(sample,monkeypatch,tmp_path,review):
    root,service,ref,risks=sample
    from security_runtime import dashboard_service
    monkeypatch.setattr(dashboard_service,'directory',lambda:tmp_path/'dashboard')
    dashboard_service.save_endpoint(40000,'a'*32)
    ready(sample,monkeypatch,review)
    result=native_closeout(service,root,risks.current_check(),time.monotonic(),set(),None)
    assert result['reason']==closeout_message(ref)
    page=closeout_page(risks,0,20)
    assert page['closeout_mode']==('REVIEW' if review else 'REPORT')
    assert page['session_url']
    if review:
        assert page['candidates'][0]['same_issue_as'] and page['evidence']
    else:
        assert '未经 Agent' in page['report_text'] and page['session_url'] in page['report_text']
        assert 'evidence' not in page
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        service.store(root)._put(db,ref,dict(row,dirty_seq=2))
    with pytest.raises(DevelopmentRiskError,match='VERSION_STALE'):closeout_page(risks,0,20)


@pytest.mark.parametrize('review',[True,False])
def test_scan_finishes_after_notice_resolves_same_edit_batch(sample,monkeypatch,review):
    root,service,ref,risks=sample
    assert incomplete_notice(service,root,ref,1,{})['reason']==closeout_message(ref)
    assert incomplete_notice(service,root,ref,1,{}) is None
    ready(sample,monkeypatch,review)
    page=closeout_page(risks,0,20)
    assert page['closeout_mode']==('REVIEW' if review else 'REPORT')
    assert page['scan_id']=='scan-1'


def test_incomplete_does_not_wait_or_claim_clean(sample):
    root,service,ref,risks=sample
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        service.store(root)._put(db,ref,dict(row,scope_unknown=True,file_watch_gaps=['FILE_WATCH_INTERRUPTED']))
    incomplete_notice(service,root,ref,1,{})
    page=closeout_page(risks,0,20)
    assert page['closeout_mode']=='INCOMPLETE' and not page['scanner_run']
    assert page['next_action'] is None and page['gaps']==['STATIC_SCAN_INCOMPLETE','FILE_WATCH_INTERRUPTED']
    assert '不能判定' in page['report_text']
    assert '文件变更收集存在缺口' not in page['report_text']


@pytest.mark.parametrize('status', ['NO_OBSERVED_CHANGES', 'RESULTS_READY'])
def test_watch_uncertainty_alone_does_not_request_report_or_scan(status):
    from types import SimpleNamespace
    state=dict(status=status,dirty_seq=1,scanned_seq=1,scope=dict(scope_unknown=True),gaps=[],
        development_result=dict(review_progress=dict(pending_scanner_ids=[],pending_business_paths=[]),
                                risks=[],next_offset=None))
    service=SimpleNamespace(get=lambda *args: state)
    row=dict(check_ref='check',dirty_seq=1,finish_requested=True)
    assert native_closeout(service,None,row,time.monotonic(),set(),None) is None


def test_report_pagination_keeps_pinned_batch_and_link(sample,monkeypatch,tmp_path):
    root,service,ref,risks=sample
    ready(sample,monkeypatch,False)
    from security_runtime import dashboard_service
    monkeypatch.setattr(dashboard_service,'directory',lambda:tmp_path/'dashboard')
    dashboard_service.save_endpoint(40000,'a'*32)
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        from copy import deepcopy
        entries=row['security_result']['risks'];second=deepcopy(next(iter(entries.values())))
        second['id']='second';entries['second']=second
        service.store(root)._put(db,ref,row)
    native_closeout(service,root,risks.current_check(),time.monotonic(),set(),None)
    first=closeout_page(risks,0,1);args=first['next_action']['arguments']
    assert args['view']=='closeout' and args['expected_seq']==1 and args['scan_id']=='scan-1'
    second=closeout_page(risks,args['offset'],args['limit'],expected_seq=args['expected_seq'],scan_id=args['scan_id'])
    assert first['risks'][0]['id']!=second['risks'][0]['id']
    assert first['session_url']==second['session_url']
    assert second['next_offset'] is None and second['next_action'] is None


def test_published_but_unavailable_results_keep_incomplete_report(sample,monkeypatch):
    root,service,ref,risks=sample
    incomplete_notice(service,root,ref,1,{})
    ready(sample,monkeypatch,False)
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        service.store(root)._put(db,ref,dict(row,risk_import_status='UNAVAILABLE'))
    page=closeout_page(risks,0,20)
    assert page['closeout_mode']=='INCOMPLETE' and page['next_action'] is None
    assert '不能判定' in page['report_text']
