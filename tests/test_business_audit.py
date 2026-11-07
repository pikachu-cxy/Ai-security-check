"""Actual evidence validation for early audit completion and invalidation."""
import pytest
from test_development_risks import sample, scanner
from security_runtime.business_audit import operate, status
from security_runtime.development_risks import review_progress


@pytest.fixture(autouse=True)
def isolated_leases(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'data'))


def test_early_business_audit_survives_later_scan_on_same_version(sample, monkeypatch):
    root, service, ref, risks = sample
    job = operate(risks, 'prepare')
    assert job['status']=='READY' and job['evidence']
    assert operate(risks,'prepare')['audit_id']==job['audit_id']
    operate(risks,'started',job['audit_id'], 'host-child-1')
    result = risks.submit([],1,audit_id=job['audit_id'],business_reviews=[dict(file_path='query.py',
        rationale='Reviewed authorization and input', evidence_refs=job['evidence_refs'], limitations=[])])
    assert status(risks.current_check())['status']=='COMPLETE'
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    progress=review_progress(risks.current_check(),risks.load())
    assert progress['business_review']=='COMPLETE' and progress['scanner_review']=='PENDING'
    service.record(root,ref,['query.py'])
    assert status(risks.current_check())['status']=='NEEDS_REVIEW'
    assert review_progress(risks.current_check(),risks.load())['pending_business_paths']==['query.py']
    with pytest.raises(ValueError,match='STALE'):
        risks.submit([],1,audit_id=job['audit_id'])


def test_cancelled_child_cannot_publish_same_version(sample):
    risks=sample[3]
    job=operate(risks,'prepare')
    operate(risks,'cancel',job['audit_id'])
    with pytest.raises(ValueError,match='STALE'):
        risks.submit([],1,audit_id=job['audit_id'],business_reviews=[])
    next_job=operate(risks,'prepare')
    assert next_job['audit_id'] != job['audit_id']
    assert operate(risks,'unsupported',next_job['audit_id'])['status']=='UNSUPPORTED'


def test_changed_evidence_without_edit_receipt_rejects_child_result(sample):
    root,_,_,risks=sample
    job=operate(risks,'prepare')
    (root/'query.py').write_text('changed = True\n')
    with pytest.raises(ValueError):
        risks.submit([],1,audit_id=job['audit_id'],business_reviews=[dict(file_path='query.py',rationale='Reviewed',
            evidence_refs=job['evidence_refs'],limitations=[])])
    assert status(risks.current_check())['status']=='READY'


def test_fast_closeout_keeps_incomplete_audit_explicit_and_wait_mode_blocks(sample, monkeypatch):
    import time
    from test_development_risks import observation
    from security_runtime.development_stop import native_closeout
    root,service,ref,risks=sample
    scanner(sample,monkeypatch)
    monkeypatch.setattr('security_runtime.mcp_tools.presentation._agent_result',lambda *a,**kw: {'scan_id':'scan-1'})
    risks.submit([observation(risks,same_issue_as='s1',report_text='Confirmed fixture with complete saved explanation.')],1)
    store=service.store(root)
    with store.transaction() as db:
        check=store._get(db,ref)
        check.update(state='RESULTS_READY',finish_requested=True)
        store._put(db,ref,check)
    result=native_closeout(service,root,store.load(ref,service.owner),time.monotonic()+1,set(),None)
    assert result['status']=='STOP_AUDIT_PENDING' and result.get('decision')=='block'
    assert '仅交付，不复核' in result['reason']
    assert native_closeout(service,root,store.load(ref,service.owner),time.monotonic()+1,set(),None) is None
    with store.transaction() as db:
        check=store._get(db,ref)
        check['effective_config']['values']['development']['business_audit_delivery']='wait'
        store._put(db,ref,check)
    result=native_closeout(service,root,store.load(ref,service.owner),time.monotonic()+1,set(),None)
    assert result['decision']=='block'


def test_disabled_review_still_delivers_complete_candidate_report(sample,monkeypatch,tmp_path):
    from security_runtime import dashboard_service
    root,service,ref,risks=sample
    scanner(sample,monkeypatch)
    with service.store(root).transaction() as db:
        check=service.store(root)._get(db,ref)
        check['effective_config']['values']['agent'].update(review_scanner_findings=False,audit_business_logic=False)
        service.store(root)._put(db,ref,check)
    monkeypatch.setattr(dashboard_service,'directory',lambda:tmp_path/'dashboard')
    dashboard_service.save_endpoint(40000,'a'*32)
    risks.sync_scanner()
    result=risks.get(batch_version=(1,'scan-1'))
    report=result['report_text']
    for label in ('**问题**','**可能影响**','**建议修复**','**尚未确认**','未经 Agent 确认','本会话风险管理'):
        assert label in report
    assert not result['review_progress']['host_review_completed']


def test_parallel_admission_limits_other_sessions_but_reuses_own_lease(tmp_path):
    from security_runtime.audit_leases import reserve,release
    root=tmp_path/'project'
    reserve(root,{'host':'codex','session':'1'*64},'first')
    reserve(root,{'host':'codex','session':'2'*64},'second')
    with pytest.raises(ValueError,match='CONCURRENCY_LIMIT'):
        reserve(root,{'host':'codex','session':'3'*64},'third')
    reserve(root,{'host':'codex','session':'1'*64},'replacement')
    release('replacement')
    reserve(root,{'host':'codex','session':'3'*64},'third')


def test_dependency_changed_after_audit_completion_invalidates_reuse(sample,monkeypatch):
    root,_,_,risks=sample
    (root/'guard.py').write_text('authorized = True\n')
    job=operate(risks,'prepare')
    dependency=risks.read('guard.py',1,1,related=True)
    risks.submit([],1,audit_id=job['audit_id'],business_reviews=[dict(file_path='query.py',rationale='Checked guard',
        evidence_refs=job['evidence_refs']+[dependency['evidence_ref']],limitations=[])])
    (root/'guard.py').write_text('authorized = False\n')
    scanner(sample,monkeypatch)
    risks.sync_scanner()
    assert status(risks.current_check())['status']=='NEEDS_REVIEW'
    assert review_progress(risks.current_check(),risks.load())['business_review']=='PENDING'
