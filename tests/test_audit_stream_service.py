"""Scoped child publication and durable inbox failure semantics."""
import pytest
from test_development_risks import sample
from security_runtime.audit_stream_service import manage, process, valid_reviews
from security_runtime.incremental_audit import record_changes


def child(sample):
    risks=sample[3]
    with risks.checks.transaction() as db:
        check=risks.checks._get(db,risks.ref)
        record_changes(check,check['observed_paths'])
        risks.checks._put(db,risks.ref,check)
    token=manage(risks,'prepare')['audit_token']
    manage(risks,'started',agent_ref='child-actual')
    args=dict(audit_token=token,agent_ref='child-actual')
    batch=process(risks,'claim',**args)['batch']
    evidence=process(risks,'read',batch_id=batch['batch_id'],windows=[dict(file_path='query.py',start_line=1,end_line=2)],**args)
    return risks,args,batch,dict(file_path='query.py',rationale='Reviewed this isolated query and its boundary.',evidence_refs=[evidence['evidence'][0]['evidence_ref']],coverage='COMPLETE',limitations=[])


def test_child_direct_save_idempotent_after_unrelated_request(sample):
    risks,args,batch,review=child(sample)
    kw=dict(batch_id=batch['batch_id'],request_id='request-one',business_reviews=[review],**args)
    result=process(risks,'submit',**kw)
    assert result['review_saved']
    assert valid_reviews(risks.current_check())['query.py']==review or 'query.py' in valid_reviews(risks.current_check())
    again=process(risks,'submit',**kw)
    assert again['repeated']
    assert len(risks.load()['reviews'])==1
    with pytest.raises(ValueError,match='CONFLICT'):
        process(risks,'submit',**dict(kw,business_reviews=[dict(review,rationale='Different payload')]))


def test_command_host_new_edit_continues_bound_executor_without_registration(sample):
    from security_runtime.business_audit import offer
    root, service, ref, _ = sample
    risks, args, batch, review = child(sample)
    assert process(risks, 'submit', batch_id=batch['batch_id'], request_id='first-file',
                   business_reviews=[review], **args)['review_saved']
    (root/'later.py').write_text('later = True\n')
    service.record(root, ref, ['later.py'])
    before = dict(risks.current_check()['audit_delegate'])
    note = offer(service.hooks, root, service.owner, ref, prefer_active_executor=True)
    assert '新增文件待审' in note and '"child-actual"' in note and 'CAUGHT_UP' in note
    assert risks.current_check()['audit_delegate'] == before
    assert offer(service.hooks, root, service.owner, ref, prefer_active_executor=True) is None


def test_changed_source_retains_inbox_without_current_coverage(sample):
    risks,args,batch,review=child(sample)
    (sample[0]/'query.py').write_text('changed = True\n')
    sample[1].record(sample[0],sample[2],['query.py'])
    result=process(risks,'submit',batch_id=batch['batch_id'],request_id='request-stale',business_reviews=[review],**args)
    assert result['received'] and not result['applied']
    assert risks.current_check()['audit_stream']['receipts']['request-stale']['payload']['business_reviews']
    assert not valid_reviews(risks.current_check())


def test_expired_lease_still_accepts_valid_result(sample):
    risks,args,batch,review=child(sample)
    with risks.checks.transaction() as db:
        check=risks.checks._get(db,risks.ref)
        check['audit_stream']['batches'][batch['batch_id']]['lease_until']=0
        risks.checks._put(db,risks.ref,check)
    assert process(risks,'submit',batch_id=batch['batch_id'],request_id='request-late',business_reviews=[review],**args)['review_saved']
    assert risks.current_check()['audit_stream']['receipts']['request-late']['late']


def test_capability_binding_and_related_scope(sample):
    risks,args,batch,_=child(sample)
    with pytest.raises(ValueError,match='EXECUTOR'):
        process(risks,'claim',**dict(args,agent_ref='unrelated'))
    with pytest.raises(ValueError,match='CAPABILITY'):
        process(risks,'claim',**dict(args,audit_token='z'*32))
    (sample[0]/'auth.py').write_text('allowed = False\n')
    query=dict(batch_id=batch['batch_id'],windows=[dict(file_path='auth.py',start_line=1,end_line=1)],**args)
    assert process(risks,'read',**query)['parent_action']=='stream_authorize_paths'
    manage(risks,'authorize_paths',related_paths=['auth.py'])
    assert process(risks,'read',**query)['evidence']
    manage(risks,'cancel')
    with pytest.raises(ValueError,match='CAPABILITY'):
        process(risks,'claim',**args)


def test_deleted_path_has_absence_evidence_and_recreation_invalidates(sample):
    risks,args,batch,_=child(sample)
    (sample[0]/'query.py').unlink()
    context=process(risks,'read',batch_id=batch['batch_id'],windows=[dict(file_path='query.py',start_line=1,end_line=2)],**args)
    evidence=context['evidence'][0]
    assert evidence['kind']=='ABSENCE' and not context['errors']
    (sample[0]/'query.py').write_text('new = True\n')
    with pytest.raises(ValueError,match='STALE'):
        risks.evidence(risks.load(),[evidence['evidence_ref']])


def test_unissued_parent_evidence_cannot_be_used_by_child(sample):
    risks,args,batch,review=child(sample)
    (sample[0]/'secret_context.py').write_text('protected = True\n')
    ref=risks.read('secret_context.py',1,1,related=True)['evidence_ref']
    with pytest.raises(ValueError,match='NOT_ISSUED'):
        process(risks,'submit',batch_id=batch['batch_id'],request_id='request-bad-ref',
                business_reviews=[dict(review,evidence_refs=[*review['evidence_refs'],ref])],**args)


def test_result_survives_publication_failure_and_recover(sample,monkeypatch):
    risks,args,batch,review=child(sample)
    original=risks._submit
    def fail(*a,**kw):raise OSError('disk busy')
    monkeypatch.setattr(risks,'_submit',fail)
    result=process(risks,'submit',batch_id=batch['batch_id'],request_id='request-recover',business_reviews=[review],**args)
    assert result['error']=='AUDIT_PUBLICATION_PENDING'
    monkeypatch.setattr(risks,'_submit',original)
    assert process(risks,'recover',request_id='request-recover',**args)['review_saved']
    assert len(risks.load()['reviews'])==1


def test_business_finding_saved_before_scan_is_in_final_batch(sample,monkeypatch):
    from test_development_risks import scanner
    risks,args,batch,review=child(sample)
    finding=dict(issue_key='stream-query',file_path='query.py',line_start=2,line_end=2,
        category='sql-injection',title='SQL注入',description='输入作为查询执行',impact='可能读取其他记录',
        fix_advice='使用参数化查询',severity='HIGH',decision='CONFIRMED',rationale='输入直接进入执行接口',
        evidence_refs=review['evidence_refs'])
    assert process(risks,'submit',batch_id=batch['batch_id'],request_id='request-finding',
                   observations=[finding],business_reviews=[review],**args)['review_saved']
    scanner(sample,monkeypatch);risks.sync_scanner()
    result=risks.get(batch_version=(risks.current_check()['dirty_seq'],'scan-1'))
    assert any(r['finding']['title']=='SQL注入' for r in result['risks'])
    assert result['review_progress']['business_review']=='COMPLETE'


def test_read_rechecks_revocation_before_return(sample,monkeypatch):
    risks,args,batch,_=child(sample)
    from security_runtime import development_views
    original=development_views.read_contexts
    def revoke_after_read(*a,**kw):
        result=original(*a,**kw)
        manage(risks,'cancel')
        return result
    monkeypatch.setattr(development_views,'read_contexts',revoke_after_read)
    with pytest.raises(ValueError,match='CAPABILITY'):
        process(risks,'read',batch_id=batch['batch_id'],windows=[dict(file_path='query.py',start_line=1,end_line=2)],**args)


def test_status_does_not_write(sample,monkeypatch):
    risks=sample[3]
    def forbidden(*a,**kw):pytest.fail('status attempted write')
    monkeypatch.setattr(risks.checks,'_put',forbidden)
    assert manage(risks,'status')['scanner_run'] is False


def test_partial_stale_batch_preserves_valid_result(sample):
    root,service,ref,risks=sample
    (root/'second.py').write_text('value = 1\n')
    service.record(root,ref,['second.py'])
    risks,args,batch,first=child(sample)
    evidence=process(risks,'read',batch_id=batch['batch_id'],windows=[dict(file_path='second.py',start_line=1,end_line=1)],**args)['evidence'][0]
    second=dict(first,file_path='second.py',evidence_refs=[evidence['evidence_ref']])
    (root/'second.py').write_text('value = 2\n');service.record(root,ref,['second.py'])
    receipt=process(risks,'submit',batch_id=batch['batch_id'],request_id='request-partial',business_reviews=[first,second],**args)
    assert receipt['applied_paths']==['query.py']
    assert receipt['pending_paths']==['second.py']
    assert set(valid_reviews(risks.current_check()))=={'query.py'}
    assert len(risks.load()['reviews'])==1
    assert receipt['next_batch']['batch']['versions'].keys()=={'second.py'}


def test_restart_resumes_received_result(sample,monkeypatch):
    from security_runtime.development_risks import DevelopmentRisks
    risks,args,batch,review=child(sample)
    def fail(*a,**kw):raise OSError('interrupted before publication')
    monkeypatch.setattr(risks,'_submit',fail)
    result=process(risks,'submit',batch_id=batch['batch_id'],request_id='request-restart',business_reviews=[review],**args)
    assert result['received'] and not result['applied']
    restarted=DevelopmentRisks(sample[1],sample[0],sample[2])
    assert process(restarted,'recover',request_id='request-restart',**args)['review_saved']
    assert len(restarted.load()['reviews'])==1
