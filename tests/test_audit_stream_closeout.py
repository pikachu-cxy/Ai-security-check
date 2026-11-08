"""Development lifecycle integration with isolated storage and no external scan."""
import pytest
from test_development_risks import sample, scanner, OWNER
from test_audit_stream_service import child
from security_runtime.audit_stream_service import manage, process, valid_reviews
from security_runtime.development_check import DevelopmentCheckService
from security_runtime.development_risks import DevelopmentRisks, review_progress
from security_runtime.incremental_audit import progress


def publish(sample,monkeypatch):
    scanner(sample,monkeypatch)
    risks=sample[3]
    with risks.checks.transaction() as db:
        row=risks.checks._get(db,risks.ref)
        row.update(state='RESULTS_READY',result={'status':'COMPLETED','gaps':[],'coverage':'FULL'})
        row['effective_config']['values']['agent']['review_scanner_findings']=False
        risks.checks._put(db,risks.ref,row)
    risks.sync_scanner()


def test_record_finish_seals_once_without_repeated_scan(sample,monkeypatch):
    root,service,ref,risks=sample
    calls=[]
    def fake_worker(hooks,path):
        calls.append(str(path))
        with service.store(root).transaction() as db:
            row=service.store(root)._get(db,ref)
            row.update(state='RESULTS_READY',scanned_seq=row['dirty_seq'])
            service.store(root)._put(db,ref,row)
    service.launcher=fake_worker
    service.record(root,ref,['query.py'])
    service.record(root,ref,['query.py'])
    service.finish(root,ref)
    sealed=progress(risks.current_check())
    assert sealed['cutoff_seq']==3
    service.finish(root,ref)
    assert len(calls)==1
    (root/'next.py').write_text('value = 1\n')
    service.record(root,ref,['next.py'])
    current=risks.current_check()
    assert progress(current,sealed['round_id'])['cutoff_seq']==3
    assert progress(current)['round_id']!=sealed['round_id']
    assert progress(current)['pending_paths']==['next.py']


def test_pending_audit_is_child_continuation_not_parent_business_review(sample,monkeypatch):
    risks,args,batch,review=child(sample)
    publish(sample,monkeypatch)
    with risks.checks.transaction() as db:
        check=risks.checks._get(db,risks.ref)
        check['effective_config']['values']['development']['business_audit_delivery']='wait'
        check['stop_closeout_notice']=dict(seq=check['dirty_seq'],scan_id='scan-1',mode='REVIEW')
        risks.checks._put(db,risks.ref,check)
    from security_runtime.development_views import closeout_page
    result=closeout_page(risks,0,None)
    assert not result.get('business_paths')
    assert result['report_text'] and not result['host_review_completed']
    assert result['audit_continuation']['pending_paths']==['query.py']
    assert result['audit_continuation']['agent_ref']=='child-actual'
    assert result['next_action'] is None


def test_early_business_finding_and_partial_coverage_survive_publication(sample,monkeypatch):
    risks,args,batch,review=child(sample)
    review=dict(review,coverage='PARTIAL',uncovered=['调用方认证入口未提供'])
    finding=dict(issue_key='business-query',file_path='query.py',line_start=2,line_end=2,
        category='sql-injection',title='业务查询注入',description='查询输入未经绑定',impact='可能读取其他数据',
        fix_advice='绑定查询参数',severity='HIGH',decision='CONFIRMED',rationale='样例输入直接进入执行接口',
        evidence_refs=review['evidence_refs'])
    result=process(risks,'submit',batch_id=batch['batch_id'],request_id='closeout-finding',
                   observations=[finding],business_reviews=[review],**args)
    assert result['review_saved']
    publish(sample,monkeypatch)
    page=risks.get(batch_version=(risks.current_check()['dirty_seq'],'scan-1'))
    assert '业务查询注入' in page['report_text'] and '调用方认证入口未提供' in page['report_text']
    assert page['review_progress']['business_review']=='PARTIAL'
    assert page['review_progress']['business_coverage_gaps']


def test_received_result_recovers_after_service_reconstruction(sample,monkeypatch):
    root,service,ref,risks=sample
    risks,args,batch,review=child(sample)
    monkeypatch.setattr(risks,'_submit',lambda *a,**kw: (_ for _ in ()).throw(OSError('interrupted')))
    receipt=process(risks,'submit',batch_id=batch['batch_id'],request_id='recover-new-service',
                    business_reviews=[review],**args)
    assert receipt['received'] and not receipt['applied']
    restored=DevelopmentCheckService(None,service.hooks,owner=OWNER,scan_path_provider=service.scan_path_provider)
    fresh=DevelopmentRisks(restored,root,ref)
    assert process(fresh,'recover',request_id='recover-new-service',**args)['review_saved']
    assert len(fresh.load()['reviews'])==1


def test_same_file_and_related_evidence_updates_enqueue_incremental_review(sample):
    root,service,ref,risks=sample
    risks,args,batch,review=child(sample)
    (root/'auth.py').write_text('allowed = False\n')
    manage(risks,'authorize_paths',related_paths=['auth.py'])
    extra=process(risks,'read',batch_id=batch['batch_id'],
        windows=[dict(file_path='auth.py',start_line=1,end_line=1)],**args)
    review['evidence_refs'].append(extra['evidence'][0]['evidence_ref'])
    assert process(risks,'submit',batch_id=batch['batch_id'],request_id='related-first',business_reviews=[review],**args)['review_saved']
    (root/'auth.py').write_text('allowed = True\n')
    service.record(root,ref,['auth.py'])
    assert set(progress(risks.current_check())['pending_paths'])=={'auth.py','query.py'}
    assert 'query.py' not in valid_reviews(risks.current_check())


def test_thousand_paths_are_batched_without_source_reads(sample):
    root,service,ref,risks=sample
    names=[f'pkg/module{i}.py' for i in range(1000)]
    service.record(root,ref,names)
    token=manage(risks,'prepare')['audit_token'];manage(risks,'started',agent_ref='large-child')
    result=process(risks,'claim',audit_token=token,agent_ref='large-child')
    assert len(result['batch']['versions'])==50
    assert len(result['progress']['pending_paths'])==1001


def test_sibling_worktrees_do_not_share_delegation(sample,tmp_path):
    root,service,ref,risks=sample
    risks,args,batch,review=child(sample)
    other=tmp_path/'worktree-other';other.mkdir();(other/'query.py').write_text('other=True\n')
    other_ref=service.begin(other,'other-task')['check_ref'];service.record(other,other_ref,['query.py'])
    other_risks=DevelopmentRisks(service,other,other_ref)
    with pytest.raises(ValueError,match='CAPABILITY'):
        process(other_risks,'claim',**args)
    assert not other_risks.current_check().get('audit_delegate')


def test_audit_disabled_task_allocates_no_stream(sample,tmp_path,monkeypatch):
    config=tmp_path/'disabled.toml';config.write_text('[agent]\naudit_business_logic=false\n')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG',str(config))
    root=tmp_path/'disabled-project';root.mkdir();(root/'a.py').write_text('x=1\n')
    original=sample[1]
    service=DevelopmentCheckService(None,original.hooks,owner=OWNER,launcher=lambda *a:None)
    ref=service.begin(root,'disabled')['check_ref'];service.record(root,ref,['a.py']);service.finish(root,ref)
    assert 'audit_stream' not in service.store(root).load(ref,OWNER)
