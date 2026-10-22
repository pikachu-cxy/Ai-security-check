import builtins
import copy
import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from security_runtime import product_metrics as metrics
from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import bounded_record
from security_runtime.context_report import report_data
from security_runtime.monitor_history import import_history
from security_runtime.monitoring.service import MonitorService
from security_runtime.storage import SQLiteStore
from security_runtime.triage_models import TriageRecord
from test_hook_runtime import repo
from test_task_security import service
from summary_fixtures import sample, snapshot


@pytest.fixture
def collector(monkeypatch):
    rows = []
    worker = SimpleNamespace(snapshot_settings=lambda:dict(mode='basic',source='saved',run='test'),
        offer=lambda row:rows.append(bounded_record(row)))
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR',raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE','basic')
    monkeypatch.setattr('security_runtime.context_cost_worker.get_worker',lambda:worker)
    return rows


def scan(root, identity='scan-one', count=2):
    return dict(scan_id=identity,target_profile={'path':str(root)},findings=[dict(id=f'finding-{i}',
        severity='HIGH',category='sql-injection',plain_title='PRIVATE_TITLE',file_path='PRIVATE_FILE') for i in range(count)])


def triage(verdict='CONFIRMED', status='VALID'):
    return TriageRecord('scan-one','finding-0','fingerprint',verdict,'HIGH','CONFIRMED',
        'PRIVATE_REASON','PRIVATE_ATTACK',[],[],[],'PRIVATE_ACTION','native','host','unknown',
        'v1','a'*64,status=status)


def test_actual_captured_bytes_counted_once_and_unconfirmed_files_not_claimed(collector,tmp_path):
    @metrics.observe_scan
    def run():
        metrics.observe_input('a.py','TARGET',b'a\r\nb\rc\n')
        metrics.observe_input('b.py','TARGET',b'not covered')
        metrics.observe_input('binary','TARGET',b'a\0b')
        metrics.observe_input('context.py','CONTEXT',b'ignore\n')
        metrics.observe_input('rules.yml','RULES',b'ignore\n')
        plan=SimpleNamespace(unscoped_error=False,scanned_files={'a.py','b.py'},errored_files={'b.py'},skipped_files={})
        return metrics.scan_fact(scan(tmp_path),{'engine':plan})
    fact=run()
    assert fact['lines']==dict(target_lines=4,confirmed_file_lines=3,target_files=3,
        confirmed_files=1,unknown_files=1,status='PARTIAL')
    assert metrics._INPUT.get() is None
    assert metrics.scan_fact(scan(tmp_path))['lines']['target_lines'] is None


def test_no_second_source_read_and_scan_exceptions_propagate(collector):
    sentinel=ValueError('original')
    @metrics.observe_scan
    def run():
        metrics.observe_input('source','TARGET',b'x')
        raise sentinel
    with pytest.raises(ValueError) as caught: run()
    assert caught.value is sentinel and metrics._INPUT.get() is None


@pytest.mark.parametrize('fault',['off','missing','broken','queue_full'])
def test_saved_triage_is_identical_when_observer_fails(collector,tmp_path,monkeypatch,fault):
    store=SQLiteStore(tmp_path/'scans.db')
    record=triage()
    if fault=='off': monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    if fault=='missing':
        original=builtins.__import__
        def imported(name,*args,**kwargs):
            if name=='product_metrics': raise ImportError('removed')
            return original(name,*args,**kwargs)
        monkeypatch.setattr(builtins,'__import__',imported)
    if fault=='broken': monkeypatch.setattr(metrics,'triage_saved',lambda record:(_ for _ in ()).throw(OSError('blocked')))
    if fault=='queue_full': monkeypatch.setattr('security_runtime.context_cost_worker.get_worker',lambda:SimpleNamespace(
        snapshot_settings=lambda:dict(mode='basic'),offer=lambda record:False))
    assert store.save_triage(record,'cache') is None
    assert store.triage_records('scan-one')['finding-0']==asdict(record)
    assert not collector


def test_acceptance_is_valid_verdict_not_schema_count_and_replays_do_not_add(collector,tmp_path):
    store=ContextCostStore(tmp_path/'metrics.db')
    facts=[metrics.scan_fact(scan(tmp_path)),metrics.assessment(triage()),metrics.assessment(triage()),
        dict(kind='VERIFICATION',reference='scan-one',source='LIVE',total=1,omitted=0,
             items=[dict(id='finding-0',outcome='SCANNER_VERIFIED_RESOLVED')])]
    for fact in facts:
        assert store.record_observation(metrics.envelope(fact,workspace=str(tmp_path)))['status']=='RECORDED'
    data=report_data(store)
    m=data['product_metrics']
    assert data['summary']['calls']==0
    assert (m['scans'],m['findings'],m['ai_confirmed'],m['ai_unknown'],m['scanner_verified_resolved'])==(1,2,1,1,1)
    assert m['known_target_lines']==0 and m['scans_without_line_evidence']==1
    for secret in ('PRIVATE_TITLE','PRIVATE_FILE','finding-0','scan-one'):
        assert secret not in json.dumps(store.snapshot())
    assert metrics.assessment(triage(status='STALE'))['items'][0]['verdict']=='UNKNOWN'


def test_latest_verification_cannot_keep_old_resolved_after_failed_recheck(collector,tmp_path):
    store=ContextCostStore(tmp_path/'metrics.db')
    for outcome in ('SCANNER_VERIFIED_RESOLVED','INCONCLUSIVE'):
        row=metrics.envelope(dict(kind='VERIFICATION',reference='scan-one',source='LIVE',total=1,omitted=0,
            items=[dict(id='finding-0',outcome=outcome)]),workspace=str(tmp_path))
        assert store.record_observation(row)['status']=='RECORDED'
    assert report_data(store)['product_metrics']['scanner_verified_resolved']==0


def test_queue_schema_rejects_source_payloads_and_invalid_counts(tmp_path):
    fact=metrics.scan_fact(scan(tmp_path))
    for changed in (dict(fact,raw_source='secret'),dict(fact,total=-1),dict(fact,total=True),dict(fact,total=3)):
        assert bounded_record(metrics.envelope(changed)) is None
    fact['items'][0]['title']='SECRET'
    assert bounded_record(metrics.envelope(fact)) is None


def test_history_import_read_only_paged_idempotent_and_scoped(collector,tmp_path):
    path=tmp_path/'scans.db'
    product=SQLiteStore(path)
    with sqlite3.connect(path) as db:
        for number,root in ((1,tmp_path),(2,tmp_path/'other'),(3,tmp_path)):
            value=scan(root,f'scan-{number}')
            db.execute('INSERT INTO scans VALUES (?,?)',(value['scan_id'],json.dumps(value)))
    product.save_triage(triage(),'cache')
    before=hashlib.sha256(path.read_bytes()).hexdigest()
    store=ContextCostStore(tmp_path/'metrics.db')
    first=import_history(store,path,workspace=tmp_path,limit=2)
    assert first['has_more'] and first['inspected_scans']==2
    last=import_history(store,path,workspace=tmp_path,limit=2,before=first['next_before'])
    assert not last['has_more']
    repeat=import_history(store,path,workspace=tmp_path)
    assert repeat['recorded']==0 and repeat['skipped']==2
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    data=report_data(store)['product_metrics']
    assert data['scans']==2 and data['findings']==4 and data['scans_without_line_evidence']==2
    assert MonitorService(store,project=tmp_path/'other').snapshot('project')['product_metrics']['scans']==0


def test_history_reports_truncation_and_never_rereads_current_code(collector,tmp_path):
    path=tmp_path/'scans.db'
    SQLiteStore(path)
    value=scan(tmp_path,count=70)
    with sqlite3.connect(path) as db: db.execute('INSERT INTO scans VALUES (?,?)',('scan-one',json.dumps(value)))
    store=ContextCostStore(tmp_path/'metrics.db')
    assert import_history(store,path,workspace=tmp_path)['status']=='RECORDED'
    result=report_data(store)['product_metrics']
    assert result['findings']==70 and result['omitted_findings']==6
    assert result['ai_unknown']==64 and result['scans_without_line_evidence']==1


def test_monitor_off_import_cannot_write_product_or_metrics(tmp_path,monkeypatch):
    path=tmp_path/'scans.db'
    SQLiteStore(path)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    store=ContextCostStore(tmp_path/'metrics.db')
    assert import_history(store,path,workspace=tmp_path)['reason_code']=='MONITOR_DISABLED'
    assert not store.path.exists()


@pytest.mark.parametrize('mode',['on','off','missing','fault','full'])
def test_real_scan_persists_same_product_outcome_with_optional_metrics(repo,tmp_path,collector,monkeypatch,mode):
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    (repo/'observed.py').write_bytes(b'first\r\nsecond\n')
    if mode=='off': monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR','0')
    elif mode=='fault': monkeypatch.setattr(metrics,'scan_completed',lambda *a:(_ for _ in ()).throw(OSError('monitor failed')))
    elif mode=='missing':
        original=builtins.__import__
        def imported(name,*args,**kwargs):
            if name=='product_metrics': raise ImportError('removed')
            return original(name,*args,**kwargs)
        monkeypatch.setattr(builtins,'__import__',imported)
    elif mode=='full': monkeypatch.setattr('security_runtime.context_cost_worker.get_worker',lambda:SimpleNamespace(
        snapshot_settings=lambda:dict(mode='basic'),offer=lambda row:False))
    store=SQLiteStore(tmp_path/'product.db')
    result=SecurityRuntime(ScannerRegistry([]),store).scan(repo,'release')
    saved=store.get_scan(result.scan_id)
    assert saved['findings']==[] and saved['release_status']=='REVIEW'
    assert saved['status']=='PARTIAL' and result.findings==[]
    facts=[row['product_fact'] for row in collector if row and 'product_fact' in row]
    if mode=='on':
        assert len(facts)==1 and facts[0]['lines']['target_lines']>=2
        assert facts[0]['lines']['confirmed_file_lines']==0
        assert facts[0]['lines']['status']=='PARTIAL'
    else: assert not facts


def test_ledger_only_publishes_committed_current_results_and_never_replays(sample,collector):
    from test_task_risk_ledger_watermark import ledger_event, apply, newer_event
    root,hooks,ledger,event=ledger_event(sample)
    assert apply(hooks,root,ledger,event)['status']=='RECORDED'
    facts=[r['product_fact'] for r in collector if r and 'product_fact' in r]
    assert facts[-1]['items'][0]['outcome']=='SCANNER_VERIFIED_RESOLVED'
    count=len(collector)
    assert apply(hooks,root,ledger,event)['already_applied']
    assert len(collector)==count
    next_event=newer_event(ledger,event)
    assert apply(hooks,root,ledger,next_event)['status']=='RECORDED'
    assert collector[-1]['product_fact']['items'][0]['outcome']=='STILL_PRESENT'


def test_import_preserves_live_line_evidence_and_live_decision(collector,tmp_path):
    store=ContextCostStore(tmp_path/'metrics.db')
    historical=metrics.scan_fact(scan(tmp_path))
    live=copy.deepcopy(historical)
    live.update(source='LIVE',lines=dict(target_lines=10,confirmed_file_lines=10,target_files=1,
        confirmed_files=1,unknown_files=0,status='OBSERVED'))
    decision=metrics.assessment(triage())
    old=metrics.assessment(triage(verdict='FALSE_POSITIVE'))
    old['source']='HISTORY'
    for fact in (live,decision,historical,old):
        store.record_observation(metrics.envelope(fact,workspace=str(tmp_path)))
    data=report_data(store)['product_metrics']
    assert data['known_target_lines']==10 and data['ai_confirmed']==1


def test_verification_limit_and_host_proposals_are_not_silent(collector,tmp_path):
    metrics.ledger_saved((dict(source='SCANNER',origin_scan_id='scan-one',finding_id=f'f-{i}',
        status='SCANNER_VERIFIED_RESOLVED') for i in range(70)),tmp_path)
    assert collector[-1]['product_fact']['omitted']==1
    metrics.proposals_saved('task-one',scan(tmp_path)['findings'],tmp_path)
    assert collector[-1]['product_fact']['kind']=='PROPOSAL'
    assert not any('verdict' in item for item in collector[-1]['product_fact']['items'])


def test_history_imports_saved_ai_decision_and_never_becomes_current_window(collector,tmp_path):
    path=tmp_path/'scans.db'
    product=SQLiteStore(path)
    with sqlite3.connect(path) as db:
        db.execute('INSERT INTO scans VALUES (?,?)',('scan-one',json.dumps(scan(tmp_path))))
    product.save_triage(triage(),'cache')
    store=ContextCostStore(tmp_path/'metrics.db')
    assert import_history(store,path,workspace=tmp_path)['recorded']==2
    data=report_data(store)['product_metrics']
    assert data['ai_confirmed']==1 and data['ai_unknown']==1
    service=MonitorService(store,project=tmp_path)
    service.task('start')
    # A newly imported old outcome must not become an operation in this window.
    event=metrics.envelope(metrics.scan_fact(scan(tmp_path,'another')),workspace=str(tmp_path))
    store.record_observation(event)
    assert service.snapshot('task')['product_metrics']['scans']==0


def test_product_outcomes_export_same_parent_and_product_alias_as_call(collector,tmp_path):
    store=ContextCostStore(tmp_path/'metrics.db')
    correlation=dict(call_id='call-one',links=[dict(kind='scan',reference='scan-one',relation='SCAN_PERSISTED')])
    store.record_observation(dict(tool='scan_project',correlation=correlation,measurements={},observations={}))
    store.record_observation(metrics.envelope(metrics.scan_fact(scan(tmp_path)),workspace=str(tmp_path),correlation=correlation))
    data=report_data(store)['associations']
    assert data['product_outcomes'][0]['parent_call_id']=='call-one'
    assert data['product_outcomes'][0]['links'][0]['subject']==data['calls'][0]['links'][0]['subject']


def test_import_rejects_metrics_alias_of_business_database(tmp_path):
    source=tmp_path/'source.db'
    SQLiteStore(source)
    target=tmp_path/'alias.db'
    os.link(source,target)
    before=source.read_bytes()
    result=import_history(ContextCostStore(target),source,workspace=tmp_path)
    assert result['reason_code']=='HISTORY_SOURCE_UNAVAILABLE'
    assert source.read_bytes()==before


def test_real_task_lifecycle_receipts_do_not_invent_scans(service,collector):
    task,root,runtime=service
    started=task.begin(root,'monitor-lifecycle')
    ref=started['task_ref']
    # A query is a repeat observation, not another scan or task.
    task.get(root,ref)
    result=task.finish(root,ref)
    assert result['status']=='NO_CHANGES' and runtime.calls==[]
    rows=[row for row in collector if row and row.get('product_fact',{}).get('kind')=='CHECK']
    assert rows and rows[0]['product_fact']['check']['status']=='IN_PROGRESS'
    assert rows[-1]['product_fact']['check']['status']=='NOT_RUN'
    report=metrics.report([dict(row,workspace_hash='workspace') for row in rows])
    assert report['scans']==0 and report['check_summary']['task_checks']==1
    assert report['check_summary']['latest']['status']=='NOT_RUN'


def test_real_review_lifecycle_reports_latest_saved_generation(service,collector):
    from test_task_security import prepared
    from task_review_helpers import review_all
    task,root,runtime=service
    ref,session,packet=prepared(service)
    generation_before=task.load(root,ref)['generation']
    review_all(task,root,ref,packet)
    assert task.load(root,ref)['generation']>generation_before
    result=task.submit(root,ref,session,[],'REVIEWED',[])
    assert result.get('status') != 'REVIEW_CONTINUE_REQUIRED'
    saved=task.load(root,ref)
    assert saved['phase']=='COMPLETE'
    rows=[dict(row,workspace_hash='workspace') for row in collector
          if row and row.get('product_fact',{}).get('kind')=='CHECK']
    facts=[row['product_fact'] for row in rows]
    assert max(fact['revision'] for fact in facts)==saved['generation']
    report=metrics.report(rows)
    assert report['scans']==0 and len(runtime.calls)==1
    assert report['check_summary']['task_checks']==1
    latest=report['check_summary']['latest']
    assert latest['status']=='PARTIAL'  # Fixture scanner explicitly covers SCOPED.
    assert 'TASK_STATIC_PARTIAL' in latest['reason_codes']
    assert latest['scope_counts']['reviewed_units']>0


def test_task_commit_survives_optional_observer_failure(service,monkeypatch):
    task,root,_=service
    monkeypatch.setattr(metrics,'task_record_observed',lambda *a:(_ for _ in ()).throw(OSError('observer unavailable')))
    response=task.begin(root,'isolated-task-observer')
    assert task.load(root,response['task_ref'])['phase']=='ACTIVE'
    assert task.finish(root,response['task_ref'])['status']=='NO_CHANGES'
