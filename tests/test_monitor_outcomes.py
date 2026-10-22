"""Acceptance of display semantics, not scanner or ledger authority tests."""
import copy
import json
from types import SimpleNamespace

import pytest

from security_runtime import product_metrics as metrics
from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import ObservationWorker, bounded_record
from security_runtime.monitor_checks import scan_check, task_check


def scan(reference='s1', *, source='LIVE', findings=None, **changes):
    finding = dict(id='f1', fingerprint='a'*24, category='sql-injection', severity='HIGH')
    value = dict(scan_id=reference, findings=[finding] if findings is None else findings,
        status='COMPLETED', execution_state='EXECUTED', coverage='FULL',
        capability_results={'CODE_SAST':'EXECUTED'}, target_profile={'files':['SECRET_PATH.py'], 'skipped_files':[]},
        rule_coverage={'status':'EXECUTED','total_files':1,'per_language':{'python':{
            'status':'EXECUTED','selected_rules':1,'executed_rules':1,'target_files':1,'scanned_files':1}}})
    value.update(changes)
    fact = metrics.scan_fact(value)
    fact['source'] = source
    return fact


def event(fact, when, workspace='workspace-a'):
    return dict(product_fact=fact, workspace_hash=workspace, finished_at=when)


def state(kind, value, reference='s1'):
    key = {'VERIFICATION':'outcome', 'ASSESSMENT':'verdict', 'HANDLING':'handling'}[kind]
    return dict(kind=kind, reference=reference, source='LIVE', total=1, omitted=0,
                items=[dict(id='f1', **{key:value})])


def test_occurrences_separate_from_stable_identity_and_workspace():
    facts = [event(scan('s1'),1),event(scan('s2'),2),event(scan('s2'),3)]
    report = metrics.report(facts)
    assert report['cumulative_finding_occurrences'] == 2
    assert report['current_risks']['pending'] is None
    assert report['current_risks']['observed_pending'] == 1
    assert report['current_risks']['coverage'] == 'PARTIAL'  # no disposition receipt
    assert report['current_risks']['excluded'] is None
    assert metrics.report(facts+[event(scan('s1'),4,'workspace-b')])['current_risks']['observed_pending']==2


def test_resolution_scan_replay_reappearance_and_old_reference():
    facts=[event(scan(),1), event(state('VERIFICATION','SCANNER_VERIFIED_RESOLVED'),2),event(scan(),3)]
    assert metrics.report(facts)['current_risks']['pending']==0
    facts += [event(scan('s2'),4),event(state('VERIFICATION','SCANNER_VERIFIED_RESOLVED'),5)]
    current=metrics.report(facts)['current_risks']
    assert current['pending'] is None and current['observed_pending']==1 and current['resolved']==0
    assert 'OLDER_REFERENCE_STATE' in current['reason_codes']
    facts += [event(state('VERIFICATION','INCONCLUSIVE','s2'),6)]
    assert metrics.report(facts)['current_risks']['pending'] is None
    assert metrics.report(facts)['current_risks']['unknown']==1


def test_absence_does_not_resolve_and_user_handling_is_separate():
    facts=[event(scan(),1),event(scan('s2',findings=[]),2)]
    assert metrics.report(facts)['current_risks']['pending'] is None
    assert metrics.report(facts)['current_risks']['observed_pending']==1
    for handling in ('EXCLUDED','DEFERRED'):
        current=metrics.report(facts+[event(state('HANDLING',handling),3)])['current_risks']
        assert current['pending']==0 and current[handling.lower()]==1 and current['resolved']==0
    facts += [event(state('HANDLING','EXCLUDED'),3),event(state('HANDLING','OPEN'),4)]
    assert metrics.report(facts)['current_risks']['pending']==1


def test_read_projection_cannot_reopen_verified_resolution():
    facts=[event(scan(),1),event(state('VERIFICATION','SCANNER_VERIFIED_RESOLVED'),2)]
    for handling in ('OPEN','UNKNOWN','EXCLUDED','RESOLVED'):
        current=metrics.report(facts+[event(state('HANDLING',handling),3)])['current_risks']
        assert current['pending']==0 and current['resolved']==1


def test_false_positive_verdict_and_explicit_revocation():
    facts=[event(scan(),1),event(state('ASSESSMENT','FALSE_POSITIVE'),2)]
    assert metrics.report(facts)['current_risks']['false_positive']==1
    assert metrics.report(facts)['current_risks']['pending']==0
    facts += [event(state('ASSESSMENT','UNKNOWN'),3)]
    assert metrics.report(facts)['current_risks']['pending'] is None
    facts += [event(scan('s2'),4)]
    assert metrics.report(facts)['current_risks']['pending'] is None
    assert metrics.report(facts)['current_risks']['observed_pending']==1


def test_old_import_cannot_replace_live_state_but_limits_coverage():
    facts=[event(scan(),1),event(state('VERIFICATION','SCANNER_VERIFIED_RESOLVED'),2),
           event(scan('old',source='HISTORY'),3)]
    current=metrics.report(facts)['current_risks']
    assert current['resolved']==1 and current['observed_pending']==0
    assert current['pending'] is None and 'HISTORICAL_ORDER_UNKNOWN' in current['reason_codes']


def test_truncation_and_legacy_identity_are_unknown_not_zero():
    fact=scan()
    fact.update(total=65,omitted=64)
    current=metrics.report([event(fact,1)])['current_risks']
    assert current['pending'] is None and current['observed_pending']==1
    fact['items'][0].pop('risk_key')
    current=metrics.report([event(fact,1)])['current_risks']
    assert current['pending'] is None and current['unknown']==1
    assert metrics.report([])['current_risks']['pending'] is None
    assert metrics.report([event(scan(findings=[]),1)])['current_risks']['pending']==0
    assert metrics.report([event(scan(findings=[], execution_state='FAILED', status='PARTIAL'),1)])['current_risks']['pending'] is None


@pytest.mark.parametrize('execution,status,expected',[
    ('EXECUTED','COMPLETED','COMPLETED'),('EXECUTED','PARTIAL','PARTIAL'),
    ('FAILED','PARTIAL','FAILED'),('UNAVAILABLE','PARTIAL','FAILED'),
    ('NO_CHANGES','NO_CHANGES','NOT_RUN'),('NOT_APPLICABLE','NOT_APPLICABLE','NOT_RUN')])
def test_check_execution_is_independent_of_line_counts(execution,status,expected):
    fact=scan(execution_state=execution,status=status)
    assert fact['check']['status']==expected
    assert fact['lines']['status']=='UNKNOWN'
    assert bounded_record(metrics.envelope(fact)) is not None


def test_vue_template_gap_and_unknown_plugin_metadata_are_allowlisted():
    fact=scan(rule_coverage={'status':'PARTIAL','per_language':{'vue':dict(
        status='PARTIAL',scope='SCRIPT_BLOCKS_ONLY',template_status='NOT_COVERED',
        selected_rules=9,executed_rules=9,target_files=1,scanned_files=1,
        files={'PRIVATE_SOURCE.vue':{'error':'PRIVATE_ERROR'}})}},
        scanner_runs=[dict(status='TIMEOUT',error='PRIVATE_ERROR',error_code='PRIVATE_TOKEN')],
        capability_results={'SECRET_USER_PATH':'FAILED'})
    check=fact['check']
    assert check['status']=='PARTIAL'
    assert {'SCANNER_TIMEOUT','VUE_TEMPLATE_NOT_COVERED','VUE_SCRIPT_BLOCKS_ONLY'} <= set(check['reason_codes'])
    assert check['capabilities']==[dict(capability='OTHER',status='FAILED')]
    assert 'PRIVATE' not in json.dumps(check) and 'SECRET_USER_PATH' not in json.dumps(check)
    assert bounded_record(metrics.envelope(fact)) is not None
    fact['check']['reason_codes'].append('SECRET_VALUE')
    assert bounded_record(metrics.envelope(fact)) is None


def test_no_execution_receipt_and_bounded_language_rows():
    assert scan_check({})['status']=='UNKNOWN'
    check=scan_check(dict(execution_state='EXECUTED',status='COMPLETED',coverage='FULL',
        rule_coverage={'status':'PARTIAL','per_language':{str(i):dict(status='PARTIAL') for i in range(100)}}))
    assert len(check['languages'])==24 and check['limited']
    assert 'OBSERVATION_LIMIT' in check['reason_codes']


def test_default_off_creates_no_metrics_and_explicit_opt_in_persists(tmp_path,monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MODE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR',raising=False)
    store=ContextCostStore(tmp_path/'metrics.db')
    assert store.monitoring()['mode']=='off'
    assert store.record_observation(metrics.envelope(scan()))['status']=='DISABLED'
    assert not store.path.exists()
    worker=ObservationWorker(lambda:store)
    assert worker.snapshot_settings()['mode']=='off'
    assert store.set_monitoring('basic')['status']=='AVAILABLE'
    fact=scan()
    assert store.record_observation(metrics.envelope(fact,workspace=str(tmp_path)))['status']=='RECORDED'
    saved=store.snapshot()['product_facts']
    assert saved[0]['product_fact']['items'][0]['risk_key'] != fact['items'][0]['risk_key']
    assert 'SECRET_PATH' not in json.dumps(saved)
    assert 'a'*24 not in json.dumps(saved)
    assert store.set_monitoring('off')['status']=='AVAILABLE'
    assert store.record_observation(metrics.envelope(fact))['status']=='DISABLED'


def test_handling_observer_bounded_and_opt_out_does_not_iterate(monkeypatch):
    monkeypatch.setattr(metrics,'enabled',lambda:None)
    def forbidden():
        raise AssertionError('off must not consume rows')
        yield
    metrics.handling_observed(forbidden(),'workspace')
    output=[]
    monkeypatch.setattr(metrics,'enabled',lambda:object())
    monkeypatch.setattr(metrics,'publish',lambda value,**kw:output.append(value))
    rows=(dict(source='SCANNER',origin_scan_id='s1',finding_id=f'f{i}',
        handling_status='EXCLUDED',status='NEEDS_RECHECK') for i in range(100))
    metrics.handling_observed(rows,'workspace')
    assert len(output[0]['items'])==64 and output[0]['omitted']==1
    assert {i['handling'] for i in output[0]['items']}=={'UNKNOWN'}


def test_task_cap_limits_unread_ranges_and_partial_review_are_separate_from_scans():
    view=dict(task_ref='task-a',status='INCOMPLETE',changed_file_count=20,
        unverified_file_count=15,baseline_file_count=1000,
        limitations=[dict(reason='SNAPSHOT_READ_FILE_BUDGET',path='SECRET_PATH'),
                     dict(reason='USER_SECRET_UNKNOWN')],
        context_read_coverage=dict(unread_range_count=2,gaps=[]),
        review_progress=dict(unit_count=49,reviewed_unit_count=34,coverage='PARTIAL'),
        static=None)
    check=task_check(view)
    assert check['status']=='PARTIAL'
    assert {'SNAPSHOT_FILE_LIMIT','TASK_SCOPE_UNVERIFIED','REVIEW_CONTEXT_UNREAD'} <= set(check['reason_codes'])
    assert check['scope_counts']['unverified_files']==15
    assert check['scope_counts']['reviewed_units']==34
    assert 'SECRET' not in json.dumps(check)
    fact=dict(kind='CHECK',reference='task-a',source='LIVE',total=0,omitted=0,items=[],check=check,revision=3)
    assert bounded_record(metrics.envelope(fact))
    report=metrics.report([event(fact,1),event(fact,2)])
    assert report['scans']==0 and report['cumulative_finding_occurrences']==0
    assert report['check_summary']['task_checks']==1 and len(report['checks'])==1
    assert report['check_summary']['latest']['status']=='PARTIAL'
    assert report['current_risks']['pending'] is None


def test_task_view_revisions_prevent_old_reads_overriding_completion(monkeypatch):
    published=[]
    monkeypatch.setattr(metrics,'enabled',lambda:object())
    monkeypatch.setattr(metrics,'publish',lambda fact,**kw:published.append(fact) or True)
    metrics._TASK_VIEWS.clear()
    active=dict(task_ref='t1',status='ACTIVE')
    done=dict(task_ref='t1',status='COMPLETE',host_review={'coverage':'FULL'},
              static=dict(status='COMPLETED',coverage='FULL',capability_results={'CODE_SAST':'EXECUTED'}))
    metrics.task_observed(active,'work',1)
    metrics.task_observed(active,'work',1)
    metrics.task_observed(done,'work',3)
    metrics.task_observed(active,'work',1)
    assert len(published)==3
    report=metrics.report([event(fact,i) for i,fact in enumerate(published)])
    assert report['check_summary']['latest']['status']=='COMPLETED'
    assert report['check_summary']['observed_checks']==1
    assert report['scans']==0


@pytest.mark.parametrize('phase,expected',[
    ('ACTIVE','IN_PROGRESS'),('READY','IN_PROGRESS'),('REVIEWING','IN_PROGRESS'),
    ('STATIC_RUNNING','IN_PROGRESS'),('CAPACITY_REQUIRED','PARTIAL'),('NO_CHANGES','NOT_RUN')])
def test_task_lifecycle_states(phase,expected):
    assert task_check(dict(status=phase))['status']==expected


def test_reappearance_does_not_silently_cancel_manual_deferral():
    report=metrics.report([event(scan(),1),event(state('HANDLING','DEFERRED'),2),event(scan('s2'),3)])
    assert report['current_risks']['pending'] is None
    assert report['current_risks']['unknown']==1


def test_new_confirmed_verdict_reopens_resolution_but_not_manual_handling():
    facts=[event(scan(),1),event(state('HANDLING','DEFERRED'),2),
           event(state('VERIFICATION','SCANNER_VERIFIED_RESOLVED'),3),
           event(state('ASSESSMENT','CONFIRMED'),4)]
    current=metrics.report(facts)['current_risks']
    assert current['pending']==0 and current['resolved']==0 and current['deferred']==1
    current=metrics.report(facts+[event(state('HANDLING','OPEN'),5)])['current_risks']
    assert current['pending']==1 and current['deferred']==0


def test_recheck_still_present_does_not_cancel_explicit_pause():
    facts=[event(scan(),1),event(state('HANDLING','EXCLUDED'),2),event(state('VERIFICATION','STILL_PRESENT'),3)]
    current=metrics.report(facts)['current_risks']
    assert current['pending']==0 and current['excluded']==1 and current['resolved']==0


def test_later_completed_scan_replaces_prior_failure_without_erasing_history():
    facts=[event(scan('failed',findings=[],execution_state='FAILED',status='PARTIAL'),1),
           event(scan('complete',findings=[]),2)]
    report=metrics.report(facts)
    assert report['check_summary']['status_counts']=={'FAILED':1,'COMPLETED':1}
    assert report['current_risks']['pending']==0
    assert report['check_summary']['latest']['status']=='COMPLETED'


def test_changing_occurrence_ids_do_not_change_stable_risk_identity():
    second=scan('s2',findings=[dict(id='f2',fingerprint='a'*24,category='sql-injection',severity='HIGH')])
    report=metrics.report([event(scan(),1),event(second,2)])
    assert report['cumulative_finding_occurrences']==2
    assert report['current_risks']['known_identities']==1
    assert report['current_risks']['observed_pending']==1


@pytest.mark.parametrize('static,reason',[
    ({'status':'COMPLETED','coverage':'PARTIAL'},'TASK_STATIC_PARTIAL'),
    ({'status':'COMPLETED','coverage':'SCOPED'},'TASK_STATIC_PARTIAL'),
    ({'status':'COMPLETED','coverage':'UNKNOWN'},'TASK_STATIC_EVIDENCE_UNKNOWN'),
    (None,'TASK_STATIC_NOT_EXECUTED')])
def test_complete_host_review_cannot_mask_partial_or_missing_static_receipt(static,reason):
    check=task_check(dict(status='COMPLETE',static=static,host_review={'coverage':'FULL'}))
    assert check['status']=='PARTIAL' and reason in check['reason_codes']


def test_maximum_product_metadata_retains_total_and_marks_omitted_details(tmp_path,monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE','basic')
    from security_runtime import context_cost
    monkeypatch.setattr(context_cost,'MAX_OBSERVATION_RECORD_BYTES',4500)
    findings=[dict(id=f'f{i}',fingerprint=f'{i:024x}',category='configuration',severity='CRITICAL') for i in range(64)]
    store=ContextCostStore(tmp_path/'bounded.db')
    result=store.record_observation(metrics.envelope(scan(findings=findings),workspace=str(tmp_path)))
    assert result['status']=='RECORDED'
    saved=store.snapshot()['product_facts']
    fact=saved[0]['product_fact']
    assert fact['total']==64 and fact['omitted']>0
    assert fact['total']==len(fact['items'])+fact['omitted']
    assert fact['check']['limited'] and 'OBSERVATION_LIMIT' in fact['check']['reason_codes']
    assert metrics.report(saved)['current_risks']['pending'] is None


def test_richer_same_generation_view_replaces_commit_projection():
    early=dict(kind='CHECK',reference='task-a',source='LIVE',total=0,omitted=0,items=[],
        check=task_check(dict(status='ACTIVE')),revision=2,projection_rank=0)
    view=copy.deepcopy(early)
    view['projection_rank']=1
    view['check']['scope_counts']['unread_ranges']=3
    assert metrics.report([event(early,1),event(view,2)])['check_summary']['latest']['scope_counts']['unread_ranges']==3


def test_same_location_host_findings_never_claim_a_shared_cross_task_identity():
    def proposal(reference):
        items=[metrics.finding_item(dict(id=f'tc1-{number}',category='authorization',severity='HIGH',
            file_path='same.py',line_start=10)) for number in (1,2)]
        assert all('risk_key' not in item for item in items)
        return dict(kind='PROPOSAL',reference=reference,source='LIVE',total=2,omitted=0,items=items)
    same=proposal('task-a')
    report=metrics.report([event(same,1),event(copy.deepcopy(same),2)])
    current=report['current_risks']
    assert report['host_proposals']==2
    assert current['pending'] is None and current['known_identities']==0
    assert current['unknown']==2 and 'IDENTITY_UNAVAILABLE' in current['reason_codes']
    report=metrics.report([event(same,1),event(proposal('task-b'),2)])
    assert report['host_proposals']==4
    assert report['current_risks']['unknown']==4
    assert report['current_risks']['pending'] is None
