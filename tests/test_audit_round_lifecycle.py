"""Development rounds own executors; no scanner or model in these tests."""
import pytest
from test_development_risks import sample
from test_audit_stream_service import child
from security_runtime.audit_stream_service import manage, process
from security_runtime.incremental_audit import cutoff
from security_runtime.development_stop import audit_report_changed


def test_next_round_requires_new_executor_and_rejects_old_capability(sample):
    risks, args, batch, review = child(sample)
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, risks.ref)
        cutoff(check)
        risks.checks._put(db, risks.ref, check)
    saved = process(risks, 'submit', batch_id=batch['batch_id'], request_id='round-one-save',
                    business_reviews=[review], **args)
    assert saved['review_saved'] and risks.current_check()['audit_delegate']['closed']
    assert process(risks, 'submit', batch_id=batch['batch_id'], request_id='round-one-save',
                   business_reviews=[review], **args)['repeated']
    sample[1].record(sample[0], sample[2], ['query.py'])
    status = manage(risks, 'status')
    assert status['host_next_action'] == 'stream_prepare'
    assert status['executor_stage'] == 'NOT_DISPATCHED'
    prepared = manage(risks, 'prepare')
    assert prepared['audit_token'] != args['audit_token']
    assert not prepared['executor_bound']
    with pytest.raises(ValueError, match='CAPABILITY|ROUND'):
        process(risks, 'claim', **args)
    registered = manage(risks, 'started', agent_ref='new-round-child', audit_token=prepared['audit_token'])
    assert registered['child_call']['arguments']['agent_ref'] == 'new-round-child'
    assert len(risks.load()['reviews']) == 1


def test_within_round_reuses_executor_without_rotating(sample):
    risks, args, batch, review = child(sample)
    before = risks.current_check()['audit_delegate'].copy()
    sample[1].record(sample[0], sample[2], ['query.py'])
    prepared = manage(risks, 'prepare')
    assert prepared['host_next_action'] == 'FOLLOWUP_EXISTING_EXECUTOR'
    assert 'audit_token' not in prepared
    assert risks.current_check()['audit_delegate'] == before


def test_late_report_revision_is_distinct_from_same_scan_notice():
    row = dict(dirty_seq=3, scan_id='scan', audit_result_revision=1,
               stop_closeout_notice=dict(seq=3, scan_id='scan', mode='REVIEW'))
    assert audit_report_changed(row)
    assert not audit_report_changed(dict(row, stop_noticed_audit_revision=1))
    assert not audit_report_changed(dict(row, stop_offered_audit_revision=1))
    assert not audit_report_changed(dict(row, dirty_seq=4))


def test_late_audit_joins_confirmed_same_sql_sink_and_keeps_both_sources(sample, monkeypatch):
    from test_three_mode_repairs import scanner_review
    primary = scanner_review(sample, monkeypatch, 'CONFIRMED')
    risks, args, batch, review = child(sample)
    value = dict(issue_key='late-query', file_path='query.py', line_start=1, line_end=2,
                 category='SQL injection', title='查询参数进入 SQL', description='输入直接进入执行位置',
                 impact='可修改查询含义', fix_advice='绑定参数', severity='HIGH', decision='CONFIRMED',
                 rationale='同一执行位置和相同源码证据', evidence_refs=review['evidence_refs'])
    saved = process(risks, 'submit', batch_id=batch['batch_id'], request_id='late-sql-save',
                    observations=[value], business_reviews=[review], **args)
    assert saved['review_saved']
    ledger = risks.load()
    assert list(ledger['risks']) == [primary]
    risk = ledger['risks'][primary]
    assert len(risk['assessments']) == 2
    assert {o['source'] for o in risk['observations']} == {'SCANNER', 'HOST_REVIEW'}
    assert risks.current_check()['audit_result_revision'] == 1


def test_late_audit_different_category_is_not_merged(sample, monkeypatch):
    from test_three_mode_repairs import scanner_review
    scanner_review(sample, monkeypatch, 'CONFIRMED')
    risks, args, batch, review = child(sample)
    value = dict(issue_key='separate-authorization', file_path='query.py', line_start=1, line_end=2,
                 category='authorization', title='独立权限问题', description='缺少独立归属检查',
                 impact='访问其他用户数据', fix_advice='校验归属', severity='HIGH', decision='CONFIRMED',
                 rationale='与 SQL 输入拼接不同的问题', evidence_refs=review['evidence_refs'])
    process(risks, 'submit', batch_id=batch['batch_id'], request_id='separate-save',
            observations=[value], business_reviews=[review], **args)
    assert len(risks.load()['risks']) == 2


def test_report_notice_reissues_only_for_new_audit_revision(sample, monkeypatch):
    from test_three_mode_repairs import scanner_review
    from security_runtime.development_stop import report_notice
    scanner_review(sample, monkeypatch, 'CONFIRMED')
    root, service, ref, risks = sample
    state = dict(scan_id='scan-1')
    row = risks.current_check()
    assert report_notice(service, root, row, state, {}, 'STOP_RESULT_NOTICE')
    assert report_notice(service, root, row, state, {}, 'STOP_RESULT_NOTICE') is None

    with risks.checks.transaction() as db:
        check = risks.checks._get(db, ref)
        check['audit_result_revision'] = 1
        risks.checks._put(db, ref, check)
    row = risks.current_check()
    assert report_notice(service, root, row, state, {}, 'STOP_RESULT_NOTICE')
    assert report_notice(service, root, row, state, {}, 'STOP_RESULT_NOTICE') is None


def test_reopened_service_does_not_reuse_previous_round_executor(sample):
    from security_runtime.development_check import DevelopmentCheckService
    from security_runtime.development_risks import DevelopmentRisks
    risks, args, batch, review = child(sample)
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, risks.ref)
        cutoff(check)
        risks.checks._put(db, risks.ref, check)
    process(risks, 'submit', batch_id=batch['batch_id'], request_id='restart-save',
            business_reviews=[review], **args)
    root, service, ref, _ = sample
    reopened = DevelopmentCheckService(None, service.hooks, owner=service.owner,
        scan_path_provider=service.scan_path_provider, launcher=lambda *a: pytest.fail('No scan'))
    reopened.record(root, ref, ['query.py'])
    current = DevelopmentRisks(reopened, root, ref)
    prepared = manage(current, 'prepare')
    assert not prepared['executor_bound'] and prepared['audit_token'] != args['audit_token']
    assert len(current.load()['reviews']) == 1


def test_native_stop_delivers_late_result_without_rescanning(sample, monkeypatch):
    import hashlib
    from test_three_mode_repairs import scanner_review
    from security_runtime.development_stop import fallback
    scanner_review(sample, monkeypatch, 'CONFIRMED')
    root, service, ref, risks = sample
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, ref)
        row.update(finish_requested=True, state='RESULTS_READY', audit_result_revision=1,
            stop_review_notice=[row['dirty_seq'], row['scan_id']],
            stop_closeout_notice=dict(seq=row['dirty_seq'], scan_id=row['scan_id'], mode='REVIEW'),
            stop_activity=dict(pending=False, base_seq=0, turn=hashlib.sha256(b'development').hexdigest()))
        risks.checks._put(db, ref, row)
    page = dict(review_progress=dict(pending_scanner_ids=[], pending_business_paths=[]),
                risks=[], next_offset=None, report_text='Latest audit report')
    monkeypatch.setattr(service, 'get', lambda *a: dict(status='RESULTS_READY',
        result_available=True, review_ready=True, development_result=page,
        dirty_seq=row['dirty_seq'], scanned_seq=row['dirty_seq'], scan_id=row['scan_id']))
    monkeypatch.setattr(service, 'finish', lambda *a: pytest.fail('Saved result must not restart'))
    assert fallback(service.hooks, root, service.owner, service=service,
        automatic=True, turn_id='unrelated') is None
    notice = fallback(service.hooks, root, service.owner, service=service,
        automatic=True, turn_id='development')
    assert notice['decision'] == 'block' and notice['status'] == 'STOP_RESULT_NOTICE'
    assert fallback(service.hooks, root, service.owner, service=service,
        automatic=True, turn_id='development') is None
