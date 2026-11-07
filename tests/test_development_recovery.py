"""Late publication, interrupted admission and independent workspace recovery."""
import time
import pytest
from test_development_check import check, execute, OWNER
from test_user_config_stop import config
from test_development_risks import sample
from test_closeout_notice import ready
from security_runtime.development_check import record_hook, owner_key
from security_runtime.development_stop import fallback, incomplete_notice
from security_runtime.development_recovery import resume, run


def native(check):
    root, service, _, _ = check
    record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='original')
    return service.store(root).read('focus:' + owner_key(OWNER))['check_ref']


@pytest.mark.parametrize('review', [True, False])
def test_late_result_delivered_on_readonly_stop_without_scan(sample, monkeypatch, review):
    root, service, ref, risks = sample
    incomplete_notice(service, root, ref, 1, {})
    ready(sample, monkeypatch, review)
    # No new edit and no matching turn: this was the lost-handoff case.
    value = fallback(service.hooks, root, service.owner, service=service,
                     turn_id='later-readonly', automatic=True)
    assert value['decision'] == 'block' and value['check_ref'] == ref
    from security_runtime.development_views import closeout_page
    page = closeout_page(risks, 0, None)
    assert page['closeout_mode'] == ('REVIEW' if review else 'REPORT')
    assert fallback(service.hooks, root, service.owner, service=service,
                    turn_id='later-readonly', automatic=True) is None


def test_interrupted_admission_resumes_original_sequence_once(check, config, monkeypatch):
    root, service, _, counts = check
    ref = native(check)
    launches = []
    a = resume(service.hooks, root, OWNER, launcher=lambda *a: launches.append(a))
    assert a['status'] == 'STOP_FALLBACK_INCOMPLETE'
    assert resume(service.hooks, root, OWNER, launcher=lambda *a: launches.append(a)) is None
    assert len(launches) == 1 and counts['calls'] == 0
    monkeypatch.setattr('security_runtime.development_check.DevelopmentCheckService._wake', lambda *a: None)
    def finish(hooks, root):
        execute(check, monkeypatch)
        return False
    monkeypatch.setattr('security_runtime.development_scheduler.recover_once', finish)
    request = service.store(root).read('recovery:' + ref)
    assert run(root, service.hooks.directory, ref, request['ticket']) == 0
    saved = service.store(root).load(ref)
    assert saved['dirty_seq'] == saved['scanned_seq'] == 1 and counts['calls'] == 1
    result = resume(service.hooks, root, OWNER)
    assert result and result['check_ref'] == ref
    from security_runtime.development_risks import DevelopmentRisks
    from security_runtime.development_views import closeout_page
    page = closeout_page(DevelopmentRisks(service, root, ref), 0, None)
    assert '未发现扫描候选漏洞' in page['report_text']
    assert resume(service.hooks, root, OWNER) is None and counts['calls'] == 1


def test_recovery_rejects_other_owner_and_superseded_sequence(check, config, monkeypatch):
    root, service, _, counts = check
    ref = native(check)
    launches = []
    assert resume(service.hooks, root, dict(OWNER, session='2'*64), launcher=launches.append) is None
    resume(service.hooks, root, OWNER, launcher=lambda *a: launches.append(a))
    request = service.store(root).read('recovery:' + ref)
    service.record(root, ref, ['app.ts'], event_id='new')
    assert run(root, service.hooks.directory, ref, request['ticket']) == 2
    assert not service.store(root).load(ref)['finish_requested'] and counts['calls'] == 0


def test_completed_previous_watch_gap_stays_on_old_delivery(check, config, monkeypatch):
    root, service, _, counts = check
    ref = native(check)
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, file_watch_gaps=['FILE_WATCH_INTERRUPTED'], scope_unknown=True))
    execute(check, monkeypatch)
    service.record(root, ref, ['app.ts'])
    current = store.load(ref)
    assert not current['file_watch_gaps'] and not current['scope_unknown']
    old = store.read('delivery:' + ref + ':1')
    assert old['file_watch_gaps'] == ['FILE_WATCH_INTERRUPTED'] and old['scope']['scope_unknown']


@pytest.mark.parametrize('phase', ['journal', 'engine_saved'])
@pytest.mark.parametrize('attempts', [1, 3])
def test_worker_saved_result_reconciles_without_second_scan(check, config, monkeypatch, phase, attempts):
    root, service, _, counts = check
    ref = native(check)
    from security_runtime import development_delivery
    original = development_delivery.publish
    class ProcessCrash(BaseException):
        pass
    def interrupted(*a):
        raise ProcessCrash('crash after engine save, before journal commit')
    from security_runtime.scan_attempt import ScanAttemptExecution
    after_scan = ScanAttemptExecution.after_scan
    if phase == 'journal':
        monkeypatch.setattr(development_delivery, 'publish', interrupted)
    else:
        monkeypatch.setattr(ScanAttemptExecution, 'after_scan', interrupted)
    with pytest.raises(ProcessCrash):
        execute(check, monkeypatch)
    assert counts['calls'] == 1
    monkeypatch.setattr(development_delivery, 'publish', original)
    monkeypatch.setattr(ScanAttemptExecution, 'after_scan', after_scan)
    with service.store(root).transaction() as db:
        row = service.store(root)._get(db, ref)
        service.store(root)._put(db, ref, dict(row, attempt_count=attempts))
    # The worker lease is released; normal recovery requeues its original row.
    assert execute(check, monkeypatch) == 0
    row = service.store(root).load(ref)
    assert counts['calls'] == 1 and row['dirty_seq'] == row['scanned_seq']
    assert row['result']['execution']['recovered_saved_result']
    assert len([r for r in service.store(root).rows() if r.get('kind') == 'delivery']) == 1


def test_recovery_launch_failure_has_durable_limit(check, config):
    root, service, _, _ = check
    ref = native(check)
    calls = []
    def broken(*args):
        calls.append(1)
        raise OSError('private launch detail')
    for _ in range(5):
        resume(service.hooks, root, OWNER, launcher=broken)
    assert len(calls) == 3
    row = service.store(root).load(ref)
    assert row['stop_closeout_notice']['reason'] == 'RECOVERY_FAILED'


def test_permanent_failure_stops_after_one_attempt(check, config, monkeypatch):
    root, service, _, _ = check
    ref = native(check)
    calls = []
    from security_runtime.development_check_worker import DevelopmentScanFailure
    def broken(*a, **k):
        calls.append(1)
        raise DevelopmentScanFailure(dict(stage='RULE_PLANNING', exception_type='FileNotFoundError'))
    monkeypatch.setattr('security_runtime.development_check_worker._scan', broken)
    execute(check, monkeypatch)
    assert calls == [1] and service.store(root).load(ref)['state'] == 'FAILED'


def test_effective_wait_is_bounded_and_scanner_zero_rejected(config):
    from security_runtime.user_config import describe_config
    assert describe_config()['effective_native_wait_seconds'] == 18
    config.write_text('[development.stop_fallback]\nnative_wait_seconds=4\n')
    assert describe_config()['effective_native_wait_seconds'] == 4
    config.write_text('[scan.execution]\nsast_timeout_seconds=0\n')
    assert describe_config()['status'] == 'INVALID'


def test_new_turn_keeps_original_pending_batch_addressable(check, config):
    root, service, _, _ = check
    ref = native(check)
    incomplete_notice(service, root, ref, 1, {})
    new = record_hook(service.hooks, root, OWNER, ['app.ts'], turn_id='next-turn')
    assert new['check_ref'] != ref
    assert service.store(root).load(new['check_ref'])['previous_closeout_ref'] == ref
    assert service.store(root).load(ref)['dirty_seq'] == 1
    launches = []
    resume(service.hooks, root, OWNER, launcher=lambda *a: launches.append(a))
    assert len(launches) == 1 and launches[0][2] == ref


def test_dead_worker_shortcuts_lease_but_unknown_pid_does_not(check, config, monkeypatch):
    root, service, _, _ = check
    ref = native(check)
    service.finish(root, ref)
    from security_runtime.development_check_worker import launch_worker
    monkeypatch.setattr('security_runtime.development_check_worker.subprocess.Popen', lambda *a, **k: None)
    assert launch_worker(service.hooks, root)
    store = service.store(root)
    worker = store.read('$worker')
    with store.transaction() as db:
        store._put(db, ref, dict(store._get(db, ref), state='RUNNING', worker_ticket=worker['ticket'], worker_pid=999999999))
    from security_runtime.development_scheduler import retire_dead_worker
    monkeypatch.setattr('os.kill', lambda *a: (_ for _ in ()).throw(PermissionError()))
    assert not retire_dead_worker(store, worker, [store.load(ref)])
    monkeypatch.setattr('os.kill', lambda *a: (_ for _ in ()).throw(ProcessLookupError()))
    assert retire_dead_worker(store, worker, [store.load(ref)])
    assert store.read('$worker')['lease_until'] == 0


def test_review_reply_loss_reads_saved_report_without_resubmission(sample, monkeypatch):
    root, service, ref, risks = sample
    ready(sample, monkeypatch)
    incomplete_notice(service, root, ref, 1, {})
    from security_runtime.development_views import closeout_page
    page = closeout_page(risks, 0, None)
    candidate = page['candidates'][0]
    evidence = risks.read('query.py', 1, 2)['evidence_ref']
    risks.submit([dict(same_issue_as=candidate['id'], decision='DISMISSED',
        rationale='Synthetic test alert', evidence_refs=[evidence])], 1, scan_id='scan-1',
        return_risks=True, final_report=True)  # Discard transport reply.
    before = len(risks.current_check()['security_result']['reviews'])
    report = closeout_page(risks, 0, None)
    assert report['closeout_mode'] == 'REPORT'
    assert '误报' in report['report_text']
    assert len(risks.current_check()['security_result']['reviews']) == before == 1
