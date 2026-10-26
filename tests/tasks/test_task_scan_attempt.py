"""Task source identity, short publication locks and superseded worker fences."""
from contextlib import contextmanager
from pathlib import Path
import threading

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.hook_state import HookStateStore
from security_runtime.progress import ScanCancelled
from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_attempt import ScanAttemptStore, source_binding
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.security import TaskSecurityService


@pytest.fixture
def actual(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'code.ts').write_text('export const value = 1;\n')
    hooks = HookStateStore(tmp_path/'hooks')
    entered, release = threading.Event(), threading.Event()
    class BlockingNative(NativeFunctionScanner):
        def scan(self, context, normalizer):
            assert not hooks.lock_held(root)
            entered.set()
            assert release.wait(10), 'test worker was not released'
            return super().scan(context, normalizer)
    runtime = SecurityRuntime(ScannerRegistry([BlockingNative()],fallback_adapters=[]),
        SQLiteStore(tmp_path/'scan.db'))
    clock = [100.0]
    service = TaskSecurityService(runtime,hooks,now=lambda:clock[0])
    return service, root, runtime, hooks, entered, release, clock


def changed(actual):
    service,root,*_ = actual
    ref = service.begin(root,'task')['task_ref']
    baseline = service.load(root,ref)['baseline']
    (root/'code.ts').write_text('export const value = 2;\n')
    return ref,baseline


def worker(service,root,ref):
    result = []
    def execute():
        try: result.append(service.finish(root,ref))
        except BaseException as error: result.append(error)
    thread = threading.Thread(target=execute)
    thread.start()
    return thread,result


def test_engine_runs_unlocked_and_hook_arrival_is_merged_without_current_claim(actual):
    service,root,_,hooks,entered,release,_ = actual
    ref,baseline = changed(actual)
    thread,result = worker(service,root,ref)
    try:
        assert entered.wait(10)
        with hooks.lock(root) as acquired:
            assert acquired
            current = service.load(root,ref)
            current['hook_pending_scope_files'] = ['code.ts']
            current['hook_checks'] = [dict(change_digest='arrived-during-scan',status='PENDING')]
            service.store(root).save(current)
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive() and result[0]['status'] == 'STALE'
    saved = service.load(root,ref)
    assert saved['baseline'] == baseline and saved['static_attempts'] == 1
    assert saved['hook_pending_scope_files'] == ['code.ts']
    assert saved['hook_checks'][0]['change_digest'] == 'arrived-during-scan'
    assert saved['static']['execution_attempt']['publication'] == 'STALE'


def test_prepare_reports_busy_for_an_actual_active_same_task_worker(actual):
    service,root,_,hooks,entered,release,_=actual
    ref,baseline=changed(actual)
    thread,result=worker(service,root,ref)
    try:
        assert entered.wait(10)
        before=service.store(root).path.read_bytes()
        assert service.prepare(root,ref)['status']=='BUSY'
        assert service.store(root).path.read_bytes()==before
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive() and result[0]['status']=='READY'
    assert service.load(root,ref)['baseline']==baseline


def test_expired_worker_cannot_publish_or_cancel_a_new_cross_process_generation(actual):
    service,root,_,hooks,entered,release,clock = actual
    ref,baseline = changed(actual)
    thread,result = worker(service,root,ref)
    try:
        assert entered.wait(10)
        clock[0] += 601
        attempts = ScanAttemptStore(hooks,root,now=service.now)
        with hooks.lock(root):
            newer = attempts.claim('HOOK','new-activity',source_binding({'arrival':2}))
            assert newer is not None
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive() and isinstance(result[0],ScanCancelled)
    assert attempts.is_current(newer)
    saved = service.load(root,ref)
    assert saved['baseline'] == baseline and saved['static_attempts'] == 1
    assert saved['phase'] == 'STALE'
    assert saved['static']['status'] == 'CANCELLED'


def test_cancel_is_propagated_retains_budget_baseline_and_next_attempt_uses_same_task(actual):
    service,root,_,hooks,entered,release,_ = actual
    ref,baseline = changed(actual)
    thread,result = worker(service,root,ref)
    try:
        assert entered.wait(10)
        attempts = ScanAttemptStore(hooks,root,now=service.now)
        row = attempts.read()['lane']
        from security_runtime.scan_attempt import AttemptLease
        lease = AttemptLease(**{key:row[key] for key in ('attempt_id','generation','lease_owner','cancel_generation')})
        with hooks.lock(root): assert attempts.cancel(lease)
    finally:
        release.set()
        thread.join(15)
    assert isinstance(result[0],ScanCancelled)
    saved = service.load(root,ref)
    assert saved['baseline'] == baseline and saved['static_attempts'] == 1
    assert saved['static']['status'] == 'CANCELLED'
    out = service.finish(root,ref)
    assert out['status'] == 'READY'
    assert service.load(root,ref)['static_attempts'] == 2
    assert service.load(root,ref)['baseline'] == baseline


def test_begin_and_finish_all_snapshot_io_are_outside_workspace_lock(actual,monkeypatch):
    service,root,_,hooks,_,release,_ = actual
    import security_runtime.tasks.security as module
    original = module.capture
    captures = []
    def checked(*args,**kwargs):
        assert not hooks.lock_held(root)
        captures.append(kwargs.get('include_text',True))
        return original(*args,**kwargs)
    monkeypatch.setattr(module,'capture',checked)
    release.set()
    ref,baseline = changed(actual)
    assert service.finish(root,ref)['status'] == 'READY'
    assert captures.count(True) == 1 and captures.count(False) >= 2
    assert service.load(root,ref)['baseline'] == baseline


def test_another_task_closed_during_unlocked_baseline_capture_keeps_attribution_gap(actual,monkeypatch):
    from security_runtime.tasks.ownership import owner_scope, session_owner, current_owner
    import security_runtime.tasks.security as module
    service,root,_,hooks,_,release,clock=actual
    service.owner=current_owner
    first_owner,second_owner=session_owner('codex','first'),session_owner('cursor','second')
    clock[0]=90
    with owner_scope(first_owner):
        first=service.begin(root,'first')['task_ref']
    original=module.capture
    capture_entered,capture_release=threading.Event(),threading.Event()
    def blocked(*args,**kwargs):
        value=original(*args,**kwargs)
        if kwargs.get('include_text',True):
            assert not hooks.lock_held(root)
            capture_entered.set()
            assert capture_release.wait(10)
        return value
    monkeypatch.setattr(module,'capture',blocked)
    clock[0]=100
    result=[]
    def begin_second():
        try:
            with owner_scope(second_owner): result.append(service.begin(root,'second'))
        except BaseException as error: result.append(error)
    thread=threading.Thread(target=begin_second)
    thread.start()
    try:
        assert capture_entered.wait(10), repr(result)
        clock[0]=105
        with owner_scope(first_owner): service.skip(root,first,'finished while another baseline was being captured')
        clock[0]=110
    finally:
        capture_release.set()
        thread.join(15)
    assert not thread.is_alive() and isinstance(result[0],dict)
    second=result[0]['task_ref']
    with owner_scope(second_owner):
        record=service.load(root,second)
        assert record['created_at']==100
        (root/'code.ts').write_text('export const value = 3;\n')
        release.set()
        service.finish(root,second)
        saved=service.load(root,second)
    assert not any(row['reason']=='CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE'
                   for row in saved['limitations'])


@pytest.mark.parametrize('changed_path',['code.ts','.semgrepignore','package.json'])
def test_a_b_a_capture_is_rejected_before_any_provider_not_hidden_by_final_live_hash(actual,monkeypatch,changed_path):
    service,root,runtime,hooks,entered,release,_ = actual
    if changed_path != 'code.ts':
        (root/changed_path).write_text('{}\n' if changed_path=='package.json' else 'old-ignore\n')
    ref,baseline = changed(actual)
    import security_runtime.runtime as module
    original = module.capture_scan_input
    expected = (root/changed_path).read_text()
    @contextmanager
    def altered(request,**kwargs):
        (root/changed_path).write_text('other-private-input\n')
        with original(request,**kwargs) as view:
            (root/changed_path).write_text(expected)
            yield view
    monkeypatch.setattr(module,'capture_scan_input',altered)
    release.set()
    with pytest.raises(ScanCancelled,match='SOURCE_MISMATCH'):
        service.finish(root,ref)
    assert not entered.is_set()
    saved = service.load(root,ref)
    assert saved['baseline'] == baseline and saved['static_attempts'] == 1
    assert saved['static']['status'] == 'CANCELLED'
    assert not list(ScanAttemptStore(hooks,root).private_parent.iterdir())
