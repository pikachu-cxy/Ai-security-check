"""Lightweight checks operate on explicit paths in isolated temporary projects."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import threading
import time

import pytest

from security_runtime.development_check import DevelopmentCheckService, DevelopmentCheckStore, record_hook
from security_runtime.development_check_worker import launch_worker, run_worker
from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.ownership import TaskOwnershipError

OWNER = dict(host='codex', session='1'*64)


@pytest.fixture
def check(tmp_path, monkeypatch):
    root = tmp_path/'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root/'app.ts').write_text('def run(value):\n    return value\n')
    (root/'unobserved.ts').write_text('eval(input())\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'private'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL', raising=False)
    hooks = HookStateStore(tmp_path/'private/hooks')
    scans = SQLiteStore(tmp_path/'private/scans.db')
    state = dict(calls=0, callback=None, inputs=[])
    class Observed(NativeFunctionScanner):
        def scan(self, context, normalizer):
            from security_runtime.verification_policy import local_recheck_requested
            assert local_recheck_requested()
            state['calls'] += 1
            state['inputs'].append(context.files)
            assert 'unobserved.ts' not in context.files
            if state['callback']:
                state['callback'](context)
            return super().scan(context, normalizer)
    runtime = SecurityRuntime(ScannerRegistry([Observed()], fallback_adapters=[]), scans)
    service = DevelopmentCheckService(runtime, hooks, owner=OWNER,
        scan_path_provider=lambda: scans.path, launcher=lambda *args: None)
    return root, service, runtime, state


def execute(check, monkeypatch, **kwargs):
    root, service, runtime, state = check
    for row in service.store(root).rows():
        if row.get('kind') == 'check' and row['state'] == 'DIRTY':
            service.finish(root, row['check_ref'])
    from security_runtime import development_check_worker
    original = development_check_worker._scan
    def observed_scan(*args, **kw):
        try:
            return original(*args, **kw)
        except Exception as error:
            state['failure'] = repr(error)
            raise
    monkeypatch.setattr(development_check_worker, '_scan', observed_scan)
    with monkeypatch.context() as launching:
        launching.setattr('security_runtime.development_check_worker.subprocess.Popen', lambda *args, **kw: None)
        assert launch_worker(service.hooks, root)
    ticket = service.store(root).read('$worker')['ticket']
    return run_worker(root, service.hooks.directory, ticket,
        runtime_factory=lambda row: runtime, debounce_seconds=0, **kwargs)


def test_begin_and_empty_finish_never_capture_source_or_scan(check, monkeypatch):
    root, service, runtime, state = check
    def forbidden(*args, **kwargs):
        raise AssertionError('whole-project capture forbidden')
    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr(runtime, 'scan', forbidden)
    first = service.begin(root, 'task-one')
    assert first['status'] == 'OPEN' and not first['baseline_created']
    assert service.begin(root, 'task-one')['check_ref'] == first['check_ref']
    assert service.finish(root, first['check_ref'])['status'] == 'NO_OBSERVED_CHANGES'
    assert service.get(root, first['check_ref'])['dirty_seq'] == 0
    assert not (service.hooks.workspace_directory(root)/'security-tasks.db').exists()


def test_hook_auto_check_adopt_replay_and_finish_then_edit(check):
    root, service, runtime, state = check
    def hook(event, paths=('app.ts',)):
        return record_hook(service.hooks, root, OWNER, paths,
            scope_unknown=False, event_id=event, scan_path=runtime.store.path, launcher=lambda *args: None)
    original = hook('event-1')
    ref = original['check_ref']
    adopted = service.begin(root, 'explicit-key')
    assert adopted['check_ref'] == ref and adopted['dirty_seq'] == 1
    assert service.begin(root, 'explicit-key')['check_ref'] == ref
    service.finish(root, ref)
    after = hook('event-2')
    assert after['check_ref'] == ref and after['dirty_seq'] == 2
    assert not after['finish_requested']
    switched = service.begin(root, 'new-task')
    assert switched['check_ref'] != ref
    replay = hook('event-1')
    assert replay['check_ref'] == ref and replay['dirty_seq'] == 2
    assert service.get(root, switched['check_ref'])['dirty_seq'] == 0


def test_burst_merges_paths_and_checks_only_observed_scope(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'burst')['check_ref']
    launches = []
    service.launcher = lambda *args: launches.append(args)
    for i in range(100):
        service.record(root, ref, ['app.ts'], event_id='edit-'+str(i))
    assert not launches and state['calls'] == 0
    assert service.get(root, ref)['status'] == 'DIRTY'
    assert service.get(root, ref)['next_action']['tool'] == 'finish_development_check'
    service.finish(root, ref)
    assert len(launches) == 1
    def forbidden(*args, **kwargs):
        raise AssertionError('whole-project capture forbidden')
    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert state['calls'] == 1 and state['inputs'] == [('app.ts',)], state.get('failure')
    assert result['dirty_seq'] == result['scanned_seq'] == 100
    assert result['scan_id'] and result['result_is_saved_version']
    assert result['scope']['full_project'] is False
    assert result['host_review_completed'] is False
    assert result['execution']['publication'] == 'COMMITTED'
    assert result['static_result']['findings_access']['arguments']['scan_id'] == result['scan_id']


def test_scan_inflight_edit_waits_for_next_finish_on_same_ref(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'race')['check_ref']
    service.record(root, ref, ['app.ts'])
    def mutate(context):
        if state['calls'] == 1:
            (root/'app.ts').write_text('def run(value):\n    return value + 1\n')
            service.record(root, ref, ['app.ts'], event_id='second')
    state['callback'] = mutate
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert state['calls'] == 1 and result['status'] == 'DIRTY'
    assert result['dirty_seq'] == 2 and result['scanned_seq'] == 1
    assert result['next_action']['tool'] == 'finish_development_check'
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert state['calls'] == 2
    assert result['dirty_seq'] == result['scanned_seq'] == 2
    assert result['execution']['source_applicability'] == 'CURRENT'


def test_unreported_inflight_edit_remains_explicitly_stale(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'external-change')['check_ref']
    service.record(root, ref, ['app.ts'])
    state['callback'] = lambda context: (root/'app.ts').write_text('different bytes\n')
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert result['status'] == 'PARTIAL'
    assert 'SOURCE_CHANGED_DURING_SCAN' in result['gaps']


def test_unknown_and_deleted_scope_never_expand_to_project(check, monkeypatch):
    root, service, runtime, state = check
    (root/'node_modules').mkdir()
    (root/'node_modules/skip.ts').write_text('ordinary text\n')
    ref = service.begin(root, 'bounded')['check_ref']
    service.record(root, ref, ['app.ts', 'removed.ts', 'node_modules/skip.ts'], scope_unknown=True)
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert result['status'] == 'PARTIAL' and result['scan_id']
    assert 'UNOBSERVED_PATHS_POSSIBLE' in result['gaps']
    assert 'DELETED_PATH_SEMANTICS_NOT_REVIEWED' in result['gaps']
    assert 'OBSERVED_FILES_NOT_SCANNED' in result['gaps']
    assert all('unobserved.ts' not in names for names in state['inputs'])


def test_unknown_only_never_constructs_runtime(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'unknown-only')['check_ref']
    service.record(root, ref, [], scope_unknown=True)
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert state['calls'] == 0 and result['status'] == 'PARTIAL'
    assert 'UNOBSERVED_PATHS_POSSIBLE' in result['gaps']


def test_result_reads_do_not_rehash_dispatch_or_scan(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'read-only-result')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert execute(check, monkeypatch) == 0
    before = service.store(root).path.read_bytes()
    (root/'app.ts').write_text('changed after check\n')
    def forbidden(*args, **kwargs):
        raise AssertionError('read must not execute')
    monkeypatch.setattr(runtime, 'scan', forbidden)
    service.launcher = forbidden
    result = service.get(root, ref)
    assert result['source_freshness'] == 'NOT_RECHECKED_ON_READ'
    assert result['scanner_run'] is False and result['result_is_saved_version']
    assert before == service.store(root).path.read_bytes()


def test_owner_path_and_signature_guards(check):
    root, service, runtime, state = check
    ref = service.begin(root, 'guarded')['check_ref']
    other = DevelopmentCheckService(None, service.hooks,
        owner=dict(host='codex', session='2'*64), launcher=lambda *args: None)
    with pytest.raises(TaskOwnershipError):
        other.record(root, ref, ['app.ts'])
    with pytest.raises(ValueError):
        service.record(root, ref, ['../outside.py'])
    with pytest.raises(ValueError):
        service.record(root, ref, ['*.py'])
    with sqlite3.connect(service.store(root).path) as db:
        db.execute('UPDATE records SET mac=? WHERE key=?', ('0'*64, ref))
    with pytest.raises(ValueError, match='signature'):
        service.get(root, ref)


def test_worker_launch_is_hidden_bounded_and_recovers_dead_running(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'launch')['check_ref']
    service.record(root, ref, ['app.ts'])
    service.finish(root, ref)
    launches = []
    monkeypatch.setattr('security_runtime.development_check_worker.subprocess.Popen',
        lambda *args, **kwargs: launches.append((args, kwargs)))
    assert launch_worker(service.hooks, root)
    assert not launch_worker(service.hooks, root)
    assert len(launches) == 1
    argv, kwargs = launches[0]
    assert '-I' in argv[0] and 'security_runtime.cli' in argv[0]
    assert 'development-check-worker' in argv[0]
    assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['stdout'] == subprocess.DEVNULL
    if os.name == 'nt':
        assert kwargs['creationflags'] & subprocess.CREATE_NO_WINDOW
    else:
        assert kwargs['start_new_session']
    queue = service.store(root)
    with queue.transaction() as db:
        row, worker = queue._get(db, ref), queue._get(db, '$worker')
        queue._put(db, ref, dict(row, state='RUNNING', worker_ticket=worker['ticket']))
        queue._put(db, '$worker', dict(worker, lease_until=0))
    assert service.get(root, ref)['status'] == 'INTERRUPTED'
    assert launch_worker(service.hooks, root)
    assert queue.load(ref)['state'] == 'QUEUED'


def test_worker_failure_keeps_pending_scope_and_can_retry_explicitly(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'provider-fails')['check_ref']
    service.record(root, ref, ['app.ts'])
    def fail(*args, **kwargs):
        raise RuntimeError('PRIVATE_SECRET')
    monkeypatch.setattr(runtime, 'scan', fail)
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert result['status'] == 'FAILED' and result['scanned_seq'] == 0
    assert 'PRIVATE_SECRET' not in json.dumps(result)
    assert service.finish(root, ref)['dirty_seq'] == 1
    assert service.store(root).load(ref)['state'] == 'QUEUED'


def test_old_finished_nonfocus_metadata_retired_without_deleting_scans(check):
    root, service, runtime, state = check
    old = service.begin(root, 'old')['check_ref']
    service.finish(root, old)
    new = service.begin(root, 'new')['check_ref']
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, old)
        store._put(db, old, dict(row, updated_at=0))
    service.begin(root, 'third')
    assert store.read(old) is None
    assert store.read(new) is not None
    assert runtime.store.path.exists()


def test_manifest_only_complete_scope_is_not_a_scanner_gap(check, monkeypatch):
    from security_runtime.capabilities import Capability
    from security_runtime.models import ScannerRun
    root, service, old_runtime, state = check
    (root/'package.json').write_text('{"name":"fixture","dependencies":{}}')
    class ManifestScanner:
        name = scanner_id = 'fixture-manifest'
        capabilities = frozenset({Capability.SECRET_SCAN, Capability.DEPENDENCY_VULN})
        def supports(self, profile, context):
            return 'package.json' in context.files
        def scan(self, context, normalizer):
            from security_runtime.verification_policy import local_recheck_requested
            assert local_recheck_requested()
            return [], ScannerRun(self.name, 'fixture', 'SUCCESS', 0)
    runtime = SecurityRuntime(ScannerRegistry([ManifestScanner()], fallback_adapters=[]), old_runtime.store)
    ref = service.begin(root, 'manifest-only')['check_ref']
    service.record(root, ref, ['package.json'])
    assert execute((root, service, runtime, state), monkeypatch) == 0
    result = service.get(root, ref)
    assert result['scan_status'] == 'COMPLETED' and result['scan_coverage'] == 'SCOPED'
    assert result['status'] == 'RESULTS_READY'
    assert 'SCANNER_COVERAGE_LIMITED' not in result['gaps']


def test_global_worker_capacity_promotes_saved_pending_workspace(check, monkeypatch):
    from security_runtime.development_check_worker import _release_capacity
    root, service, runtime, state = check
    roots = [root]
    for index in (2, 3):
        other = root.parent/('project'+str(index))
        other.mkdir()
        (other/'app.ts').write_text('export const value = 1;\n')
        roots.append(other)
    for index, selected in enumerate(roots):
        ref = service.begin(selected, 'capacity-'+str(index))['check_ref']
        service.record(selected, ref, ['app.ts'])
        service.finish(selected, ref)
    launches = []
    monkeypatch.setattr('security_runtime.development_check_worker.subprocess.Popen',
        lambda *args, **kwargs: launches.append(args[0]))
    assert launch_worker(service.hooks, roots[0])
    assert launch_worker(service.hooks, roots[1])
    assert not launch_worker(service.hooks, roots[2])
    assert len(launches) == 2
    ticket = service.store(roots[0]).read('$worker')['ticket']
    _release_capacity(service.hooks, ticket)
    assert len(launches) == 3 and service.store(roots[2]).read('$worker')


def test_arrival_between_last_queue_read_and_retirement_is_not_lost(check, monkeypatch):
    root, service, runtime, state = check
    ref = service.begin(root, 'exit-arrival')['check_ref']
    service.record(root, ref, ['app.ts'])
    original = DevelopmentCheckStore.rows
    injected = []
    def arriving(queue):
        rows = original(queue)
        if (queue.root == root and state['calls'] == 1 and not injected
                and not any(row.get('state') == 'QUEUED' for row in rows)):
            injected.append(True)
            (root/'app.ts').write_text('export const value = 2;\n')
            service.record(root, ref, ['app.ts'], event_id='at-retirement')
            service.finish(root, ref)
        return rows
    monkeypatch.setattr(DevelopmentCheckStore, 'rows', arriving)
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert injected and state['calls'] == 2
    assert result['scanned_seq'] == result['dirty_seq'] == 2
