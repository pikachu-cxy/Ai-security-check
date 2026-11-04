"""Async requests use fake engines/temporary projects; never scan a user project."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.scan_jobs import ScanJobs, run_worker
from security_runtime.storage import SQLiteStore
from security_runtime.workspace_application import WorkspaceApplication


@pytest.fixture
def jobs(tmp_path, monkeypatch):
    root = tmp_path/'project'
    root.mkdir()
    (root/'app.py').write_text('pass\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL', raising=False)
    hooks = HookStateStore(tmp_path/'state/hooks')
    store = SQLiteStore(tmp_path/'state/scans.db')
    return ScanJobs(hooks, root, scan_path=store.path)


def submit(jobs, key='request-0001', **kwargs):
    return jobs.submit(key, launcher=lambda *a: None, **kwargs)


def fake_app(jobs, *, entered=None, release=None, fail=False):
    def scan(*args, **kwargs):
        if entered:
            entered.set()
        if release:
            assert release.wait(5)
        if fail:
            raise RuntimeError('password=PRIVATE-MATERIAL')
        kwargs['progress'].emit('SCANNER_STARTED', scanner='fake')
        return dict(scan_id='fake-scan', status='PARTIAL', scanner_runs=[dict(status='SUCCESS')])
    return SimpleNamespace(scan_project=scan, scan_files=scan, scan=scan)


def execute(jobs, ref, **kwargs):
    row = jobs.load(ref)
    return run_worker(str(jobs.root), jobs.hooks.directory, ref, row['ticket'],
                      application_factory=lambda row: fake_app(jobs, **kwargs))


def test_return_immediately_and_reconnect_without_rescan(jobs):
    first = submit(jobs)
    assert first['status'] == 'QUEUED' and first['scanner_run'] is False
    assert first['scan_id'] is None and first['result_available'] is False
    other = ScanJobs(jobs.hooks, jobs.root, scan_path=jobs.scan_path)
    assert submit(other)['job_ref'] == first['job_ref']
    assert len(other.listing()['jobs']) == 1
    assert execute(other, first['job_ref']) == 0
    assert submit(other)['job_ref'] == first['job_ref']
    assert other.status(first['job_ref'])['status'] == 'COMPLETED'
    assert execute(other, first['job_ref']) == 2


def test_scan_worker_launch_does_not_override_hidden_console(jobs, monkeypatch):
    calls = []
    monkeypatch.setattr('security_runtime.scan_jobs.subprocess.Popen',
        lambda *args, **options: calls.append((args, options)))
    first = jobs.submit('hidden-worker-001')
    again = jobs.submit('hidden-worker-001')
    assert first['job_ref'] == again['job_ref'] and len(calls) == 1
    arguments, options = calls[0]
    assert 'scan-job-worker' in arguments[0]
    assert options['stdin'] == options['stdout'] == options['stderr'] == subprocess.DEVNULL
    assert options['close_fds']
    if os.name == 'nt':
        assert options['creationflags'] & subprocess.CREATE_NO_WINDOW
        assert not options['creationflags'] & (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_CONSOLE)
    else:
        assert options['start_new_session']


def test_parallel_retries_launch_once_and_alias_survives_completion(jobs):
    calls = []
    def launch(queue, row):
        calls.append(row['job_ref'])
    with ThreadPoolExecutor(max_workers=8) as pool:
        result = list(pool.map(lambda i: jobs.submit('request-%04d'%i, launcher=launch), range(8)))
    assert len({r['job_ref'] for r in result}) == 1
    assert len(calls) == 1
    ref = result[0]['job_ref']
    assert execute(jobs, ref) == 0
    assert jobs.submit('request-0007', launcher=launch)['job_ref'] == ref
    assert len(calls) == 1


def test_same_key_cannot_change_scope_or_force_a_second_scan(jobs):
    first = submit(jobs)
    with pytest.raises(ValueError, match='different scan request'):
        submit(jobs, force_rescan=True)
    assert jobs.status(first['job_ref'])['status'] == 'QUEUED'


def test_same_workspace_jobs_wait_without_running_together(jobs):
    first = submit(jobs)['job_ref']
    second = submit(jobs, 'request-0002', mode='files', files=['app.py'])['job_ref']
    entered, release, second_entered = threading.Event(), threading.Event(), threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(execute, jobs, first, entered=entered, release=release)
        assert entered.wait(5)
        two = pool.submit(execute, jobs, second, entered=second_entered)
        try:
            assert not second_entered.wait(.2)
            assert jobs.status(second)['status'] == 'QUEUED'
        finally:
            release.set()
        assert one.result(5) == two.result(5) == 0
    assert second_entered.is_set()
    assert all(jobs.status(ref)['status'] == 'COMPLETED' for ref in (first, second))


def test_different_workspaces_do_not_share_worker_queue(jobs, tmp_path):
    other_root = tmp_path/'other'; other_root.mkdir()
    other = ScanJobs(jobs.hooks, other_root, scan_path=jobs.scan_path)
    first, second = submit(jobs)['job_ref'], submit(other)['job_ref']
    entered, release, other_entered = threading.Event(), threading.Event(), threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(execute, jobs, first, entered=entered, release=release)
        assert entered.wait(5)
        two = pool.submit(execute, other, second, entered=other_entered)
        try:
            assert other_entered.wait(5)
            assert two.result(5) == 0
        finally:
            release.set()
        assert one.result(5) == 0


@pytest.mark.parametrize('kwargs', [dict(mode='bad'), dict(files=['app.py']),
    dict(mode='files', files=[]), dict(mode='files', files=['../outside.py']),
    dict(mode='quick', force_rescan=True)])
def test_invalid_scope_rejected_before_queue_write(jobs, kwargs):
    with pytest.raises(ValueError):
        submit(jobs, **kwargs)
    assert not jobs.path.exists()


def test_foreign_workspace_and_tampered_reference_rejected(jobs, tmp_path):
    ref = submit(jobs)['job_ref']
    other_root = tmp_path/'other'
    other_root.mkdir()
    other = ScanJobs(jobs.hooks, other_root, scan_path=jobs.scan_path)
    with pytest.raises(ValueError):
        other.status(ref)
    with pytest.raises(ValueError):
        jobs.status('../explicit-scan-jobs.db')
    assert run_worker(jobs.root, jobs.hooks.directory, ref, 'wrong-ticket') == 2


def test_expired_worker_is_not_restarted_by_reads_or_retries(jobs):
    ref = submit(jobs)['job_ref']
    jobs.now = lambda: 10**12
    assert jobs.status(ref)['status'] == 'INTERRUPTED'
    assert submit(jobs)['status'] == 'INTERRUPTED'
    assert jobs.result(ref)['status'] == 'INTERRUPTED'
    assert jobs.load(ref)['state'] == 'QUEUED'


def test_detached_launch_and_failure_status(jobs, monkeypatch):
    calls = []
    monkeypatch.setattr('security_runtime.scan_jobs.subprocess.Popen', lambda *a, **kw: calls.append((a, kw)))
    first = jobs.submit('launch-0001')
    args, kw = calls[0]
    assert 'scan-job-worker' in args[0] and not kw.get('shell', False)
    assert kw['stdin'] == subprocess.DEVNULL and kw['stdout'] == subprocess.DEVNULL
    assert kw['cwd'] == str(jobs.path.parent)
    if os.name != 'nt':
        assert kw['start_new_session'] is True
    def fail(*a, **kw):
        raise OSError('private launcher details')
    monkeypatch.setattr('security_runtime.scan_jobs.subprocess.Popen', fail)
    failed = jobs.submit('launch-0002', mode='quick')
    assert failed['status'] == 'FAILED' and failed['reason_code'] == 'WORKER_START_FAILED'
    assert 'private launcher' not in json.dumps(failed)


def test_worker_failure_is_bounded_and_cannot_become_a_success(jobs):
    ref = submit(jobs)['job_ref']
    assert execute(jobs, ref, fail=True) == 2
    status = jobs.status(ref)
    assert status['status'] == 'FAILED' and not status['result_available']
    assert 'PRIVATE-MATERIAL' not in json.dumps(jobs.rows())


def test_progress_is_available_while_worker_runs(jobs):
    ref = submit(jobs)['job_ref']
    entered, release = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: execute(jobs, ref, entered=entered, release=release))
    worker.start()
    try:
        assert entered.wait(5)
        assert jobs.status(ref)['status'] == 'RUNNING'
        assert submit(jobs)['job_ref'] == ref
        assert jobs.result(ref)['result_available'] is False
    finally:
        release.set()
        worker.join(5)
    assert jobs.status(ref)['providers']['fake']['event'] == 'SCANNER_STARTED'


def test_result_retrieval_is_saved_and_read_only(jobs):
    ref = submit(jobs)['job_ref']
    execute(jobs, ref)
    scan = dict(scan_id='fake-scan', target_profile=dict(path=str(jobs.root), files=[], languages=[]),
        status='PARTIAL', coverage='PARTIAL', summary='fake result', findings=[],
        release_status='REVIEW', duration_ms=1, scanner_runs=[])
    import sqlite3
    with sqlite3.connect(jobs.scan_path) as db:
        db.execute('INSERT INTO scans VALUES (?,?)', ('fake-scan', json.dumps(scan)))
    before = jobs.path.read_bytes()
    result = jobs.result(ref)
    assert result['scan_id'] == 'fake-scan' and result['result_is_saved_version']
    assert result['retrieval_scanner_run'] is False
    assert result['status'] == 'PARTIAL' and result['execution']['scanner_run'] is True
    assert result['timing']['total_ms'] >= result['timing']['scan']['request_ms']
    assert result['duration_ms_scope'] == 'BEFORE_FINALIZATION'
    assert result['timing']['host_analysis_ms'] is None
    assert jobs.path.read_bytes() == before
    (jobs.root/'app.py').write_text('changed after original scan\n')
    assert jobs.result(ref)['scan_id'] == 'fake-scan'


def test_wait_result_returns_original_result_and_yields_protocol_loop(jobs):
    ref = submit(jobs)['job_ref']
    import sqlite3
    scan = dict(scan_id='fake-scan', target_profile=dict(path=str(jobs.root), files=[], languages=[]),
        status='PARTIAL', coverage='PARTIAL', summary='fake', findings=[],
        release_status='REVIEW', duration_ms=1, scanner_runs=[])
    with sqlite3.connect(jobs.scan_path) as db:
        db.execute('INSERT INTO scans VALUES (?,?)', ('fake-scan', json.dumps(scan)))

    async def scenario():
        waiting = asyncio.create_task(jobs.wait_result(ref, wait_seconds=2))
        await asyncio.sleep(0.05)
        assert not waiting.done()
        await asyncio.to_thread(execute, jobs, ref)
        return await waiting

    result = asyncio.run(scenario())
    assert result['scan_id'] == 'fake-scan'
    assert result['result_is_saved_version'] and not result['retrieval_scanner_run']
    assert len(jobs.rows()) == 1


def test_wait_timeout_and_cancellation_do_not_modify_or_restart_job(jobs):
    ref = submit(jobs)['job_ref']
    before = jobs.path.read_bytes()
    result = asyncio.run(jobs.wait_result(ref, wait_seconds=0))
    assert result['status'] == 'QUEUED' and result['timing']['total_ms'] is None
    assert result['next_action']['tool'] == 'get_scan_result'

    async def cancel():
        waiting = asyncio.create_task(jobs.wait_result(ref, wait_seconds=2))
        await asyncio.sleep(0.05)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
    asyncio.run(cancel())
    assert jobs.path.read_bytes() == before
    for value in (-1, 26, True):
        with pytest.raises(ValueError, match='wait_seconds'):
            asyncio.run(jobs.wait_result(ref, wait_seconds=value))


def test_mcp_async_tools_and_reconnect(jobs, monkeypatch):
    from security_runtime.mcp_server import create_server
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    monkeypatch.setattr('security_runtime.scan_jobs.launch', lambda *a: None)
    runtime = SecurityRuntime(ScannerRegistry([], fallback_adapters=[]), SQLiteStore(jobs.scan_path))
    def connect():
        return create_server(runtime, hook_coordinator=HookCoordinator(runtime, jobs.hooks), global_mode=False)
    async def call(server, name, **args):
        result = await server.call_tool(name, dict(workspace_path=str(jobs.root), **args))
        if isinstance(result, tuple):
            return result[1]
        if isinstance(result, list):
            return json.loads(result[0].text)
        return result.structuredContent
    first = asyncio.run(call(connect(), 'start_scan', request_key='mcp-request-0001'))
    assert first['status'] == 'QUEUED'
    second = asyncio.run(call(connect(), 'get_scan_status', job_ref=first['job_ref']))
    assert second['job_ref'] == first['job_ref']
    assert asyncio.run(call(connect(), 'list_scan_jobs'))['total'] == 1
    result = asyncio.run(call(connect(), 'get_scan_result', job_ref=first['job_ref'], wait_seconds=0))
    assert result['status'] == 'QUEUED' and not result['result_available']


def test_independent_process_completes_without_a_client(jobs):
    ref = submit(jobs)['job_ref']
    ticket = jobs.load(ref)['ticket']
    # The independent process runs a fake application, never a scanner binary.
    script = '''
import sys,time
from types import SimpleNamespace
from security_runtime.scan_jobs import run_worker
def factory(row):
    def scan(*args, **kwargs):
        time.sleep(.2)
        kwargs['progress'].emit('SCANNER_COMPLETED', scanner='fake')
        return dict(scan_id='child-result',status='PARTIAL',scanner_runs=[])
    return SimpleNamespace(scan_project=scan)
raise SystemExit(run_worker(*sys.argv[1:],application_factory=factory))
'''
    process = subprocess.Popen([sys.executable, '-B', '-c', script,
        str(jobs.root), str(jobs.hooks.directory), ref, ticket],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=os.name != 'nt')
    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0, stderr.decode()
    # A new service object/connection reads the completed original job.
    reconnected = ScanJobs(jobs.hooks, jobs.root, scan_path=jobs.scan_path)
    assert reconnected.status(ref)['scan_id'] == 'child-result'
    assert reconnected.status(ref)['status'] == 'COMPLETED'
    assert submit(reconnected)['job_ref'] == ref


def test_reading_unknown_jobs_does_not_create_storage(jobs):
    assert jobs.listing()['total'] == 0
    assert not jobs.path.exists()
    with pytest.raises(ValueError):
        jobs.status('sj1-'+'a'*32)
    assert not jobs.path.exists()


def test_signed_job_payload_tampering_rejected(jobs):
    import sqlite3
    ref = submit(jobs)['job_ref']
    with sqlite3.connect(jobs.path) as db:
        raw = json.loads(db.execute('SELECT data FROM records WHERE key=?',(ref,)).fetchone()[0])
        raw['scan_path'] = '/unowned/path'
        db.execute('UPDATE records SET data=? WHERE key=?',(json.dumps(raw),ref))
    with pytest.raises(ValueError, match='signature mismatch'):
        jobs.status(ref)


def test_files_request_retry_keeps_original_job_after_source_deletion(jobs):
    first = submit(jobs, mode='files', files=['app.py'])
    execute(jobs, first['job_ref'])
    (jobs.root/'app.py').unlink()
    assert submit(jobs, mode='files', files=['app.py'])['job_ref'] == first['job_ref']


def test_worker_cannot_run_twice_while_original_is_active(jobs):
    ref = submit(jobs)['job_ref']
    entered, release = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: execute(jobs, ref, entered=entered, release=release))
    worker.start()
    try:
        assert entered.wait(5)
        assert execute(jobs, ref) == 2
        assert jobs.status(ref)['status'] == 'RUNNING'
    finally:
        release.set()
        worker.join(5)


@pytest.mark.parametrize('maximum', [1, 0])
def test_worker_preserves_discovery_limit_diagnostic(jobs, tmp_path, monkeypatch, maximum):
    from security_runtime.target import TargetDetector
    config = tmp_path/'config.toml'
    config.write_text(f'[scan.discovery]\nmax_files = {maximum}\n')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(config))
    (jobs.root/'second.py').write_text('pass\n')
    ref = submit(jobs)['job_ref']
    row = jobs.load(ref)
    def scan(*args, **kwargs):
        TargetDetector().detect(jobs.root)
        return dict(scan_id='fake-scan', status='COMPLETE', scanner_runs=[])
    code = run_worker(jobs.root, jobs.hooks.directory, ref, row['ticket'],
                      application_factory=lambda row: SimpleNamespace(scan_project=scan))
    reconnected = ScanJobs(jobs.hooks, jobs.root, scan_path=jobs.scan_path)
    status = reconnected.result(ref) if maximum else reconnected.status(ref)
    if maximum:
        assert code == 2 and status['status'] == 'FAILED'
        assert status['reason_code'] == 'TARGET_DISCOVERY_LIMIT_EXCEEDED'
        diagnostic = status['failure_diagnostic']
        assert diagnostic['failure_stage'] == 'TARGET_DISCOVERY'
        assert diagnostic['limit'] == 1 and diagnostic['observed'] == 2
        assert diagnostic['configuration']['unified_file_key'] == 'scan.discovery.max_files'
        assert '0 disables' in diagnostic['remediation']
        assert not status['scanner_run'] and not status['result_available']
        assert reconnected.status(ref)['failure_diagnostic'] == diagnostic
    else:
        assert code == 0 and reconnected.status(ref)['status'] == 'COMPLETED'
