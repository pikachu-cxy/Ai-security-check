"""Synthetic regression checks; these are never desktop Hook acceptance."""
import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

import security_runtime.background_preparation as background
from security_runtime.background_preparation import PreparationStore, run_worker, start_background_preparation
from security_runtime.hook_state import HookStateStore
from test_personal_install_readiness import readiness, mock_prepare
from test_global_integration import installed, projects
from test_secret_recheck_coverage import secret_engine
from test_closeout_regression import closeout_fixture

BUILD = 'a'*64
COMMAND = ['owned-runtime']


@pytest.fixture
def job(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    store = PreparationStore()
    value, created = store.reserve(COMMAND, BUILD)
    assert created
    return store, value


def run(job, **kwargs):
    store, value = job
    return run_worker(value['job_id'], value['ticket'], store=store, command=COMMAND, build=BUILD, **kwargs)


def waiter(job, tmp_path):
    root = tmp_path/'project'
    root.mkdir(exist_ok=True)
    hooks = HookStateStore(tmp_path/'state'/'hooks')
    assert job[0].enqueue(root, 'co1-'+'b'*32, hooks, BUILD, tmp_path/'state')
    return root, hooks


def test_status_is_readonly_and_does_not_create_state(tmp_path):
    path = tmp_path/'nothing'/'preparation.db'
    assert PreparationStore(path).status()['status'] == 'NOT_STARTED'
    assert not path.parent.exists()


def test_install_returns_after_schedule_and_offline_never_schedules(installed, monkeypatch):
    import security_runtime.personal_install as personal
    monkeypatch.setattr('security_runtime.global_integration.GlobalCodexIntegration', lambda **kw: installed)
    mock_prepare(monkeypatch, readiness(ready=False, freshness='STALE'))
    calls = []
    monkeypatch.setattr(personal, 'start_background_preparation',
        lambda executable=None: calls.append(executable) or {'status': 'QUEUED', 'ready': False})
    result = personal.install_personal_codex()
    assert calls == [None] and result['installation']['local_files_ready']
    assert not result['installation']['scan_ready'] and '无需手动' in result['installation']['message']
    assert result['execution']['network_query'] is False
    personal.install_personal_codex(offline=True)
    assert len(calls) == 1


def test_repeat_start_reuses_live_worker_and_does_not_inherit_console(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    store = PreparationStore(tmp_path/'state'/'preparation.db')
    calls = []
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **kw: calls.append((a, kw)))
    one = start_background_preparation('known', store=store, build=BUILD)
    two = start_background_preparation('known', store=store, build=BUILD)
    assert len(calls) == 1 and one['job_id'] == two['job_id'] and two['reused']
    assert calls[0][1]['close_fds'] and calls[0][1]['stdout'] == subprocess.DEVNULL
    if __import__('os').name == 'nt':
        assert calls[0][1]['creationflags'] & subprocess.CREATE_NO_WINDOW
    assert 'ticket' not in one


def test_failed_launch_is_not_reported_ready_and_retry_gets_new_ticket(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    store = PreparationStore(tmp_path/'state'/'preparation.db')
    def fail(*a, **kw): raise OSError('private detail')
    monkeypatch.setattr(subprocess, 'Popen', fail)
    one = start_background_preparation('known', store=store, build=BUILD)
    two = start_background_preparation('known', store=store, build=BUILD)
    assert one['status'] == two['status'] == 'FAILED' and not two['ready']
    assert one['job_id'] != two['job_id'] and 'private detail' not in json.dumps(two)


@pytest.mark.parametrize('bad', ['build', 'command', 'ticket', 'duplicate'])
def test_worker_requires_exact_owned_build_command_and_ticket(job, bad):
    store, value = job
    if bad == 'duplicate':
        assert store.claim(value['job_id'], value['ticket'], COMMAND, BUILD)
    assert not store.claim(value['job_id'], 'wrong' if bad == 'ticket' else value['ticket'],
        ['different'] if bad == 'command' else COMMAND, 'c'*64 if bad == 'build' else BUILD)


def test_worker_reuses_existing_downloader_adaptive_limits_and_receipt(job, tmp_path):
    waiter(job, tmp_path)
    calls = []
    def prepare(**kw):
        calls.append(kw)
        assert job[0].status()['status'] == 'PREPARING'
        return readiness()
    def resume(command, item):
        assert command == COMMAND and item['status'] == 'WAITING'
        assert job[0].status()['status'] == 'RESUMING'
        return 'COMPLETED'
    assert run(job, prepare=prepare, resume=resume) == 0
    assert calls[0]['adaptive'] and calls[0]['max_wait_seconds'] == 1800 and calls[0]['idle_seconds'] == 30
    assert job[0].status()['ready'] and not job[0].waiters()


@pytest.mark.parametrize('bad', ['partial', 'exception', 'invalid'])
def test_failure_preserves_pending_without_running_or_claiming_safe(job, tmp_path, bad):
    waiter(job, tmp_path)
    def prepare(**kw):
        if bad == 'exception': raise RuntimeError('private content')
        return {} if bad == 'invalid' else readiness(ready=False, freshness='STALE')
    def resume(*args): pytest.fail('Unready preparation must not scan')
    assert run(job, prepare=prepare, resume=resume) == 2
    assert not job[0].status()['ready'] and len(job[0].waiters()) == 1
    assert 'private content' not in json.dumps(job[0].status())


def test_lease_expiry_read_does_not_write_and_old_worker_cannot_publish(job):
    store, value = job
    before = store.path.read_bytes()
    store.now = lambda: value['lease_until']+1
    assert store.status()['status'] == 'INTERRUPTED' and store.path.read_bytes() == before
    newer, created = store.reserve(COMMAND, BUILD)
    assert created
    assert not store.update(value['job_id'], value['ticket'], status='READY', ready=True)
    assert store.status()['job_id'] == newer['job_id']


def test_waiter_tampering_does_not_execute_another_workspace(job, tmp_path):
    waiter(job, tmp_path)
    with sqlite3.connect(job[0].path) as db:
        raw = json.loads(db.execute('SELECT data FROM waiting').fetchone()[0])
        raw['workspace'] = str(tmp_path/'another')
        db.execute('UPDATE waiting SET data=?', (json.dumps(raw),))
    assert not job[0].waiters()


def test_no_eta_is_invented_after_progress_stops(job):
    store, value = job
    store.update(value['job_id'], value['ticket'], progress_at=store.now()-11,
        estimate={'bytes_per_second': 2, 'remaining_seconds': 4})
    assert store.status()['estimate'] is None


def test_late_queue_arrival_prevents_ready_transition(job, tmp_path):
    store, value = job
    store.update(value['job_id'], value['ticket'], status='RESUMING', ready=True)
    epoch = store.status()['queue_epoch']
    waiter(job, tmp_path)
    assert not store.finish_if_epoch(value['job_id'], value['ticket'], epoch)
    assert store.status()['status'] == 'RESUMING'


def test_new_generation_registration_survives_old_queue_completion(job, tmp_path):
    root, hooks = waiter(job, tmp_path)
    old = job[0].waiters()[0]
    assert job[0].enqueue(root, old['closeout_ref'], hooks, BUILD, tmp_path/'state', generation=2)
    job[0].finish_waiter(old, 'COMPLETED')
    current = job[0].waiters()
    assert len(current) == 1 and current[0]['generation'] == 2


def test_busy_resume_is_bounded_and_preserves_original_waiter_status(job, tmp_path):
    waiter(job, tmp_path)
    calls = []
    def busy(*a): calls.append(a); return 'NEEDS_RETRY'
    assert run(job, prepare=lambda **kw: readiness(), resume=busy) == 0
    assert len(calls) == 1 and job[0].status()['ready']
    with sqlite3.connect(job[0].path) as db:
        item = json.loads(db.execute('SELECT data FROM waiting').fetchone()[0])
    assert item['status'] == 'NEEDS_RETRY' and item['attempts'] == 1


def test_prepare_and_run_during_download_keep_same_closeout_and_attempt_budget(secret_engine, tmp_path, monkeypatch):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    store = PreparationStore()
    store.reserve(COMMAND, service.build['build_id'])
    root = secret_engine[0]
    first = service.prepare(root, ['fixture.ts'], host='codex', session='session', source='HOOK_SCHEDULED_CLOSEOUT')
    second = service.prepare(root, ['fixture.ts'], host='codex', session='session', source='HOOK_SCHEDULED_CLOSEOUT')
    assert first['closeout_ref'] == second['closeout_ref'] and first['background_registered']
    count = secret_engine[3]['calls']
    result = service.run(first['closeout_ref'], root)
    assert result['waiting_for_preparation'] and result['attempts'] == 0
    assert secret_engine[3]['calls'] == count
    stop = service.stop(root, 'codex', 'session', False)
    assert stop['status'] == 'ALLOW_STOP_PENDING' and 'decision' not in stop


def test_resume_checks_latest_version_and_retains_edit_during_scan(secret_engine, tmp_path, monkeypatch):
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    store = PreparationStore()
    value, _ = store.reserve(COMMAND, service.build['build_id'])
    root, path, _, _, _ = secret_engine
    first = service.prepare(root, ['fixture.ts'], host='codex', session='session')
    path.write_text('// New content during preparation\n')
    store.update(value['job_id'], value['ticket'], status='RESUMING', ready=True)
    original_scan = service.runtime.scan
    def edit(*a, **kw):
        result = original_scan(*a, **kw)
        path.write_text('// Even newer during recheck\n')
        service.hooks.pending_activity(root, 'codex', 'session', mark=True)
        return result
    monkeypatch.setattr(service.runtime, 'scan', edit)
    result = service.run(first['closeout_ref'], root)
    assert result['generation'] > first['generation']
    assert result['status'] == 'NEEDS_RETRY' and not result['current_version']
    assert service.hooks.pending_activity(root, 'codex', 'session')


def test_quick_scan_uses_available_engines_offline_and_registers_saved_scope(secret_engine, tmp_path, monkeypatch):
    from security_runtime.verification_policy import local_recheck_requested
    service, _, _ = closeout_fixture(secret_engine, tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    PreparationStore().reserve(COMMAND, service.build['build_id'])
    original = service.runtime._scan
    observed = []
    def scan(*a, **kw):
        observed.append(local_recheck_requested())
        return original(*a, **kw)
    monkeypatch.setattr(service.runtime, '_scan', scan)
    result = service.runtime.scan(secret_engine[0], 'quick')
    assert observed == [True] and result.scanner_runs
    assert result.background_preparation['background_registered']
    assert result.background_preparation['closeout_ref'].startswith('co1-')
