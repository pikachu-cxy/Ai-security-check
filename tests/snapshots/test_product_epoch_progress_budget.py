"""Real source/control IO with explicit slow-metadata or stalled-work injection.

Injected delays verify scheduling contracts; they are not scale measurements.
"""
from collections import deque
from concurrent.futures import Future
import os
import time
import uuid

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_capture import platform_supported
from security_runtime.product_epoch_jobs import ProductEpochJobs
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.product_epoch_store import ProductEpochError
import security_runtime.product_epoch_store as storage


pytestmark = pytest.mark.skipif(not platform_supported(), reason='Requires descriptor observations')
OWNER = dict(host='codex', session='a' * 64)


class ManualExecutor:
    def __init__(self):
        self.pending = deque()

    def submit(self, function, *arguments):
        future = Future()
        self.pending.append((future, function, arguments))
        return future

    def drain(self, maximum=256):
        for _ in range(maximum):
            if not self.pending:
                return
            future, function, arguments = self.pending.popleft()
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(function(*arguments))
                except BaseException as error:
                    future.set_exception(error)
                    raise
        pytest.fail('Finite isolated scheduler kept resubmitting without a terminal result')


def service_fixture(tmp_path, **policy):
    root = tmp_path.resolve()/'source'
    root.mkdir()
    hooks = HookStateStore(tmp_path.resolve()/'private')
    for index in range(3):
        (root/f'{index}.py').write_bytes(b'value = 1\n')
    return ProductEpochService(hooks, root, now=lambda: 1000.0, policy=policy or None)


def delayed_load(monkeypatch, service):
    load = service.store.load

    def slow(*arguments, **keywords):
        time.sleep(0.025)  # Explicit simulation of slow verified control reads.
        return load(*arguments, **keywords)

    monkeypatch.setattr(service.store, 'load', slow)


def test_slow_control_does_not_starve_finite_enumeration(tmp_path, monkeypatch):
    service = service_fixture(tmp_path, scope_seconds=0.05, step_seconds=0.01)
    initial = service.ensure(OWNER)
    delayed_load(monkeypatch, service)
    try:
        for _ in range(8):
            status = service.step(OWNER)
            if status['state'] == 'SEALED':
                break
        assert status['epoch_ref'] == initial['epoch_ref']
        assert status['state'] == 'SEALED', status
        assert status['scope_closed'] is True
    finally:
        service.close()


def test_expired_scope_closes_even_when_source_time_slice_is_exhausted(tmp_path):
    service = service_fixture(tmp_path, scope_seconds=0)
    initial = service.ensure(OWNER)
    try:
        with service.store.db(write=True) as (db, key):
            header = service.store.load(db, key, ref=initial['epoch_ref'])
            service._enumerate(db, key, header, time.monotonic()-1, 0)
            assert header['scope_closed'] is True
            assert header['scope_close_reason'] == 'DEADLINE'
            assert header['gap_reasons'] == {'SCOPE_DEADLINE': 1}
            service.store.save(db, key, header)
        assert service.status()['epoch_ref'] == initial['epoch_ref']
    finally:
        service.close()


def test_slow_control_does_not_starve_already_closed_observations(tmp_path, monkeypatch):
    service = service_fixture(tmp_path, step_files=1, step_seconds=0.01)
    initial = service.ensure(OWNER)
    try:
        for _ in range(20):
            status = service.step(OWNER)
            if status['scope_closed']:
                break
        assert status['state'] == 'OBSERVING' and status['counts']['pending_files'] > 0
        before = service.lookup(initial['epoch_ref'], ['0.py', '1.py', '2.py'])
        delayed_load(monkeypatch, service)
        for _ in range(8):
            status = service.step(OWNER)
            if status['state'] == 'SEALED':
                break
        assert status['epoch_ref'] == initial['epoch_ref']
        assert status['state'] == 'SEALED', status
        assert status['counts']['members'] == status['counts']['observed'] == 3
        after = service.lookup(initial['epoch_ref'], ['0.py', '1.py', '2.py'])
        for old, new in zip(before['results'], after['results']):
            if old['observed']:
                assert old == new
    finally:
        service.close()


def test_no_progress_pauses_without_rewriting_epoch_and_explicit_retry_resumes(tmp_path, monkeypatch):
    service = service_fixture(tmp_path)
    initial = service.ensure(OWNER)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)

    def stalled(db, key, header, deadline, units):
        # Simulate no source work while durable retry/control noise changes.
        header['worker_token'] = uuid.uuid4().hex
        header['observation_intervals'] += 1
        return units

    original = service._enumerate
    monkeypatch.setattr(service, '_enumerate', stalled)
    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService',
                        lambda *arguments, **keywords: service)
    try:
        first = jobs.start(service.root, service.hooks, OWNER)
        executor.drain(maximum=16)
        paused = first.result(timeout=0)
        assert paused['state'] == 'WAITING_PROGRESS'
        assert paused['reason'] == 'PRODUCT_EPOCH_NO_PROGRESS'
        assert paused['epoch_ref'] == initial['epoch_ref']
        assert not executor.pending
        original_header = service.status()
        assert original_header['state'] == 'ENUMERATING'
        assert original_header['counts']['members'] == 0
        monkeypatch.setattr(service, '_enumerate', original)
        continued = jobs.start(service.root, service.hooks, OWNER)
        assert continued is not first
        executor.drain()
        assert continued.result(timeout=0)['state'] == 'SEALED'
        assert continued.result(timeout=0)['epoch_ref'] == initial['epoch_ref']
        assert continued.result(timeout=0)['counts']['observed'] == 3
    finally:
        jobs.close()
        service.close()


def test_partial_file_bytes_are_real_progress_across_many_turns(tmp_path, monkeypatch):
    service = service_fixture(tmp_path, step_bytes=64)
    (service.root/'large.bin').write_bytes(b'x'*4096)
    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService',
                        lambda *arguments, **keywords: service)
    executor, jobs = ManualExecutor(), None
    jobs = ProductEpochJobs(executor)
    try:
        result = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        status = result.result(timeout=0)
        assert status['state'] == 'SEALED'
        assert status['counts']['observed'] == 4
        assert service.lookup(status['epoch_ref'], ['large.bin'])['results'][0]['observed'] is True
    finally:
        jobs.close()
        service.close()


@pytest.mark.parametrize('excluded', ['ignored', 'special'])
def test_excluded_entries_still_advance_finite_enumeration(tmp_path, monkeypatch, excluded):
    names = [f'excluded-{index}' for index in range(20)]
    service = service_fixture(tmp_path, step_files=1,
        ignored_names=names if excluded == 'ignored' else [])
    for path in service.root.iterdir():
        path.unlink()
    for name in names:
        if excluded == 'ignored':
            (service.root/name).write_bytes(b'ignored')
        else:
            os.mkfifo(service.root/name)
    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService',
                        lambda *arguments, **keywords: service)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        result = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        status = result.result(timeout=0)
        assert status['state'] == 'SEALED'
        assert status['counts']['members'] == 0
        assert status['counts']['gaps'] == 0
    finally:
        jobs.close()
        service.close()


def test_existing_epoch_ensure_capacity_pause_is_recoverable_without_recapture(tmp_path, monkeypatch):
    service = service_fixture(tmp_path)
    initial = service.ensure(OWNER)
    quota = storage.MAX_DATABASE_BYTES
    monkeypatch.setattr(storage, 'MAX_DATABASE_BYTES', service.store.path.stat().st_size-1)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        first = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        paused = first.result(timeout=0)
        assert paused['state'] == 'WAITING_CAPACITY'
        assert paused['epoch_ref'] == initial['epoch_ref']
        monkeypatch.setattr(storage, 'MAX_DATABASE_BYTES', quota)
        continued = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        assert continued.result(timeout=0)['epoch_ref'] == initial['epoch_ref']
        assert continued.result(timeout=0)['state'] == 'SEALED'
    finally:
        jobs.close()
        service.close()


def test_capacity_error_does_not_mask_missing_original_history(tmp_path, monkeypatch):
    service = service_fixture(tmp_path)
    service.ensure(OWNER)
    key = service.hooks.workspace_directory(service.root)/'snapshot.key'
    key.unlink()
    monkeypatch.setattr(storage, 'MAX_DATABASE_BYTES', service.store.path.stat().st_size-1)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        result = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
            result.result(timeout=0)
        assert not key.exists()
    finally:
        jobs.close()
        service.close()


def test_sealed_epoch_needs_no_capacity_retry_after_readonly_verification(tmp_path, monkeypatch):
    service = service_fixture(tmp_path)
    initial = service.ensure(OWNER)
    for _ in range(16):
        status = service.step(OWNER)
        if status['state'] == 'SEALED':
            break
    assert status['state'] == 'SEALED'
    monkeypatch.setattr(storage, 'MAX_DATABASE_BYTES', service.store.path.stat().st_size-1)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        future = jobs.start(service.root, service.hooks, OWNER)
        executor.drain()
        result = future.result(timeout=0)
        assert result['state'] == 'SEALED'
        assert result['epoch_ref'] == initial['epoch_ref']
        assert result['counts']['observed'] == 3
    finally:
        jobs.close()
        service.close()
