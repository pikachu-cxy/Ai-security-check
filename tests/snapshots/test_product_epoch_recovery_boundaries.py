"""Recovery regressions; source and private state live only in tmp_path."""
from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
import sqlite3
import threading

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_capture import DirectoryObservation, StableHashReader, platform_supported
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.product_epoch_store import ProductEpochError


pytestmark = pytest.mark.skipif(not platform_supported(), reason='Requires POSIX descriptor observations')
OWNER = dict(host='codex', session='a' * 64)


def make_service(tmp_path, **policy):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    return ProductEpochService(HookStateStore(tmp_path.resolve() / 'private'), root,
                               now=lambda: 1000.0, policy=policy or None)


def finish(service, limit=100):
    status = service.status()
    for _ in range(limit):
        if status['state'] == 'SEALED':
            return status
        status = service.step(OWNER)
    pytest.fail(f'Finite isolated fixture did not seal: {status}')


def test_non_utf8_name_records_gap_and_preserves_valid_paths(tmp_path):
    service = make_service(tmp_path)
    names = ['first.py', 'second.py', 'third.py']
    for name in names:
        (service.root / name).write_bytes(b'value=1\n')
    try:
        fd = os.open(os.fsencode(service.root) + b'/bad_\xff.py', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        if error.errno == errno.EILSEQ:
            pytest.skip('The host filesystem rejects non-UTF8 names before product code runs (EILSEQ)')
        raise
    try:
        os.write(fd, b'value=1\n')
    finally:
        os.close(fd)
    try:
        initial = service.ensure(OWNER)
        final = finish(service)
        assert final['epoch_ref'] == initial['epoch_ref']
        assert final['gaps']['reasons']['PATH_UNSUPPORTED'] == 1
        rows = service.lookup(initial['epoch_ref'], names)['results']
        assert all(row['observed'] for row in rows)
    finally:
        service.close()


def test_enumerator_surrogate_return_records_path_gap_without_dropping_valid_paths(tmp_path, monkeypatch):
    """Inject an abnormal enumeration result; this is not a real-name FS test."""
    service = make_service(tmp_path)
    names = ['first.py', 'second.py', 'third.py']
    for name in names:
        (service.root / name).write_bytes(b'value=1\n')
    next_entry, injected = DirectoryObservation.next, []

    def surrogate_result(directory):
        if not injected:
            injected.append(True)
            return 'bad_\udcff.py', (service.root / names[0]).stat()
        return next_entry(directory)

    monkeypatch.setattr(DirectoryObservation, 'next', surrogate_result)
    try:
        first = service.ensure(OWNER)
        final = finish(service)
        assert injected and final['epoch_ref'] == first['epoch_ref']
        assert final['gaps']['reasons'] == {'PATH_UNSUPPORTED': 1}
        assert final['counts']['members'] == final['counts']['observed'] == len(names)
        assert all(row['observed'] for row in service.lookup(first['epoch_ref'], names)['results'])
    finally:
        service.close()


def transaction_rollback_fixture(tmp_path, monkeypatch, error):
    service = make_service(tmp_path, step_files=2)
    names = [f'file-{index}.py' for index in range(8)]
    for name in names:
        (service.root / name).write_bytes(b'value=1\n')
    initial = service.ensure(OWNER)
    save, calls = service.store.save, []

    def fail_once(db, key, header):
        if not calls:
            calls.append(True)
            assert db.execute('SELECT count(*) FROM members').fetchone()[0] == 2
            raise error('One isolated control publication failure')
        return save(db, key, header)

    monkeypatch.setattr(service.store, 'save', fail_once)
    try:
        with pytest.raises(error if error is RuntimeError else ProductEpochError):
            service.step(OWNER)
        rolled_back = service.status()
        assert rolled_back['counts']['members'] == 0
        assert rolled_back['epoch_ref'] == initial['epoch_ref']
        final = finish(service)
        rows = service.lookup(initial['epoch_ref'], names)['results']
        print('ROLLBACK_RESULT', error.__name__, json.dumps(dict(counts=final['counts'],
              observed={row['path']: row['observed'] for row in rows}), sort_keys=True))
        assert final['epoch_ref'] == initial['epoch_ref']
        assert final['counts']['members'] == final['counts']['observed'] == len(names)
        assert all(row['observed'] for row in rows)
    finally:
        service.close()


def test_runtime_error_rollback_replays_scandir_in_same_service(tmp_path, monkeypatch):
    transaction_rollback_fixture(tmp_path, monkeypatch, RuntimeError)


def test_sqlite_error_rollback_replays_scandir_control(tmp_path, monkeypatch):
    transaction_rollback_fixture(tmp_path, monkeypatch, sqlite3.OperationalError)


@pytest.mark.parametrize('error_type', [RuntimeError, KeyboardInterrupt])
def test_exception_invalidates_context_before_releasing_writer_guard(tmp_path, monkeypatch, error_type):
    service = make_service(tmp_path, step_files=2)
    for index in range(4):
        (service.root / f'file-{index}.py').write_bytes(b'value=1\n')
    service.ensure(OWNER)
    failure = error_type('Isolated interrupted control publication')
    closed_under_guard, close = [], service.close

    def fail_save(db, key, header):
        assert service._directory is not None
        raise failure

    def checked_close():
        closed_under_guard.append(service._writer_locks.lock_held(service.root))
        close()

    monkeypatch.setattr(service.store, 'save', fail_save)
    monkeypatch.setattr(service, 'close', checked_close)
    try:
        with pytest.raises(error_type) as caught:
            service.step(OWNER)
        assert caught.value is failure
        assert closed_under_guard == [True]
        assert service._directory is service._reader is None and service._resumed is True
        assert service.status()['counts']['members'] == 0
    finally:
        service.close()


@pytest.mark.parametrize('readonly_failure', [False, True])
def test_busy_caller_does_not_close_active_same_instance_reader(tmp_path, monkeypatch, readonly_failure):
    service = make_service(tmp_path, step_bytes=64)
    (service.root / 'large.py').write_bytes(b'value=1\n' * 512)
    entered, release = threading.Event(), threading.Event()

    class GatedReader(StableHashReader):
        def _read_chunk(self, size):
            raw = super()._read_chunk(size)
            if not entered.is_set():
                entered.set()
                assert release.wait(10), 'The isolated source-read gate was not released'
            return raw

    service._reader_factory = GatedReader
    first = service.ensure(OWNER)
    status, caller = service.status, threading.get_ident()

    def checked_status(epoch_ref=None):
        if readonly_failure and threading.get_ident() == caller:
            raise ProductEpochError('PRODUCT_EPOCH_HISTORY_UNAVAILABLE')
        return status(epoch_ref)

    monkeypatch.setattr(service, 'status', checked_status)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            reading = executor.submit(service.step, OWNER)
            try:
                assert entered.wait(10), 'Product source reading did not start'
                reader = service._reader
                assert reader is not None and not reading.done()
                if readonly_failure:
                    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
                        service.step(OWNER)
                else:
                    assert service.step(OWNER)['state'] == 'BUSY'
                assert service._reader is reader and reader.fd is not None
                assert os.fstat(reader.fd).st_size == 4096
                assert service._resumed is False and not reading.done()
            finally:
                release.set()
            assert reading.result(timeout=10)['epoch_ref'] == first['epoch_ref']
    finally:
        service.close()


def partial_reader_fixture(tmp_path, *, reopen):
    policy = dict(step_bytes=64)
    service = make_service(tmp_path, **policy)
    (service.root / 'large.py').write_bytes(b'value=1\n' * 512)
    first = service.ensure(OWNER)
    try:
        for _ in range(10):
            status = service.step(OWNER)
            if service._reader is not None and service._reader.read_bytes > 0:
                break
        else:
            pytest.fail('Fixture never reached a real partial hash')
        assert status['state'] == 'OBSERVING' and status['scope_closed'] is True
        assert service._reader.read_bytes == 64
        progress = []
        for _ in range(12):
            service.close()
            if reopen:
                service = ProductEpochService(service.hooks, service.root, now=service.now, policy=policy)
            status = service.step(OWNER)
            progress.append(dict(state=status['state'], attempts=status['current_path_attempts'],
                                 bytes=service._reader.read_bytes if service._reader else 0))
            assert status['epoch_ref'] == first['epoch_ref']
            if status['state'] == 'SEALED':
                break
        print('PARTIAL_RESULT', 'reopen' if reopen else 'same_service', json.dumps(progress))
        assert status['state'] == 'SEALED', 'Lost partial context must not restart the same prefix indefinitely'
        row = service.lookup(first['epoch_ref'], ['large.py'])['results'][0]
        assert row['status'] == 'GAP' and row['attempts'] == 3
        assert status['counts']['members'] == status['counts']['gaps'] == 1
    finally:
        service.close()


def test_same_service_close_counts_partial_hash_context_loss(tmp_path):
    partial_reader_fixture(tmp_path, reopen=False)


def test_reopened_service_counts_partial_hash_context_loss_control(tmp_path):
    partial_reader_fixture(tmp_path, reopen=True)


def test_normal_finite_names_control(tmp_path):
    service = make_service(tmp_path, step_files=2)
    names = [f'file-{index}.py' for index in range(8)]
    for name in names:
        (service.root / name).write_bytes(b'value=1\n')
    try:
        first = service.ensure(OWNER)
        final = finish(service)
        assert final['epoch_ref'] == first['epoch_ref']
        assert final['counts']['members'] == final['counts']['observed'] == len(names)
        assert all(row['observed'] for row in service.lookup(first['epoch_ref'], names)['results'])
    finally:
        service.close()
