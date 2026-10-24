"""Slow product source IO must not block a task's actual before admission."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_capture import StableHashReader, platform_supported
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import LedgerRuntime


pytestmark = pytest.mark.skipif(not platform_supported(), reason='Requires safe descriptor observations')


def test_product_source_read_cannot_hold_task_before_admission_lock(tmp_path):
    root = tmp_path.resolve()/'project'
    root.mkdir()
    original = b'value = 1\n'
    (root/'source.py').write_bytes(original)
    core = HookCoordinator(LedgerRuntime(), HookStateStore(tmp_path.resolve()/'hooks'),
                           workspace_resolver=lambda _: root)
    owner = session_owner('codex', 'actual-before-during-product-source-read')
    product = ProductEpochService(core.store, root)
    entered, release = threading.Event(), threading.Event()

    class SlowRealReader(StableHashReader):
        def _read_chunk(self, size):
            raw = super()._read_chunk(size)
            if not entered.is_set():
                entered.set()
                assert release.wait(15), 'Fixture source IO gate was never released'
            return raw

    product._reader_factory = SlowRealReader
    initial = product.ensure(owner)
    tasks = TaskSecurityService(core.runtime, core.store, owner=owner)
    with ThreadPoolExecutor(max_workers=1) as executor:
        reading = executor.submit(product.step, owner)
        try:
            assert entered.wait(10), 'Product did not reach its real source read'
            assert not release.is_set() and not reading.done()
            admitted = tasks.begin(root, 'independent-actual-before', check_policy=POLICY)
            assert not release.is_set(), 'Task admission was checked only after releasing product IO'
            assert admitted['status'] == 'ACTIVE', admitted
            task = tasks.load(root, admitted['task_ref'])
            assert task['phase'] == 'ACTIVE'
            assert tasks.before_lines(root, task, 'source.py') == ['value = 1']
            assert task['baseline']['capture_stats']['hash_complete'] is True
            assert task['baseline']['capture_stats']['body_complete'] is True
            assert not core.runtime.calls
        finally:
            release.set()
            try:
                assert reading.result(timeout=10)['epoch_ref'] == initial['epoch_ref']
            finally:
                product.close()


def test_main_workspace_lock_never_bypasses_another_product_writer(tmp_path):
    root = tmp_path.resolve()/'project'
    root.mkdir()
    (root/'source.py').write_bytes(b'original product source\n')
    hooks = HookStateStore(tmp_path.resolve()/'hooks')
    owner = session_owner('codex', 'product-writer')
    product = ProductEpochService(hooks, root)
    entered, release = threading.Event(), threading.Event()

    class SlowRealReader(StableHashReader):
        def _read_chunk(self, size):
            raw = super()._read_chunk(size)
            if not entered.is_set():
                entered.set()
                assert release.wait(15), 'Fixture source IO gate was never released'
            return raw

    product._reader_factory = SlowRealReader
    original = product.ensure(owner)
    with ThreadPoolExecutor(max_workers=1) as executor:
        reading = executor.submit(product.step, owner)
        try:
            assert entered.wait(10)
            with hooks.lock(root) as acquired:
                assert acquired, 'Product source IO still holds the main workspace lock'
                peer = ProductEpochService(hooks, root/'..'/'project')
                assert hooks.lock_held(peer.root)
                assert not peer._writer_locks.lock_held(peer.root)
                contender = session_owner('cursor', 'another-product-writer')
                for operation in (peer.ensure, peer.step):
                    status = operation(contender)
                    assert status['state'] == 'BUSY'
                    assert status['epoch_ref'] == original['epoch_ref']
                    assert status['counts']['members'] == status['counts']['observed'] == 0
                assert not release.is_set() and not reading.done()
                peer.close()
        finally:
            release.set()
            try:
                assert reading.result(timeout=10)['epoch_ref'] == original['epoch_ref']
            finally:
                product.close()
