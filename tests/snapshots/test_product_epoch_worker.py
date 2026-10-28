"""Durable worker recovery uses actual original product observations."""
import copy
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.product_epoch_worker import EpochQueue, launch, run_worker
from security_runtime.tasks.ownership import session_owner


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'runtime-state'))
    root = tmp_path/'source'
    root.mkdir()
    for n in range(37):
        (root/f'source_{n:03d}.py').write_text(f'value = {n}\n')
    hooks = HookStateStore(tmp_path/'private')
    owner = session_owner('codex', 'background-product')
    service = ProductEpochService(hooks, root, policy=dict(step_files=7, scope_seconds=3600))
    original = service.ensure(owner)
    queue = EpochQueue(hooks, root)
    queue.submit(service, owner, original)
    yield root, hooks, owner, service, queue, original
    service.close()


def ticket(queue, value='test-ticket'):
    with queue.transaction() as db:
        queue._put(db, '$worker', dict(ticket=value, lease_until=queue.now()+60))
    return value


def run(sample, value='test-ticket'):
    root, hooks, _, _, queue, _ = sample
    return run_worker(str(root), str(hooks.directory), ticket(queue, value))


def test_worker_finishes_original_finite_scope_without_a_scanner_or_ensure(sample, monkeypatch):
    root, hooks, owner, service, queue, original = sample
    monkeypatch.setattr(ProductEpochService, 'ensure', lambda *a, **k: pytest.fail('Worker recreated an epoch'))
    assert run(sample) == 0
    current = service.status(epoch_ref=original['epoch_ref'])
    assert current['state'] == queue.read('$job')['state'] == 'SEALED'
    assert current['counts']['members'] == current['counts']['observed'] == 37
    assert current['counts']['gaps'] == 0
    (root/'later.py').write_text('added_after_scope = True\n')
    assert run(sample, 'replay') == 0
    assert service.status(epoch_ref=original['epoch_ref']) == current
    assert not current['strict_task_preimage_eligible'] and current['representation'] == 'HASH_ONLY'


def test_interruption_resumes_committed_original_epoch_and_original_hashes(sample, monkeypatch):
    root, _, owner, service, queue, original = sample
    real = ProductEpochService.step
    calls = []
    def interrupt(instance, actor, **kwargs):
        result = real(instance, actor, **kwargs)
        calls.append(result)
        if result['counts']['observed'] >= 7:
            raise SystemExit('simulated process loss after committed source progress')
        return result
    with monkeypatch.context() as scoped:
        scoped.setattr(ProductEpochService, 'step', interrupt)
        with pytest.raises(SystemExit):
            run(sample)
    middle = service.status(epoch_ref=original['epoch_ref'])
    observed = service.lookup(original['epoch_ref'], ['source_000.py'])['results'][0]
    assert middle['counts']['observed'] >= 7 and observed['observed']
    (root/'source_000.py').write_text('edited_after_accepted_observation = True\n')
    assert run(sample, 'recovered') == 0
    assert service.lookup(original['epoch_ref'], ['source_000.py'])['results'][0] == observed
    assert service.status(epoch_ref=original['epoch_ref'])['counts']['observed'] == 37
    assert queue.read('$job')['epoch_ref'] == original['epoch_ref']


@pytest.mark.parametrize('pause', ['WAITING_CAPACITY', 'BUSY', 'WAITING_PROGRESS'])
def test_pause_has_no_automatic_spin_and_explicit_retry_keeps_original_job(sample, monkeypatch, pause):
    _, _, owner, service, queue, original = sample
    initial = copy.deepcopy(queue.read('$job'))
    calls = []
    real = ProductEpochService.step
    def paused(instance, actor, **kwargs):
        calls.append(actor)
        return dict(real(instance, actor, **kwargs), state=pause)
    with monkeypatch.context() as scoped:
        scoped.setattr(ProductEpochService, 'step', paused)
        assert run(sample) == 0
    assert calls == [owner]
    assert queue.read('$job')['state'] == pause and not queue.pending()
    assert not launch(queue.hooks, queue.root)
    resumed = queue.submit(service, owner, service.status(epoch_ref=original['epoch_ref']))
    assert resumed['epoch_ref'] == original['epoch_ref'] and resumed['created_at'] == initial['created_at']
    assert run(sample, 'resumed') == 0
    assert queue.read('$job')['state'] == 'SEALED'


def test_invalid_worker_ticket_does_not_step_or_change_queue(sample, monkeypatch):
    root, hooks, _, _, queue, _ = sample
    ticket(queue)
    before = queue.path.read_bytes(), queue.path.stat().st_mtime_ns
    monkeypatch.setattr(ProductEpochService, 'step', lambda *a, **k: pytest.fail('Invalid ticket stepped source'))
    assert run_worker(str(root), str(hooks.directory), 'other-ticket') == 2
    assert (queue.path.read_bytes(), queue.path.stat().st_mtime_ns) == before


def test_deleted_original_source_store_is_not_recreated(sample, monkeypatch):
    _, _, _, service, queue, _ = sample
    shutil.rmtree(service.store.directory)
    service.store.marker.unlink()
    monkeypatch.setattr(ProductEpochService, 'ensure', lambda *a, **k: pytest.fail('Missing history was recaptured'))
    assert run(sample) == 2
    assert queue.read('$job')['state'] == 'HISTORY_UNAVAILABLE'
    assert not service.store.directory.exists() and not service.store.marker.exists()


def test_failed_queue_checkpoint_cannot_undo_accepted_source_or_reset_epoch(sample):
    root, hooks, owner, service, queue, original = sample
    ticket(queue)
    with sqlite3.connect(queue.path) as db:
        db.execute("CREATE TRIGGER queue_fault BEFORE INSERT ON records WHEN NEW.key='$job' "
                   "BEGIN SELECT RAISE(ABORT, 'queue checkpoint failed'); END")
    with pytest.raises(sqlite3.IntegrityError):
        run_worker(str(root), str(hooks.directory), 'test-ticket')
    middle = service.status(epoch_ref=original['epoch_ref'])
    assert middle['progress']['enumerated_entries'] > 0
    assert queue.read('$job')['state'] == 'QUEUED'
    with sqlite3.connect(queue.path) as db:
        db.execute('DROP TRIGGER queue_fault')
    assert run(sample, 'after-rollback') == 0
    assert queue.read('$job')['epoch_ref'] == original['epoch_ref']


def test_registered_recovery_dispatches_original_job_without_task_or_epoch_creation(sample, monkeypatch):
    from security_runtime.task_dispatcher import register, recover_registered
    root, hooks, _, service, queue, _ = sample
    register(hooks, root)
    dispatched = []
    monkeypatch.setattr('security_runtime.product_epoch_worker.launch', lambda h, r: dispatched.append(r))
    monkeypatch.setattr(ProductEpochService, 'ensure', lambda *a, **k: pytest.fail('Recovery created an epoch'))
    before = service.store.path.read_bytes()
    assert recover_registered() == 1
    assert dispatched == [root] and service.store.path.read_bytes() == before


def test_actual_cli_child_completes_without_parent_polling(sample, monkeypatch):
    root, hooks, _, service, queue, original = sample
    # The development test runs the source CLI. Independent wheel acceptance
    # separately exercises its normal installed runtime_command.
    import security_runtime
    package_parent = str(Path(security_runtime.__file__).resolve().parent.parent)
    code = 'import sys;sys.path.insert(0,'+repr(package_parent)+');from security_runtime.cli import main;sys.exit(main())'
    monkeypatch.setattr('security_runtime.background_preparation.runtime_command',
                        lambda: [sys.executable, '-I', '-B', '-c', code])
    assert launch(hooks, root)
    assert not launch(hooks, root)
    deadline = time.monotonic()+40
    while queue.pending() and time.monotonic() < deadline:
        time.sleep(.1)
    assert queue.read('$job')['state'] == 'SEALED', queue.read('$job')
    assert service.status(epoch_ref=original['epoch_ref'])['counts']['observed'] == 37


def test_closing_connection_polling_preserves_registered_job_and_original_epoch(sample, monkeypatch):
    from security_runtime.product_epoch_jobs import ProductEpochJobs
    from test_product_epoch_scheduler import ManualExecutor
    root, hooks, owner, service, queue, original = sample
    # Match the original test policy; the monitor cannot adopt another policy.
    real = ProductEpochService
    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService',
        lambda h, r: real(h, r, policy=service.policy))
    launched = []
    monkeypatch.setattr('security_runtime.product_epoch_worker.launch', lambda h, r: launched.append(r))
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor, detached=True)
    future = jobs.start(root, hooks, owner)
    executor.run_one()
    assert queue.pending() and not future.done() and launched
    jobs.close()
    assert future.cancelled() and queue.pending()
    assert service.status(epoch_ref=original['epoch_ref'])['state'] == 'ENUMERATING'
    assert run(sample) == 0
    assert queue.read('$job')['state'] == 'SEALED'


def test_launch_failure_is_retryable_in_same_connection_without_losing_original_job(sample, monkeypatch):
    from security_runtime.product_epoch_jobs import ProductEpochJobs
    from test_product_epoch_scheduler import ManualExecutor
    root, hooks, owner, service, queue, original = sample
    real = ProductEpochService
    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService',
        lambda h, r: real(h, r, policy=service.policy))
    def failed(*args, **kwargs):
        raise OSError('isolated process launch failure')
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor, detached=True)
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr('security_runtime.product_epoch_worker.subprocess.Popen', failed)
            first = jobs.start(root, hooks, owner)
            executor.run_one()
        assert first.result(timeout=0)['state'] == 'BUSY'
        assert queue.pending() and queue.read('$worker')['lease_until'] == 0
        assert queue.read('$job')['epoch_ref'] == original['epoch_ref']
        monkeypatch.setattr('security_runtime.product_epoch_worker.launch', lambda *a: True)
        second = jobs.start(root, hooks, owner)
        executor.run_one()
        assert second is not first and not second.done() and queue.pending()
    finally:
        jobs.close()
