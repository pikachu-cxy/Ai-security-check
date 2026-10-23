import copy
import threading
import uuid

import pytest

from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.queued_closeout import enqueue, execute_one, cancel, status
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.scan_attempt import ScanAttemptStore, source_binding
from security_runtime.task_closeout_worker import run_worker
from test_task_security import service


@pytest.fixture(autouse=True)
def private_dispatcher(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'dispatcher-state'))


def setup(sample, name='a', clock=None):
    old, root, engine = sample
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', name),
                               **({'now':lambda:clock[0]} if clock else {}))
    ref = task.begin(root, name, check_policy=POLICY)['task_ref']
    return task, root, ref


def test_enqueue_deduplicates_without_inventory(service, monkeypatch):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    first = enqueue(task, root, ref, launch=False)
    monkeypatch.setattr('security_runtime.tasks.queued_closeout.capture_end',
                        lambda *a:pytest.fail('duplicate submission recaptured sources'))
    assert enqueue(task, root, ref, launch=False)['job_ref'] == first['job_ref']
    assert not service[2].calls


def test_busy_wait_then_automatic_worker_without_second_finish(service):
    task, root, ref = setup(service)
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('changed = True\n')
    enqueue(task, root, ref, launch=False)
    attempts = ScanAttemptStore(task.hooks, root)
    with task.hooks.lock(root) as locked:
        assert locked
        lease = attempts.claim('MANUAL', 'busy-test', source_binding({'test':1}))
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'RETRY_WAIT'
    queue = CloseoutQueue(task.hooks, root)
    with queue.transaction() as db:
        row = queue._get(db, ref)
        queue._put(db, ref, dict(row, next_attempt_at=0))
        queue._put(db, '$worker', dict(ticket='worker-test', lease_until=queue.now()+60))
    with task.hooks.lock(root) as locked:
        assert locked
        attempts.finish(lease, outcome='COMPLETED')
    assert run_worker(root, task.hooks.directory, 'worker-test',
                      service_factory=lambda owner:task, idle_wait=0) == 0
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    assert task.load(root, ref)['baseline'] == baseline
    assert len(service[2].calls) == 1
    assert task.load(root, ref)['phase'] != 'COMPLETE'


def test_busy_does_not_read_source(service, monkeypatch):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    enqueue(task, root, ref, launch=False)
    attempts = ScanAttemptStore(task.hooks, root)
    with task.hooks.lock(root):
        attempts.claim('MANUAL', 'busy-test', source_binding({'test':1}))
    monkeypatch.setattr(task, '_fresh', lambda *a:pytest.fail('Busy read sources'))
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'RETRY_WAIT'


def test_changed_queued_source_never_gets_current_pass(service):
    task, root, ref = setup(service)
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('version = 1\n')
    enqueue(task, root, ref, launch=False)
    (root/'routes.py').write_text('version = 2\n')
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'STALE'
    assert len(service[2].calls) == 1
    assert task.end_lines(root, task.load(root, ref), 'routes.py') == ['version = 1']
    assert task.load(root, ref)['baseline'] == baseline


def test_claim_recovery_fences_old_worker(service):
    clock = [100000.0]
    task, root, ref = setup(service, clock=clock)
    (root/'routes.py').write_text('version = 1\n')
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root, now=lambda:clock[0])
    first = queue.claim(ref, 'old', seconds=2)
    assert queue.claim(ref, 'other') is None
    clock[0] += 3
    second = queue.claim(ref, 'new')
    assert second['generation'] > first['generation']
    assert not queue.finish(first, 'READY_FOR_REVIEW')
    assert queue.finish(second, 'READY_FOR_REVIEW')


def test_owner_cannot_cancel_or_read_other_queue(service):
    a, root, ar = setup(service)
    b, _, br = setup(service, 'b')
    (root/'routes.py').write_text('version = 1\n')
    enqueue(a, root, ar, launch=False)
    enqueue(b, root, br, launch=False)
    with pytest.raises(ValueError):
        cancel(b, root, ar)
    with pytest.raises(ValueError):
        status(b, root, ar)
    assert cancel(a, root, ar)['status'] == 'CANCELLED'
    assert status(b, root, br)['status'] == 'QUEUED'


def test_cancelled_request_cannot_publish(service):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('version = 1\n')
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root)
    claim = queue.claim(ref, uuid.uuid4().hex)
    cancel(task, root, ref)
    assert not queue.current(claim)
    assert not queue.finish(claim, 'READY_FOR_REVIEW')


def test_legacy_finish_is_not_enqueued(service):
    task, root, engine = service
    ref = task.begin(root, 'legacy')['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('version = 1\n')
    assert enqueue(task, root, ref, launch=False)['status'] == 'READY'
    assert CloseoutQueue(task.hooks, root).read(ref) is None
    assert task.load(root, ref)['baseline'] == baseline


def test_tampered_queue_is_not_executed(service):
    task, root, ref = setup(service)
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root)
    with queue.transaction() as db:
        db.execute('UPDATE records SET data=? WHERE key=?', ('{}', ref))
    with pytest.raises(ValueError, match='signature'):
        execute_one(task, root, ref)
    assert not service[2].calls


def test_two_workers_only_one_claim(service):
    task, root, ref = setup(service)
    enqueue(task, root, ref, launch=False)
    claims = []
    def claim():
        claims.append(CloseoutQueue(task.hooks, root).claim(ref, uuid.uuid4().hex))
    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(row is not None for row in claims) == 1


def test_prepare_never_bypasses_background_queue(service, monkeypatch):
    old, root, engine = service
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', 'background'))
    ref = task.begin(root, 'one', check_policy=POLICY, background_closeout=True)['task_ref']
    monkeypatch.setattr(task, 'finish', lambda *a:pytest.fail('prepare started a foreground scan'))
    assert task.prepare(root, ref)['status'] == 'NOT_QUEUED'
    (root/'routes.py').write_text('version = 2\n')
    enqueue(task, root, ref, launch=False)
    assert task.prepare(root, ref)['status'] == 'QUEUED'
    assert not engine.calls


def test_no_change_submission_cannot_certify_later_edits(service):
    task, root, ref = setup(service)
    enqueue(task, root, ref, launch=False)
    (root/'routes.py').write_text('version = 3\n')
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'STALE'


def test_cancel_during_scan_retains_original_baseline(service):
    task, root, ref = setup(service)
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('version = 4\n')
    enqueue(task, root, ref, launch=False)
    service[2].mutate = lambda root:cancel(task, root, ref)
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'CANCELLED'
    assert task.load(root, ref)['baseline'] == baseline
