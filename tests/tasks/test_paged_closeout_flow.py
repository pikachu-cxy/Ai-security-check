"""Exercise real queue/worker/review consumers with fixed-input fixtures."""
import copy
import sqlite3

import pytest

from security_runtime.tasks.closeout_queue import CloseoutQueue, LEGACY_CONTRACT
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks.durable import TaskOperationError, SignedRecords, operation_failure
from security_runtime.tasks.closeout_pages import restore
from test_closeout_queue import setup, private_dispatcher
from test_task_security import service
from task_review_helpers import review_all


def test_paged_queue_reaches_complete_v3_review_without_large_control_lists(service):
    task, root, ref = setup(service)
    before = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('changed = True\n')
    assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
    queue = CloseoutQueue(task.hooks, root)
    row = queue.read(ref)
    assert 'hashes' not in row['end'] and row['changes_ref']
    from security_runtime.tasks.queued_inputs import QueuedInputs
    inputs = QueuedInputs(task.hooks, root)
    saved_input = inputs.read(row['input_ref'])
    assert 'hashes' not in saved_input and 'snapshot_scope' in saved_input
    assert execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    packet = task.prepare(root, ref)
    assert packet['status'] == 'REVIEW_REQUIRED'
    review_all(task, root, ref, packet)
    result = task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['status'] == 'COMPLETE'
    assert task.load(root, ref)['baseline'] == before


def test_legacy_inline_queue_remains_readable_and_executable(service):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root)
    row = queue.read(ref)
    end = restore(task.store(root), task.load(root, ref), row['end'])
    # Released inline jobs are not rewritten by new readers.
    with queue.transaction() as db:
        row = queue._get(db, ref)
        queue._put(db, ref, dict(row, contract=LEGACY_CONTRACT, end=end, changes_ref=None))
    assert execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'


def test_cleanup_error_does_not_hide_original_queue_capacity_failure(service, monkeypatch):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    failed = [False]
    original_read = CloseoutQueue.read
    def submit(*args, **kwargs):
        failed[0] = True
        raise TaskOperationError('TASK_OPERATION_CAPACITY_REQUIRED', observed=4000001, limit=4000000)
    def read(self, key):
        if failed[0]:
            raise TaskOperationError('TASK_OPERATION_STORAGE_INVALID')
        return original_read(self, key)
    monkeypatch.setattr(CloseoutQueue, 'submit', submit)
    monkeypatch.setattr(CloseoutQueue, 'read', read)
    with pytest.raises(TaskOperationError) as error:
        enqueue(task, root, ref, launch=False)
    assert error.value.reason_code == 'TASK_OPERATION_CAPACITY_REQUIRED'
    assert error.value.observed == 4000001


@pytest.mark.parametrize('code,reason', [(sqlite3.SQLITE_FULL,'TASK_OPERATION_DISK_FULL'),
    (sqlite3.SQLITE_BUSY,'TASK_OPERATION_BUSY')])
def test_sqlite_failure_keeps_typed_reason_and_readable_schema(service, code, reason):
    task, root, _ = setup(service)
    store = SignedRecords(task.hooks, root, 'sql-failure.db')
    with pytest.raises(TaskOperationError) as failed:
        with store.transaction():
            error = sqlite3.OperationalError('private diagnostic must not be reflected')
            error.sqlite_errorcode = code
            raise error
    result = operation_failure(failed.value)
    assert result['reason_code'] == reason
    assert 'private diagnostic' not in str(result)
    assert store.rows() == []
