"""Failure evidence is bounded, source-free and fenced like the queue result."""
import copy
import json
import sqlite3

import pytest

from security_runtime.tasks.execution_diagnostics import failure_diagnostic, validate
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks.risk_feedback import project_disposition, current_hashes
from test_closeout_queue import setup, private_dispatcher  # noqa: F401
from test_task_security import service  # noqa: F401


def test_diagnostic_discards_messages_paths_args_and_locals():
    namespace = {'__name__': 'security_runtime.test_fixture'}
    exec(compile('def fail():\n secret = "private-source"\n raise ValueError("private-message C:/private/path")',
                 'C:/private/code.py', 'exec'), namespace)
    try:
        namespace['fail']()
    except ValueError as error:
        diagnostic = failure_diagnostic(error, 'TASK_CLOSEOUT')
    assert diagnostic['location'] == dict(module='security_runtime.test_fixture', function='fail', line=3)
    assert diagnostic['exception_type'] == 'ValueError'
    assert diagnostic['security_proof'] is False
    assert 'private' not in json.dumps(diagnostic)
    assert len(json.dumps(diagnostic)) < 600


def test_wrapped_sqlite_code_survives_without_exception_text():
    try:
        db = sqlite3.connect(':memory:')
        try:
            db.deserialize(b'broken database')
            db.execute('PRAGMA quick_check')
        finally:
            db.close()
    except sqlite3.DatabaseError as cause:
        try:
            raise RuntimeError('private-wrapper') from cause
        except RuntimeError as error:
            diagnostic = failure_diagnostic(error, 'RESTORE_END')
    assert diagnostic['exception_type'] == 'RuntimeError'
    assert diagnostic['storage_error'] == 'SQLITE_NOTADB'
    assert 'private' not in json.dumps(diagnostic)


def test_unknown_exception_name_is_not_echoed():
    custom = type('PrivateCustomerToken', (Exception,), {})
    assert failure_diagnostic(custom('private'), 'LOAD_TASK')['exception_type'] == 'OTHER'
    with pytest.raises(ValueError):
        validate(dict(failure_diagnostic(ValueError(), 'LOAD_TASK'), secret='private'))


def test_queue_preserves_stage_without_mutating_baseline(service, monkeypatch):
    task, root, ref = setup(service)
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('changed = True\n')
    enqueue(task, root, ref, launch=False)
    def fail(*args, **kwargs):
        raise ValueError('private-source-and-token')
    monkeypatch.setattr(task, '_finish', fail)
    assert execute_one(task, root, ref)
    result = status(task, root, ref)
    assert result['status'] == 'FAILED' and result['reason'] == 'TASK_EXECUTION_UNAVAILABLE'
    assert result['diagnostic_status'] == 'RECORDED'
    assert result['execution_diagnostic']['stage'] == 'TASK_CLOSEOUT'
    assert result['execution_diagnostic']['exception_type'] == 'ValueError'
    assert result['execution_diagnostic']['location']['module'] == 'security_runtime.tasks.queued_closeout'
    assert 'private' not in json.dumps(result)
    assert task.load(root, ref)['baseline'] == baseline
    assert not service[2].calls


def test_missing_historical_diagnostic_is_not_invented(service):
    task, root, ref = setup(service)
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root)
    claim = queue.claim(ref, 'worker')
    queue.finish(claim, 'FAILED', 'TASK_EXECUTION_UNAVAILABLE')
    result = status(task, root, ref)
    assert result['diagnostic_status'] == 'NOT_RECORDED'
    assert result['execution_diagnostic'] is None


def test_expired_worker_cannot_publish_failure_diagnostic(service):
    clock = [100000.0]
    task, root, ref = setup(service, clock=clock)
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root, now=lambda: clock[0])
    old = queue.claim(ref, 'old', seconds=2)
    clock[0] += 3
    current = queue.claim(ref, 'current')
    diagnostic = failure_diagnostic(ValueError('private'), 'TASK_CLOSEOUT')
    assert not queue.finish(old, 'FAILED', diagnostic=diagnostic)
    assert queue.finish(current, 'READY_FOR_REVIEW')
    assert 'last_failure_diagnostic' not in queue.read(ref)
    assert 'execution_diagnostic' not in status(task, root, ref)


def test_static_failure_is_available_in_saved_and_public_result(service, monkeypatch):
    task, root, engine = service
    ref = task.begin(root, 'static-failure')['task_ref']
    (root/'routes.py').write_text('changed = True\n')
    def fail(*args, **kwargs):
        raise RuntimeError('private-scanner-error')
    monkeypatch.setattr(engine, 'scan', fail)
    result = task.finish(root, ref)
    diagnostic = result['static']['failure_diagnostic']
    assert result['static']['status'] == 'FAILED'
    assert diagnostic['stage'] == 'STATIC_SCAN'
    assert diagnostic['exception_type'] == 'RuntimeError'
    assert task.load(root, ref)['static']['failure_diagnostic'] == diagnostic
    assert 'private' not in json.dumps(diagnostic)


@pytest.mark.parametrize('proof_kind,expected', [('current', 'RESOLVED'), ('stale', 'OPEN'),
    ('missing', 'OPEN'), ('unreadable', 'OPEN')])
def test_scanner_verified_resolution_still_requires_current_proof(service, proof_kind, expected):
    task, root, _ = service
    proof = current_hashes(root, ['routes.py'])
    if proof_kind == 'stale':
        (root/'routes.py').write_text('changed = True\n')
    elif proof_kind == 'missing':
        proof = {}
    elif proof_kind == 'unreadable':
        (root/'routes.py').unlink()
    row = dict(status='SCANNER_VERIFIED_RESOLVED', proof_hashes=proof)
    result = project_disposition(task.hooks, root, row, dict(status='NOT_MARKED', folded=False))
    assert result['handling_status'] == expected
    assert result['reminder_suppressed'] is (expected == 'RESOLVED')
    assert row['status'] == 'SCANNER_VERIFIED_RESOLVED'
