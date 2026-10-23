"""Pagination authenticates one locked record without weakening rejection."""
from contextlib import contextmanager

import pytest

from security_runtime.tasks.ownership import TaskOwnershipError, session_owner
from security_runtime.task_review.protocol import UnsupportedTaskReviewProtocol
from test_task_security import prepared, service  # noqa: F401


def operations(tasks, root, ref, session, unit_id):
    return {
        'read': lambda: tasks.read(root, ref, session, 'routes.py', 1, 1),
        'plan': lambda: tasks.review_plan(root, ref, session),
        'batch': lambda: tasks.submit_batch(root, ref, session, [unit_id], 'PARTIAL', ['Remaining context']),
        'method': lambda: tasks.review_method(root, ref, session),
    }


def test_successful_pagination_loads_one_record_inside_the_workspace_lock(service, monkeypatch):
    tasks, root, _ = service
    ref, session, packet = prepared(service)
    unit_id = packet['plan']['units'][0]['unit_id']
    original = tasks.load
    loads = []

    def tracked(*args, **kwargs):
        loads.append(tasks.hooks.lock_held(root))
        return original(*args, **kwargs)

    monkeypatch.setattr(tasks, 'load', tracked)
    for operation in operations(tasks, root, ref, session, unit_id).values():
        loads.clear()
        operation()
        assert loads == [True]


@pytest.mark.parametrize('rejection', ['owner', 'protocol'])
@pytest.mark.parametrize('busy', [False, True])
def test_owner_and_protocol_rejections_still_precede_busy_without_persistence(service, monkeypatch, rejection, busy):
    tasks, root, _ = service
    tasks.owner = session_owner('codex', 'original')
    ref, session, packet = prepared(service)
    unit_id = packet['plan']['units'][0]['unit_id']
    if rejection == 'owner':
        tasks.owner = session_owner('codex', 'another')
        error = TaskOwnershipError
    else:
        record = tasks.load(root, ref)
        record['review_protocol'] = 2
        tasks.store(root).save(record)
        error = UnsupportedTaskReviewProtocol
    before = tasks.store(root).path.read_bytes()

    if busy:
        @contextmanager
        def unavailable(*args, **kwargs):
            yield False
        monkeypatch.setattr(tasks.hooks, 'lock', unavailable)

    for operation in operations(tasks, root, ref, session, unit_id).values():
        with pytest.raises(error):
            operation()
    assert tasks.store(root).path.read_bytes() == before


def test_current_file_change_remains_stale_before_any_evidence_is_saved(service):
    tasks, root, _ = service
    ref, session, _ = prepared(service)
    before = tasks.store(root).path.read_bytes()
    (root / 'routes.py').write_text('changed after preparing review\n', encoding='utf-8')
    with pytest.raises(ValueError, match='source changed'):
        tasks.read(root, ref, session, 'routes.py', 1, 1)
    assert tasks.store(root).path.read_bytes() == before
