"""Large fixed inventories must not consume inline review-record capacity."""
import copy
from contextlib import contextmanager
import json
import sqlite3

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.closeout_state import encode
from security_runtime.task_review import plan, transport
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.activity import POLICY
from test_task_security import service
from task_review_helpers import review_all


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def finished(sample, count=3):
    original, root, engine = sample
    for index in range(count - 3):
        (root / f'm{index:05}.py').write_text('value = 1\n')
    task = TaskSecurityService(engine, original.hooks,
        owner=session_owner('codex', 'paged-capacity'),
        frozen_body_contexts=True, capture_sources=True)
    ref = task.begin(root, 'paged-capacity', check_policy=POLICY)['task_ref']
    (root / 'text_utils.py').write_text('def normalize_text(text):\n    return " ".join(text.split())\n')
    (root / 'test_text_utils.py').write_text('from text_utils import normalize_text\nassert normalize_text(" a  b ") == "a b"\n')
    assert task.finish(root, ref)['status'] == 'READY'
    return task, root, ref, engine


@pytest.mark.parametrize('count', [6002, 12001])
def test_large_inventory_two_changes_complete_original_review(service, count):
    task, root, ref, engine = finished(service, count)
    before = task.load(root, ref)
    assert len(before['baseline']['hashes']) == count
    assert len(encode(before)) > 4_000_000
    packet = task.prepare(root, ref)
    assert packet['status'] == 'REVIEW_REQUIRED'
    review_all(task, root, ref, packet)
    result = task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert result['status'] == 'COMPLETE'
    after = task.load(root, ref)
    assert after['baseline'] == before['baseline'] and after['end'] == before['end']
    assert len(engine.calls) == 1
    with sqlite3.connect(task.store(root).path) as db:
        raw = db.execute('SELECT data FROM security_tasks WHERE ref=?', (ref,)).fetchone()[0]
    head = json.loads(raw)
    assert len(raw.encode()) < 100_000
    for field in ('baseline', 'end'):
        assert 'paged_entries' in head[field] and 'hashes' not in head[field]


def old_diagnosis(record):
    snapshot = plan._snapshot(record)
    return dict(status='CAPACITY_REQUIRED', reason_code='TASK_REVIEW_RECORD_CAPACITY',
        snapshot_id=snapshot, plan_id='tp3-' + plan._digest([record['task_ref'], snapshot])[:32],
        unit_count=len(record['changes']), reviewed_unit_count=0, source_delivery_started=False,
        required_record_bytes=len(encode(record)) + 4096, maximum_record_bytes=4_000_000)


def test_old_false_capacity_resumes_original_task_even_after_idle_deadline(service):
    task, root, ref, engine = finished(service)
    old = task.load(root, ref)
    old['review_capacity'] = old_diagnosis(old)
    old['review_deadline'] = task.now() - 1
    task.store(root).save(old)
    packet = task.prepare(root, ref)
    assert packet['status'] == 'REVIEW_REQUIRED'
    current = task.load(root, ref)
    assert 'review_capacity' not in current
    assert current['baseline'] == old['baseline'] and current['end'] == old['end']
    assert current['static'] == old['static'] and len(engine.calls) == 1


@pytest.mark.parametrize('field', ['source', 'ref', 'hash'])
def test_capacity_does_not_hide_unverified_snapshot_maps(service, field):
    task, root, ref, _ = finished(service)
    record = task.load(root, ref)
    if field == 'hash':
        record['baseline']['hashes']['routes.py'] = 'f' * 64
    elif field == 'source':
        record['baseline']['paged_entries']['source'] = 'f' * 64
    else:
        record['baseline']['paged_entries']['ref'] = 'invalid'
    with pytest.raises(ValueError):
        transport.record_capacity(record)


def test_real_control_metadata_is_still_counted(service):
    task, root, ref, _ = finished(service)
    record = task.load(root, ref)
    record['real_control_metadata'] = 'x' * 4_000_000
    assert not transport.record_capacity(record)['fits']
    assert plan.record_capacity(record)['status'] == 'CAPACITY_REQUIRED'


def test_capacity_matches_stored_head_without_page_writes(service, monkeypatch):
    task, root, ref, _ = finished(service)
    record = task.load(root, ref)
    from security_runtime.tasks.security_state import stored_record_projection
    with sqlite3.connect(task.store(root).path) as db:
        head = json.loads(db.execute('SELECT data FROM security_tasks WHERE ref=?', (ref,)).fetchone()[0])
    def forbidden(*args, **kwargs):
        pytest.fail('Capacity calculation attempted source-page I/O')
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.pack', forbidden)
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages._store', forbidden)
    original = copy.deepcopy(record)
    assert stored_record_projection(record) == head
    assert transport.record_capacity(record)['required_record_bytes'] == len(encode(head)) + 4096
    assert record == original


@pytest.mark.parametrize('invalid', ['changed_source', 'other_owner', 'already_delivered', 'new_capacity'])
def test_legacy_retry_cannot_bypass_version_owner_or_delivered_work(service, invalid):
    task, root, ref, engine = finished(service)
    record = task.load(root, ref)
    record['review_capacity'] = old_diagnosis(record)
    if invalid == 'already_delivered':
        record['review_capacity']['source_delivery_started'] = True
    elif invalid == 'new_capacity':
        record['review_capacity']['capacity_basis'] = transport.CAPACITY_BASIS
    task.store(root).save(record)
    before = task.load(root, ref)
    if invalid == 'changed_source':
        (root / 'text_utils.py').write_text('value = 2\n')
        assert task.prepare(root, ref)['status'] == 'STALE'
    elif invalid == 'other_owner':
        other = TaskSecurityService(engine, task.hooks, owner=session_owner('codex', 'other'))
        with pytest.raises(ValueError, match='another session'):
            other.prepare(root, ref)
    else:
        assert task.prepare(root, ref)['status'] == 'CAPACITY_REQUIRED'
    assert task.load(root, ref) == before and len(engine.calls) == 1


def test_retry_transaction_failure_preserves_diagnosis_and_original_sources(service, monkeypatch):
    task, root, ref, engine = finished(service)
    record = task.load(root, ref)
    record['review_capacity'] = old_diagnosis(record)
    task.store(root).save(record)
    before = task.load(root, ref)
    connect = sqlite3.connect
    class FailingConnection(sqlite3.Connection):
        def execute(self, statement, parameters=()):
            result = super().execute(statement, parameters)
            if statement.upper().startswith('INSERT OR REPLACE INTO SECURITY_TASKS'):
                raise sqlite3.IntegrityError('retry transaction failed')
            return result
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, 'connect', lambda *args, **kwargs:
                      connect(*args, **dict(kwargs, factory=FailingConnection)))
        with pytest.raises(sqlite3.IntegrityError, match='retry transaction failed'):
            task.prepare(root, ref)
    assert task.load(root, ref) == before and len(engine.calls) == 1
    # A new service instance resumes only the same retained task.
    resumed = TaskSecurityService(engine, task.hooks, owner=session_owner('codex', 'paged-capacity'))
    assert resumed.prepare(root, ref)['status'] == 'REVIEW_REQUIRED'
    assert resumed.load(root, ref)['baseline'] == before['baseline']


def test_closed_legacy_capacity_needs_explicit_recovery_and_preserves_closure(service):
    task, root, ref, engine = finished(service)
    old = task.load(root, ref)
    old['review_capacity'] = old_diagnosis(old)
    task.store(root).save(old)
    assert task.skip(root, ref, 'Record capacity blocked the original review')['status'] == 'INCOMPLETE'
    before = task.load(root, ref)
    assert task.prepare(root, ref)['status'] == 'INCOMPLETE'
    assert task.load(root, ref) == before
    packet = task.prepare(root, ref, resume_capacity=True)
    assert packet['status'] == 'REVIEW_REQUIRED'
    current = task.load(root, ref)
    assert current['baseline'] == before['baseline'] and current['static'] == before['static']
    assert current['capacity_recoveries'][0]['previous_skip_reason'] == before['skip_reason']
    assert len(engine.calls) == 1
    review_all(task, root, ref, packet)
    assert task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])['status'] == 'COMPLETE'


@pytest.mark.parametrize('kind', ['ordinary_incomplete', 'completed', 'changed_source', 'other_owner'])
def test_explicit_recovery_cannot_reopen_other_terminal_work(service, kind):
    task, root, ref, engine = finished(service)
    if kind != 'ordinary_incomplete':
        record = task.load(root, ref)
        record['review_capacity'] = old_diagnosis(record)
        task.store(root).save(record)
    task.skip(root, ref, 'Original closure')
    if kind == 'completed':
        record = task.load(root, ref)
        record['phase'] = 'COMPLETE'
        task.store(root).save(record)
    before = task.load(root, ref)
    if kind == 'changed_source':
        (root / 'text_utils.py').write_text('value = 2\n')
        assert task.prepare(root, ref, resume_capacity=True)['status'] == 'STALE'
    elif kind == 'other_owner':
        other = TaskSecurityService(engine, task.hooks, owner=session_owner('codex', 'other'))
        with pytest.raises(ValueError, match='another session'):
            other.prepare(root, ref, resume_capacity=True)
    else:
        assert task.prepare(root, ref, resume_capacity=True)['status'] in {'INCOMPLETE', 'COMPLETE'}
    assert task.load(root, ref) == before and len(engine.calls) == 1


@pytest.mark.parametrize('change', ['build_only', 'rules', 'cancelled', 'cancel_race'])
def test_background_capacity_resume_preserves_scan_identity_and_cancellation(service, monkeypatch, change):
    from security_runtime.tasks.queued_closeout import enqueue, execute_one, execution_identity
    from security_runtime.tasks.closeout_queue import CloseoutQueue
    original, root, engine = service
    task = TaskSecurityService(engine, original.hooks, owner=session_owner('codex', 'capacity-worker'),
                               frozen_body_contexts=True, capture_sources=True)
    ref = task.begin(root, 'queued-capacity', check_policy=POLICY, background_closeout=True)['task_ref']
    (root / 'added.py').write_text('value = 1\n')
    assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
    assert execute_one(task, root, ref)
    record = task.load(root, ref)
    record['review_capacity'] = old_diagnosis(record)
    task.store(root).save(record)
    original_execution = execution_identity()
    current_execution = dict(original_execution, build_id='new-runtime-metadata-fix')
    if change == 'rules':
        current_execution['rule_pack_checksum'] = 'changed-rules'
    if change == 'cancelled':
        CloseoutQueue(task.hooks, root).cancel(ref, task._owner())
    if change == 'cancel_race':
        original_lock = task.hooks.lock
        @contextmanager
        def cancel_before_prepare_commit(*args, **kwargs):
            with original_lock(*args, **kwargs) as acquired:
                if acquired:
                    CloseoutQueue(task.hooks, root).cancel(ref, task._owner())
                yield acquired
        monkeypatch.setattr(task.hooks, 'lock', cancel_before_prepare_commit)
    monkeypatch.setattr('security_runtime.tasks.queued_closeout.execution_identity', lambda: current_execution)
    before = task.load(root, ref)
    result = task.prepare(root, ref)
    if change == 'build_only':
        assert result['status'] == 'REVIEW_REQUIRED'
        assert CloseoutQueue(task.hooks, root).read(ref)['configuration']['execution'] == original_execution
        assert task.load(root, ref)['static'] == before['static']
    else:
        assert result['status'] in {'STALE', 'CANCELLED'}
        assert task.load(root, ref) == before
    assert len(engine.calls) == 1
