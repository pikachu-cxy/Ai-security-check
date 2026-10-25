"""Large end/change manifests remain outside queue and task control JSON."""
import copy
import json
import sqlite3

import pytest

from security_runtime.closeout_state import encode
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.closeout_pages import restore
from security_runtime.tasks.closeout_index import project
from security_runtime.tasks.durable import SignedRecords, TaskOperationError, operation_failure
from security_runtime.tasks.snapshot_gc import collect_pages
from test_task_snapshot_gc import sample, record, snapshot


def test_twelve_thousand_changes_are_paged_and_queue_remains_small(sample):
    root, hooks, clock, owner, state, _ = sample
    original = state.save(record(sample, end=None), new=True)
    original = state.get(original['task_ref'])
    baseline = copy.deepcopy(original['baseline'])
    names = [f'src/group_{i//100:03d}/module_{i:05d}.py' for i in range(12000)]
    end = dict(hashes={p:'a'*64 for p in names}, texts={},
        inventory=names, read_priority=[], limitations=[], read_limitations=[],
        inventory_complete=True, redaction_version=3,
        preimages={p:dict(path=p, raw_sha256='a'*64, body_sha256='b'*64,
            workspace_id='c'*64, task_ref='ts1-'+'d'*32, mac='e'*64,
            contract='original-body-reference', created_at=clock[0], expires_at=clock[0]+86400,
            body_bytes=10, line_count=1, source='RAW_TASK_BODY_V3') for p in names},
        version_ref='ts1-'+'d'*32)
    assert len(encode(end)) > 4_000_000
    queue = CloseoutQueue(hooks, root, now=lambda:clock[0])
    queue.submit(original, end, {})
    row = queue.read(original['task_ref'])
    assert len(encode(row)) < 16000
    assert 'preimages' not in row['end'] and 'hashes' not in row['end']
    assert row['changes_ref']['snapshot'] == row['end']['paged_entries']
    collect_pages(state)  # Unfinished worker references pin the complete end.
    cursor, changes = 0, []
    while True:
        page = queue.change_page(original['task_ref'], owner, cursor=cursor)
        changes.extend(page['changes'])
        if page['next_cursor'] is None:
            break
        assert page['next_cursor'] > cursor
        cursor = page['next_cursor']
    assert len(changes) == 12001  # Includes deletion of original source.py.
    assert len({v['path'] for v in changes}) == 12001
    assert any(v['path'] == names[-1] for v in changes)
    restored = restore(state, original, row['end'])
    full, unknown = project(restored)
    saved = state.save(dict(original, end=restored, changes=full, unverified_paths=unknown))
    with sqlite3.connect(state.path) as db:
        raw = db.execute('SELECT data FROM security_tasks WHERE ref=?',(saved['task_ref'],)).fetchone()[0]
    assert len(raw.encode()) < 16000
    assert 'changes' not in json.loads(raw)
    loaded = state.get(saved['task_ref'])
    assert len(loaded['changes']) == 12001 and loaded['baseline'] == baseline
    assert loaded['end']['hashes'] == end['hashes']


def test_first_transaction_rollback_leaves_readable_queue_and_original_error(sample):
    root, hooks, _, _, _, _ = sample
    store = SignedRecords(hooks, root, 'rollback-test.db')
    with pytest.raises(TaskOperationError) as failure:
        with store.transaction() as db:
            store._put(db, 'job', {'large':'x'*4_000_000})
    out = operation_failure(failure.value)
    assert out['status'] == 'CAPACITY_REQUIRED'
    assert out['capacity']['required_bytes'] > out['capacity']['limit_bytes']
    assert store.read('job') is None and store.rows() == []
    with store.transaction() as db:
        store._put(db, 'job', {'small':True})
    assert store.read('job')['small']


def test_existing_zero_byte_queue_recovers_without_rebuilding_baseline(sample):
    root, hooks, _, _, state, _ = sample
    original = state.save(record(sample, end=None), new=True)
    original = state.get(original['task_ref'])
    queue = CloseoutQueue(hooks, root)
    queue.path.touch(mode=0o600)
    before = queue.path.stat().st_mtime_ns
    assert queue.read(original['task_ref']) is None and queue.rows() == []
    assert queue.path.stat().st_size == 0 and queue.path.stat().st_mtime_ns == before
    with queue.transaction() as db:
        queue._put(db, '$worker', {'ticket':'fixture'})
    assert queue.rows() and state.get(original['task_ref'])['baseline'] == original['baseline']


def test_nonempty_wrong_schema_is_not_adopted(sample):
    root, hooks, _, _, _, _ = sample
    store = SignedRecords(hooks, root, 'wrong-schema.db')
    with sqlite3.connect(store.path) as db:
        db.execute('CREATE TABLE unrelated (data TEXT)')
    store.path.chmod(0o600)
    original = store.path.read_bytes()
    with pytest.raises(TaskOperationError):
        store.read('job')
    with pytest.raises(TaskOperationError):
        with store.transaction():
            pass
    assert store.path.read_bytes() == original


def test_foreign_task_snapshot_cannot_be_rebound_to_current_queue(sample):
    root, hooks, clock, _, state, _ = sample
    first = state.save(record(sample, index=1, end=None), new=True)
    second = state.save(record(sample, index=2, end=None), new=True)
    first, second = state.get(first['task_ref']), state.get(second['task_ref'])
    queue = CloseoutQueue(hooks, root, now=lambda:clock[0])
    queue.submit(first, snapshot('first-end'), {})
    queue.submit(second, snapshot('second-end'), {})
    foreign = queue.read(second['task_ref'])['end']
    with pytest.raises(TaskOperationError, match='SNAPSHOT_UNAVAILABLE'):
        restore(state, first, foreign)
    assert state.get(first['task_ref'])['baseline'] == first['baseline']


def test_legacy_unmanaged_inline_submission_keeps_original_end(sample):
    root, hooks, clock, owner, _, _ = sample
    legacy = dict(record(sample, end=None), contract='task-security-v1',
                  capture_policy='BATCHED_FILES_V1')
    end = snapshot('legacy-end')
    queue = CloseoutQueue(hooks, root, now=lambda:clock[0])
    queue.submit(legacy, end, {})
    row = queue.read(legacy['task_ref'])
    assert row['end'] == end and row['changes_ref'] is None
    assert queue.view(legacy['task_ref'], owner)['status'] == 'QUEUED'
