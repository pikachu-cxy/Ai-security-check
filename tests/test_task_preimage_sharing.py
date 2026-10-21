"""Physical sharing must preserve logical quotas and authentic task evidence."""
import json
import sqlite3

import pytest

from security_runtime import task_preimages as preimages
from security_runtime.task_preimages import TaskPreimageUnavailable
from test_task_preimages import sample, put, read, FIRST, SECOND, THIRD  # noqa: F401


def legacy_body(store):
    with store.writer(FIRST) as writer:
        reference = put(writer)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE task_preimages SET body=(SELECT body FROM task_preimage_blobs)')
        db.execute('DROP TABLE task_preimage_blobs')
    return reference


def test_all_32_task_baselines_share_content_but_not_authority(sample, monkeypatch):
    store, _ = sample
    refs = []
    for i in range(32):
        task = 'ts1-'+f'{i:032x}'
        with store.writer(task) as writer:
            ref = put(writer)
            if i == 0:
                monkeypatch.setattr(preimages, 'MAX_WORKSPACE_BYTES', ref['body_bytes'])
            # Same bytes at another path also share the physical BLOB.
            put(writer, 'auth.py')
        refs.append((task, ref))
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*),sum(length(body)) FROM task_preimage_blobs').fetchone() == (1, refs[0][1]['body_bytes'])
        assert db.execute('SELECT count(*),sum(length(body)) FROM task_preimages').fetchone() == (64, 0)
    for task, reference in refs:
        assert read(store, task, 'routes.py', reference)
    with pytest.raises(TaskPreimageUnavailable, match='REFERENCE_UNVERIFIED'):
        read(store, refs[1][0], 'routes.py', refs[0][1])


def test_legacy_references_read_unchanged_before_and_after_migration(sample):
    store, _ = sample
    first = legacy_body(store)
    original = json.dumps(first, sort_keys=True)
    assert read(store, FIRST, 'routes.py', first)
    with store.writer(SECOND) as writer:
        second = put(writer)
    assert json.dumps(first, sort_keys=True) == original
    assert read(store, FIRST, 'routes.py', first) == read(store, SECOND, 'routes.py', second)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM task_preimage_blobs').fetchone() == (1,)


def test_legacy_duplicate_bodies_release_capacity_before_new_capture(sample, monkeypatch):
    store, _ = sample
    with store.writer(FIRST) as writer:
        first = put(writer)
    with store.writer(SECOND) as writer:
        second = put(writer)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE task_preimages SET body=(SELECT body FROM task_preimage_blobs)')
        db.execute('DROP TABLE task_preimage_blobs')
    monkeypatch.setattr(preimages, 'MAX_WORKSPACE_BYTES', first['body_bytes'])
    with store.writer(THIRD) as writer:
        third = put(writer)
    assert read(store, FIRST, 'routes.py', first) == read(store, SECOND, 'routes.py', second)
    assert read(store, THIRD, 'routes.py', third)


def test_shared_body_lives_until_last_reference_not_first_task_ttl(sample):
    store, clock = sample
    with store.writer(FIRST) as writer:
        first = put(writer)
    clock[0] += 1
    with store.writer(SECOND) as writer:
        second = put(writer)
    clock[0] = first['expires_at']
    with store.writer(THIRD):
        pass
    assert read(store, SECOND, 'routes.py', second)
    with pytest.raises(TaskPreimageUnavailable, match='EXPIRED'):
        read(store, FIRST, 'routes.py', first)
    store.discard(SECOND)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM task_preimage_blobs').fetchone() == (0,)


def test_shared_storage_does_not_remove_per_task_logical_limit(sample, monkeypatch):
    store, _ = sample
    with store.writer(FIRST) as writer:
        first = put(writer)
    monkeypatch.setattr(preimages, 'MAX_TASK_BYTES', first['body_bytes'])
    with store.writer(SECOND) as writer:
        put(writer)
        with pytest.raises(TaskPreimageUnavailable, match='TASK_BYTE_BUDGET'):
            put(writer, 'auth.py')


@pytest.mark.parametrize('target', ['legacy-body', 'legacy-metadata', 'shared-body', 'missing-shared'])
def test_corrupt_content_is_never_healed_by_sharing(sample, target):
    store, _ = sample
    if target.startswith('legacy'):
        first = legacy_body(store)
    else:
        with store.writer(FIRST) as writer:
            first = put(writer)
    with sqlite3.connect(store.path) as db:
        if target == 'legacy-body':
            db.execute('UPDATE task_preimages SET body=?', (b'["corrupt"]',))
        elif target == 'legacy-metadata':
            db.execute('UPDATE task_preimages SET metadata=?', ('{}',))
        elif target == 'shared-body':
            db.execute('UPDATE task_preimage_blobs SET body=?', (b'["corrupt"]',))
        else:
            db.execute('DELETE FROM task_preimage_blobs')
    with pytest.raises(TaskPreimageUnavailable):
        read(store, FIRST, 'routes.py', first)
    with pytest.raises(TaskPreimageUnavailable):
        with store.writer(SECOND) as writer:
            put(writer)


def test_migration_rolls_back_with_batch_failure_and_retries_original_bytes(sample):
    store, _ = sample
    first = legacy_body(store)
    with pytest.raises(RuntimeError):
        with store.writer(SECOND) as writer:
            put(writer)
            raise RuntimeError('injected interruption')
    assert read(store, FIRST, 'routes.py', first)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT length(body) FROM task_preimages').fetchone()[0] > 0
    with store.writer(SECOND) as writer:
        second = put(writer)
    assert read(store, SECOND, 'routes.py', second)
