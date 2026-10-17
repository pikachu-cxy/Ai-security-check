"""Private before-version storage invariants; no scanner/build invocation."""
from copy import deepcopy
import hashlib
import json
import os
import sqlite3

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.local_evidence import safe_source
import security_runtime.task_preimages as preimages
from security_runtime.task_preimages import TaskPreimageStore, TaskPreimageUnavailable


FIRST = 'ts1-'+'1'*32
SECOND = 'ts1-'+'2'*32
THIRD = 'ts1-'+'3'*32


@pytest.fixture
def sample(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path/'private-state')
    hooks.key(root)
    clock = [1000.0]
    return TaskPreimageStore(hooks, root, now=lambda: clock[0]), clock


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(writer, path='routes.py', raw=b'def route(user):\n    return auth.check(user)\n'):
    return writer.put(path, raw, safe_source(raw.decode('utf-8-sig')))


def read(store, ref, path, reference):
    return store.read(ref, path, reference['raw_sha256'], reference)


def reason(error):
    return error.value.reason_code


def test_large_project_retains_all_fourteen_late_changed_preimages(sample):
    store, _ = sample
    large = b'value = source.read_checked(item)\n'*1500
    small = b'allowed = auth.check(user)\n'
    references = {}
    with store.writer(FIRST) as writer:
        for i in range(719):
            name = f'src/file_{i:03}.py'
            references[name] = put(writer, name, large if i >= 705 else small)
    assert sum(ref['body_bytes'] for ref in references.values()) > 512_000
    assert len(json.dumps(references).encode()) < 512_000
    for i in range(705, 719):
        name = f'src/file_{i:03}.py'
        assert read(store, FIRST, name, references[name]) == safe_source(large.decode())
        assert references[name]['line_count'] == 1500


def test_raw_credentials_are_never_persisted_and_reference_is_small(sample):
    store, _ = sample
    raw = b"password = 'test-private-password'\nvalue = 'private-business-literal'\n"
    with store.writer(FIRST) as writer:
        reference = put(writer, raw=raw)
    assert len(json.dumps(reference).encode()) < 1000
    assert reference['raw_sha256'] == sha(raw)
    assert reference['source'] == 'SANITIZED_WORKSPACE_BEFORE_TASK'
    assert read(store, FIRST, 'routes.py', reference) == safe_source(raw.decode())
    persisted = store.path.read_bytes()
    assert b'test-private-password' not in persisted
    assert b'private-business-literal' not in persisted


def test_caller_cannot_pass_unredacted_text_as_sanitized_lines(sample):
    store, _ = sample
    raw = b"password = 'test-secret'\n"
    with store.writer(FIRST) as writer:
        with pytest.raises(TaskPreimageUnavailable) as error:
            writer.put('routes.py', raw, raw.decode().splitlines())
        assert reason(error) == 'TASK_PREIMAGE_SANITIZATION_UNVERIFIED'
        valid = put(writer, 'safe.py')
    assert read(store, FIRST, 'safe.py', valid)
    assert b'test-secret' not in store.path.read_bytes()


def test_batch_rolls_back_on_exception_and_returned_reference_is_unusable(sample):
    store, _ = sample
    with pytest.raises(RuntimeError):
        with store.writer(FIRST) as writer:
            reference = put(writer)
            raise RuntimeError('fixture failure')
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_SOURCE_UNAVAILABLE'
    # Rolled-back batches do not reserve a namespace or consume its quota.
    with store.writer(FIRST) as writer:
        valid = put(writer)
    assert read(store, FIRST, 'routes.py', valid)


def test_caught_sqlite_failure_still_invalidates_entire_writer(sample):
    store, _ = sample
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(FIRST) as writer:
            reference = put(writer)
            class BrokenConnection:
                def execute(self, *args):
                    raise sqlite3.OperationalError('fixture disk full')
            writer.db = BrokenConnection()
            with pytest.raises(sqlite3.OperationalError):
                put(writer, 'second.py')
    assert reason(error) == 'TASK_PREIMAGE_STORE_UNAVAILABLE'
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_SOURCE_UNAVAILABLE'


def test_task_is_immutable_and_closed_writer_cannot_keep_writing(sample):
    store, _ = sample
    with store.writer(FIRST) as writer:
        original = put(writer)
        assert put(writer) == original
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer, raw=b'different = auth.check(user)\n')
        assert reason(error) == 'TASK_PREIMAGE_IMMUTABLE'
    with pytest.raises(TaskPreimageUnavailable) as error:
        put(writer, 'later.py')
    assert reason(error) == 'TASK_PREIMAGE_WRITER_CLOSED'
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(FIRST):
            pass
    assert reason(error) == 'TASK_PREIMAGE_TASK_ALREADY_CAPTURED'
    assert read(store, FIRST, 'routes.py', original)


@pytest.mark.parametrize('path', ['../outside.py', '/absolute.py', 'C:/outside.py',
    'routes.py:stream', 'a/../routes.py', './routes.py', 'a//routes.py', '.',
    '.env', 'nested/.env.private', 'a\\routes.py'])
def test_paths_and_environment_are_rejected(sample, path):
    store, _ = sample
    with store.writer(FIRST) as writer:
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer, path)
        assert reason(error) == 'TASK_PREIMAGE_PATH_REJECTED'


@pytest.mark.parametrize('ref', ['ts1-'+'0'*31, 'ts1-'+'A'*32, '../foreign', None])
def test_invalid_task_namespace_never_creates_a_database(sample, ref):
    store, _ = sample
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(ref):
            pass
    assert reason(error) == 'TASK_PREIMAGE_TASK_REJECTED'
    assert not store.path.exists()


def test_cross_task_path_hash_and_workspace_references_are_rejected(sample, tmp_path):
    store, clock = sample
    with store.writer(FIRST) as writer:
        reference = put(writer)
    for task, path, expected in [(SECOND, 'routes.py', reference['raw_sha256']),
        (FIRST, 'other.py', reference['raw_sha256']), (FIRST, 'routes.py', '0'*64)]:
        with pytest.raises(TaskPreimageUnavailable) as error:
            store.read(task, path, expected, reference)
        assert reason(error) == 'TASK_PREIMAGE_REFERENCE_UNVERIFIED'
    other_root = tmp_path/'other'
    other_root.mkdir()
    store.hooks.key(other_root)
    other = TaskPreimageStore(store.hooks, other_root, now=lambda: clock[0])
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(other, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_REFERENCE_UNVERIFIED'
    assert not other.path.exists()


@pytest.mark.parametrize('field,value', [('raw_sha256', '0'*64), ('body_sha256', '0'*64),
    ('body_bytes', 1), ('line_count', 999), ('source', 'GIT_HEAD'), ('created_at', 2),
    ('expires_at', 999999), ('mac', '0'*64)])
def test_reference_tampering_never_returns_content(sample, field, value):
    store, _ = sample
    with store.writer(FIRST) as writer:
        original = put(writer)
    changed = deepcopy(original)
    changed[field] = value
    with pytest.raises(TaskPreimageUnavailable) as error:
        store.read(FIRST, 'routes.py', original['raw_sha256'], changed)
    assert reason(error) == 'TASK_PREIMAGE_REFERENCE_UNVERIFIED'


@pytest.mark.parametrize('column,value', [('body', b'["forged()"]'), ('metadata', '{}'),
    ('mac', '0'*64), ('created', 1), ('expires', 999999)])
def test_database_tampering_is_detected(sample, column, value):
    store, _ = sample
    with store.writer(FIRST) as writer:
        reference = put(writer)
    with sqlite3.connect(store.path) as db:
        db.execute(f'UPDATE task_preimages SET {column}=?', (value,))
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_CONTENT_UNVERIFIED'


def test_expired_content_cannot_be_read_and_next_writer_prunes_it(sample):
    store, clock = sample
    with store.writer(FIRST) as writer:
        reference = put(writer)
    clock[0] += preimages.TTL
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_EXPIRED'
    with store.writer(SECOND) as writer:
        current = put(writer)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT task_ref FROM task_preimages').fetchall() == [(SECOND,)]
        assert db.execute('SELECT task_ref FROM task_preimage_batches').fetchall() == [(SECOND,)]
    assert read(store, SECOND, 'routes.py', current)


def test_clock_rollback_cannot_extend_reference_lifetime(sample):
    store, clock = sample
    with store.writer(FIRST) as writer:
        reference = put(writer)
    clock[0] -= 1
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_EXPIRED'


def test_file_task_workspace_and_task_count_quotas_are_separate(sample, monkeypatch):
    store, _ = sample
    raw = b'checked = auth.check(user)\n'
    cost = len(preimages._body(safe_source(raw.decode())))
    monkeypatch.setattr(preimages, 'MAX_TASK_BYTES', cost)
    monkeypatch.setattr(preimages, 'MAX_WORKSPACE_BYTES', 2*cost)
    monkeypatch.setattr(preimages, 'MAX_TASKS', 3)
    with store.writer(FIRST) as writer:
        first = put(writer, raw=raw)
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer, 'extra.py', raw)
        assert reason(error) == 'TASK_PREIMAGE_TASK_BYTE_BUDGET'
    with store.writer(SECOND) as writer:
        second = put(writer, raw=raw)
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(THIRD) as writer:
            put(writer, raw=raw)
    assert reason(error) == 'TASK_PREIMAGE_WORKSPACE_BYTE_BUDGET'
    monkeypatch.setattr(preimages, 'MAX_TASKS', 2)
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(THIRD):
            pass
    assert reason(error) == 'TASK_PREIMAGE_TASK_COUNT_BUDGET'
    assert read(store, FIRST, 'routes.py', first)
    assert read(store, SECOND, 'routes.py', second)


def test_per_file_and_file_count_budgets_are_enforced_before_insert(sample, monkeypatch):
    store, _ = sample
    with store.writer(FIRST) as writer:
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer, raw=b'x'*(preimages.MAX_FILE_BYTES+1))
        assert reason(error) == 'TASK_PREIMAGE_FILE_BUDGET'
        monkeypatch.setattr(preimages, 'MAX_FILE_BODY_BYTES', 10)
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer)
        assert reason(error) == 'TASK_PREIMAGE_FILE_BUDGET'
        monkeypatch.setattr(preimages, 'MAX_FILE_BODY_BYTES', 2_000_000)
        monkeypatch.setattr(preimages, 'MAX_TASK_FILES', 1)
        put(writer)
        with pytest.raises(TaskPreimageUnavailable) as error:
            put(writer, 'second.py')
        assert reason(error) == 'TASK_PREIMAGE_FILE_COUNT_BUDGET'


def test_discard_only_removes_requested_task_and_reads_never_recreate_it(sample):
    store, _ = sample
    with store.writer(FIRST) as writer:
        first = put(writer)
    with store.writer(SECOND) as writer:
        second = put(writer)
    store.discard(FIRST)
    store.discard(FIRST)
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', first)
    assert reason(error) == 'TASK_PREIMAGE_SOURCE_UNAVAILABLE'
    assert read(store, SECOND, 'routes.py', second)


def test_empty_preimage_has_zero_lines_and_missing_database_is_not_recreated(sample):
    store, _ = sample
    with store.writer(FIRST) as writer:
        reference = put(writer, raw=b'')
    assert reference['line_count'] == 0
    assert read(store, FIRST, 'routes.py', reference) == []
    store.path.unlink()
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_SOURCE_UNAVAILABLE'
    assert not store.path.exists()


def test_missing_key_is_not_silently_replaced(sample):
    store, _ = sample
    key_path = store.path.parent/'snapshot.key'
    key_path.unlink()
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(FIRST):
            pass
    assert reason(error) == 'TASK_PREIMAGE_KEY_UNAVAILABLE'
    assert not key_path.exists() and not store.path.exists()


@pytest.mark.parametrize('suffix', ['', '-journal', '-wal', '-shm'])
def test_linked_database_or_sidecar_is_rejected(sample, tmp_path, suffix):
    store, _ = sample
    target = tmp_path/'foreign-state'
    target.write_bytes(b'foreign untouched')
    link = store.path if not suffix else store.path.with_name(store.path.name+suffix)
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('This platform does not allow creating test symlinks')
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(FIRST):
            pass
    assert reason(error) == 'TASK_PREIMAGE_STATE_PATH_REJECTED'
    assert target.read_bytes() == b'foreign untouched'


def test_hardlinked_database_is_rejected(sample, tmp_path):
    store, _ = sample
    target = tmp_path/'foreign-state'
    target.write_bytes(b'foreign untouched')
    try:
        os.link(target, store.path)
    except OSError:
        pytest.skip('This platform does not allow creating test hardlinks')
    with pytest.raises(TaskPreimageUnavailable) as error:
        with store.writer(FIRST):
            pass
    assert reason(error) == 'TASK_PREIMAGE_STATE_PATH_REJECTED'
    assert target.read_bytes() == b'foreign untouched'


def test_concurrent_writer_failure_does_not_commit_partial_second_batch(sample, monkeypatch):
    store, _ = sample
    # No sleeps/threads: a zero-timeout connection deterministically exercises
    # SQLite's independent writer lock while the first writer is active.
    original_connect = sqlite3.connect
    def impatient_connect(*args, **kwargs):
        kwargs['timeout'] = 0
        return original_connect(*args, **kwargs)
    monkeypatch.setattr(preimages.sqlite3, 'connect', impatient_connect)
    with store.writer(FIRST) as first_writer:
        first = put(first_writer)
        with pytest.raises(TaskPreimageUnavailable) as error:
            with store.writer(SECOND) as second_writer:
                put(second_writer)
        assert reason(error) == 'TASK_PREIMAGE_STORE_UNAVAILABLE'
    assert read(store, FIRST, 'routes.py', first)
    with store.writer(SECOND) as writer:
        second = put(writer)
    assert read(store, SECOND, 'routes.py', second)


def test_bodies_larger_than_the_allowed_read_bound_fail_closed(sample, monkeypatch):
    store, _ = sample
    with store.writer(FIRST) as writer:
        reference = put(writer)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE task_preimages SET body=?', (b'x'*10000,))
    monkeypatch.setattr(preimages, 'MAX_FILE_BODY_BYTES', 1000)
    with pytest.raises(TaskPreimageUnavailable) as error:
        read(store, FIRST, 'routes.py', reference)
    assert reason(error) == 'TASK_PREIMAGE_CONTENT_UNVERIFIED'
