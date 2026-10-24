"""Reference GC retains live/legacy captures and validates before deleting."""
from dataclasses import replace
import gc
import json
import sqlite3
import tracemalloc

import pytest

from security_runtime.snapshot_store import (
    SnapshotBinding, SnapshotStore, SnapshotStoreError, TASK_PAGES_GC_DOMAIN,
    _gc_canonical_path, _relative,
)


KEY = b'k' * 32
OWNER = dict(host='codex', session='a' * 64)


@pytest.fixture
def store(tmp_path):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    return SnapshotStore(tmp_path.resolve() / 'private', workspace_root=root, key=KEY)


def binding(index, domain=TASK_PAGES_GC_DOMAIN):
    return SnapshotBinding(f'task-{index}', OWNER, f'source-{index}', 3,
                           retention_domain=domain)


def sealed(store, index, *, raw=b'original', domain=TASK_PAGES_GC_DOMAIN):
    original = binding(index, domain)
    ref = store.create(original)['ref']
    store.append_page(ref, original, [('source.py', raw)], expected_cursor=None, cursor='one')
    store.seal(ref, original, expected_files=1, inventory_complete=True)
    return ref, original


def database_state(store):
    with sqlite3.connect(store.path) as db:
        return {table: db.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()
                for table in ('captures', 'entries', 'objects', 'usage')}


def test_retention_opt_in_does_not_change_legacy_binding(store):
    old = binding('old', None)
    original = store._binding(old)
    assert 'retention_domain' not in original
    assert store._binding(replace(old, retention_domain=None)) == original
    old_ref, old = sealed(store, 'old', domain=None)
    other_ref, other = sealed(store, 'other', domain='OTHER_MANAGED_DOMAIN')
    new_ref, new = sealed(store, 'new')
    result = store.collect_unreferenced(set())
    assert result['collected_captures'] == 1
    assert store.read_content(old_ref, old, 'source.py') == b'original'
    assert store.read_content(other_ref, other, 'source.py') == b'original'
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        store.resume(new_ref, new)


def test_shared_object_survives_until_last_reference_is_collected(store):
    shared = b'shared immutable body'
    first, first_binding = sealed(store, 1, raw=shared)
    second, second_binding = sealed(store, 2, raw=shared)
    before_size = store.path.stat().st_size
    first_result = store.collect_unreferenced({second})
    assert first_result['collected_captures'] == 1
    assert first_result['released_logical_bytes'] > 65536
    assert store.read_content(second, second_binding, 'source.py') == shared
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM objects').fetchone()[0] == 1
    last_result = store.collect_unreferenced([])
    assert last_result['collected_captures'] == 1
    assert last_result['logical_bytes_after'] == 0
    assert last_result['released_logical_bytes'] == first_result['logical_bytes_after']
    assert not last_result['physical_compaction_performed']
    assert store.path.stat().st_size == before_size
    assert database_state(store)['objects'] == []
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        store.resume(first, first_binding)


def test_unfinished_and_waiting_captures_are_never_collected(store):
    constrained = SnapshotStore(store.directory, workspace_root=store.root, key=KEY,
                                max_storage_bytes=250_000)
    active_binding, waiting_binding = binding('active'), binding('waiting')
    active = constrained.create(active_binding)['ref']
    constrained.append_page(active, active_binding, [('source.py', b'active')],
                            expected_cursor=None, cursor='one')
    waiting = constrained.create(waiting_binding)['ref']
    result = constrained.append_page(waiting, waiting_binding, [('source.py', b'x' * 200_000)],
                                     expected_cursor=None, cursor='one')
    assert result['state'] == 'WAITING_CAPACITY'
    old, old_binding = sealed(constrained, 'finished')
    result = constrained.collect_unreferenced(set())
    assert result['collected_captures'] == 1 and not result['has_more']
    assert constrained.resume(active, active_binding)['state'] == 'CAPTURING'
    assert constrained.read_content(active, active_binding, 'source.py') == b'active'
    assert constrained.resume(waiting, waiting_binding)['state'] == 'WAITING_CAPACITY'
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        constrained.resume(old, old_binding)


def test_capture_budget_leaves_a_finite_followup_batch(store):
    refs = [sealed(store, index)[0] for index in range(3)]
    results = [store.collect_unreferenced(set(), max_captures=1) for _ in refs]
    assert [value['collected_captures'] for value in results] == [1, 1, 1]
    assert [value['remaining_candidates'] for value in results] == [2, 1, 0]
    assert [value['has_more'] for value in results] == [True, True, False]
    assert results[-1]['logical_bytes_after'] == 0
    assert store.collect_unreferenced(set())['released_logical_bytes'] == 0


@pytest.mark.parametrize('damage', ['header_mac', 'entry_mac', 'usage_mac', 'entry_missing',
                                   'entry_column', 'header_column', 'body'])
def test_corruption_anywhere_rolls_back_entire_collection(store, damage):
    candidate, _ = sealed(store, 'candidate', raw=b'candidate body')
    protected, _ = sealed(store, 'protected', raw=b'protected body')
    with sqlite3.connect(store.path) as db:
        if damage == 'header_mac':
            db.execute('UPDATE captures SET mac=? WHERE ref=?', ('0' * 64, protected))
        elif damage == 'entry_mac':
            db.execute('UPDATE entries SET mac=? WHERE ref=?', ('0' * 64, protected))
        elif damage == 'usage_mac':
            db.execute('UPDATE usage SET mac=?', ('0' * 64,))
        elif damage == 'entry_missing':
            db.execute('DELETE FROM entries WHERE ref=?', (protected,))
        elif damage == 'entry_column':
            db.execute('UPDATE entries SET path=? WHERE ref=?', ('renamed.py', protected))
        elif damage == 'header_column':
            db.execute('UPDATE captures SET task=? WHERE ref=?', ('renamed-task', protected))
        else:
            db.execute('UPDATE objects SET body=? WHERE body=?', (b'corrupt body', b'protected body'))
    before = database_state(store)
    with pytest.raises(SnapshotStoreError):
        store.collect_unreferenced({protected})
    assert database_state(store) == before
    assert any(row[0] == candidate for row in before['captures'])


def test_missing_protected_reference_is_not_treated_as_unreferenced(store):
    sealed(store, 'candidate')
    before = database_state(store)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        store.collect_unreferenced({'ws2-' + 'f' * 32})
    assert database_state(store) == before


def test_failure_after_deletes_rolls_back_capture_objects_and_quota(store, monkeypatch):
    ref, owner = sealed(store, 'candidate')
    before = database_state(store)

    def fail_quota_update(db, used):
        assert db.execute('SELECT count(*) FROM captures').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM objects').fetchone()[0] == 0
        raise sqlite3.OperationalError('Fixture quota commit failure')

    monkeypatch.setattr(store, '_set_usage', fail_quota_update)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_STORAGE_UNAVAILABLE$'):
        store.collect_unreferenced(set())
    assert database_state(store) == before
    assert store.read_content(ref, owner, 'source.py') == b'original'


def test_authentic_but_replayed_usage_does_not_hide_retained_bytes(store):
    sealed(store, 'first')
    with sqlite3.connect(store.path) as db:
        previous = db.execute('SELECT bytes,mac FROM usage').fetchone()
    sealed(store, 'second', raw=b'another original')
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE usage SET bytes=?,mac=?', previous)
    before = database_state(store)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_USAGE_MISMATCH$'):
        store.collect_unreferenced(set())
    assert database_state(store) == before


def test_absent_store_is_never_created_by_collection(store):
    result = store.collect_unreferenced(set())
    assert result['collected_captures'] == result['released_logical_bytes'] == 0
    assert result['logical_bytes_before'] == result['logical_bytes_after'] == 0
    assert not store.directory.exists()
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        store.collect_unreferenced({'ws2-' + 'f' * 32})
    assert not store.directory.exists()


def test_collection_frees_capacity_for_same_waiting_capture(store):
    constrained = SnapshotStore(store.directory, workspace_root=store.root, key=KEY,
                                max_storage_bytes=160_000)
    sealed(constrained, 'retired', raw=b'x' * 10_000)
    waiting_binding = binding('waiting')
    waiting = constrained.create(waiting_binding)['ref']
    entries = [('next.py', b'y' * 25_000)]
    before = constrained.append_page(waiting, waiting_binding, entries,
                                     expected_cursor=None, cursor='one')
    assert before['state'] == 'WAITING_CAPACITY' and before['entry_count'] == 0
    collected = constrained.collect_unreferenced({waiting})
    assert collected['collected_captures'] == 1 and collected['released_logical_bytes'] > 65_536
    after = constrained.append_page(waiting, waiting_binding, entries,
                                    expected_cursor=None, cursor='one')
    assert after['ref'] == waiting and after['entry_count'] == 1
    assert constrained.seal(waiting, waiting_binding, expected_files=1,
                             inventory_complete=True)['state'] == 'SEALED'
    assert constrained.read_content(waiting, waiting_binding, 'next.py') == entries[0][1]


@pytest.mark.parametrize('raw', [b'', b'body'])
def test_empty_source_and_empty_capture_follow_exact_usage_accounting(store, raw):
    sealed(store, 'with-body', raw=raw)
    empty_binding = binding('empty')
    empty = store.create(empty_binding)['ref']
    store.seal(empty, empty_binding, expected_files=0, inventory_complete=True)
    result = store.collect_unreferenced(set())
    assert result['collected_captures'] == 2
    assert result['logical_bytes_after'] == 0


@pytest.mark.parametrize('kwargs', [dict(max_captures=0), dict(max_captures=True),
                                   dict(max_captures=257), dict(retention_domain='')])
def test_invalid_gc_budget_or_domain_creates_nothing(store, kwargs):
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_GC_REQUEST_INVALID$'):
        store.collect_unreferenced(set(), **kwargs)
    assert not store.directory.exists()


def test_temporary_indices_use_file_storage_and_bounded_cache(store, monkeypatch):
    sealed(store, 'candidate')
    original_connect, observed = sqlite3.connect, []

    class InspectConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('CREATE TEMP TABLE'):
                observed.append((super().execute('PRAGMA temp_store').fetchone()[0],
                                 super().execute('PRAGMA temp.cache_size').fetchone()[0],
                                 super().execute('PRAGMA temp.max_page_count').fetchone()[0],
                                 super().execute('PRAGMA temp.page_size').fetchone()[0]))
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, 'connect',
                        lambda *args, **kwargs: original_connect(*args, factory=InspectConnection, **kwargs))
    assert store.collect_unreferenced(set())['logical_bytes_after'] == 0
    assert len(observed) == 4
    assert all(mode == 1 and cache == -2048 and pages * size <= store.database_quota
               for mode, cache, pages, size in observed)
    with original_connect(store.path) as db:
        assert {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} == {
            'captures', 'entries', 'objects', 'usage'}


def test_actual_temporary_capacity_exhaustion_preserves_persistent_store(store, monkeypatch):
    ref, owner = sealed(store, 'candidate')
    before, original_connect = database_state(store), sqlite3.connect

    class TinyTempConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('PRAGMA temp.max_page_count='):
                # The real SQLite TEMP database fills while creating indices.
                sql = 'PRAGMA temp.max_page_count=2'
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, 'connect',
                        lambda *args, **kwargs: original_connect(*args, factory=TinyTempConnection, **kwargs))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_WAITING_CAPACITY$'):
        store.collect_unreferenced(set())
    assert database_state(store) == before
    assert store.read_content(ref, owner, 'source.py') == b'original'


@pytest.mark.parametrize('statement', ['INSERT INTO temp.gc_objects', 'INSERT INTO temp.gc_delete_objects'])
def test_temporary_index_write_failure_precedes_persistent_deletes(store, monkeypatch, statement):
    sealed(store, 'candidate')
    before, original_connect, failed, deleted = database_state(store), sqlite3.connect, [], []

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('DELETE FROM '):
                deleted.append(sql)
            if sql.startswith(statement):
                failed.append(sql)
                raise sqlite3.OperationalError('Fixture TEMP write failure')
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, 'connect',
                        lambda *args, **kwargs: original_connect(*args, factory=FailingConnection, **kwargs))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_STORAGE_UNAVAILABLE$'):
        store.collect_unreferenced(set())
    assert failed and not deleted
    assert database_state(store) == before


@pytest.mark.parametrize('field', ['entry_count', 'source_bytes'])
def test_authentic_large_expected_integer_is_rejected_without_overflow(store, field):
    ref, _ = sealed(store, 'candidate')
    with sqlite3.connect(store.path) as db:
        data = db.execute('SELECT data FROM captures WHERE ref=?', (ref,)).fetchone()[0]
        header = json.loads(data)
        header.update(state='CAPTURING', **{field: 2 ** 100})
        raw = json.dumps(header, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        db.execute('UPDATE captures SET data=?,mac=? WHERE ref=?', (raw, store._mac(header), ref))
    before = database_state(store)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        store.collect_unreferenced(set())
    assert database_state(store) == before


def test_duplicate_authenticated_path_is_rejected_even_without_unique_index(store, monkeypatch):
    owner = binding('duplicate-path')
    ref = store.create(owner)['ref']
    store.append_page(ref, owner, [('first.py', b'one'), ('other.py', b'two')],
                      expected_cursor=None, cursor='one')
    store.seal(ref, owner, expected_files=2, inventory_complete=True)
    with sqlite3.connect(store.path) as db:
        db.execute('ALTER TABLE entries RENAME TO previous_entries')
        db.execute('CREATE TABLE entries (ref TEXT, seq INTEGER, path TEXT, data BLOB, mac TEXT, '
                   'PRIMARY KEY(ref,seq))')
        db.execute('INSERT INTO entries SELECT * FROM previous_entries')
        db.execute('DROP TABLE previous_entries')
        item = json.loads(db.execute('SELECT data FROM entries WHERE ref=? AND seq=2', (ref,)).fetchone()[0])
        item['path'] = 'first.py'
        raw = json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        db.execute('UPDATE entries SET path=?,data=?,mac=? WHERE ref=? AND seq=2',
                   (item['path'], raw, store._mac(item), ref))
    before, original_connect, deleted = database_state(store), sqlite3.connect, []

    class ObserveConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('DELETE FROM '):
                deleted.append(sql)
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, 'connect',
                        lambda *args, **kwargs: original_connect(*args, factory=ObserveConnection, **kwargs))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_RECORD_INVALID$'):
        store.collect_unreferenced(set())
    assert not deleted
    assert database_state(store) == before


def test_missing_referenced_object_stops_collection_before_any_delete(store, monkeypatch):
    sealed(store, 'candidate', raw=b'candidate')
    protected, _ = sealed(store, 'protected', raw=b'protected')
    with sqlite3.connect(store.path) as db:
        db.execute('DELETE FROM objects WHERE body=?', (b'protected',))
    before, original_connect, deleted = database_state(store), sqlite3.connect, []

    class ObserveConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('DELETE FROM '):
                deleted.append(sql)
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, 'connect',
                        lambda *args, **kwargs: original_connect(*args, factory=ObserveConnection, **kwargs))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        store.collect_unreferenced({protected})
    assert not deleted
    assert database_state(store) == before


def test_conflicting_authenticated_sizes_for_shared_hash_are_rejected(store):
    candidate, _ = sealed(store, 'candidate', raw=b'shared')
    protected, _ = sealed(store, 'protected', raw=b'shared')
    with sqlite3.connect(store.path) as db:
        entry = json.loads(db.execute('SELECT data FROM entries WHERE ref=?', (protected,)).fetchone()[0])
        header = json.loads(db.execute('SELECT data FROM captures WHERE ref=?', (protected,)).fetchone()[0])
        entry['size'] += 1
        header['source_bytes'] += 1
        for table, value in (('entries', entry), ('captures', header)):
            raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
            db.execute(f'UPDATE {table} SET data=?,mac=? WHERE ref=?', (raw, store._mac(value), protected))
    before = database_state(store)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        store.collect_unreferenced({protected})
    assert database_state(store) == before
    assert any(row[0] == candidate for row in before['captures'])


@pytest.mark.parametrize('path', [
    '', '.', '..', '/', '/source.py', '//server/share/source.py',
    './source.py', 'dir/../source.py', 'dir//source.py', 'dir/source.py/',
    'dir/./source.py', 'C:/source.py', 'C:source.py', 'dir/stream:data',
    'dir\\source.py', 'dir/source.py ', 'dir/source.py.', 'dir/\0source.py',
    '[outside workspace]', '[outside workspace]/source.py', '文件/源码.py',
    'dir/a b.py', 'dir/line\nbreak.py', 'source.py', 'dir/.hidden', 'dir/.../file.py',
])
def test_gc_path_validation_preserves_existing_canonical_path_contract(path):
    try:
        original = path not in {'', '.'} and _relative(path) == path
    except ValueError:
        original = False
    assert _gc_canonical_path(path) == original


def test_gc_python_peak_does_not_track_full_entry_or_object_inventory(store):
    peaks = []
    for count in (2_000, 20_000):
        owner = binding(f'peak-{count}')
        ref, cursor = store.create(owner)['ref'], None
        for first in range(0, count, 256):
            entries = [(f'files/{index:08d}.py', f'unique body {index}'.encode())
                       for index in range(first, min(first + 256, count))]
            next_cursor = str(first)
            store.append_page(ref, owner, entries, expected_cursor=cursor, cursor=next_cursor)
            cursor = next_cursor
        store.seal(ref, owner, expected_files=count, inventory_complete=True)
        del entries
        gc.collect()
        # Fixture construction and full-state assertions are outside the
        # measurement. This measures Python allocations, not SQLite cache/RSS.
        tracemalloc.start()
        try:
            result = store.collect_unreferenced(set(), max_captures=1)
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
        assert result['collected_captures'] == 1
        assert result['logical_bytes_after'] == 0
    print(f'GC Python peaks for 2000/20000 unique entries: {peaks[0]}/{peaks[1]} bytes')
    assert peaks[1] <= max(1_000_000, peaks[0] * 3)


def test_large_object_is_hashed_in_bounded_chunks_and_tail_damage_is_rejected(store):
    sealed(store, 'candidate')
    protected, _ = sealed(store, 'large-protected', raw=b'large body ' * 300_000)
    gc.collect()
    tracemalloc.start()
    try:
        result = store.collect_unreferenced({protected})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert result['collected_captures'] == 1
    assert peak < 1_000_000
    sealed(store, 'second-candidate')
    with sqlite3.connect(store.path) as db:
        digest, raw = db.execute('SELECT hash,body FROM objects WHERE length(body)>3000000').fetchone()
        db.execute('UPDATE objects SET body=? WHERE hash=?', (raw[:-1] + b'!', digest))
    before = database_state(store)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        store.collect_unreferenced({protected})
    assert database_state(store) == before
