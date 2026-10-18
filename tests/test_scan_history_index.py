import json
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime import scan_history_index as history
from security_runtime.models import ScanResult, TargetProfile
from security_runtime.storage import ReadOnlySQLiteStore, SQLiteStore


def record(scan_id, workspace):
    return dict(scan_id=scan_id, target_profile=dict(path=str(workspace)), findings=[])


def legacy_write(path, value):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('INSERT OR REPLACE INTO scans VALUES (?,?)',
                   (value['scan_id'], json.dumps(value)))


def legacy_latest(path, workspace):
    with closing(sqlite3.connect(path)) as db:
        for row in db.execute('SELECT data FROM scans ORDER BY rowid DESC'):
            value = json.loads(row[0])
            if Path(value['target_profile']['path']).resolve() == Path(workspace).resolve():
                return value
    return None


def legacy_database(path, values=()):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        db.executemany('INSERT INTO scans VALUES (?,?)',
                       [(value['scan_id'], json.dumps(value)) for value in values])


def test_two_column_writer_stays_compatible_and_readonly_merges_old_writes(tmp_path):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'project'
    store = SQLiteStore(path)
    store.save(ScanResult('initial', 'quick', TargetProfile(str(workspace)),
                          'COMPLETED', [], [], 'done', 'SAFE', 0))
    with closing(sqlite3.connect(path)) as db:
        assert [row[1] for row in db.execute('PRAGMA table_info(scans)')] == ['id', 'data']
        assert not db.execute('SELECT 1 FROM scan_history_dirty').fetchone()
    legacy_write(path, record('new-by-old-runtime', workspace))
    before = path.read_bytes()
    readonly = ReadOnlySQLiteStore(path)
    assert readonly.latest_scan(workspace)['scan_id'] == 'new-by-old-runtime'
    assert path.read_bytes() == before
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM scan_history_dirty').fetchone()[0] == 1


def test_replace_moves_existing_id_and_workspace_without_leaving_a_stale_hit(tmp_path):
    path = tmp_path / 'history.db'
    first, second = tmp_path / 'first', tmp_path / 'second'
    legacy_database(path, [record('old', first), record('replace-me', first)])
    SQLiteStore(path)
    legacy_write(path, record('replace-me', second))
    readonly = ReadOnlySQLiteStore(path)
    assert readonly.latest_scan(first)['scan_id'] == 'old'
    assert readonly.latest_scan(second)['scan_id'] == 'replace-me'
    assert readonly.latest_scan(first) == legacy_latest(path, first)
    store = SQLiteStore(path)
    assert store.latest_scan(second) == legacy_latest(path, second)


def test_old_update_delete_and_rowid_reuse_are_visible_without_maintenance(tmp_path):
    path = tmp_path / 'history.db'
    first, second = tmp_path / 'first', tmp_path / 'second'
    legacy_database(path, [record('old', first), record('latest', first)])
    SQLiteStore(path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('UPDATE scans SET id=?,data=? WHERE id=?',
                   ('renamed', json.dumps(record('renamed', second)), 'latest'))
    readonly = ReadOnlySQLiteStore(path)
    assert readonly.latest_scan(first)['scan_id'] == 'old'
    assert readonly.latest_scan(second)['scan_id'] == 'renamed'
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('DELETE FROM scans WHERE id=?', ('renamed',))
        db.execute('INSERT INTO scans(rowid,id,data) VALUES (?,?,?)',
                   (2, 'reused', json.dumps(record('reused', first))))
    assert readonly.latest_scan(second) is None
    assert readonly.latest_scan(first)['scan_id'] == 'reused'
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('DELETE FROM scans')
    assert readonly.latest_scan(first) is None


def test_batched_migration_resumes_and_legacy_changes_during_it_are_not_lost(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    first, second = tmp_path / 'first', tmp_path / 'second'
    legacy_database(path, [record(f'scan-{i}', first if i % 2 else second) for i in range(12)])
    monkeypatch.setattr(history, 'BACKFILL_LIMIT', 2)
    SQLiteStore(path)
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM scan_history_index').fetchone()[0] == 2
        assert db.execute("SELECT value FROM scan_history_meta WHERE name='seed_complete'").fetchone()[0] == '0'
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(first) == legacy_latest(path, first)
    assert path.read_bytes() == before
    third = tmp_path / 'third'
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(record('scan-0', third)), 'scan-0'))
    legacy_write(path, record('scan-10', first))
    legacy_write(path, record('arrived-later', second))
    for _ in range(8):
        SQLiteStore(path)
    with closing(sqlite3.connect(path)) as db:
        assert not db.execute('SELECT 1 FROM scan_history_dirty').fetchone()
    readonly = ReadOnlySQLiteStore(path)
    assert readonly.latest_scan(first) == legacy_latest(path, first)
    assert readonly.latest_scan(second) == legacy_latest(path, second)
    assert readonly.latest_scan(third)['scan_id'] == 'scan-0'


def test_dirty_overflow_falls_back_without_truncating_older_matching_history(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    wanted, other = tmp_path / 'wanted', tmp_path / 'other'
    store = SQLiteStore(path)
    legacy_write(path, record('wanted-old', wanted))
    for i in range(5):
        legacy_write(path, record(f'other-{i}', other))
    monkeypatch.setattr(history, 'DIRTY_READ_LIMIT', 2)
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(wanted)['scan_id'] == 'wanted-old'
    assert path.read_bytes() == before
    assert store.latest_scan(wanted)['scan_id'] == 'wanted-old'


def test_byte_overflow_uses_compatibility_query_and_leaves_large_row_pending(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'workspace'
    store = SQLiteStore(path)
    value = record('large', workspace)
    value['details'] = 'x' * 1000
    legacy_write(path, value)
    monkeypatch.setattr(history, 'INPUT_BYTES', 100)
    assert store.latest_scan(workspace) == value
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM scan_history_dirty').fetchone()[0] == 1
    assert ReadOnlySQLiteStore(path).latest_scan(workspace) == value


@pytest.mark.parametrize('bad', ['not-json', '{}', '{"target_profile":{"path":123}}'])
def test_invalid_legacy_record_preserves_query_errors_and_does_not_break_migration(tmp_path, bad):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'workspace'
    legacy_database(path, [record('valid', workspace)])
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('INSERT INTO scans VALUES (?,?)', ('invalid', bad))
    store = SQLiteStore(path)
    with pytest.raises(Exception) as expected:
        legacy_latest(path, workspace)
    before = path.read_bytes()
    with pytest.raises(type(expected.value)):
        ReadOnlySQLiteStore(path).latest_scan(workspace)
    assert path.read_bytes() == before
    with pytest.raises(type(expected.value)):
        store.latest_scan(workspace)
    legacy_write(path, record('newer-valid', workspace))
    assert ReadOnlySQLiteStore(path).latest_scan(workspace)['scan_id'] == 'newer-valid'


def test_old_or_incompatible_cache_is_read_without_migration(tmp_path):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'workspace'
    legacy_database(path, [record('legacy', workspace)])
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(workspace)['scan_id'] == 'legacy'
    assert path.read_bytes() == before
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE scan_history_index (future TEXT)')
    store = SQLiteStore(path)
    legacy_write(path, record('still-writable', workspace))
    assert store.latest_scan(workspace)['scan_id'] == 'still-writable'
    with closing(sqlite3.connect(path)) as db:
        assert [row[1] for row in db.execute('PRAGMA table_info(scan_history_index)')] == ['future']


def test_unknown_contract_keeps_cache_untouched_and_uses_legacy_query(tmp_path):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'workspace'
    store = SQLiteStore(path)
    legacy_write(path, record('known', workspace))
    store.latest_scan(workspace)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE scan_history_meta SET value='future-contract'")
    SQLiteStore(path)
    legacy_write(path, record('future-write', workspace))
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(workspace)['scan_id'] == 'future-write'
    assert path.read_bytes() == before


def test_missing_tracking_trigger_uses_compatibility_then_reseeds_old_updates(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    first, second = tmp_path / 'first', tmp_path / 'second'
    legacy_database(path, [record(f'scan-{i}', first) for i in range(8)])
    SQLiteStore(path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('DROP TRIGGER scan_history_update')
        db.execute('UPDATE scans SET data=? WHERE id=?', (json.dumps(record('scan-0', second)), 'scan-0'))
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(second)['scan_id'] == 'scan-0'
    assert path.read_bytes() == before
    monkeypatch.setattr(history, 'BACKFILL_LIMIT', 2)
    store = SQLiteStore(path)
    assert ReadOnlySQLiteStore(path).latest_scan(second)['scan_id'] == 'scan-0'
    for _ in range(4):
        store.latest_scan(first)
    assert store.latest_scan(second)['scan_id'] == 'scan-0'


def test_query_time_relative_workspace_resolution_matches_legacy_semantics(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    legacy_database(path, [record('relative', 'workspace')])
    SQLiteStore(path)
    monkeypatch.chdir(second)
    assert ReadOnlySQLiteStore(path).latest_scan(second / 'workspace') == legacy_latest(path, second / 'workspace')


def test_clean_index_avoids_decoding_unrelated_history(tmp_path):
    path = tmp_path / 'history.db'
    wanted, other = tmp_path / 'wanted', tmp_path / 'other'
    legacy_database(path, [record('wanted-oldest', wanted)] + [record(f'other-{i}', other) for i in range(600)])
    for _ in range(5):
        SQLiteStore(path)
    original = json.loads
    with patch.object(history.json, 'loads', wraps=original) as loads:
        assert ReadOnlySQLiteStore(path).latest_scan(wanted)['scan_id'] == 'wanted-oldest'
    assert loads.call_count == 1


def test_pending_merge_and_index_candidate_share_one_read_snapshot(tmp_path):
    path = tmp_path / 'history.db'
    workspace = tmp_path / 'workspace'
    SQLiteStore(path)
    legacy_write(path, record('before', workspace))
    SQLiteStore(path)
    with closing(sqlite3.connect(path)) as setup:
        assert setup.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
    with closing(sqlite3.connect(path)) as reader:
        reader.execute('PRAGMA query_only=ON')
        injected = []

        def write_after_dirty_read(sql):
            if sql.startswith('SELECT DISTINCT workspace_path') and not injected:
                injected.append(True)
                legacy_write(path, record('during-read', workspace))

        reader.set_trace_callback(write_after_dirty_read)
        assert history.latest(reader, workspace)['scan_id'] == 'before'
        assert injected
    assert ReadOnlySQLiteStore(path).latest_scan(workspace)['scan_id'] == 'during-read'


def test_workspace_cap_falls_back_and_global_latest_keeps_original_order(tmp_path, monkeypatch):
    path = tmp_path / 'history.db'
    legacy_database(path, [record(f'scan-{i}', tmp_path / f'workspace-{i}') for i in range(5)])
    store = SQLiteStore(path)
    monkeypatch.setattr(history, 'WORKSPACE_LIMIT', 2)
    assert ReadOnlySQLiteStore(path).latest_scan(tmp_path / 'workspace-0')['scan_id'] == 'scan-0'
    assert store.latest_scan()['scan_id'] == 'scan-4'


def test_missing_state_and_empty_legacy_database_stay_read_only(tmp_path):
    missing = tmp_path / 'missing' / 'history.db'
    assert ReadOnlySQLiteStore(missing).latest_scan(tmp_path) is None
    assert not missing.parent.exists()
    path = tmp_path / 'empty.db'
    with closing(sqlite3.connect(path)):
        pass
    before = path.read_bytes()
    assert ReadOnlySQLiteStore(path).latest_scan(tmp_path) is None
    assert path.read_bytes() == before
