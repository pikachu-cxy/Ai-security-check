"""Recovery never grants authority, replays events, or overwrites bad history."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3

import pytest

from security_runtime.cli import main
from security_runtime.recent_hooks import Observation, RecentHookStore
from security_runtime.hook_diagnostic_recovery import MAX_GENERATIONS


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path))
    return RecentHookStore()


def broken(store):
    raw = b'private corrupt diagnostic bytes\0' * 100
    store.path.write_bytes(raw)
    return raw


def observation(store):
    return Observation('handle_hook_event', {}, store=store)


def test_readonly_query_never_repairs_corruption(store, capsys):
    raw = broken(store)
    before = {p.name: p.read_bytes() for p in store.path.parent.iterdir()}
    assert main(['hooks', 'recent', '--unbound', '--json']) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'UNAVAILABLE'
    assert {p.name: p.read_bytes() for p in store.path.parent.iterdir()} == before
    assert store.path.read_bytes() == raw


def test_explicit_repair_retains_original_and_backup_without_fake_events(store, capsys):
    original = store.path
    raw = broken(store)
    assert main(['hooks', 'repair-diagnostics', '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'RECOVERED' and result['generation'] == 1
    assert result['scanner_run'] is False and result['source_modified'] is False
    assert result['authoritative_state_changed'] is False
    assert original.read_bytes() == raw
    assert Path(result['backup_path']).read_bytes() == raw
    current = RecentHookStore()
    assert current.path != original
    recent = current.recent(unbound=True)
    assert recent['records'] == [] and recent['history_recovery']['previous_history'] == 'UNAVAILABLE'
    assert current.repair()['status'] == 'NOT_NEEDED'


def test_real_observation_recovers_and_late_old_process_cannot_replace_new_history(store):
    original = store.path
    raw = broken(store)
    current = observation(store)
    assert current.available and current.persisted
    current.finish(dict(status='READY', scanner_run=False))
    assert original.read_bytes() == raw
    assert len(store.recent(unbound=True)['records']) == 1
    # A legacy process only knows the old filename, not the generation pointer.
    original.write_bytes(b'late legacy writer')
    assert store.recent(unbound=True)['records'][0]['completed']
    backups = list(original.parent.glob('hook-diagnostics.db.corrupt-*.db'))
    assert len(backups) == 1 and backups[0].read_bytes() == raw


def test_malformed_btree_with_valid_sqlite_header_is_recovered(store):
    assert observation(store).available
    original = store.path
    raw = bytearray(original.read_bytes())
    raw[100] = 0  # Invalid page-one B-tree type; retain the valid SQLite header.
    original.write_bytes(raw)
    current = observation(store)
    assert current.available and current.persisted
    assert original.read_bytes() == raw
    assert store.history.facts()['generation'] == 1
    assert len(store.recent(unbound=True)['records']) == 1


def test_healthy_and_empty_stores_are_not_rotated(store):
    assert store.repair()['status'] == 'NOT_INSTALLED'
    store.path.touch()
    assert store.repair()['status'] == 'NOT_NEEDED'
    current = observation(store)
    assert current.available
    before = store.path.read_bytes()
    assert store.repair()['status'] == 'NOT_NEEDED'
    assert store.path.read_bytes() == before
    assert not store.history.marker.exists()


@pytest.mark.parametrize('code', [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR])
def test_noncorruption_errors_do_not_rotate_or_backup(store, monkeypatch, code):
    def fail(*args, **kwargs):
        error = sqlite3.OperationalError('private-error')
        error.sqlite_errorcode = code
        raise error
    monkeypatch.setattr(store, '_write', fail)
    current = observation(store)
    assert not current.available
    assert not store.history.marker.exists()
    assert not list(store.history.base.parent.glob('*.corrupt-*.db'))


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
def test_sidecars_block_recovery_without_deleting_any_bytes(store, suffix):
    raw = broken(store)
    sidecar = Path(str(store.path) + suffix)
    sidecar.write_bytes(b'pending state')
    with pytest.raises(ValueError, match='sidecars'):
        store.repair()
    assert store.path.read_bytes() == raw and sidecar.read_bytes() == b'pending state'
    assert not store.history.marker.exists()


def test_hardlinked_original_is_not_recovered(store, tmp_path):
    raw = broken(store)
    os.link(store.path, tmp_path/'other.db')
    with pytest.raises(ValueError, match='owned regular'):
        store.repair()
    assert store.path.read_bytes() == raw


def test_interrupted_pointer_publication_resumes_same_backup(store, monkeypatch):
    raw = broken(store)
    import security_runtime.hook_diagnostic_recovery as recovery
    publish = recovery.atomic_bytes
    def fail(*args):
        raise OSError('publication interrupted')
    monkeypatch.setattr(recovery, 'atomic_bytes', fail)
    with pytest.raises(OSError):
        store.repair()
    assert not store.history.marker.exists()
    monkeypatch.setattr(recovery, 'atomic_bytes', publish)
    assert store.repair()['status'] == 'RECOVERED'
    backups = list(store.history.base.parent.glob('*.corrupt-*.db'))
    assert len(backups) == 1 and backups[0].read_bytes() == raw


def test_changed_source_before_publication_does_not_publish(store, monkeypatch):
    original = store.path
    broken(store)
    initialize = store._initialize
    def changed(path):
        initialize(path)
        original.write_bytes(b'changed by old process')
    monkeypatch.setattr(store, '_initialize', changed)
    with pytest.raises(ValueError, match='changed before publication'):
        store.repair()
    assert not store.history.marker.exists()


def test_missing_or_tampered_generation_never_falls_back(store):
    broken(store)
    store.repair()
    active = store.path
    active.unlink()
    with pytest.raises(FileNotFoundError):
        store.recent(unbound=True)
    descriptor = json.loads(store.history.marker.read_bytes())
    descriptor['database'] = '../scans.db'
    store.history.marker.write_text(json.dumps(descriptor))
    with pytest.raises(ValueError):
        store.repair()


def test_generation_budget_is_bounded(store):
    for count in range(1, MAX_GENERATIONS+1):
        broken(store)
        assert store.repair()['generation'] == count
    raw = broken(store)
    with pytest.raises(ValueError, match='budget exhausted'):
        store.repair()
    assert store.path.read_bytes() == raw


def test_cli_repair_failure_is_safe_json_and_retains_original(store, monkeypatch, capsys):
    raw = broken(store)
    def failure(self):
        raise sqlite3.OperationalError('private filesystem detail')
    monkeypatch.setattr(RecentHookStore, 'repair', failure)
    assert main(['hooks', 'repair-diagnostics', '--json']) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['reason_code'] == 'HOOK_DIAGNOSTIC_RECOVERY_UNAVAILABLE'
    assert result['security_proof'] is False
    assert 'private' not in json.dumps(result) and store.path.read_bytes() == raw


def test_concurrent_writers_publish_one_generation(store):
    raw = broken(store)
    original = store.path
    def write(_):
        return observation(RecentHookStore())
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(write, range(2)))
    assert all(record.available for record in records)
    assert len(store.recent(unbound=True)['records']) == 2
    assert store.history.facts()['generation'] == 1
    assert original.read_bytes() == raw
    assert len(list(original.parent.glob('*.corrupt-*.db'))) == 1
