"""Cross-context path defaults and lossless, one-time legacy migration."""
import json
import os
import sqlite3
from pathlib import Path

import pytest

from security_runtime import windows_migration as migration
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.user_paths import windows_root, windows_directory


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setenv('USERPROFILE', str(tmp_path))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'AppData/Local'))
    monkeypatch.setenv('APPDATA', str(tmp_path / 'AppData/Roaming'))
    for key in migration.OVERRIDES.values():
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr('security_runtime.delivery_processes.running_slot_builds', lambda root, **kw: set())
    return tmp_path


def put(path, data=b'original'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.mark.skipif(os.name != 'nt', reason='Windows defaults')
def test_defaults_do_not_follow_host_appdata(profile, monkeypatch):
    from security_runtime.storage import SQLiteStore
    from security_runtime.user_config import config_path
    from security_runtime.toolchain import default_data_root
    from security_runtime.personal_install import _default_delivery_root
    expected = (profile/'.asr', profile/'.asr/state/scans.db',
                profile/'.asr/config/config.toml', profile/'.asr/data')
    for prefix in ('AppData', 'AppData/Local/Packages/host/LocalCache'):
        monkeypatch.setenv('LOCALAPPDATA', str(profile/prefix/'Local'))
        monkeypatch.setenv('APPDATA', str(profile/prefix/'Roaming'))
        assert (_default_delivery_root(), SQLiteStore.default_path(), config_path(), default_data_root()) == expected


def test_migrate_config_database_and_keys_retains_originals(profile):
    config = put(profile/'AppData/Roaming/ai-security-runtime/config.toml', b'[agent]\naudit_business_logic = true\n')
    state = profile/'AppData/Local/AI Security Runtime'
    key = put(state/'hooks/owner/snapshot.key', b'x'*32)
    with sqlite3.connect(state/'scans.db') as db:
        db.execute('create table evidence (value text)')
        db.execute("insert into evidence values ('retained')")
    cache = put(profile/'AppData/Local/AI-Security-Runtime/cache/metadata.json')
    result = migration.migrate_user_directories()
    assert result['status'] == 'COMPLETE'
    assert windows_directory('config').joinpath('config.toml').read_bytes() == config.read_bytes()
    assert windows_directory('state').joinpath('hooks/owner/snapshot.key').read_bytes() == key.read_bytes()
    with sqlite3.connect(windows_directory('state')/'scans.db') as db:
        assert db.execute('select value from evidence').fetchone() == ('retained',)
    assert cache.exists() and key.exists() and config.exists()


def test_repeated_install_never_inventories_legacy_files_or_processes(profile, monkeypatch):
    migration.migrate_user_directories()
    monkeypatch.setattr(migration, '_sources', lambda *a: pytest.fail('repeat enumerated profiles'))
    monkeypatch.setattr(migration, '_inventory', lambda *a: pytest.fail('repeat hashed files'))
    monkeypatch.setattr('security_runtime.delivery_processes.running_slot_builds', lambda *a: pytest.fail('repeat probed processes'))
    assert migration.migrate_user_directories()['status'] == 'COMPLETE'


def test_divergent_overlay_requires_source_and_preserves_both(profile):
    external = profile/'AppData'
    overlay = profile/'AppData/Local/Packages/host/LocalCache'
    a = put(external/'Local/AI Security Runtime/history.json', b'external')
    b = put(overlay/'Local/AI Security Runtime/history.json', b'host')
    with pytest.raises(IntegrationDiagnostic, match='LEGACY_USER_DIRECTORIES_CONFLICT'):
        migration.migrate_user_directories()
    assert not windows_directory('state').exists()
    migration.migrate_user_directories(legacy_appdata=overlay)
    assert (windows_directory('state')/'history.json').read_bytes() == b'host'
    assert a.read_bytes() == b'external' and b.read_bytes() == b'host'


def test_destination_conflict_never_overwritten(profile):
    put(profile/'AppData/Local/AI Security Runtime/record', b'old')
    current = put(windows_directory('state')/'record', b'current')
    with pytest.raises(IntegrationDiagnostic, match='DESTINATION_CONFLICT'):
        migration.migrate_user_directories()
    assert current.read_bytes() == b'current'


@pytest.mark.parametrize('running', [{'old-build'}, None])
def test_running_old_runtime_blocks_migration(profile, monkeypatch, running):
    put(profile/'AppData/Local/AI Security Runtime/record')
    (profile/'AppData/Local/ASR').mkdir()
    monkeypatch.setattr('security_runtime.delivery_processes.running_slot_builds', lambda root, **kw: running)
    with pytest.raises(IntegrationDiagnostic, match='STILL_RUNNING'):
        migration.migrate_user_directories()
    assert not windows_directory('state').exists()


def test_source_change_during_copy_is_not_published(profile, monkeypatch):
    source = put(profile/'AppData/Local/AI Security Runtime/record')
    real = migration.shutil.copyfileobj
    def changing(stream, output):
        real(stream, output)
        source.write_bytes(b'new concurrent content')
    monkeypatch.setattr(migration.shutil, 'copyfileobj', changing)
    with pytest.raises(IntegrationDiagnostic, match='DIRECTORIES_CHANGED'):
        migration.migrate_user_directories()
    assert not windows_directory('state').exists()
    assert source.read_bytes() == b'new concurrent content'


def test_copy_failure_is_retryable_and_keeps_source(profile, monkeypatch):
    source = put(profile/'AppData/Local/AI Security Runtime/record')
    original = migration.shutil.copyfileobj
    monkeypatch.setattr(migration.shutil, 'copyfileobj', lambda *a, **k: (_ for _ in ()).throw(OSError('fixture')))
    with pytest.raises(OSError):
        migration.migrate_user_directories()
    assert source.read_bytes() == b'original'
    assert not (windows_root()/'user-directories.json').exists()
    monkeypatch.setattr(migration.shutil, 'copyfileobj', original)
    assert migration.migrate_user_directories()['status'] == 'COMPLETE'


def test_unreadable_legacy_file_reports_fixed_diagnostic(profile, monkeypatch):
    # A live host can delete or rewrite a file between enumeration and hashing.
    # That must surface as a known cause, never as a bare OSError that reads
    # like a broken download package.
    put(profile/'AppData/Local/AI Security Runtime/record')
    def vanishing(stream, algorithm):
        raise OSError(22, 'Invalid argument')
    monkeypatch.setattr(migration.hashlib, 'file_digest', vanishing)
    with pytest.raises(IntegrationDiagnostic, match='LEGACY_DIRECTORY_IDENTITY_UNKNOWN'):
        migration.migrate_user_directories()
    assert 'LEGACY_DIRECTORY_IDENTITY_UNKNOWN' in migration.MESSAGES
    assert not windows_directory('state').exists()
    assert not (windows_root()/'user-directories.json').exists()


def test_explicit_profile_does_not_consume_future_default_migration(profile, monkeypatch):
    put(profile/'AppData/Local/AI Security Runtime/record')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(profile/'custom'))
    migration.migrate_user_directories()
    assert not windows_directory('state').exists()
    monkeypatch.delenv('SECURITY_RUNTIME_STATE_DIR')
    migration.migrate_user_directories()
    assert (windows_directory('state')/'record').read_bytes() == b'original'


def test_malformed_marker_fails_without_legacy_work(profile):
    put(windows_root()/'user-directories.json', json.dumps({'contract': 'wrong'}).encode())
    with pytest.raises(IntegrationDiagnostic, match='MIGRATION_INVALID'):
        migration.migrate_user_directories()


def test_explicit_missing_legacy_source_is_not_a_fresh_install(profile):
    with pytest.raises(IntegrationDiagnostic, match='LEGACY_APPDATA_UNAVAILABLE'):
        migration.migrate_user_directories(legacy_appdata=profile/'missing')
    assert not (windows_root()/'user-directories.json').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows scan-store relocation')
def test_signed_task_and_legacy_scan_reference_survive_migration(profile, monkeypatch):
    from security_runtime.development_check import DevelopmentCheckService
    from security_runtime.hook_state import HookStateStore
    from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore
    source = profile/'AppData/Local/AI Security Runtime'
    scans = SQLiteStore(source/'scans.db')
    workspace = profile/'project'
    workspace.mkdir()
    owner = dict(host='codex', session='1'*64)
    service = DevelopmentCheckService(None, HookStateStore(source/'hooks'),
        owner=owner, scan_path_provider=lambda: scans.path, launcher=lambda *a: None)
    ref = service.begin(workspace, 'preserved-task')['check_ref']
    service.record(workspace, ref, ['app.py'])
    migration.migrate_user_directories()
    restored = DevelopmentCheckService(None, HookStateStore(windows_directory('state')/'hooks'),
        owner=owner, launcher=lambda *a: None)
    assert restored.get(workspace, ref)['dirty_seq'] == 1
    row = next(row for row in restored.store(workspace).rows() if row['key'] == ref)
    assert row['scan_path'] == str(source/'scans.db')
    assert ReadOnlySQLiteStore(source/'scans.db').path == windows_directory('state')/'scans.db'
    assert SQLiteStore(source/'scans.db').path == windows_directory('state')/'scans.db'
    assert ReadOnlySQLiteStore(profile/'unrelated/scans.db').path == profile/'unrelated/scans.db'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(source))
    assert ReadOnlySQLiteStore(source/'scans.db').path == source/'scans.db'
