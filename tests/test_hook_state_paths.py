"""Native state IO never changes workspace identity or logical safety gates."""
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.hook_runtime import HookSnapshot
from security_runtime.hook_state import HookStateStore, atomic_bytes, identity, native_io_path, no_links


def snapshot(root):
    result = dict(status='COMPARISON_BASELINE', last_check_status='NOT_CHECKED',
        coverage='NONE', execution_state='NOT_EXECUTED', capabilities={}, scanner_runs=[],
        delta=dict(new=0, persisting=0, resolved=0, additional_occurrences=0,
                   removed_occurrences=0, families=[]))
    return dict(HookSnapshot('hook-v1', identity(os.path.normcase(str(root))), 'codex',
        identity('session'), identity('synthetic-snapshot'), [], {}, None, 0, result,
        {}).__dict__)


def long_directory(tmp_path):
    return tmp_path / ('state-' + 'x' * 70) / ('nested-' + 'y' * 70) / 'hooks'


def test_normal_roundtrip_keeps_logical_directory_and_identity(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    directory = tmp_path / 'state'
    store = HookStateStore(directory)
    assert store.directory == directory
    assert store.workspace_directory(root).name == identity(os.path.normcase(str(root)))
    path = store.path(root, 'codex', 'session')
    assert path.name == identity('codex\0session') + '.json'
    value = snapshot(root)
    with store.lock(root) as acquired:
        assert acquired
        key = store.key(root)
        store.save(path, value)
        assert store.load(path) == (value, False)
    restarted = HookStateStore(directory)
    assert restarted.key(root) == key
    assert restarted.load(restarted.path(root, 'codex', 'session')) == (value, False)
    assert restarted.directory == directory


@pytest.mark.skipif(os.name != 'nt', reason='Win32 extended path representation')
def test_windows_long_state_roundtrip_restart_tamper_and_pending(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    directory = long_directory(tmp_path)
    store = HookStateStore(directory)
    assert store.directory == directory and not str(store.directory).startswith('\\\\?\\')
    path = store.path(root, 'codex', 'session')
    assert len(str(path)) > 260 and str(path).startswith('\\\\?\\')
    assert path.parent.name == identity(os.path.normcase(str(root)))
    value = snapshot(root)
    with store.lock(root) as acquired:
        assert acquired
        key = store.key(root)
        sequence = store.pending_activity(root, 'codex', 'session', mark=True)
        assert sequence is not None
        assert store.pending_activity(root, 'codex', 'session', completed=sequence) is None
        store.save(path, value)
        assert store.load(path) == (value, False)
    restarted = HookStateStore(directory)
    assert restarted.key(root) == key
    assert restarted.load(restarted.path(root, 'codex', 'session')) == (value, False)
    malformed = dict(value, unexpected='synthetic-marker')
    atomic_bytes(path, json.dumps(malformed).encode())
    assert restarted.load(path) == (None, True)
    assert path.read_bytes() == json.dumps(malformed).encode()


@pytest.mark.skipif(os.name != 'nt', reason='Win32 atomic rename path limit')
def test_windows_atomic_bytes_accepts_unprefixed_long_path(tmp_path):
    logical = long_directory(tmp_path) / ('workspace-' + 'z' * 64) / 'record.json'
    assert len(str(logical)) > 260
    atomic_bytes(logical, b'first')
    native = native_io_path(logical)
    assert native.read_bytes() == b'first'
    atomic_bytes(logical, b'second')
    assert native.read_bytes() == b'second'
    assert not list(native.parent.glob('.hook-*'))


def test_logical_directory_still_rejects_state_inside_workspace(tmp_path):
    from security_runtime.baseline_seed import WorkspaceBaselineSeeds
    from security_runtime.remediation import RemediationService
    from security_runtime.storage import SQLiteStore
    root = (tmp_path / 'project').resolve(); root.mkdir()
    store = HookStateStore(root / 'local-state')
    assert store.directory.absolute().is_relative_to(root)
    seeds = WorkspaceBaselineSeeds(integration=object(), coordinator=SimpleNamespace(store=store))
    with pytest.raises(ValueError, match='Baseline state must be outside workspace'):
        seeds.capture_session(root, 'session')
    scans = SQLiteStore(tmp_path / 'outside/scans.db')
    service = RemediationService(scans, hooks=HookStateStore(tmp_path / 'outside/hooks'),
                                 directory=root / 'local-state')
    result = service.on_hook({}, root, 'session', host='codex')
    assert result['reason_code'] == 'USER_STATE_MUST_BE_OUTSIDE_WORKSPACE'
    assert not (root / 'local-state').exists()


def test_relative_native_path_targets_same_location(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    relative = Path('state') / 'record.json'
    native = native_io_path(relative)
    if os.name == 'nt':
        assert native == native_io_path(tmp_path / relative)
    else:
        assert native == relative
    atomic_bytes(relative, b'fixture')
    assert native.read_bytes() == b'fixture'


@pytest.mark.skipif(os.name == 'nt', reason='Non-Windows path behavior')
def test_non_windows_paths_are_unchanged(tmp_path):
    for path in (Path('relative/state'), tmp_path / 'absolute/state'):
        assert native_io_path(path) == path


@pytest.mark.skipif(os.name != 'nt', reason='Win32 native path spelling')
def test_windows_native_path_is_idempotent_and_preserves_unc_spelling():
    local = Path('C:/synthetic/state')
    assert native_io_path(native_io_path(local)) == native_io_path(local)
    # Pure spelling conversion; never access a share or broaden Host admission.
    unc = Path(r'\\synthetic-host\synthetic-share\state')
    assert str(native_io_path(unc)) == r'\\?\UNC\synthetic-host\synthetic-share\state'
    assert native_io_path(native_io_path(unc)) == native_io_path(unc)


@pytest.mark.skipif(os.name != 'nt', reason='Win32 device namespaces')
@pytest.mark.parametrize('raw', [
    r'\\.\C:\synthetic', r'\\?\GLOBALROOT\Device\synthetic', r'\\?\PIPE\synthetic',
    r'\\?\UNC\.\pipe\synthetic', r'\\?\UNC\..\share\synthetic'])
def test_windows_device_paths_fail_closed(raw):
    with pytest.raises(ValueError, match='device paths are not supported'):
        native_io_path(Path(raw))


@pytest.mark.skipif(os.name != 'nt', reason='Win32 ambiguous filename spelling')
@pytest.mark.parametrize('raw', [
    'C:/synthetic/trailing./record.json', 'C:/synthetic/trailing /record.json',
    'C:/synthetic/CON/record.json', 'C:/synthetic/NUL.json',
    'C:/synthetic/COM1/record.json', 'C:/synthetic/LPT1.json',
    'C:/synthetic/COM\u00b9/record.json', 'C:/synthetic/record.json:stream'])
def test_windows_ambiguous_names_fail_closed(raw):
    with pytest.raises(ValueError, match='path spelling is not supported'):
        native_io_path(Path(raw))


def test_native_state_paths_keep_link_rejection(tmp_path):
    outside = tmp_path / 'outside'; outside.mkdir()
    link = tmp_path / 'linked-state'
    if os.name == 'nt':
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(outside)],
                                capture_output=True)
        if result.returncode:
            pytest.skip('Junction creation unavailable')
        assert link.is_junction()
    else:
        link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='links are not supported'):
        no_links(native_io_path(link / 'record.json'))
    with pytest.raises(ValueError, match='links are not supported'):
        atomic_bytes(link / 'record.json', b'must-not-write')
    with pytest.raises(ValueError, match='links are not supported'):
        HookStateStore(link).path(tmp_path / 'project', 'codex', 'session')
    with pytest.raises(ValueError, match='links are not supported'):
        no_links(link / '..' / 'safe' / 'record.json')
    with pytest.raises(ValueError, match='links are not supported'):
        atomic_bytes(link / '..' / 'safe' / 'record.json', b'must-not-write')
    assert not list(outside.iterdir())
