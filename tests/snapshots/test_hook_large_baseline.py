"""Retained hook-v1 maps keep their original limits and small scan scopes.

New SessionStart product epochs have separate real-file acceptance tests. These
fixtures explicitly preserve the historical full-map comparison contract.
"""
import copy
import json
import os
import subprocess

import pytest

from security_runtime.global_workspace import source_snapshot
from security_runtime.hook_runtime import (
    HookCoordinator, capture_recheck_expectation, capture_snapshot, validate_state,
)
from security_runtime.hook_state import HookStateStore, MAX_STATE_BYTES
from legacy_hook_helpers import legacy_comparison


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail('Session comparison capture must not invoke a scanner')


def git(root, *arguments):
    subprocess.run(['git', '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false',
                    '-c', 'user.name=Hook fixture',
                    '-c', 'user.email=hook@example.invalid', '-C', str(root), *arguments],
                   check=True, capture_output=True, timeout=20)


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path.resolve() / 'runtime-state'))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', os.devnull)
    for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
                'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
                'GIT_CONFIG', 'GIT_CONFIG_COUNT'):
        monkeypatch.delenv(key, raising=False)
    names = [f'module_{index:04d}.py' for index in range(1001)]
    for name in names:
        (root / name).write_text('value = 1\n', encoding='utf-8')
    return root, names


def baseline(root, tmp_path, capture):
    store = HookStateStore(tmp_path.resolve() / 'hook-state')
    original = legacy_comparison(store, root, 'codex', 'large-baseline', capture=capture)
    assert original['schema_version'] == 'hook-v1'
    path = store.path(root, 'codex', 'large-baseline')
    original_bytes = path.read_bytes()
    coordinator = HookCoordinator(NoScanner(), store, workspace_resolver=lambda value: value,
                                  snapshot_capture=capture)
    result = coordinator.handle_lifecycle('SESSION_START', root, 'codex', 'large-baseline')
    state, recovered = store.load(path)
    assert state == original
    assert path.read_bytes() == original_bytes
    return result, state, recovered, store


@pytest.mark.parametrize('tracked', [False, True])
def test_git_1001_files_establishes_complete_session_comparison(source, tmp_path, tracked):
    root, names = source
    git(root, 'init', '-q')
    if tracked:
        git(root, 'add', '.')
        git(root, 'commit', '-qm', 'Fixture')
    result, state, recovered, store = baseline(root, tmp_path, capture_snapshot)
    assert result['status'] == 'BASELINE_ESTABLISHED'
    assert result['baseline_publish_status'] == 'RETAINED'
    assert result['execution']['scanner_run'] is False
    assert result['project_scan_status'] == 'NOT_REQUESTED'
    assert not recovered and set(state['file_digests']) == set(names)
    assert state['changed_files'] == ([] if tracked else names)
    assert len(store.path(root, 'codex', 'large-baseline').read_bytes()) < MAX_STATE_BYTES


def test_non_git_1001_files_establishes_complete_session_comparison(source, tmp_path):
    root, names = source
    result, state, recovered, _ = baseline(root, tmp_path, source_snapshot)
    assert result['status'] == 'BASELINE_ESTABLISHED'
    assert result['baseline_publish_status'] == 'RETAINED'
    assert result['execution']['scanner_run'] is False
    assert not recovered
    assert state['changed_files'] == names and set(state['file_digests']) == set(names)


def test_one_file_recheck_can_use_1001_file_comparison_inventory(source, tmp_path):
    root, names = source
    git(root, 'init', '-q')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'Fixture')
    key = b'x' * 32
    captured = capture_snapshot(root, key)
    (root / names[-1]).write_text('value = 2\n', encoding='utf-8')
    current = capture_snapshot(root, key)
    assert current.file_digests[names[-1]] != captured.file_digests[names[-1]]
    checked = capture_recheck_expectation(root, current, key, [names[-1]])
    assert set(checked.file_digests) == set(names)


def test_one_file_edit_after_1001_file_baseline_keeps_scanner_scope_small(source, tmp_path):
    from test_hook_runtime import FakeRuntime
    root, names = source
    git(root, 'init', '-q')
    git(root, 'add', '.')
    git(root, 'commit', '-qm', 'Fixture')
    runtime = FakeRuntime()
    store = HookStateStore(tmp_path.resolve() / 'hook-state')
    original = legacy_comparison(store, root, 'codex', 'large-baseline')
    assert original['schema_version'] == 'hook-v1'
    original_bytes = store.path(root, 'codex', 'large-baseline').read_bytes()
    coordinator = HookCoordinator(runtime, store, cooldown_ms=0)
    initial = coordinator.handle_lifecycle('SESSION_START', root, 'codex', 'large-baseline')
    assert initial['baseline_publish_status'] == 'RETAINED' and not runtime.calls
    assert store.path(root, 'codex', 'large-baseline').read_bytes() == original_bytes
    (root / names[-1]).write_text('value = 2\n', encoding='utf-8')
    result = coordinator.handle('FILE_CHANGED', root, 'codex', 'large-baseline')
    assert result['execution']['scanner_run'] is True
    assert runtime.calls == [(names[-1],)]
    state, recovered = store.load(store.path(root, 'codex', 'large-baseline'))
    assert not recovered and set(state['file_digests']) == set(names)


def test_oversize_state_is_rejected_without_replacing_original(source, tmp_path):
    root, _ = source
    git(root, 'init', '-q')
    _, state, _, store = baseline(root, tmp_path, capture_snapshot)
    path = store.path(root, 'codex', 'large-baseline')
    original = path.read_bytes()
    oversized = copy.deepcopy(state)
    oversized['file_digests'] = {f'module_{index:06d}.py': 'a' * 64 for index in range(25000)}
    assert len(json.dumps(oversized, ensure_ascii=True, separators=(',', ':')).encode()) > MAX_STATE_BYTES
    with pytest.raises(ValueError, match='Hook state budget exceeded'):
        validate_state(oversized)
    with pytest.raises(ValueError, match='Hook state budget exceeded'):
        store.save(path, oversized)
    assert path.read_bytes() == original


@pytest.mark.parametrize('capture', [capture_snapshot, source_snapshot])
def test_comparison_identity_byte_budget_rejects_whole_capture(source, monkeypatch, capture):
    root, _ = source
    if capture is capture_snapshot:
        git(root, 'init', '-q')
    monkeypatch.setattr('security_runtime.hook_state.MAX_STATE_BYTES', 1000)
    with pytest.raises(ValueError, match='Hook snapshot identity byte budget exceeded|SNAPSHOT_INVENTORY_BUDGET_OR_BOUNDARY_EXCEEDED'):
        capture(root, b'x' * 32)


@pytest.mark.parametrize('capture', [capture_snapshot, source_snapshot])
def test_source_byte_budget_remains_independent_of_file_count(source, monkeypatch, capture):
    root, _ = source
    if capture is capture_snapshot:
        git(root, 'init', '-q')
    monkeypatch.setattr('security_runtime.hook_runtime.MAX_BYTES', 1)
    with pytest.raises(ValueError, match='content budget exceeded|SNAPSHOT_BUDGET_EXCEEDED'):
        capture(root, b'x' * 32)
