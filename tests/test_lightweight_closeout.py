"""Lightweight development still binds results and rejects stale task leases."""
from types import SimpleNamespace

import pytest

from security_runtime.scan_attempt import ScanAttemptExecution, ScanAttemptLost
from security_runtime.workspace_application import WorkspaceApplication


def test_exact_bound_root_does_not_launch_git(tmp_path, monkeypatch):
    from security_runtime.workspace import WorkspaceResolver
    def unexpected(*args, **kwargs):
        raise AssertionError('redundant Git workspace discovery')
    monkeypatch.setattr(WorkspaceResolver, 'resolve', unexpected)
    app = WorkspaceApplication(None, None, binding=SimpleNamespace(root=str(tmp_path)),
                               scan_path_provider=None)
    assert app.bound_path(str(tmp_path)) == str(tmp_path)
    assert app.bound_path(None) == str(tmp_path)


def test_captured_result_keeps_lease_check_without_source_read(tmp_path):
    store = SimpleNamespace(private_parent=tmp_path, read=lambda: {'lane': {}},
                            is_current=lambda *args: False)
    execution = ScanAttemptExecution(store, object(), captured_only=True)
    def unexpected():
        raise AssertionError('closeout must not reread source')
    view = SimpleNamespace(input_id='input', request=SimpleNamespace(source_kind='WORKTREE'),
                           check_current=unexpected)
    assert execution.applicability(view).state == 'CAPTURED'
    with pytest.raises(ScanAttemptLost, match='SCAN_ATTEMPT_SUPERSEDED'):
        execution.checkpoint(force=True)


def test_native_version_cache_survives_workspace_change_but_not_binary_change(tmp_path, monkeypatch):
    from security_runtime.toolchain import ToolManager
    from security_runtime import scanner_cache
    monkeypatch.setattr(scanner_cache, '_process', scanner_cache.ProcessPreparations())
    manager = ToolManager(tmp_path / 'tools')
    binary = tmp_path / 'gitleaks'
    binary.write_bytes(b'first binary')
    calls = []
    monkeypatch.setattr(manager, '_probe_version',
                        lambda *args: calls.append(1) or manager.versions['gitleaks'])
    first = tmp_path / 'first'; first.mkdir()
    second = tmp_path / 'second'; second.mkdir()
    monkeypatch.chdir(first)
    manager._version('gitleaks', binary)
    monkeypatch.chdir(second)
    manager._version('gitleaks', binary)
    assert len(calls) == 1
    binary.write_bytes(b'second binary')
    manager._version('gitleaks', binary)
    assert len(calls) == 2
