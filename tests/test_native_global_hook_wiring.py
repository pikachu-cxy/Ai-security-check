"""Factory wiring only; these tests do not invoke desktop Hook events."""
import subprocess

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.global_mcp import GlobalWorkspaces


def test_global_workspace_child_retains_native_check_in_hook_and_manual_registries(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
    captured = {}

    def server(runtime, **kwargs):
        captured.update(runtime=runtime, **kwargs)
        return object()

    monkeypatch.setattr('security_runtime.mcp_server.create_server', server)
    GlobalWorkspaces._child(root, tmp_path / 'runtime-state', object())
    core = captured['hook_coordinator']
    assert any(type(adapter) is NativeFunctionScanner for adapter in core.runtime.registry.adapters)
    assert any(type(adapter) is NativeFunctionScanner for adapter in captured['runtime'].registry.adapters)
    assert core.runtime.store is captured['runtime'].store
    assert captured['hook_advisory_only'] is False
