"""Shared workspace engine factory, independent of editor configuration."""
from .global_workspace import resolve_workspace, source_snapshot
from .hook_state import HookStateStore
from .workspace import WorkspaceResolver


class NoProjectSeed:
    @staticmethod
    def load(root):
        return None, 'GLOBAL_SESSION_BASELINE'


def workspace_services(root, directory):
    from .runtime import SecurityRuntime
    from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter, TrivyAdapter
    from .dynamic_function import NativeFunctionScanner
    from .osv import OSVDependencyAdapter
    from .toolchain import ToolManager
    from .storage import SQLiteStore
    from .hook_runtime import HookCoordinator
    manager = ToolManager()
    registry = ScannerRegistry([SemgrepAdapter(manager), NativeFunctionScanner(),
        GitleaksAdapter(manager), TrivyAdapter(manager)], tool_manager=manager,
        fallback_adapters=[OSVDependencyAdapter(manager)])
    store = SQLiteStore(directory / 'scans.db')
    runtime = SecurityRuntime(ScannerRegistry(tool_manager=manager), store)
    hook_runtime = SecurityRuntime(registry, store)
    is_git = WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git
    core = HookCoordinator(hook_runtime, HookStateStore(directory / 'hooks'),
        workspace_resolver=resolve_workspace,
        snapshot_capture=None if is_git else source_snapshot,
        seeds=NoProjectSeed(), activity_wait_seconds=10)
    return runtime, core, is_git
