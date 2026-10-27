"""Shared workspace engine factory, independent of editor configuration."""
from .global_workspace import resolve_workspace, source_snapshot
from .hook_state import HookStateStore
from .workspace import WorkspaceResolver


class NoProjectSeed:
    @staticmethod
    def load(root):
        return None, 'GLOBAL_SESSION_BASELINE'


def assemble_remediation(runtime, coordinator, *, factory=None):
    """Shared product construction; trusted embeddings may supply a constructor.

    Workspace claims and MCP arguments never choose this constructor. The impact
    gate is installed after its workspace-bound callback has been constructed.
    """
    from .remediation import RemediationService
    service = (factory or RemediationService)(getattr(runtime, 'store', None),
        hooks=coordinator.store, registry=coordinator.managed_registry())
    if factory is None:
        service.agent_tickets.enabled = True
    return service


def bind_impact_gate(service, gate):
    """Required product wiring, including custom global workspace factories."""
    if not callable(gate):
        raise ValueError('PRODUCT_IMPACT_GATE_REQUIRED')
    service.impact_gate = gate


def workspace_mcp_server(root, directory, binding):
    """Compose one bound product server; transport hosts share this assembly."""
    from .mcp_server import create_server
    from .remediation import RemediationService
    from .remediation_policy import RemediationConfig
    runtime, core, is_git = workspace_services(root, directory)

    def remediation_factory(store, **kwargs):
        # Preferences are user-wide; evidence, grants and task state are local.
        return RemediationService(store, config=RemediationConfig(), inline_agent_tickets=True, **kwargs)

    return create_server(runtime, hook_coordinator=core,
        remediation_factory=remediation_factory, workspace_binding=binding,
        global_mode=False, hook_advisory_only=not is_git), core


def workspace_services(root, directory):
    from .runtime import SecurityRuntime
    from .scanners import ScannerRegistry, OpenGrepAdapter, GitleaksAdapter, TrivyAdapter
    from .dynamic_function import NativeFunctionScanner
    from .toolchain import ToolManager
    from .storage import SQLiteStore
    from .hook_runtime import HookCoordinator
    manager = ToolManager()
    registry = ScannerRegistry([OpenGrepAdapter(manager), NativeFunctionScanner(),
        GitleaksAdapter(manager), TrivyAdapter(manager)], tool_manager=manager,
        fallback_adapters=[])
    store = SQLiteStore(directory / 'scans.db')
    runtime = SecurityRuntime(ScannerRegistry(tool_manager=manager), store)
    hook_runtime = SecurityRuntime(registry, store)
    is_git = WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git
    core = HookCoordinator(hook_runtime, HookStateStore(directory / 'hooks'),
        workspace_resolver=resolve_workspace,
        snapshot_capture=None if is_git else source_snapshot,
        seeds=NoProjectSeed(), activity_wait_seconds=10, task_audit_mode=True)
    return runtime, core, is_git
