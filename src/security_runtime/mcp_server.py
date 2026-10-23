"""MCP protocol interface; all operations delegate to SecurityRuntime."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .logging_utils import mcp_log_level
from .runtime import SecurityRuntime
from .integration_state import DogfoodEvent, IntegrationStateStore, WorkspaceBinding
from .mcp_contracts import MCPRegistry

logger = logging.getLogger(__name__)


from .mcp_tools.presentation import _agent_finding, _agent_result


def create_server(runtime: SecurityRuntime | None = None, *, remediation_factory=None,
                  hook_coordinator=None, workspace_binding=None, global_mode=None,
                  hook_advisory_only=False, include_functional_verification=False):
    if global_mode is True or (global_mode is None and os.getenv('SECURITY_RUNTIME_GLOBAL') == '1'):
        from .global_mcp import create_global_server
        return create_global_server(host=os.getenv('SECURITY_RUNTIME_HOST', 'codex'))
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.server.fastmcp import server as fastmcp_server
        from mcp.types import CallToolResult, TextContent, ToolAnnotations
    except ImportError as exc:
        raise ImportError("Install MCP support with: pip install -e '.[mcp]'") from exc
    # The SDK's generic Settings.lifespan annotation references FastMCP. Rebuild
    # it with the defining module's namespace before BaseSettings reads fields.
    fastmcp_server.Settings.model_rebuild(_types_namespace=vars(fastmcp_server))
    # A summary-only connection must not initialize/migrate a writable DB.
    # Existing scan/triage/fix tools acquire their normal runtime on demand.
    engine = runtime
    def runtime_engine():
        nonlocal engine
        if engine is None:
            engine = SecurityRuntime()
        return engine
    closeout_engine = None
    def closeout_service():
        nonlocal closeout_engine
        from .closeout import CloseoutService
        if closeout_engine is None:
            closeout_engine = CloseoutService(runtime_engine(), hook_coordinator.store)
        return closeout_engine
    binding = workspace_binding or WorkspaceBinding.from_environment()
    from .guidance.mcp_guidance import MCP_INSTRUCTIONS
    server = FastMCP("AI Security Runtime", instructions=MCP_INSTRUCTIONS, log_level=mcp_log_level())
    registry = MCPRegistry(server)
    from .workspace_services import assemble_remediation, bind_impact_gate
    from .hook_runtime import HookCoordinator
    hook_coordinator = hook_coordinator or HookCoordinator(runtime)
    # Trusted embedding only, never environment/MCP claims. Default Codex has
    # no atomic edit bridge and cannot opt into Fast Fix through tool arguments.
    remediation = assemble_remediation(runtime, hook_coordinator, factory=remediation_factory)
    from .functional_verification import FunctionalVerificationService
    # Trusted internal embedding only; personal MCP discovery hides these tools.
    # Enabling discovery never supplies repair or project-execution authority.
    functional = FunctionalVerificationService(remediation) if include_functional_verification else None
    # Only an explicit Deep tool request opts this connection into finalization.
    # Core security rechecks never discover or run optional project verifiers.
    from collections import deque
    deep_requests = deque(maxlen=16)
    from .codex_host_claims import CodexClaimGuard
    codex_claim_guard = CodexClaimGuard()

    def lifecycle_claims(args, expected):
        from .codex_event_adapter import CodexEventAdapter
        from .host_event_runtime import inconclusive
        normalized, diag, reason = CodexEventAdapter().bind_project(args,
            binding=binding, guard=codex_claim_guard, expected=expected)
        if reason:
            data = {**inconclusive(reason), **diag, 'scanner_run': False, 'scanner_skipped_reason': reason}
            return diag, data, None
        from .recent_hooks import observe
        diag.update(normalized.diagnostics())
        observe('CLAIMS_VALID', **diag)
        return diag, None, normalized

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def handle_hook_event(event: str, workspace_path: str, session_id: str, tool_name: str,
                          turn_id: str, tool_use_id: str, tool_input: dict | None = None,
                          permission_mode: str | None = None) -> dict:
        """Codex MCP Hook POC: PostToolUse edits only. Untrusted metadata claims, no source/tool response/transcript. Requires SECURITY_RUNTIME_WORKSPACE binding; delegates bounded offline checks to HookCoordinator, never calls a model or edits/builds target."""
        from .codex_mcp_hook import codex_hook_output, handle_codex_hook
        from .hook_runtime import HookCoordinator
        data = handle_codex_hook(event, workspace_path, session_id, tool_name, tool_input,
                                 binding=binding,
                                  turn_id=turn_id, tool_use_id=tool_use_id, permission_mode=permission_mode,
                                  claim_guard=codex_claim_guard,
                                 coordinator=hook_coordinator, remediation=None if hook_advisory_only else remediation)
        from .build_identity import build_identity
        data['runtime_build_id'] = build_identity().get('build_id')
        return CallToolResult(structuredContent=data, content=[TextContent(
            type='text', text=json.dumps(codex_hook_output(data), ensure_ascii=False))])

    # Event-specific invocation claims. SDK validation must not echo rejected
    # values (including accidentally supplied source/Secret) in errors or logs.
    registry.harden(('handle_hook_event',))
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def handle_readiness_event(event: str, workspace_path: str, session_id: str,
                               permission_mode: str | None = None) -> dict:
        """Observe bound Codex SessionStart readiness only. Untrusted metadata claims; no prompt/source/transcript. Writes bounded hashed integration metadata, never scans, builds, calls a model or edits target source. Ready is not safe."""
        from .integration_readiness import handle_readiness
        from .codex_mcp_hook import codex_hook_output
        diag, rejected, normalized = lifecycle_claims(dict(event=event, workspace_path=workspace_path,
                                               session_id=session_id, permission_mode=permission_mode), 'SessionStart')
        data = rejected or handle_readiness(event, workspace_path, session_id, binding=binding,
                                           tools=registry.names())
        if rejected:
            data.update({'continue': True, 'systemMessage': '安全检查尚未成功接入当前项目，暂时无法确认检查结果。'})
        data = {**diag, **data}
        if data.get('status')=='READY':
            from .tasks.ownership import issue_session_ref, session_context
            root=Path(binding.root)
            token=issue_session_ref(hook_coordinator.store,root,'codex',session_id)
            data['task_session_ref']=token
            data['hookSpecificOutput']['additionalContext']+='\n'+session_context(token)
        return CallToolResult(structuredContent=data, content=[TextContent(
            type='text', text=json.dumps(codex_hook_output(data), ensure_ascii=False))])

    registry.harden(('handle_readiness_event',))
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def handle_stop_event(event: str, workspace_path: str, session_id: str, stop_hook_active: bool,
                          turn_id: str | None = None, permission_mode: str | None = None) -> dict:
        """Quiet Codex Stop. Preserve only an existing user-approved repair continuation. Never prepare/dispatch a scan or task review from a chat ending."""
        from .host_event_runtime import handle_normalized_event
        from .codex_mcp_hook import codex_hook_output
        diag, rejected, normalized = lifecycle_claims(dict(event=event, workspace_path=workspace_path,
                                               session_id=session_id, stop_hook_active=stop_hook_active,
                                               turn_id=turn_id, permission_mode=permission_mode), 'Stop')
        data = rejected
        if data is None:
            data, _ = handle_normalized_event(normalized, coordinator=hook_coordinator,
                                              continuation=remediation.continuation)
            # No runtime construction, workspace inventory or new closeout on
            # ordinary chat. Explicit tools still resume signed pending work.
        data = {**diag, **data}
        from .build_identity import build_identity
        data['runtime_build_id'] = build_identity().get('build_id')
        return CallToolResult(structuredContent=data, content=[TextContent(
            type='text', text=json.dumps({} if rejected else codex_hook_output(data), ensure_ascii=True))])

    registry.harden(('handle_stop_event',))
    # Connection-local opaque handoffs hold hashes only, never packet source.
    triage_sessions={}

    from .workspace_application import WorkspaceApplication
    from .storage import SQLiteStore
    application = WorkspaceApplication(runtime_engine, hook_coordinator.store, binding=binding,
        scan_path_provider=lambda: engine.store.path if engine is not None else SQLiteStore.default_path())
    bound_path = application.bound_path
    task_service = application.task_service
    impact_owner = application.impact_owner
    impact_service = application.impact_service
    issued_tasks = application.issued_tasks
    native_session_bindings = application.native_session_bindings
    try:
        from .monitoring.mcp import register as register_usage_monitor
        register_usage_monitor(server, registry, application=application)
    except Exception:
        pass  # Missing/broken optional monitoring never prevents Core startup.

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_closeout_check(workspace_path: str | None = None, files: list[str] | None = None,
                               source_scan_id: str | None = None) -> dict:
        """Persist an explicit offline Core closeout plan. No edit, build, model or repair grant."""
        return closeout_service().prepare(bound_path(workspace_path), files, source_scan_id=source_scan_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def run_closeout_check(closeout_ref: str, workspace_path: str | None = None) -> dict:
        """Execute saved Runtime plan with generation/lease/version receipts; no edits or grants."""
        return closeout_service().run(closeout_ref, bound_path(workspace_path))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_closeout_status(closeout_ref: str, workspace_path: str | None = None) -> dict:
        """Read saved closeout and current version validity; never scan or declare safety."""
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        from .closeout import CloseoutService
        from .scanners import ScannerRegistry
        from types import SimpleNamespace
        reader = engine or SimpleNamespace(store=ReadOnlySQLiteStore(SQLiteStore.default_path()),
                                          registry=ScannerRegistry())
        return CloseoutService(reader, hook_coordinator.store).get(closeout_ref, bound_path(workspace_path))

    def check_scan(scan_id: str) -> None:
        if binding is None:
            return
        scan = runtime_engine().store.get_scan(scan_id)
        if scan is None or Path(scan["target_profile"]["path"]).resolve() != Path(binding.root):
            raise ValueError("Scan does not belong to this MCP workspace")

    def check_finding(finding_id: str) -> None:
        if binding is None:
            return
        record = runtime_engine().store.get_finding(finding_id)
        if record is None or Path(record[1]["target_profile"]["path"]).resolve() != Path(binding.root):
            raise ValueError("Finding does not belong to this MCP workspace")

    def event(value: DogfoodEvent, *, connected: bool = False) -> None:
        if os.getenv("SECURITY_RUNTIME_MCP_SELF_TEST") == "1":
            return
        try:
            state = IntegrationStateStore()
            state.event(value)
            if connected and binding is not None and binding.integration_id in {"cursor", "workbuddy"} and os.getenv("SECURITY_RUNTIME_MCP_SELF_TEST") != "1":
                state.client_invoked(binding.integration_id, Path(binding.root))
        except Exception as exc:
            logger.warning("dogfood_event_failed reason=%s", type(exc).__name__)

    from .mcp_tools import task_review, risk_disposition, explicit_audit, repair
    from .workspace_services import bind_impact_gate
    bind_impact_gate(remediation, application.impact_check)
    task_review.register(server, registry, application=application)
    repair.register(server, registry, application=application, runtime_engine=runtime_engine,
        peek_runtime=lambda: engine, hook_coordinator=hook_coordinator, remediation=remediation,
        functional=functional, deep_requests=deep_requests,
        include_functional_verification=include_functional_verification,
        check_finding=check_finding, event=event)
    risk_disposition.register(server, registry, application=application,
        runtime_engine=runtime_engine, check_scan=check_scan)
    explicit_audit.register(server, registry, application=application, runtime_engine=runtime_engine,
        hook_coordinator=hook_coordinator, remediation=remediation,
        include_functional_verification=include_functional_verification, check_scan=check_scan, event=event)
    for task_tool_name in ('begin_security_task', 'prepare_task_risk_fix', 'cancel_task_risk_fix',
                           'finish_security_task', 'prepare_task_security_review',
                           'get_task_review_plan', 'get_task_review_method', 'submit_task_review_batch',
                           'read_task_review_context', 'submit_task_security_review', 'get_task_security_review', 'get_task_risk_ledger',
                           'prepare_task_risk_feedback', 'submit_task_risk_feedback', 'mark_task_risk_false_positive',
                           'revoke_task_risk_feedback', 'get_task_risk_feedback', 'set_task_risk_disposition'):
        registry.harden((task_tool_name,))


    # Stable feedback diagnostics must survive both local SDK validation and the
    # global router. Never expose arbitrary input/path/SDK exception text.
    from .feedback_contract import (FEEDBACK_TOOLS, disposition_unavailable,
                                    feedback_failure, feedback_reason)
    from mcp.server.fastmcp.exceptions import ToolError
    def feedback_wrapper(original):
        async def feedback_call(name, arguments, *args, **kwargs):
            try:
                return await original(name, arguments, *args, **kwargs)
            except Exception as exc:
                if name not in FEEDBACK_TOOLS and not disposition_unavailable(exc):
                    raise
                reason = feedback_reason(exc, name)
                failure = feedback_failure(reason)
                error = ToolError(reason + ': ' + failure['message'])
                error.reason_code = reason
                raise error from exc
        return feedback_call
    registry.wrap_dispatch(feedback_wrapper)
    registry.validate_raw_inputs()

    from .recent_hooks import install_project_observer
    install_project_observer(server, binding)
    registry.observe_context_cost(workspace=binding.root if binding is not None else None)
    return server


def serve() -> None:
    create_server().run(transport="stdio")
