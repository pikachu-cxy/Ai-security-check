"""MCP protocol interface; all operations delegate to SecurityRuntime."""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import asdict
from pathlib import Path

from .logging_utils import mcp_log_level
from .runtime import SecurityRuntime
from .integration_state import DogfoodEvent, IntegrationStateStore, WorkspaceBinding
from .workspace import WorkspaceResolver

logger = logging.getLogger(__name__)


def _agent_finding(finding: dict) -> dict:
    return {key: finding[key] for key in ("id", "category", "severity", "confidence", "plain_title", "file_path", "line_start", "impact", "fix_advice", "technical_details", "triage_status", "verdict", "triage_confidence", "exploitability", "triage") if key in finding}


def _agent_result(result) -> dict:
    return {
        "scan_id": result.scan_id,
        "workspace": result.target_profile.path,
        "status": result.status,
        "execution_state": result.execution_state,
        "coverage_scope": result.coverage_scope,
        "capability_results": result.capability_results,
        "capability_details": result.capability_details,
        "rule_coverage": {key:value for key,value in result.rule_coverage.items() if key!='scope_files'},
        "coverage": result.coverage,
        "summary": result.summary,
        "findings": [_agent_finding(f.__dict__) for f in result.findings],
        "recommendation": result.release_status,
        "duration_ms": result.duration_ms,
        "scanner_runs": [asdict(run) for run in result.scanner_runs],
    }


def create_server(runtime: SecurityRuntime | None = None):
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
    binding = WorkspaceBinding.from_environment()
    from .host_guidance import HOST_INSTRUCTIONS
    server = FastMCP("AI Security Runtime", instructions=HOST_INSTRUCTIONS, log_level=mcp_log_level())
    from .remediation import RemediationService
    from .hook_runtime import HookCoordinator
    hook_coordinator = HookCoordinator(runtime)
    remediation = RemediationService(getattr(runtime, 'store', None), hooks=hook_coordinator.store)
    from .functional_verification import FunctionalVerificationService
    functional = FunctionalVerificationService(remediation)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def handle_hook_event(event: str, workspace_path: str, session_id: str, tool_name: str) -> dict:
        """Codex MCP Hook POC: PostToolUse edits only. Untrusted metadata claims, no source/tool response/transcript. Requires SECURITY_RUNTIME_WORKSPACE binding; delegates bounded offline checks to HookCoordinator, never calls a model or edits/builds target."""
        from .codex_mcp_hook import codex_hook_output, handle_codex_hook
        from .hook_runtime import HookCoordinator
        data = handle_codex_hook(event, workspace_path, session_id, tool_name, binding=binding,
                                 coordinator=hook_coordinator, remediation=remediation)
        return CallToolResult(structuredContent=data, content=[TextContent(
            type='text', text=json.dumps(codex_hook_output(data), ensure_ascii=True))])

    # This POC accepts exactly four claims. SDK validation must not echo rejected
    # values (including accidentally supplied source/Secret) in errors or logs.
    hook_tool = server._tool_manager.get_tool('handle_hook_event')
    hook_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    hook_tool.fn_metadata.arg_model.model_rebuild(force=True)
    hook_tool.parameters = hook_tool.fn_metadata.arg_model.model_json_schema()
    # Connection-local opaque handoffs hold hashes only, never packet source.
    triage_sessions={}

    def register_handoff(data, task_binding=None):
        expired=[key for key,value in triage_sessions.items() if time.monotonic()-value[2]>900]
        for key in expired: triage_sessions.pop(key,None)
        if len(triage_sessions)>=64: triage_sessions.pop(next(iter(triage_sessions)))
        token=secrets.token_urlsafe(32)
        triage_sessions[token]=(data['scan_id'],{p['finding_id']:p['context_hash'] for p in data['packets']},
                                time.monotonic(),task_binding)
        data['triage_session']=token
        data['triage_session_expires_in_seconds']=900
        return data

    def bound_path(value: str | None) -> str | None:
        if binding is None:
            return value
        candidate = Path(value) if value is not None else Path(binding.root)
        if not candidate.is_absolute():
            candidate = Path(binding.root) / candidate
        resolved = WorkspaceResolver().resolve(candidate, allow_non_git_explicit=True).path
        if resolved != Path(binding.root):
            raise ValueError("Requested workspace is outside this MCP connection")
        return binding.root

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

    @server.tool()
    def scan_diff(workspace_path: str | None = None, mode: str = "quick", path: str | None = None) -> dict:
        """Scan changed files in a local Git repository."""
        if mode not in {"quick", "feature"}:
            raise ValueError("mode must be quick or feature")
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        logger.info("scan_diff started")
        root = bound_path(workspace_path if workspace_path is not None else path)
        result = runtime_engine().scan(root, mode)
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           mode, result.duration_ms, len(result.findings), result.coverage), connected=True)
        logger.info("scan_diff finished scan_id=%s", result.scan_id)
        return _agent_result(result)

    @server.tool()
    def scan_project(workspace_path: str | None = None, path: str | None = None) -> dict:
        """Run a full local project scan."""
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        root = bound_path(workspace_path if workspace_path is not None else path)
        result = runtime_engine().scan(root, "release")
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           "release", result.duration_ms, len(result.findings), result.coverage), connected=True)
        return _agent_result(result)

    @server.tool()
    def get_findings(scan_id: str) -> list[dict]:
        """Retrieve findings from a previous scan."""
        check_scan(scan_id)
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root), connected=True)
        from .triage import TriageService
        view=TriageService(runtime_engine().store).view(scan_id)
        rows={row['finding_id']:row for row in view['findings']}
        found=[]
        for finding in runtime_engine().get_findings(scan_id):
            row=rows[finding['id']]
            item=_agent_finding(finding)
            item['triage_status']=row['triage_status']
            item['triage']=row['triage']
            if row['triage_status']=='VALID':
                item.update(verdict=row['triage']['verdict'],triage_confidence=row['triage']['confidence'],exploitability=row['triage']['exploitability'])
            found.append(item)
        return found

    @server.tool()
    def prepare_triage(scan_id: str, finding_ids: list[str] | None = None, categories: list[str] | None = None, limit: int = 20) -> dict:
        """Return bounded redacted UNTRUSTED_CODE evidence to this host agent; does not invoke AI."""
        check_scan(scan_id)
        from .triage import TriageService
        data=TriageService(runtime_engine().store).prepare(scan_id,finding_ids,categories,limit)
        return register_handoff(data)

    @server.tool()
    def submit_triage(scan_id: str, results: list[dict], triage_session: str) -> dict:
        """Validate structured host analysis and evidence references; preserves every raw finding."""
        check_scan(scan_id)
        session=triage_sessions.get(triage_session)
        if session is None or session[0]!=scan_id or time.monotonic()-session[2]>900:
            raise ValueError('Invalid or expired triage handoff session; prepare evidence again')
        if not results or len(results)>20 or any(not isinstance(item,dict) or
            session[1].get(item.get('finding_id'))!=item.get('context_hash') for item in results):
            raise ValueError('Triage result does not belong to this evidence handoff')
        if session[3] is not None:
            from .task_triage import TaskTriageService
            reference,workspace=session[3]
            resolved=TaskTriageService(runtime_engine().store).resolve(reference,workspace,
                bound_workspace=binding.root if binding else None)
            if resolved['status']!='RESOLVED':
                raise ValueError('Task changed or reference expired; refresh get_security_summary and prepare again')
        from .triage import TriageService
        data=TriageService(runtime_engine().store).submit(scan_id,results)
        if session[3] is not None:
            data['execution']={'host_result_accepted':True,'accepted_records':data['accepted'],
                               'patch_applied':False,'target_build':False,'tests_or_scanner_recheck':False}
        for item in results: session[1].pop(item['finding_id'],None)
        return data

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_runtime_info() -> dict:
        """Read runtime version/features and same-environment reconnect guidance. Check required tool subset, not exact count; never scans or writes state."""
        from .host_guidance import runtime_info
        return runtime_info(remediation_config=remediation.config)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_security_summary(workspace_path: str | None = None, scan_id: str | None = None, details: bool = False) -> dict:
        """Read workspace tasks without scans, AI or writes. User 'continue first' selects that response's recommended_tasks[0].continuation; never resolve T01 against a new summary."""
        from .security_summary import SecuritySummaryService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        path = engine.store.path if engine is not None else SQLiteStore.default_path()
        return SecuritySummaryService(ReadOnlySQLiteStore(path)).get(
            workspace_path, scan_id, details=details, bound_workspace=binding.root if binding else None)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_triage(task_ref: str, workspace_path: str | None = None, limit: int = 20, retry_failed: bool = False) -> dict:
        """Continue the displayed task using its task_ref, never T01 or user UUIDs. Host analyzes packets then submit_triage; no model invocation here."""
        from .task_triage import TaskTriageService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        from .triage import TriageService
        path=engine.store.path if engine is not None else SQLiteStore.default_path()
        service=TaskTriageService(ReadOnlySQLiteStore(path))
        resolved=service.resolve(task_ref,workspace_path,bound_workspace=binding.root if binding else None)
        if resolved['status']!='RESOLVED': return resolved
        data=service.prepare(resolved,TriageService(runtime_engine().store),limit=limit,retry_failed=retry_failed)
        return register_handoff(data,(task_ref,resolved['workspace'])) if data['packets'] else data

    @server.tool()
    def get_triage(scan_id: str) -> dict:
        """Independent triage coverage and grouped view; never changes scan coverage."""
        check_scan(scan_id)
        from .triage import TriageService
        return TriageService(runtime_engine().store).view(scan_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def prepare_task_fix(task_ref: str, workspace_path: str | None = None, remediation_ref: str | None = None) -> dict:
        """Prepare bounded constraints/evidence for the exact displayed task. Host edits; no scanner, model, network or writes here."""
        from .task_fix import TaskFixService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        if remediation_ref is not None:
            if binding is None:
                return remediation._fail('WORKSPACE_BINDING_REQUIRED')
            return remediation.prepare(remediation_ref, task_ref, bound_path(workspace_path))
        path = engine.store.path if engine is not None else SQLiteStore.default_path()
        service = TaskFixService(ReadOnlySQLiteStore(path))
        resolved = service.tasks.resolve(task_ref, workspace_path, bound_workspace=binding.root if binding else None)
        if resolved['status'] != 'RESOLVED':
            return resolved
        gate = remediation.task_gate(task_ref, resolved['workspace'])
        if gate is not None:
            return gate
        return service.prepare(task_ref, workspace_path,
            bound_workspace=binding.root if binding else None)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def confirm_remediation(confirmation_ref: str, task_ref: str, approve: bool, workspace_path: str | None = None) -> dict:
        """Only after an explicit user reply: report approve=true for permission or false for refusal. Never infer consent. Consume exact connection-local pending confirmation; no source, Secret, prompt or transcript input. Host choice is UNTRUSTED_HOST_REPORT, not authenticated human consent. Returns a bounded repair grant only after approval; stale/restarted references require refresh."""
        if binding is None:
            return remediation._fail('WORKSPACE_BINDING_REQUIRED')
        try:
            from .hook_state import no_links
            if workspace_path is not None and (not isinstance(workspace_path, str) or len(workspace_path) > 4096 or
                    '${' in workspace_path or any(ord(c) < 32 for c in workspace_path)):
                return remediation._fail('WORKSPACE_CLAIM_REJECTED')
            claim = Path(workspace_path) if workspace_path is not None else Path(binding.root)
            if not claim.is_absolute():
                return remediation._fail('WORKSPACE_CLAIM_REJECTED')
            candidate = Path(os.path.abspath(claim))
            if not candidate.is_relative_to(Path(binding.root)):
                return remediation._fail('WORKSPACE_CLAIM_REJECTED')
            no_links(candidate)
            root = bound_path(workspace_path)
            return remediation.confirm(confirmation_ref, task_ref, root, approve=approve)
        except Exception:
            return remediation._fail('CONFIRMATION_REJECTED_REFRESH_REQUIRED')

    confirmation_tool = server._tool_manager.get_tool('confirm_remediation')
    confirmation_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    confirmation_tool.fn_metadata.arg_model.model_rebuild(force=True)
    confirmation_tool.parameters = confirmation_tool.fn_metadata.arg_model.model_json_schema()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def prepare_functional_verification(remediation_ref: str, task_ref: str, workspace_path: str | None = None) -> dict:
        """Plan existing local verifiers only after Runtime-authorized repair has signed SCANNER_VERIFIED_RESOLVED. No shell/source/log/host status input; never runs builds in HookCoordinator."""
        return functional.prepare(remediation_ref,task_ref,workspace_path or (binding.root if binding else None),
                                  bound_workspace=binding.root if binding else None)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def run_functional_verification(functional_ref: str) -> dict:
        """Consume the current connection's exact bounded plan. Executes only with enforceable local isolation; otherwise NOT_AVAILABLE. Independent security/functional/production statuses, no auto-revert/retry or dependency downloads."""
        return functional.run(functional_ref,bound_workspace=binding.root if binding else None)

    for name in ('prepare_functional_verification','run_functional_verification'):
        tool = server._tool_manager.get_tool(name)
        tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
        tool.fn_metadata.arg_model.model_rebuild(force=True)
        tool.parameters = tool.fn_metadata.arg_model.model_json_schema()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def verify_task_fix(task_ref: str, workspace_path: str | None = None, host_reported_execution: dict[str, bool] | None = None, remediation_ref: str | None = None) -> dict:
        """Locally recheck every original task member with originating scanners/equivalence, bounded and offline. Never edits/builds target; engine caches/temp files may be written. Host reports are untrusted claims."""
        from .task_fix import TaskFixService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        if remediation_ref is not None:
            if binding is None:
                return remediation._fail('WORKSPACE_BINDING_REQUIRED')
            return remediation.verify(remediation_ref, task_ref, bound_path(workspace_path),
                                      host_reported_execution=host_reported_execution)
        path = engine.store.path if engine is not None else SQLiteStore.default_path()
        service = TaskFixService(ReadOnlySQLiteStore(path), getattr(engine, 'registry', None))
        resolved = service.tasks.resolve(task_ref, workspace_path, bound_workspace=binding.root if binding else None)
        if resolved['status'] != 'RESOLVED':
            return resolved
        gate = remediation.task_gate(task_ref, resolved['workspace'])
        if gate is not None:
            return gate
        return service.verify(
            task_ref, workspace_path, bound_workspace=binding.root if binding else None,
            host_reported_execution=host_reported_execution)

    @server.tool()
    def generate_fix(finding_id: str) -> dict:
        """Create a safe coding task without editing source."""
        check_finding(finding_id)
        result = runtime_engine().generate_fix(finding_id)
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, fix_generated=True), connected=True)
        return result

    @server.tool()
    def verify(finding_id: str, workspace_path: str | None = None) -> dict:
        """Recheck a finding with its originating scanner."""
        check_finding(finding_id)
        result = runtime_engine().verify(finding_id, bound_path(workspace_path))
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root, verify_result=result["status"]), connected=True)
        return result

    return server


def serve() -> None:
    create_server().run(transport="stdio")
