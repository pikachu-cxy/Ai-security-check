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
from .functional_host import FunctionalExecutionReport

logger = logging.getLogger(__name__)


def _agent_finding(finding: dict) -> dict:
    from .finding_quality import quality_finding
    result = {key: finding[key] for key in ("id", "category", "severity", "confidence", "plain_title", "file_path", "line_start", "line_end", "impact", "fix_advice", "technical_details", "triage_status", "verdict", "triage_confidence", "exploitability", "triage") if key in finding}
    try:
        result['quality'] = quality_finding(finding)
    except ValueError:
        # Never drop an existing scanner observation because a derived review
        # contract cannot safely represent its location.
        result['quality'] = None
        result['quality_diagnostic'] = 'INVALID_REVIEW_LOCATION'
    return result


def _agent_result(result) -> dict:
    from .target import selection_summary
    return {
        "scan_id": result.scan_id,
        "workspace": result.target_profile.path,
        "status": result.status,
        "execution_state": result.execution_state,
        "coverage_scope": result.coverage_scope,
        "capability_results": result.capability_results,
        "capability_details": result.capability_details,
        "rule_coverage": {key:value for key,value in result.rule_coverage.items() if key!='scope_files'},
        "background_preparation": result.background_preparation,
        "coverage": result.coverage,
        "summary": result.summary,
        "findings": [_agent_finding(f.__dict__) for f in result.findings],
        "recommendation": result.release_status,
        "duration_ms": result.duration_ms,
        "scanner_runs": [asdict(run) for run in result.scanner_runs],
        "target_selection": selection_summary(result.target_profile),
    }


def create_server(runtime: SecurityRuntime | None = None, *, remediation_factory=None,
                  hook_coordinator=None, workspace_binding=None, global_mode=None,
                  hook_advisory_only=False, include_functional_verification=False,
                  include_batch_review: bool | None = None):
    if include_batch_review is None:
        include_batch_review = os.getenv('SECURITY_RUNTIME_BATCH_REVIEW') == '1'
    if global_mode is True or (global_mode is None and os.getenv('SECURITY_RUNTIME_GLOBAL') == '1'):
        from .global_mcp import create_global_server
        return create_global_server(host=os.getenv('SECURITY_RUNTIME_HOST', 'codex'),
                                    include_batch_review=include_batch_review)
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
    from .host_guidance import HOST_INSTRUCTIONS
    instructions = HOST_INSTRUCTIONS
    if include_batch_review:
        from .host_guidance import EXPERIMENTAL_BATCH_INSTRUCTIONS
        instructions += '\n' + EXPERIMENTAL_BATCH_INSTRUCTIONS
    server = FastMCP("AI Security Runtime", instructions=instructions, log_level=mcp_log_level())
    from .remediation import RemediationService
    from .hook_runtime import HookCoordinator
    hook_coordinator = hook_coordinator or HookCoordinator(runtime)
    # Trusted embedding only, never environment/MCP claims. Default Codex has
    # no atomic edit bridge and cannot opt into Fast Fix through tool arguments.
    remediation = (remediation_factory or RemediationService)(getattr(runtime, 'store', None),
        hooks=hook_coordinator.store, registry=hook_coordinator.managed_registry())
    if remediation_factory is None:
        # Same connected MCP lifetime; ordinary command/embedded hosts keep the
        # legacy prepare contract unless their trusted constructor opts in.
        remediation.agent_tickets.enabled = True
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
    hook_tool = server._tool_manager.get_tool('handle_hook_event')
    hook_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    hook_tool.fn_metadata.arg_model.model_rebuild(force=True)
    hook_tool.parameters = hook_tool.fn_metadata.arg_model.model_json_schema()
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def handle_readiness_event(event: str, workspace_path: str, session_id: str,
                               permission_mode: str | None = None) -> dict:
        """Observe bound Codex SessionStart readiness only. Untrusted metadata claims; no prompt/source/transcript. Writes bounded hashed integration metadata, never scans, builds, calls a model or edits target source. Ready is not safe."""
        from .integration_readiness import handle_readiness
        from .codex_mcp_hook import codex_hook_output
        diag, rejected, normalized = lifecycle_claims(dict(event=event, workspace_path=workspace_path,
                                               session_id=session_id, permission_mode=permission_mode), 'SessionStart')
        data = rejected or handle_readiness(event, workspace_path, session_id, binding=binding,
                                           tools={t.name for t in server._tool_manager.list_tools()})
        if rejected:
            data.update({'continue': True, 'systemMessage': '安全检查尚未成功接入当前项目，暂时无法确认检查结果。'})
        data = {**diag, **data}
        return CallToolResult(structuredContent=data, content=[TextContent(
            type='text', text=json.dumps(codex_hook_output(data), ensure_ascii=False))])

    readiness_tool = server._tool_manager.get_tool('handle_readiness_event')
    readiness_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    readiness_tool.fn_metadata.arg_model.model_rebuild(force=True)
    readiness_tool.parameters = readiness_tool.fn_metadata.arg_model.model_json_schema()
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

    stop_tool = server._tool_manager.get_tool('handle_stop_event')
    stop_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    stop_tool.fn_metadata.arg_model.model_rebuild(force=True)
    stop_tool.parameters = stop_tool.fn_metadata.arg_model.model_json_schema()
    # Connection-local opaque handoffs hold hashes only, never packet source.
    triage_sessions={}

    def register_handoff(data, task_binding=None, continuation_args=None):
        expired=[key for key,value in triage_sessions.items() if time.monotonic()-value[2]>900]
        for key in expired: triage_sessions.pop(key,None)
        if len(triage_sessions)>=64: triage_sessions.pop(next(iter(triage_sessions)))
        token=secrets.token_urlsafe(32)
        triage_sessions[token]=(data['scan_id'],{p['finding_id']:p['context_hash'] for p in data['packets']},
                                time.monotonic(),task_binding,continuation_args)
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

    task_engine = None
    def task_service():
        nonlocal task_engine
        from .task_security import TaskSecurityService
        if task_engine is None:
            task_engine = TaskSecurityService(runtime_engine, hook_coordinator.store)
        return task_engine

    def batch_service():
        from .task_security_batch import TaskSecurityBatchService
        def read_scan(scan_id):
            # Read already-persisted observations only. This callback never
            # invokes a scanner and is not a current-version coverage proof.
            store = getattr(runtime_engine(), 'store', None)
            reader = getattr(store, 'get_scan', None)
            return reader(scan_id) if reader is not None else None
        return TaskSecurityBatchService(task_service(), scan_reader=read_scan)

    batch_tool_names = ()
    if include_batch_review:
        @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
        def prepare_security_batch(task_ref: str, checkpoint_key: str, workspace_path: str | None = None) -> dict:
            """Experimental checkpoint after synchronous file-edit Hooks return. Freeze bounded sanitized source and static records; no scan, model, build, edit or task finish. The host must enforce the returned restricted reviewer profile or use the legacy task-end workflow."""
            data = batch_service().prepare(bound_path(workspace_path), task_ref, checkpoint_key)
            return data

        @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
        def read_security_batch_context(task_ref: str, batch_ref: str, review_session: str,
                                        file_path: str, start_line: int = 1, end_line: int = 80,
                                        workspace_path: str | None = None) -> dict:
            """Read a version-pinned sanitized batch window; never substitute newer working-tree source. Evidence and cumulative task budgets are recorded. The dedicated reviewer connection binds all task/session identifiers at startup."""
            return batch_service().read(bound_path(workspace_path), task_ref, batch_ref,
                                        review_session, file_path, start_line, end_line)

        @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
        def submit_security_batch_review(task_ref: str, batch_ref: str, review_session: str,
                                         findings: list[dict], coverage: str, limitations: list[str],
                                         workspace_path: str | None = None) -> dict:
            """Parent host submits read-only reviewer output. Snapshot-valid historical results can be stored; current applicability is separate. No source edit, scanner proof, task completion or repair authority."""
            return batch_service().submit(bound_path(workspace_path), task_ref, batch_ref,
                                           review_session, findings, coverage, limitations)

        @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
        def get_security_batches(task_ref: str, workspace_path: str | None = None) -> dict:
            """Read batch execution, freshness and task coverage; never dispatch, scan or restart expired work."""
            return batch_service().get(bound_path(workspace_path), task_ref)

        batch_tool_names = ('prepare_security_batch', 'read_security_batch_context',
                            'submit_security_batch_review', 'get_security_batches')

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def begin_security_task(task_key: str, workspace_path: str | None = None) -> dict:
        """Before the first source/config edit of an actual development task, snapshot the current workspace (including existing dirty files). Unique task_key per task, no prompt/source. No scan/model/build/edit. Never call for ordinary chat or restart after editing to fake a baseline."""
        return task_service().begin(bound_path(workspace_path), task_key)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def finish_security_task(task_ref: str, workspace_path: str | None = None, skip_review_reason: str | None = None) -> dict:
        """Before the development summary, compare against the exact task baseline. No actual changes: no checks/message. Actual changes: one bounded static check of task scope, then prepare_task_security_review even with zero scanner alerts. No repairs, model, target builds or Stop continuation."""
        if skip_review_reason is not None:
            return task_service().skip(bound_path(workspace_path), task_ref, skip_review_reason)
        return task_service().finish(bound_path(workspace_path), task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_security_review(task_ref: str, workspace_path: str | None = None) -> dict:
        """Obtain sanitized task diff, actual static findings/coverage and canonical quick Skill. Host agent reasons before its final development summary; zero static alerts still require context review. Returns bounded source-version-bound review session, never a repair grant."""
        return task_service().prepare(bound_path(workspace_path), task_ref)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def read_task_review_context(task_ref: str, review_session: str, file_path: str,
                                 start_line: int = 1, end_line: int = 80, workspace_path: str | None = None,
                                 source_version: str = 'CURRENT') -> dict:
        """Read a sanitized task-source window (current or signed preimage for a deleted file). At most 80 lines per response: larger requested ranges return has_more/next_read for the same task/session/path/version. Follow next_read within the unchanged 10-related-file, 40-unique-read and 64KB cumulative budgets. Unread requested ranges require PARTIAL; pagination never rescans or resets budgets. Correct recoverable CONTEXT_REQUEST_REJECTED parameters in the same session; unsupported documentation is not a connection failure. Returns evidence_id bound to actual path/range/hash/version. No .env content, links, path escapes, external commands or network."""
        from .task_security import TaskContextError
        try:
            return task_service().read(bound_path(workspace_path), task_ref, review_session, file_path, start_line, end_line, source_version)
        except TaskContextError as exc:
            return exc.response(task_ref, review_session)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def submit_task_security_review(task_ref: str, review_session: str, findings: list[dict],
                                    coverage: str, limitations: list[str], workspace_path: str | None = None,
                                    risk_resolutions: list[dict] | None = None,
                                    integration_review: dict | None = None) -> dict:
        """Submit host reasoning with Runtime-issued evidence. See packet submission_contract. Accepts only current task versions, bounded candidates and explicit limitations; validates structure/version, never proves exploitability or scanner coverage. Merge development_summary into normal dev response; do not ask user to continue."""
        return task_service().submit(bound_path(workspace_path), task_ref, review_session, findings,
                                     coverage, limitations, risk_resolutions, integration_review=integration_review)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_security_review(task_ref: str, workspace_path: str | None = None, finding_offset: int = 0, finding_limit: int = 20) -> dict:
        """Read same task result after reconnect with current-source freshness. Never rescans or invokes a model; host candidates and real scanner evidence stay distinct. No automatic repair authority."""
        return task_service().get(bound_path(workspace_path), task_ref, finding_offset, finding_limit)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_task_risk_ledger(task_ref: str, workspace_path: str | None = None, offset: int = 0, limit: int = 30) -> dict:
        """Read per-original-finding outcomes and current-source freshness. No scan, edits or repair authority. Native checks and host code review remain distinct; use exact original task_ref."""
        return task_service().risk_ledger(bound_path(workspace_path), task_ref, offset, limit)

    for task_tool_name in ('begin_security_task', 'finish_security_task', 'prepare_task_security_review',
                           'read_task_review_context', 'submit_task_security_review', 'get_task_security_review', 'get_task_risk_ledger') + batch_tool_names:
        task_tool = server._tool_manager.get_tool(task_tool_name)
        task_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
        task_tool.fn_metadata.arg_model.model_rebuild(force=True)
        task_tool.parameters = task_tool.fn_metadata.arg_model.model_json_schema()

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

    @server.tool()
    def scan_diff(workspace_path: str | None = None, mode: str = "quick", path: str | None = None, summary: bool = False) -> dict:
        """Scan changed files in a local Git repository."""
        if mode not in {"quick", "feature"}:
            raise ValueError("mode must be quick or feature")
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        logger.info("scan_diff started")
        root = bound_path(workspace_path if workspace_path is not None else path)
        from .target import DiscoveryLimitError
        try:
            result = runtime_engine().scan(root, mode)
        except DiscoveryLimitError as exc:
            return exc.to_dict()
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           mode, result.duration_ms, len(result.findings), result.coverage), connected=True)
        logger.info("scan_diff finished scan_id=%s", result.scan_id)
        return scan_response(result, summary)

    @server.tool()
    def scan_project(workspace_path: str | None = None, path: str | None = None, summary: bool = False) -> dict:
        """Run a full local project scan."""
        if workspace_path is not None and path is not None and workspace_path != path:
            raise ValueError("Specify only one workspace path")
        root = bound_path(workspace_path if workspace_path is not None else path)
        from .target import DiscoveryLimitError
        try:
            result = runtime_engine().scan(root, "release")
        except DiscoveryLimitError as exc:
            return exc.to_dict()
        event(DogfoodEvent(binding.integration_id if binding else "generic-mcp", result.target_profile.path,
                           "release", result.duration_ms, len(result.findings), result.coverage), connected=True)
        return scan_response(result, summary)

    def scan_response(result, summary):
        data = _agent_result(result)
        if summary:
            data['finding_count'] = len(data.pop('findings'))
            data['findings_access'] = {'tool':'get_findings', 'arguments':{
                'scan_id':result.scan_id, 'view':'summary', 'limit':20}}
        return data

    @server.tool()
    def get_findings(scan_id: str, include_evidence: bool = False, finding_id: str | None = None, context_lines: int = 5,
                     view: str = 'full', offset: int = 0, limit: int | None = None) -> list[dict] | dict:
        """List findings/review state; opt into bounded redacted local evidence, optionally for one existing scanner id. Evidence distinguishes original EXACT code from STALE/unverifiable current_context. quality.finding_id remains review-only."""
        check_scan(scan_id)
        from .mcp_views import page_bounds, finding_summary, paged
        page_limit = page_bounds(view, offset, limit, evidence=include_evidence)
        if not 0 <= context_lines <= 20:
            raise ValueError('Context lines must be between 0 and 20')
        from .local_evidence import LocalEvidenceService
        local_evidence = LocalEvidenceService(runtime_engine().store.get_scan(scan_id)) if include_evidence else None
        if binding:
            event(DogfoodEvent(binding.integration_id, binding.root), connected=True)
        from .triage import TriageService
        triage_view=TriageService(runtime_engine().store).view(scan_id)
        rows={row['finding_id']:row for row in triage_view['findings']}
        from .finding_quality import FindingQualityService
        from .storage import ReadOnlySQLiteStore
        try:
            quality = FindingQualityService(ReadOnlySQLiteStore(runtime_engine().store.path)).view(scan_id)
            quality_rows = {r['scanner_finding_id']: r for r in quality['findings']}
        except ValueError:
            quality_rows = {}
        originals = [f for f in runtime_engine().get_findings(scan_id)
                     if finding_id is None or f['id'] == finding_id]
        if finding_id is not None and not originals:
            raise ValueError('Finding does not belong to this scan')
        selected = originals if view == 'full' else originals[offset:offset+page_limit]
        found=[]
        for finding in selected:
            row=rows[finding['id']]
            item=_agent_finding(finding)
            if finding['id'] in quality_rows:
                item['quality'] = quality_rows[finding['id']]
            else:
                item['quality_diagnostic'] = 'QUALITY_REVIEW_UNAVAILABLE'
            item['triage_status']=row['triage_status']
            item['triage']=row['triage']
            if row['triage_status']=='VALID':
                item.update(verdict=row['triage']['verdict'],triage_confidence=row['triage']['confidence'],exploitability=row['triage']['exploitability'])
            if local_evidence is not None:
                item['local_evidence'] = local_evidence.detail(finding, context_lines)
            found.append(finding_summary(item) if view == 'summary' else item)
        if view == 'full': return found
        return paged(found, len(originals), offset, page_limit, tool='get_findings', arguments={
            'scan_id':scan_id, 'view':view, 'include_evidence':include_evidence,
            'finding_id':finding_id, 'context_lines':context_lines})

    @server.tool()
    def prepare_triage(scan_id: str, finding_ids: list[str] | None = None, categories: list[str] | None = None, limit: int = 20,
                       pending_only: bool = False, retry_failed: bool = False) -> dict:
        """Return bounded redacted UNTRUSTED_CODE evidence to this host agent; does not invoke AI."""
        check_scan(scan_id)
        from .triage import TriageService
        data=TriageService(runtime_engine().store).prepare(scan_id,finding_ids,categories,limit,
            pending_only=pending_only,retry_failed=retry_failed)
        return register_handoff(data, continuation_args={'scan_id':scan_id,
            'finding_ids':finding_ids,'categories':categories,'limit':min(limit,5),
            'pending_only':True,'retry_failed':retry_failed})

    @server.tool()
    def submit_triage(scan_id: str, results: list[dict], triage_session: str, compact: bool = False) -> dict:
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
        data=TriageService(runtime_engine().store).submit(scan_id,results,compact=compact)
        if session[3] is not None:
            data['execution']={'host_result_accepted':True,'accepted_records':data['accepted'],
                               'patch_applied':False,'target_build':False,'tests_or_scanner_recheck':False}
        for item in results: session[1].pop(item['finding_id'],None)
        if compact:
            data['handoff_remaining'] = len(session[1])
            if session[3] is not None:
                data['continuation']={'tool':'prepare_task_triage','arguments':{
                    'task_ref':session[3][0],'workspace_path':session[3][1],
                    'limit':5,'include_existing_reviews':False}}
            else:
                data['continuation']={'tool':'prepare_triage','arguments':session[4]}
        return data

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_runtime_info() -> dict:
        """Read runtime version/features and same-environment reconnect guidance. Check required tool subset, not exact count; never scans or writes state."""
        from .host_guidance import runtime_info
        return runtime_info(remediation_config=remediation.config,
                            include_functional_verification=include_functional_verification,
                            include_batch_review=include_batch_review)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_professional_guidance() -> dict:
        """Read product-owned versioned deep-audit guidance. No workspace/source/URL input, network, scan, repair permission or writes. Ordinary Hooks do not invoke this tool."""
        from .professional_guidance import get_professional_guidance as load_guidance
        return load_guidance()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_scan_preparation_status() -> dict:
        """Read current component diagnoses, repair guidance and background progress; no download or scan.
        component_health.notify reports new faults/recovery once across connections.
        If notify=false, do not repeat prior alerts. Explicit status questions may
        still describe current availability. receipt/current_readiness reflect
        current checks; background_status/background_receipt are historical and
        must not be described as an active stalled job. No pending scan is resumed.
        Readiness is not project scan proof.
        """
        from .background_preparation import read_preparation_status
        return read_preparation_status()

    guidance_tool = server._tool_manager.get_tool('get_professional_guidance')
    guidance_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    guidance_tool.fn_metadata.arg_model.model_rebuild(force=True)
    guidance_tool.parameters = guidance_tool.fn_metadata.arg_model.model_json_schema()

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_security_summary(workspace_path: str | None = None, scan_id: str | None = None, details: bool = False) -> dict:
        """Read workspace tasks without scans, AI or writes. User 'continue first' selects that response's recommended_tasks[0].continuation; never resolve T01 against a new summary."""
        from .security_summary import SecuritySummaryService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        path = engine.store.path if engine is not None else SQLiteStore.default_path()
        return SecuritySummaryService(ReadOnlySQLiteStore(path), hooks=hook_coordinator.store).get(
            workspace_path, scan_id, details=details, bound_workspace=binding.root if binding else None)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def prepare_task_triage(task_ref: str, workspace_path: str | None = None, limit: int = 20, retry_failed: bool = False,
                            include_existing_reviews: bool = True) -> dict:
        """Continue the displayed task using its task_ref, never T01 or user UUIDs. Host analyzes packets then submit_triage; no model invocation here."""
        from .task_triage import TaskTriageService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        from .triage import TriageService
        path=engine.store.path if engine is not None else SQLiteStore.default_path()
        service=TaskTriageService(ReadOnlySQLiteStore(path))
        resolved=service.resolve(task_ref,workspace_path,bound_workspace=binding.root if binding else None)
        if resolved['status']!='RESOLVED': return resolved
        data=service.prepare(resolved,TriageService(runtime_engine().store),limit=limit,retry_failed=retry_failed)
        if not include_existing_reviews:
            data.pop('existing_reviews',None)
            data['existing_reviews_truncated'] = bool(data['existing_review_count'])
        return register_handoff(data,(task_ref,resolved['workspace'])) if data['packets'] else data

    @server.tool()
    def get_triage(scan_id: str, view: str = 'full', offset: int = 0, limit: int | None = None) -> dict:
        """Independent triage coverage and grouped view; never changes scan coverage."""
        check_scan(scan_id)
        from .triage import TriageService
        from .mcp_views import page_bounds, paged
        page_limit=page_bounds(view,offset,limit)
        data=TriageService(runtime_engine().store).view(scan_id)
        if view == 'full': return data
        rows=data.pop('findings')
        selected=rows[offset:offset+page_limit]
        if view == 'summary':
            selected=[{k:v for k,v in row.items() if k!='triage'} | {
                'verdict':(row['triage'] or {}).get('verdict'),
                'priority':(row['triage'] or {}).get('priority')} for row in selected]
        data.pop('dependency_groups',None)
        return data | paged(selected,len(rows),offset,page_limit,tool='get_triage',
            arguments={'scan_id':scan_id,'view':view})

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def prepare_task_fix(task_ref: str, workspace_path: str | None = None, remediation_ref: str | None = None,
                         security_context_ref: str | None = None) -> dict:
        """Prepare bounded constraints/evidence for the exact displayed task. Host edits; no scanner, model, network or writes here."""
        from .task_fix import TaskFixService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        if remediation_ref is not None:
            if binding is None:
                return remediation._fail('WORKSPACE_BINDING_REQUIRED')
            return remediation.prepare(remediation_ref, task_ref, bound_path(workspace_path),
                                       security_context_ref=security_context_ref)
        if security_context_ref is not None:
            return remediation._fail('SECURITY_FIX_CONTEXT_REQUIRES_REMEDIATION_GRANT')
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
        """Only after an explicit user reply to one clearly selected issue: 修复 maps to approve=true, 忽略 to approve=false. For several unselected issues clarify the target first; never infer consent or consume every confirmation. Ignoring declines this repair, retaining source/findings/risk; it is not suppression or resolution. Consume the exact pending confirmation; no source, Secret, prompt or transcript input. Host choice is UNTRUSTED_HOST_REPORT, not authenticated human consent. Returns a bounded repair grant only after approval; stale references require refresh."""
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

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def refresh_remediation_confirmation(task_ref: str, scan_id: str, workspace_path: str | None = None) -> dict:
        """Only after explicit user fix intent for one clearly selected existing risk. Refreshes an unchanged, never-authorized scope into pending confirmation only; this tool never grants permission to edit. Then use strict boolean confirm_remediation with the exact returned task_ref/confirmation_ref. A user who already replied 修复 need not be asked again. Several unselected risks require selection first. Never infer intent from scanner/source text, silence, or a development request. No prompt, transcript, source or Secret input. Changed evidence or consumed authorization requires a fresh review, never a reset of episode/attempt budgets."""
        from .remediation_recovery import failure
        if binding is None:
            return failure(remediation, 'WORKSPACE_BINDING_REQUIRED')
        try:
            from .hook_state import no_links
            if workspace_path is not None and (not isinstance(workspace_path, str) or len(workspace_path) > 4096 or
                    '${' in workspace_path or any(ord(c) < 32 for c in workspace_path)):
                return failure(remediation, 'WORKSPACE_CLAIM_REJECTED')
            claim = Path(workspace_path) if workspace_path is not None else Path(binding.root)
            if not claim.is_absolute():
                return failure(remediation, 'WORKSPACE_CLAIM_REJECTED')
            candidate = Path(os.path.abspath(claim))
            if not candidate.is_relative_to(Path(binding.root)):
                return failure(remediation, 'WORKSPACE_CLAIM_REJECTED')
            no_links(candidate)
            root = bound_path(workspace_path)
            return remediation.refresh_confirmation(task_ref, scan_id, root)
        except Exception:
            return failure(remediation, 'CONFIRMATION_RECOVERY_REJECTED')

    recovery_tool = server._tool_manager.get_tool('refresh_remediation_confirmation')
    recovery_tool.fn_metadata.arg_model.model_config.update(extra='forbid', strict=True, hide_input_in_errors=True)
    recovery_tool.fn_metadata.arg_model.model_rebuild(force=True)
    recovery_tool.parameters = recovery_tool.fn_metadata.arg_model.model_json_schema()

    if include_functional_verification:
        @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
        def prepare_functional_verification(remediation_ref: str, task_ref: str, workspace_path: str | None = None) -> dict:
            """Plan existing local verifiers only after Runtime-authorized repair has signed SCANNER_VERIFIED_RESOLVED. No shell/source/log/host status input; never runs builds in HookCoordinator."""
            output = functional.prepare(remediation_ref,task_ref,workspace_path or (binding.root if binding else None),
                                        bound_workspace=binding.root if binding else None)
            if output.get('security_verification', {}).get('status') == 'SCANNER_VERIFIED_RESOLVED':
                pair = (remediation_ref, task_ref)
                if pair not in deep_requests:
                    deep_requests.append(pair)
            return output

        @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
        def run_functional_verification(functional_ref: str, execution_result: FunctionalExecutionReport | None = None) -> dict:
            """Accept bounded untrusted host execution results for the exact plan. Without a report returns the host plan; Runtime never executes target commands. No argv/shell override/source/raw logs/Secret input. Functional reports cannot alter scanner facts."""
            return functional.run(functional_ref, execution_result=execution_result,
                                  bound_workspace=binding.root if binding else None)

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
            root = bound_path(workspace_path)
            checked = remediation.verify(remediation_ref, task_ref, root,
                                         host_reported_execution=host_reported_execution)
            if (remediation_ref, task_ref) in deep_requests:
                return functional.finalize(remediation_ref, task_ref, Path(root), checked)
            return checked
        path = engine.store.path if engine is not None else SQLiteStore.default_path()
        service = TaskFixService(ReadOnlySQLiteStore(path), getattr(engine, 'registry', None), hooks=hook_coordinator.store)
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

    from .recent_hooks import install_project_observer
    install_project_observer(server, binding)
    return server


def serve() -> None:
    create_server().run(transport="stdio")
