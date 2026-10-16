"""Thin user-level MCP router; security logic remains workspace-bound."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .global_workspace import (resolve_workspace, workspace_state, source_snapshot, write_bootstrap,
                               workspace_rejection, WORKSPACE_REJECTIONS)
from .hook_state import HookStateStore, identity, no_links
from .integration_state import WorkspaceBinding
from .workspace import WorkspaceResolver
from .host_events import EventKind, OperationClass
from .codex_event_adapter import CodexEventAdapter

HOOKS = {'handle_readiness_event', 'handle_hook_event', 'handle_stop_event'}
GLOBAL_READS = {'get_runtime_info', 'get_professional_guidance', 'get_scan_preparation_status'}
LIMIT = 16
MAX_SESSIONS = 64
# Leave room for admission/transport within the native 30-second startup Hook.
# Waiting reuses the existing job; it never starts another baseline scan.
BOOTSTRAP_WAIT_SECONDS = 20


def global_runtime_info(*, include_batch_review=False):
    from .host_guidance import runtime_info
    info = runtime_info(include_batch_review=include_batch_review)
    info['features'] = {**info['features'], 'global_runtime_integration': 'v0.1'}
    info['integration_scope'] = 'GLOBAL'
    info['workspace_routing'] = 'EXPLICIT_WORKSPACE_CLAIM'
    return info


class GlobalWorkspaces:
    def __init__(self, *, base=None, integration=None, child_factory=None, host='codex', include_batch_review=False):
        from .host_connectors import connector
        self.connector = connector(host)
        self.host = host
        from .storage import SQLiteStore
        self.base = Path(base or SQLiteStore.default_path().parent / ('cursor-workspaces' if host == 'cursor' else 'global-workspaces')).absolute()
        no_links(self.base)
        if integration is None:
            if host == 'cursor':
                from .cursor_connector import CursorConnectorInstallation
                integration = CursorConnectorInstallation()
            else:
                from .global_integration import GlobalCodexIntegration
                integration = GlobalCodexIntegration(home=os.getenv('SECURITY_RUNTIME_CODEX_HOME'))
        self.integration = integration
        self.child_factory = child_factory or (lambda root, directory, binding: self._child(
            root, directory, binding, include_batch_review=include_batch_review))
        self.children = {}
        self.sessions = {}
        from .codex_host_claims import CodexClaimGuard
        self.claim_guard = CodexClaimGuard()
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='runtime-bootstrap')
        self.lock = threading.RLock()

    @staticmethod
    def _child(root, directory, binding, *, include_batch_review=False):
        from .mcp_server import create_server
        from .workspace_services import workspace_services
        from .remediation import RemediationService
        from .remediation_policy import RemediationConfig
        runtime, core, is_git = workspace_services(root, directory)
        def remediation_factory(store, **kwargs):
            # User policy stays user-wide; grants/proofs/DB stay workspace-local.
            return RemediationService(store, config=RemediationConfig(), inline_agent_tickets=True, **kwargs)
        server = create_server(runtime, hook_coordinator=core, remediation_factory=remediation_factory,
                               workspace_binding=binding, global_mode=False, hook_advisory_only=not is_git,
                               include_batch_review=include_batch_review)
        # Same explicit connected-Hook opt-in as the existing default factory.
        # Do not enable deterministic source writes or Deep verification here.
        return server, core

    def root(self, value):
        return resolve_workspace(value, excluded=(self.base, self.integration.home))

    def admit(self, root):
        with self.lock:
            if root in self.children:
                return self.children[root]
            if len(self.children) >= LIMIT:
                raise ValueError('WORKSPACE_CONNECTION_BUDGET_EXCEEDED')
            # Installed config fingerprints are checked without recursively
            # starting a probe MCP process or consulting Codex private state.
            health = self.integration.configuration_status()
            if health['overall'] != 'CONFIGURED':
                raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
            rows = self.integration.inspect_project(root)
            if any(row['related'] for row in rows):
                raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')
            directory = workspace_state(root, self.base)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            no_links(directory)
            workspace = WorkspaceResolver().resolve(root, allow_non_git_source=True)
            binding = WorkspaceBinding(identity(os.path.normcase(str(root)))[:24], str(root),
                                       str(root) if workspace.is_git else '', self.host, 'PROJECT', '')
            self.children[root] = self.child_factory(root, directory, binding)
            return self.children[root]

    def validate_layers(self, cwd):
        if self.integration.configuration_status()['overall'] != 'CONFIGURED':
            raise ValueError('GLOBAL_CONFIGURATION_NOT_READY')
        if any(row['related'] for row in self.integration.inspect_project(cwd)):
            raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')

    def bind_session(self, session, root):
        if (not isinstance(session, str) or not session.strip() or len(session) > 500
            or '${' in session or any(ord(c) < 32 for c in session)):
            raise ValueError('INVALID_SESSION_CLAIM')
        key = hashlib.sha256(session.encode()).hexdigest()
        with self.lock:
            if key in self.sessions and self.sessions[key] != root:
                raise ValueError('SESSION_WORKSPACE_MISMATCH')
            if key not in self.sessions and len(self.sessions) >= MAX_SESSIONS:
                raise ValueError('SESSION_CONNECTION_BUDGET_EXCEEDED')
            self.sessions[key] = root
        return key

    def binding_diagnostics(self, root, session):
        """Observe existing canonical registration; never create a binding."""
        key = hashlib.sha256(session.encode()).hexdigest()
        with self.lock:
            bound = self.sessions.get(key)
            return {'workspace_registered': root in self.children,
                    'registered_workspace_hash': identity(os.path.normcase(str(root))) if root in self.children else None,
                    'session_binding_present': bound is not None,
                    'session_workspace_hash': identity(os.path.normcase(str(bound))) if bound is not None else None}

    def bootstrap(self, root, session):
        key = (root, self.bind_session(session, root))
        _, core = self.admit(root)
        with self.lock:
            future = self.jobs.get(key)
            if future is None:
                write_bootstrap(root, 'INITIALIZING', 'NOT_ESTABLISHED', base=self.base)
                future = self.executor.submit(self._initialize, root, session, core)
                self.jobs[key] = future
                return {'status': 'INITIALIZING', 'previous_status': 'NEW_WORKSPACE', 'security_proof': False}
            if not future.done():
                return {'status': 'INITIALIZING', 'security_proof': False}
            return future.result()

    def _initialize(self, root, session, core):
        from .hooks import HookEvent
        from .baseline_seed import WorkspaceBaselineSeeds
        from .progress import ScanCancelled
        try:
            is_git = WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git
            if is_git:
                # A clean tracked file may already contain a risk. Dirty-only
                # initialization would misattribute that risk to a later edit.
                snapshot = WorkspaceBaselineSeeds(integration=self.integration, coordinator=core).capture_session(root, session)
                result = snapshot['last_result']
                status = 'READY'
            else:
                result = core.handle(HookEvent.SESSION_START, root, 'codex', session, _baseline_only=True)
                persisted, _ = core.store.load(core.store.path(root, 'codex', session))
                valid = persisted is not None and persisted['change_digest'] == result.get('change_digest')
                status = 'READY' if valid and (result.get('baseline_comparison_usable') is True
                    or result.get('baseline_comparison_usable') is None and result.get('coverage') in {'FULL', 'SCOPED'}
                    or result.get('coverage') == 'NONE' and not result.get('scanner_runs')) else 'DEGRADED'
            write_bootstrap(root, status, result['status'], base=self.base)
            gaps = (snapshot if is_git else persisted or {}).get('unproven_sast_files') or []
            return {'status': status, 'baseline_status': result['status'],
                    'baseline_coverage': result['coverage'],
                    'baseline_capabilities': result['capabilities'],
                    'baseline_unproven_code_file_count': len(gaps),
                    'baseline_unproven_code_files': gaps[:20],
                    'baseline_code_gaps_truncated': len(gaps) > 20,
                    'target_selection': getattr(core.snapshot_capture(root, core.store.key(root)), 'target_selection', None),
                    'security_proof': False, 'initial_scope': 'BOUNDED_QUICK_BASELINE'}
        except ScanCancelled:
            write_bootstrap(root, 'DEGRADED', 'BASELINE_DEADLINE_EXCEEDED', base=self.base)
            return {'status': 'DEGRADED', 'reason_code': 'BASELINE_DEADLINE_EXCEEDED', 'security_proof': False}
        except (ValueError, OSError):
            write_bootstrap(root, 'DEGRADED', 'BASELINE_CHECK_INCONCLUSIVE', base=self.base)
            return {'status': 'DEGRADED', 'reason_code': 'BASELINE_CHECK_INCONCLUSIVE', 'security_proof': False}
        except Exception:
            write_bootstrap(root, 'ERROR', 'INITIALIZATION_INCONCLUSIVE', base=self.base)
            return {'status': 'ERROR', 'reason_code': 'INITIALIZATION_INCONCLUSIVE', 'security_proof': False}

    async def wait_for_bootstrap(self, root, session, readiness):
        """Keep startup ahead of edits, without cancelling a slow worker.

        SessionStart is the only caller. Read-only events and ordinary edits do
        not acquire a new wait, start a scan, or manufacture a pre-edit baseline.
        """
        if readiness.get('status') != 'INITIALIZING':
            return readiness
        key = (root, self.bind_session(session, root))
        with self.lock:
            future = self.jobs.get(key)
        if future is None:
            return readiness
        wrapped = asyncio.wrap_future(future)
        try:
            return await asyncio.wait_for(asyncio.shield(wrapped), BOOTSTRAP_WAIT_SECONDS)
        except TimeoutError:
            return readiness

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)


class _NoProjectSeed:
    @staticmethod
    def load(root):
        return None, 'GLOBAL_SESSION_BASELINE'


def _advisory(reason, readiness=None, claims=None, recovery=None):
    from mcp.types import CallToolResult, TextContent
    data = {'status': 'INCONCLUSIVE', 'reason_code': reason, 'coverage': 'UNKNOWN',
            'scanner_run': False, 'workspace_readiness': readiness or {'status': 'DEGRADED'},
            'source_modified': False, 'security_proof': False}
    if claims is not None:
        data.update(claims)
        data['scanner_skipped_reason'] = reason
    from .integration_readiness import readiness_message
    message = {
        'WORKSPACE_INITIALIZING': readiness_message('INITIALIZING'),
        'WORKSPACE_DEGRADED': readiness_message('DEGRADED'),
        'WORKSPACE_ERROR': readiness_message('ERROR'),
        'WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE': '缺少改动前的检查记录，暂时无法确定风险是否由本次改动引入。当前结果不能证明改动安全。',
    }.get(reason, '本次安全检查未完成，暂时无法确认改动是否安全。建议先检查工具连接和项目设置。')
    text = {'continue': True, 'systemMessage': message}
    if recovery is not None:
        data['configuration_recovery'] = recovery
        text['systemMessage'] += ' ' + recovery['message']
        if recovery.get('question'):
            text['systemMessage'] += ' ' + recovery['question']
    return CallToolResult(structuredContent=data, content=[TextContent(type='text', text=json.dumps(text))])


def create_global_server(*, workspaces=None, host='codex', include_batch_review=False):
    from .mcp_server import create_server
    from mcp.types import CallToolResult, TextContent
    from jsonschema import Draft202012Validator
    # Obtain the original registry/instructions without creating a writable DB.
    server = create_server(global_mode=False, include_batch_review=include_batch_review)
    pool = workspaces or GlobalWorkspaces(host=host, include_batch_review=include_batch_review)
    active_host = getattr(pool, 'host', host)
    server.global_workspaces = pool
    server._mcp_server.instructions += ('\nGlobal host integration: workspace_path is an untrusted claim. '
        'For every workspace tool supply the current workspace_path, even if only one workspace is admitted. '
        'Never infer a workspace from an opaque reference or use the last workspace. '
        'INITIALIZING/DEGRADED readiness is not a security proof; Core Hooks never request Deep Verification.')
    original_tools = server._tool_manager
    infos = {t.name: t for t in original_tools.list_tools() if active_host != 'cursor' or t.name not in HOOKS}
    if active_host == 'cursor':
        from .host_connectors import CURSOR_INSTRUCTIONS
        server._mcp_server.instructions += CURSOR_INSTRUCTIONS

    async def listed():
        from mcp.types import Tool
        result = []
        for tool in infos.values():
            schema = json.loads(json.dumps(tool.parameters))
            schema['additionalProperties'] = False
            if tool.name not in HOOKS and tool.name not in GLOBAL_READS and 'workspace_path' not in schema['properties']:
                schema['properties']['workspace_path'] = {'anyOf': [{'type': 'string'}, {'type': 'null'}], 'default': None,
                    'description': 'Required for global workspace routing, including a single admitted workspace. Never inferred from an opaque ref.'}
            description = tool.description
            if tool.name in HOOKS:
                description = 'Global cwd-routed Hook. ' + description.replace('Requires SECURITY_RUNTIME_WORKSPACE binding;', 'Requires validated workspace admission;')
            result.append(Tool(name=tool.name, description=description, inputSchema=schema,
                               outputSchema=tool.output_schema, annotations=tool.annotations))
        return result

    schemas = None
    host_adapter = CodexEventAdapter()

    async def call(name, arguments):
        nonlocal schemas
        if schemas is None:
            schemas = {t.name: t.inputSchema for t in await listed()}
        from .codex_host_claims import EVENTS
        claim_diag = (host_adapter.validate_claims(arguments, EVENTS[name], schemas[name])
                      if name in HOOKS and name in schemas else None)
        if (name not in schemas or not isinstance(arguments, dict)
                or not Draft202012Validator(schemas[name]).is_valid(arguments)
                or claim_diag is not None and claim_diag['host_claim_status'] != 'VALID'):
            return _advisory('INVALID_HOST_CLAIMS', claims=claim_diag)
        if name == 'get_runtime_info':
            info = global_runtime_info(include_batch_review=include_batch_review)
            info['host_connector'] = active_host
            return CallToolResult(structuredContent=info, content=[TextContent(type='text', text=json.dumps(info))])
        if name == 'get_professional_guidance':
            from .professional_guidance import get_professional_guidance
            guide = get_professional_guidance()
            return CallToolResult(structuredContent=guide, content=[TextContent(type='text', text=json.dumps(guide))])
        if name == 'get_scan_preparation_status':
            from .background_preparation import read_preparation_status
            value = read_preparation_status()
            return CallToolResult(structuredContent=value, content=[TextContent(type='text', text=json.dumps(value))])
        handler_entered = False
        binding_stage = 'RESOLVING_ROOT'
        try:
            claim = arguments.get('workspace_path')
            alias = arguments.get('path') if name in {'scan_diff', 'scan_project'} else None
            if claim is None and alias is not None:
                claim = alias
            if claim is not None:
                root = pool.root(claim)
            else:
                raise ValueError('WORKSPACE_CLAIM_REQUIRED')
            if claim_diag is not None:
                # Only compare filesystem identities after the strict resolver
                # has rejected links, unsafe roots and traversal. Subdirectories
                # bind to the nearest Git root; registration is not a prerequisite.
                candidate = Path(claim).resolve(strict=True)
                if not candidate.is_relative_to(root):
                    raise ValueError('WORKSPACE_CANONICALIZATION_MISMATCH')
                claim_diag.update(workspace_claim_match=True,
                    workspace_claim_hash=identity(os.path.normcase(str(candidate))),
                    resolved_workspace_hash=identity(os.path.normcase(str(root))),
                    workspace_relation='SAME_ROOT' if candidate == root else 'SUBDIRECTORY',
                    workspace_rejection_reason=None)
                claim_diag.update(pool.binding_diagnostics(root, arguments['session_id']))
            if alias is not None and pool.root(alias) != root:
                raise ValueError('WORKSPACE_CLAIM_REQUIRED')
            binding_stage = 'VALIDATING_CONFIGURATION'
            if claim_diag is not None:
                claim_diag['workspace_binding_stage'] = binding_stage
                from .recent_hooks import observe
                observe('HOOK_RECEIVED', **claim_diag)
            pool.validate_layers(claim or root)
            binding_stage = 'ADMITTING_WORKSPACE'
            child, _ = pool.admit(root)
            if name in HOOKS:
                claim_diag.update(pool.binding_diagnostics(root, arguments['session_id']))
                binding_stage = 'BINDING_SESSION'
                pool.bind_session(arguments['session_id'], root)
                claim_diag['session_claim_match'] = True
                claim_diag.update(pool.binding_diagnostics(root, arguments['session_id']))
                binding_stage = 'VALIDATING_INVOCATION'
                rejected = host_adapter.accept_invocation(arguments, root, claim_diag, pool.claim_guard)
                if rejected:
                    claim_diag.update(workspace_binding_stage=binding_stage, workspace_rejection_reason=rejected)
                    return _advisory(rejected, claims=claim_diag)
                claim_diag['workspace_binding_stage'] = binding_stage
                from .recent_hooks import observe
                observe('CLAIMS_VALID', **claim_diag)
                normalized = host_adapter.normalize(arguments, root, binding_diagnostics=claim_diag)
                claim_diag.update(normalized.diagnostics())
                classification = host_adapter.legacy_classification(normalized)
                read_only_hook = (normalized.kind == EventKind.WORKSPACE_ACTIVITY
                                  and normalized.operation == OperationClass.READ_ONLY)
                if normalized.kind == EventKind.WORKSPACE_ACTIVITY:
                    observe('CLAIMS_VALID', tool_classification=classification, **normalized.diagnostics())
            if name in HOOKS and not read_only_hook and normalized.kind != EventKind.SESSION_STOP:
                binding_stage = 'BOOTSTRAPPING'
                claim_diag['workspace_binding_stage'] = binding_stage
                pre_snapshot_missing = False
                if normalized.kind == EventKind.WORKSPACE_ACTIVITY:
                    core = pool.children[root][1]
                    previous, _ = core.store.load(core.store.path(root, normalized.context.host, normalized.context._session))
                    pre_snapshot_missing = previous is None
                    if pre_snapshot_missing:
                        observe('RECONCILIATION_STARTED', snapshot_available=False,
                            snapshot_source='LAZY_BOOTSTRAP', snapshot_generation=None,
                            pre_snapshot_match=None, content_delta_detected=None,
                            reconciliation_reason='NO_TRUSTED_PRE_EDIT_SNAPSHOT')
                readiness = pool.bootstrap(root, arguments['session_id'])
                if normalized.kind == EventKind.SESSION_START:
                    readiness = await pool.wait_for_bootstrap(root, arguments['session_id'], readiness)
                    from .integration_readiness import readiness_message
                    data = {'status': readiness['status'], 'readiness_status': 'READINESS_OBSERVED',
                            'workspace_id': identity(os.path.normcase(str(root))),
                            'workspace_readiness': readiness, 'security_proof': False}
                    data.update(claim_diag)
                    return CallToolResult(structuredContent=data, content=[TextContent(type='text', text=json.dumps({
                        'continue': True, 'systemMessage': readiness_message(readiness['status'])}))])
                if readiness['status'] != 'READY':
                    # SessionStart may be missed while MCP is connecting. A
                    # mutation Hook can retry the bounded bootstrap; if it is
                    # still initializing, fail soft without inventing a scan.
                    if normalized.kind == EventKind.WORKSPACE_ACTIVITY:
                        readiness = pool.bootstrap(root, arguments['session_id'])
                    if readiness['status'] != 'READY':
                        return _advisory('WORKSPACE_' + readiness['status'], readiness, claims=claim_diag)
                if pre_snapshot_missing:
                    # This comparison point was captured after the tool ran.
                    # It can serve future edits, never prove this edit was absent.
                    data = _advisory('WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE', readiness, claims=claim_diag)
                    data.structuredContent.update(snapshot_available=False, snapshot_source='LAZY_BOOTSTRAP',
                        snapshot_generation=None, pre_snapshot_match=None, content_delta_detected=None,
                        workspace_mutation_observed=None, changed_file_count=None,
                        reconciliation_reason='NO_TRUSTED_PRE_EDIT_SNAPSHOT')
                    return data
            forwarded = dict(arguments)
            if alias is not None:
                forwarded['path'] = None
            handler_entered = True
            binding_stage = 'FORWARDING_TOOL'
            if claim_diag is not None:
                claim_diag['workspace_binding_stage'] = binding_stage
            child_tool = child._tool_manager.get_tool(name)
            if 'workspace_path' in child_tool.parameters['properties']:
                forwarded['workspace_path'] = str(root)
            else:
                forwarded.pop('workspace_path', None)
            # No parsing/rebuilding references or credentials; all other values
            # are forwarded byte-for-byte as supplied to this request's root.
            result = await child._tool_manager.call_tool(name, forwarded, convert_result=True)
            if claim_diag is not None and isinstance(result, CallToolResult) and result.structuredContent is not None:
                # Child rejection wins; never overwrite a rejected claim status.
                claim_diag['workspace_binding_stage'] = 'COMPLETE'
                result.structuredContent = {**claim_diag, **result.structuredContent}
            return result
        except Exception as exc:
            if handler_entered or not isinstance(exc, ValueError):
                from .recent_hooks import observe
                observe('HANDLER_ERROR', handler_reason='HANDLER_EXCEPTION')
            # Never echo an arbitrary path, source-like argument or SDK error.
            # Fixed protocol reasons are useful without reflecting host input.
            reason = str(exc)
            allowed = {'WORKSPACE_CLAIM_REQUIRED', 'GLOBAL_CONFIGURATION_NOT_READY',
                       'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR', 'SESSION_WORKSPACE_MISMATCH',
                       'WORKSPACE_CONNECTION_BUDGET_EXCEEDED', 'SESSION_CONNECTION_BUDGET_EXCEEDED',
                       'INVALID_SESSION_CLAIM'}
            allowed |= WORKSPACE_REJECTIONS
            if claim_diag is not None:
                claim_diag['host_claim_status'] = 'REJECTED'
                claim_diag.update(workspace_binding_stage=binding_stage,
                                  workspace_rejection_reason=workspace_rejection(exc, binding_stage))
                if reason == 'SESSION_WORKSPACE_MISMATCH':
                    claim_diag['session_claim_match'] = False
                elif claim_diag['workspace_claim_match'] is None:
                    claim_diag['workspace_claim_match'] = False
            recovery = None
            if not handler_entered and binding_stage in {'VALIDATING_CONFIGURATION', 'ADMITTING_WORKSPACE'}:
                from .integration_recovery import CONFIGURATION_REASONS, configuration_recovery
                if reason in CONFIGURATION_REASONS:
                    if active_host == 'cursor':
                        recovery = dict(host='cursor', reason_code=reason,
                            message='请查看 Cursor 全局连接状态并处理配置冲突；现有用户配置已保留。')
                    else:
                        try:
                            recovery = configuration_recovery(pool.integration, claim or root, reason=reason)
                        except (ValueError, OSError, TypeError, RecursionError):
                            pass
            return _advisory(reason if reason in allowed else 'WORKSPACE_OR_REFERENCE_REJECTED', claims=claim_diag,
                             recovery=recovery)

    # Preserve the public FastMCP helpers for deterministic local tests as well
    # as the actual low-level stdio handlers. Project registry remains untouched.
    routed_call = call
    gap_notices = OrderedDict()
    gap_notice_lock = threading.Lock()
    async def quiet_stop_call(name, arguments):
        result = await routed_call(name, arguments)
        if name in {'handle_hook_event', 'handle_readiness_event'}:
            data = result.structuredContent or {}
            # Native Hosts consume additionalContext as model instructions.
            # systemMessage alone can be invisible to the agent, hiding a real
            # missed check behind a successful file edit. Keep gaps explicit;
            # this presentation never grants repair or manual-scan authority.
            if ((name == 'handle_readiness_event' and data.get('status') != 'READY') or
                    (data.get('status') in {'INCONCLUSIVE', 'BUSY', 'FAILED', 'PARTIAL'}
                     and data.get('scanner_run') is False
                     and (not data.get('user_feedback') or data.get('feedback_kind') == 'CHECK_GAP'))):
                payload = json.loads(result.content[0].text)
                message = payload.get('systemMessage')
                if message:
                    event = 'SessionStart' if name == 'handle_readiness_event' else 'PostToolUse'
                    # A failed readiness/configuration check is not evidence
                    # that a file changed. Keep diagnostics, but do not turn
                    # read-only or malformed events into chat warnings.
                    valid = host_adapter.validate_claims(arguments,
                        'SessionStart' if event == 'SessionStart' else 'PostToolUse', schemas.get(name))
                    operation = data.get('normalized_operation_class')
                    if event == 'PostToolUse' and operation is None and valid['host_claim_status'] == 'VALID':
                        from .codex_event_adapter import classify_bash_command
                        operation = (classify_bash_command(arguments.get('tool_input'))
                            if arguments.get('tool_name') == 'Bash' else OperationClass.DIRECT_FILE_MUTATION.value)
                    if (name not in schemas or valid['host_claim_status'] != 'VALID' or
                            event == 'PostToolUse' and (operation == OperationClass.READ_ONLY.value
                            or data.get('workspace_mutation_observed') is False)):
                        data.pop('user_feedback', None)
                        return CallToolResult(structuredContent=data,
                            content=[TextContent(type='text', text='{}')])
                    # One generic gap per turn, not one per tool invocation.
                    # A later editing turn must still be able to report its own
                    # gap. Real risk/repair feedback never enters this cache.
                    key = tuple(identity(str(value)) for value in (
                        arguments['workspace_path'], arguments['session_id'],
                        arguments.get('turn_id') if event == 'PostToolUse' else 'SessionStart'))
                    with gap_notice_lock:
                        duplicate = key in gap_notices
                        gap_notices[key] = None
                        gap_notices.move_to_end(key)
                        while len(gap_notices) > 512:
                            gap_notices.popitem(last=False)
                    if duplicate:
                        data.pop('user_feedback', None)
                        return CallToolResult(structuredContent=data,
                            content=[TextContent(type='text', text='{}')])
                    if event == 'PostToolUse':
                        if not message.startswith('本次操作'):
                            message = '本次操作已结束，但自动安全检查未完成。' + message
                    data['user_feedback'] = {'message': message}
                    presentation = (
                        '仅当本轮实际修改了源代码或配置，且该改动的检查在总结时仍未完成，'
                        '才在正常开发总结中简要说明一次本轮检查缺口，不能称检查通过。'
                        '普通聊天、只读操作和未改动文件的操作不展示此提示；'
                        '后续检查完成时不保留旧的未完成提示，其他轮次不重复沿用。'
                        '这只是检查状态，不是发现了漏洞；没有具体诊断时不要推断连接或配置有误。')
                    payload['systemMessage'] = message
                    payload['hookSpecificOutput'] = {'hookEventName': event, 'additionalContext':
                        '用户提示\n' + message + '\n\n呈现要求\n'
                        + presentation +
                        '检查未完成不代表文件编辑失败，不要重复编辑、撤销或自行修复。'
                        '不主动补扫、重建检查事件或运行构建测试，不索取内部引用。'}
                    result.structuredContent = data
                    result.content = [TextContent(type='text', text=json.dumps(payload))]
        if name == 'handle_stop_event' and (result.structuredContent or {}).get('decision') != 'block':
            # Validation/admission failures are diagnostics too. A broken or
            # unready connection must not add a warning to every ordinary chat.
            return CallToolResult(structuredContent=result.structuredContent,
                                  content=[TextContent(type='text', text='{}')])
        return result
    call = quiet_stop_call
    from .recent_hooks import instrument
    call = instrument(call, schemas={name: tool.parameters for name, tool in infos.items()},
                      resolve_root=lambda arguments: pool.root(arguments.get('workspace_path'))
                      if isinstance(arguments, dict) else None)
    server.list_tools = listed
    server.call_tool = call
    server._mcp_server.list_tools()(listed)
    server._mcp_server.call_tool(validate_input=False)(call)
    from contextlib import asynccontextmanager
    original_lifespan = server._mcp_server.lifespan
    @asynccontextmanager
    async def lifespan(inner):
        async with original_lifespan(inner) as context:
            try:
                yield context
            finally:
                pool.close()
    server._mcp_server.lifespan = lifespan
    return server
