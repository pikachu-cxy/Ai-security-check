"""Thin user-level MCP router; security logic remains workspace-bound."""
from __future__ import annotations

import hashlib
import json
import os
import threading
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
GLOBAL_READS = {'get_runtime_info', 'get_professional_guidance'}
LIMIT = 16
MAX_SESSIONS = 64


def global_runtime_info():
    from .host_guidance import runtime_info
    info = runtime_info()
    info['features'] = {**info['features'], 'global_runtime_integration': 'v0.1'}
    info['integration_scope'] = 'GLOBAL'
    info['workspace_routing'] = 'EXPLICIT_WORKSPACE_CLAIM'
    return info


class GlobalWorkspaces:
    def __init__(self, *, base=None, integration=None, child_factory=None):
        from .storage import SQLiteStore
        self.base = Path(base or SQLiteStore.default_path().parent / 'global-workspaces').absolute()
        no_links(self.base)
        if integration is None:
            from .global_integration import GlobalCodexIntegration
            integration = GlobalCodexIntegration(home=os.getenv('SECURITY_RUNTIME_CODEX_HOME'))
        self.integration = integration
        self.child_factory = child_factory or self._child
        self.children = {}
        self.sessions = {}
        from .codex_host_claims import CodexClaimGuard
        self.claim_guard = CodexClaimGuard()
        self.jobs = {}
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='runtime-bootstrap')
        self.lock = threading.RLock()

    @staticmethod
    def _child(root, directory, binding):
        from .mcp_server import create_server
        from .runtime import SecurityRuntime
        from .scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter, TrivyAdapter
        from .osv import OSVDependencyAdapter
        from .toolchain import ToolManager
        from .storage import SQLiteStore
        from .hook_runtime import HookCoordinator
        from .remediation import RemediationService
        from .remediation_policy import RemediationConfig
        manager = ToolManager()
        registry = ScannerRegistry([SemgrepAdapter(manager), GitleaksAdapter(manager), TrivyAdapter(manager)],
                                   tool_manager=manager, fallback_adapters=[OSVDependencyAdapter(manager)])
        store = SQLiteStore(directory / 'scans.db')
        # Explicit manual MCP operations retain the existing full registry.
        # Hook dependency checks are selected only for changed dependency inputs
        # and remain offline, without preparing tools/data or building targets.
        runtime = SecurityRuntime(ScannerRegistry(tool_manager=manager), store)
        hook_runtime = SecurityRuntime(registry, store)
        is_git = WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git
        core = HookCoordinator(hook_runtime, HookStateStore(directory / 'hooks'),
                               workspace_resolver=lambda value: resolve_workspace(value),
                               snapshot_capture=None if is_git else source_snapshot,
                               seeds=_NoProjectSeed())
        def remediation_factory(store, **kwargs):
            # User policy stays user-wide; grants/proofs/DB stay workspace-local.
            return RemediationService(store, config=RemediationConfig(), inline_agent_tickets=True, **kwargs)
        server = create_server(runtime, hook_coordinator=core, remediation_factory=remediation_factory,
                               workspace_binding=binding, global_mode=False, hook_advisory_only=not is_git)
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
                                       str(root) if workspace.is_git else '', 'codex', 'PROJECT', '')
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
            if WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git:
                # A clean tracked file may already contain a risk. Dirty-only
                # initialization would misattribute that risk to a later edit.
                snapshot = WorkspaceBaselineSeeds(integration=self.integration, coordinator=core).capture_session(root, session)
                result = snapshot['last_result']
                status = 'READY'
            else:
                result = core.handle(HookEvent.SESSION_START, root, 'codex', session, _baseline_only=True)
                persisted, _ = core.store.load(core.store.path(root, 'codex', session))
                valid = persisted is not None and persisted['change_digest'] == result.get('change_digest')
                status = 'READY' if valid and result.get('coverage') in {'FULL', 'SCOPED', 'NONE'} else 'DEGRADED'
            write_bootstrap(root, status, result['status'], base=self.base)
            return {'status': status, 'baseline_status': result['status'],
                    'security_proof': False, 'initial_scope': 'BOUNDED_QUICK_BASELINE'}
        except (ValueError, OSError, ScanCancelled):
            write_bootstrap(root, 'DEGRADED', 'BASELINE_CHECK_INCONCLUSIVE', base=self.base)
            return {'status': 'DEGRADED', 'reason_code': 'BASELINE_CHECK_INCONCLUSIVE', 'security_proof': False}
        except Exception:
            write_bootstrap(root, 'ERROR', 'INITIALIZATION_INCONCLUSIVE', base=self.base)
            return {'status': 'ERROR', 'reason_code': 'INITIALIZATION_INCONCLUSIVE', 'security_proof': False}

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


def create_global_server(*, workspaces=None):
    from .mcp_server import create_server
    from mcp.types import CallToolResult, TextContent
    from jsonschema import Draft202012Validator
    # Obtain the original registry/instructions without creating a writable DB.
    server = create_server(global_mode=False)
    pool = workspaces or GlobalWorkspaces()
    server.global_workspaces = pool
    server._mcp_server.instructions += ('\nGlobal Codex integration: Hook workspace_path is an untrusted cwd claim. '
        'For every workspace tool supply the current workspace_path, even if only one workspace is admitted. '
        'Never infer a workspace from an opaque reference or use the last workspace. '
        'INITIALIZING/DEGRADED readiness is not a security proof; Core Hooks never request Deep Verification.')
    original_tools = server._tool_manager
    infos = {t.name: t for t in original_tools.list_tools()}

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
                      if name in HOOKS else None)
        if (name not in schemas or not isinstance(arguments, dict)
                or not Draft202012Validator(schemas[name]).is_valid(arguments)
                or claim_diag is not None and claim_diag['host_claim_status'] != 'VALID'):
            return _advisory('INVALID_HOST_CLAIMS', claims=claim_diag)
        if name == 'get_runtime_info':
            info = global_runtime_info()
            return CallToolResult(structuredContent=info, content=[TextContent(type='text', text=json.dumps(info))])
        if name == 'get_professional_guidance':
            from .professional_guidance import get_professional_guidance
            guide = get_professional_guidance()
            return CallToolResult(structuredContent=guide, content=[TextContent(type='text', text=json.dumps(guide))])
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
            if name in HOOKS and not read_only_hook:
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
                    try:
                        recovery = configuration_recovery(pool.integration, claim or root, reason=reason)
                    except (ValueError, OSError, TypeError, RecursionError):
                        pass
            return _advisory(reason if reason in allowed else 'WORKSPACE_OR_REFERENCE_REJECTED', claims=claim_diag,
                             recovery=recovery)

    # Preserve the public FastMCP helpers for deterministic local tests as well
    # as the actual low-level stdio handlers. Project registry remains untouched.
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
