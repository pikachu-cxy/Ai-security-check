"""Thin user-level MCP router; security logic remains workspace-bound."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import threading
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from .global_workspace import (resolve_workspace, workspace_state, source_snapshot, write_bootstrap,
                               workspace_rejection, WORKSPACE_REJECTIONS)
from .hook_state import HookStateStore, identity, no_links
from .integration_state import WorkspaceBinding
from .workspace import WorkspaceResolver
from .host_events import EventKind, OperationClass
from .codex_event_adapter import CodexEventAdapter
from .bootstrap_diagnostics import BASELINE_REASONS, BaselinePreparationError, baseline_failure_reason

HOOKS = {'handle_readiness_event', 'handle_hook_event', 'handle_stop_event'}
GLOBAL_READS = {'get_runtime_info', 'get_professional_guidance', 'get_scan_preparation_status'}
TASK_REVIEW_TOOLS = {'begin_security_task', 'finish_security_task', 'prepare_task_security_review',
    'get_task_review_plan', 'get_task_review_method', 'submit_task_review_batch',
    'read_task_review_context', 'submit_task_security_review', 'get_task_security_review',
    'get_task_risk_ledger', 'prepare_task_risk_feedback', 'submit_task_risk_feedback',
    'mark_task_risk_false_positive', 'revoke_task_risk_feedback', 'get_task_risk_feedback',
    'set_task_risk_disposition'}
LIMIT = 16
MAX_SESSIONS = 64
# Leave room for admission/transport within the native 30-second startup Hook.
# Waiting reuses the existing job; it never starts another baseline scan.
BOOTSTRAP_WAIT_SECONDS = 20


def global_runtime_info():
    from .host_guidance import runtime_info
    info = runtime_info()
    info['features'] = {**info['features'], 'global_runtime_integration': 'v0.1'}
    info['integration_scope'] = 'GLOBAL'
    info['workspace_routing'] = 'EXPLICIT_WORKSPACE_CLAIM'
    return info


class GlobalWorkspaces:
    def __init__(self, *, base=None, integration=None, child_factory=None, host='codex'):
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
        from .workspace_services import workspace_services
        from .remediation import RemediationService
        from .remediation_policy import RemediationConfig
        runtime, core, is_git = workspace_services(root, directory)
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
                restored = self._restore_existing(root, session, core)
                if restored is not None:
                    return self._remember_ready(key, restored)
                try:
                    write_bootstrap(root, 'INITIALIZING', 'NOT_ESTABLISHED', base=self.base, session_id=session)
                except (ValueError, OSError) as exc:
                    failed = Future()
                    failed.set_result(self._initialization_failure(root, session, 'DEGRADED', baseline_failure_reason(exc)))
                    self.jobs[key] = failed
                    return failed.result()
                future = self.executor.submit(self._initialize, root, session, core)
                self.jobs[key] = future
                return {'status': 'INITIALIZING', 'previous_status': 'NEW_WORKSPACE', 'security_proof': False}
            if not future.done():
                return {'status': 'INITIALIZING', 'security_proof': False}
            result = future.result()
            if result['status'] != 'READY':
                # A failed worker is not a permanent session veto. Recover only
                # an existing, validated comparison point from this same host,
                # workspace and session. Never rescan/rebaseline after an edit.
                restored = self._restore_existing(root, session, core,
                    recovered_from=result.get('reason_code'))
                if restored is not None:
                    return self._remember_ready(key, restored)
            return result

    def _remember_ready(self, key, result):
        future = Future()
        future.set_result(result)
        self.jobs[key] = future
        return result

    def _snapshot_readiness(self, root, session, snapshot, *, reused=False, recovered_from=None,
                            target_selection=None):
        result = snapshot['last_result']
        gaps = snapshot.get('unproven_sast_files') or []
        value = {'status': 'READY', 'baseline_status': result['status'],
                 'baseline_coverage': result['coverage'],
                 'baseline_capabilities': result['capabilities'],
                 'baseline_unproven_code_file_count': len(gaps),
                 'baseline_unproven_code_files': gaps[:20],
                 'baseline_code_gaps_truncated': len(gaps) > 20,
                 'target_selection': target_selection,
                 'baseline_reused': reused, 'security_proof': False,
                 'initial_scope': 'EXISTING_SESSION_SNAPSHOT' if reused else 'BOUNDED_QUICK_BASELINE'}
        if recovered_from in BASELINE_REASONS:
            value['recovered_from'] = recovered_from
        write_bootstrap(root, 'READY', result['status'], base=self.base, session_id=session,
                        recovered_from=value.get('recovered_from'))
        return value

    def _restore_existing(self, root, session, core, *, recovered_from=None):
        from .baseline_seed import WorkspaceBaselineSeeds
        try:
            snapshot = WorkspaceBaselineSeeds(integration=self.integration, coordinator=core).existing_session(
                root, session, host=self.host)
            if snapshot is not None:
                return self._snapshot_readiness(root, session, snapshot, reused=True,
                                               recovered_from=recovered_from)
        except (ValueError, OSError):
            pass  # Keep the original failure; no guessed baseline or raw error.
        return None

    def _initialization_failure(self, root, session, status, reason):
        value = {'status': status, 'reason_code': reason, 'security_proof': False}
        try:
            write_bootstrap(root, status, reason, base=self.base, reason_code=reason, session_id=session)
        except (ValueError, OSError):
            pass  # Unwritable diagnostics must not hide the actual failure.
        return value

    def _initialize(self, root, session, core):
        from .hooks import HookEvent
        from .baseline_seed import WorkspaceBaselineSeeds
        from .progress import ScanCancelled
        try:
            is_git = WorkspaceResolver().resolve(root, allow_non_git_source=True).is_git
            if is_git:
                # A clean tracked file may already contain a risk. Dirty-only
                # initialization would misattribute that risk to a later edit.
                seeds = WorkspaceBaselineSeeds(integration=self.integration, coordinator=core)
                snapshot = seeds.capture_session(root, session, host=self.host)
                return self._snapshot_readiness(root, session, snapshot,
                    target_selection=getattr(seeds, 'target_selection', None))
            else:
                result = core.handle(HookEvent.SESSION_START, root, 'codex', session, _baseline_only=True)
                persisted, _ = core.store.load(core.store.path(root, 'codex', session))
                valid = persisted is not None and persisted['change_digest'] == result.get('change_digest')
                status = 'READY' if valid and (result.get('baseline_comparison_usable') is True
                    or result.get('baseline_comparison_usable') is None and result.get('coverage') in {'FULL', 'SCOPED'}
                    or result.get('coverage') == 'NONE' and not result.get('scanner_runs')) else 'DEGRADED'
            if status == 'READY':
                return self._snapshot_readiness(root, session, persisted, target_selection=result.get('target_selection'))
            failure = self._initialization_failure(root, session, 'DEGRADED', 'BASELINE_COVERAGE_INSUFFICIENT')
            failure.update(baseline_status=result['status'], baseline_coverage=result['coverage'],
                baseline_capabilities=result['capabilities'], target_selection=result.get('target_selection'))
            return failure
        except ScanCancelled:
            return self._initialization_failure(root, session, 'DEGRADED', 'BASELINE_DEADLINE_EXCEEDED')
        except BaselinePreparationError as exc:
            return self._initialization_failure(root, session, 'DEGRADED', exc.code)
        except PermissionError:
            return self._initialization_failure(root, session, 'DEGRADED', 'BASELINE_STATE_PERMISSION_DENIED')
        except (ValueError, OSError) as exc:
            return self._initialization_failure(root, session, 'DEGRADED', baseline_failure_reason(exc))
        except subprocess.TimeoutExpired:
            return self._initialization_failure(root, session, 'DEGRADED', 'BASELINE_GIT_SNAPSHOT_UNAVAILABLE')
        except Exception:
            return self._initialization_failure(root, session, 'ERROR', 'INITIALIZATION_INCONCLUSIVE')

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
        'WORKSPACE_DEGRADED': readiness_message('DEGRADED', (readiness or {}).get('reason_code')),
        'WORKSPACE_ERROR': readiness_message('ERROR', (readiness or {}).get('reason_code')),
        'WORKSPACE_BASELINE_ATTRIBUTION_UNAVAILABLE': '本次修改尚未完成前后比较：缺少修改前的检查记录，无法判断风险是否由本次修改引入。后续修改会继续自动检查。',
    }.get(reason, '自动安全检查未启动：检查请求未被接受，请查看产品连接和项目接入状态。')
    if (readiness or {}).get('reason_code') in BASELINE_REASONS:
        data['bootstrap_reason'] = readiness['reason_code']
    text = {'continue': True, 'systemMessage': message}
    if recovery is not None:
        data['configuration_recovery'] = recovery
        text['systemMessage'] += ' ' + recovery['message']
        if recovery.get('question'):
            text['systemMessage'] += ' ' + recovery['question']
    return CallToolResult(structuredContent=data, content=[TextContent(type='text', text=json.dumps(text))])


def _task_request_rejected(reason):
    """Task protocol errors say nothing about project admission/readiness."""
    from mcp.types import CallToolResult, TextContent
    message = {
        'TASK_CONNECTION_SCOPE_MISMATCH':
            '原任务只绑定创建时的工具连接，没有可恢复的聊天身份。当前请求不能续接该记录；'
            '若原连接已断开，该任务无法跨连接恢复。已有改动和记录保留，不要用修改后的文件补作修改前记录。',
        'TASK_SESSION_SCOPE_MISMATCH':
            '当前请求的聊天身份与原任务不一致，未继续或结束该任务。请回到原聊天续接原任务；'
            '已有修改前记录保留，不要新建任务替代原记录。',
        'TASK_SESSION_BINDING_REQUIRED':
            '原任务已绑定聊天，但当前请求缺少对应的会话身份。请在原聊天沿用已有任务和有效会话记录继续；'
            '不需要重新编辑文件或重新建立修改前记录。',
        'TASK_OWNER_UNAVAILABLE':
            '原任务没有保存可确认的会话归属，当前请求不能续接或结束该记录。已有改动和记录保留；'
            '不能把当前聊天当成原任务所有者，也不能从修改后重新建立修改前记录。',
        'TASK_REVIEW_REVISION_CAPACITY':
            '任务历史与本次复核材料超出存储容量，前一版本记录已保留。当前版本尚未完成复核。',
        'REVIEW_PLAN_REVISION_INVALID':
            '复核版本与原任务记录无法核对，未采用旧证据，也未重建修改前记录。请保留原任务进行诊断。',
        'REVIEW_PLAN_SNAPSHOT_FIXED':
            '当前复核计划不能直接重建。请沿用原任务结束本次改动，再准备对应版本的复核。',
        'REVIEW_PLAN_STALE':
            '复核对应的代码已变化，旧证据不能提交到新版本。请在原任务中结束本次改动并准备新版本复核。',
        'REVIEW_PLAN_SESSION_MISMATCH':
            '本次请求使用了旧的复核会话。请使用原任务当前版本返回的复核会话继续。',
    }.get(reason, '任务复核请求未被接受。请使用当前任务返回的参数继续；这不表示项目准备或产品连接失败。')
    data = dict(status='INCONCLUSIVE', reason_code=reason, scanner_run=False,
        source_modified=False, security_proof=False, repair_authorized=False,
        message=message)
    return CallToolResult(structuredContent=data,
        content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])


def create_global_server(*, workspaces=None, host='codex'):
    from .mcp_server import create_server
    from mcp.types import CallToolResult, TextContent
    from jsonschema import Draft202012Validator
    # Obtain the original registry/instructions without creating a writable DB.
    server = create_server(global_mode=False)
    pool = workspaces or GlobalWorkspaces(host=host)
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
            if tool.name not in HOOKS and tool.name not in GLOBAL_READS:
                schema['properties']['workspace_path'] = {'type': 'string', 'minLength': 1,
                    'description': 'Required for global workspace routing, including a single admitted workspace. Never inferred from an opaque ref.'}
                schema['required'] = list(dict.fromkeys([*schema.get('required', []), 'workspace_path']))
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
            from .repair_impact_contract import IMPACT_TOOLS, impact_failure
            if name in IMPACT_TOOLS:
                data = impact_failure('IMPACT_INPUT_INVALID')
                return CallToolResult(isError=True, structuredContent=data,
                    content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])
            from .feedback_contract import FEEDBACK_TOOLS, feedback_failure
            if name in FEEDBACK_TOOLS:
                data = feedback_failure('FEEDBACK_INPUT_INVALID')
                return CallToolResult(isError=True, structuredContent=data,
                    content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])
            if name in TASK_REVIEW_TOOLS:
                return _task_request_rejected('TASK_REQUEST_INVALID')
            return _advisory('INVALID_HOST_CLAIMS', claims=claim_diag)
        if name == 'get_runtime_info':
            info = global_runtime_info()
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
                session_token = None
                if normalized.kind == EventKind.SESSION_START:
                    from .task_ownership import issue_session_ref
                    # Claims/configuration/admission were already checked.
                    # Establish stable routing before launching a slow worker;
                    # the token attests no scanner or comparison-point result.
                    session_token = issue_session_ref(pool.children[root][1].store,
                        root, active_host, arguments['session_id'])
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
                if readiness.get('reason_code') in BASELINE_REASONS:
                    claim_diag['bootstrap_reason'] = readiness['reason_code']
                if readiness.get('recovered_from') in BASELINE_REASONS:
                    claim_diag['bootstrap_recovered_from'] = readiness['recovered_from']
                if normalized.kind == EventKind.SESSION_START:
                    readiness = await pool.wait_for_bootstrap(root, arguments['session_id'], readiness)
                    from .integration_readiness import readiness_message
                    data = {'status': readiness['status'], 'readiness_status': 'READINESS_OBSERVED',
                            'workspace_id': identity(os.path.normcase(str(root))),
                            'workspace_readiness': readiness, 'security_proof': False}
                    data.update(claim_diag)
                    if readiness.get('reason_code') in BASELINE_REASONS:
                        data['bootstrap_reason'] = readiness['reason_code']
                    output={'continue':True,'systemMessage':readiness_message(readiness['status'], readiness.get('reason_code'))}
                    # Identity routing is independent of initial scan readiness.
                    # Slow/busy scanners must not silently downgrade a native
                    # conversation into an unresumable connection-owned task.
                    from .task_ownership import session_context
                    data['task_session_ref']=session_token
                    output['hookSpecificOutput']={'hookEventName':'SessionStart','additionalContext':session_context(session_token)}
                    return CallToolResult(structuredContent=data, content=[TextContent(type='text', text=json.dumps({
                        **output}))])
                if readiness['status'] != 'READY':
                    # Observe an existing worker or restore a published session
                    # comparison point; never rerun a failed scan after edits.
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
            from .task_ownership import owner_scope, session_owner
            if name in HOOKS:
                owner=session_owner(active_host,arguments['session_id'])
            else:
                owner=None
            # Ambiguous host identity remains connection-scoped. Never accept
            # a model-supplied owner or choose the last observed conversation.
            with owner_scope(owner):
                result = await child._tool_manager.call_tool(name, forwarded, convert_result=True)
            if claim_diag is not None and isinstance(result, CallToolResult) and result.structuredContent is not None:
                # Child rejection wins; never overwrite a rejected claim status.
                claim_diag['workspace_binding_stage'] = 'COMPLETE'
                result.structuredContent = {**claim_diag, **result.structuredContent}
            return result
        except Exception as exc:
            from .repair_impact_contract import IMPACT_TOOLS, impact_failure
            if name in IMPACT_TOOLS:
                data = impact_failure(exc)
                return CallToolResult(isError=True, structuredContent=data,
                    content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])
            from .feedback_contract import (FEEDBACK_TOOLS, disposition_unavailable,
                                            feedback_failure, feedback_reason)
            if handler_entered and (name in FEEDBACK_TOOLS or disposition_unavailable(exc)):
                reason = feedback_reason(exc, name)
                if reason.startswith('TASK_'):
                    return _task_request_rejected(reason)
                data = feedback_failure(reason)
                return CallToolResult(isError=True, structuredContent=data,
                    content=[TextContent(type='text', text=json.dumps(data, ensure_ascii=False))])
            if handler_entered and name in TASK_REVIEW_TOOLS:
                # Ownership, expired sessions, unsupported protocol versions and
                # malformed review requests must not masquerade as a broken
                # workspace. Never reflect arbitrary SDK/source/path errors.
                from .task_ownership import TaskOwnershipError
                from .task_review_plan import ReviewPlanError
                from .task_review_revisions import ReviewRevisionError
                cause = exc
                for _ in range(8):
                    if isinstance(cause, TaskOwnershipError):
                        return _task_request_rejected(cause.reason_code)
                    if (isinstance(cause, (ReviewPlanError, ReviewRevisionError))
                            and cause.reason_code in {
                                'TASK_REVIEW_REVISION_CAPACITY', 'REVIEW_PLAN_REVISION_INVALID',
                                'REVIEW_PLAN_SNAPSHOT_FIXED', 'REVIEW_PLAN_STALE',
                                'REVIEW_PLAN_SESSION_MISMATCH'}):
                        return _task_request_rejected(cause.reason_code)
                    cause = cause.__cause__ or cause.__context__
                    if cause is None:
                        break
                return _task_request_rejected('TASK_REQUEST_REJECTED')
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
    def gap_key(arguments, event):
        return tuple(identity(str(value)) for value in (
            arguments['workspace_path'], arguments['session_id'],
            arguments.get('turn_id') if event == 'PostToolUse' else 'SessionStart'))

    async def quiet_stop_call(name, arguments):
        result = await routed_call(name, arguments)
        data = (result.structuredContent or {}) if isinstance(result, CallToolResult) else {}
        if (name == 'handle_hook_event' and data.get('host_claim_status') == 'VALID'
                and data.get('workspace_mutation_observed') is True and data.get('scanner_run') is True
                and data.get('status') == 'SCANNED' and data.get('coverage') in {'FULL', 'SCOPED'}):
            key = gap_key(arguments, 'PostToolUse')
            with gap_notice_lock:
                resolved = key in gap_notices
                gap_notices.pop(key, None)
            if resolved:
                data['previous_check_gap_resolved'] = True
                payload = json.loads(result.content[0].text)
                context = payload.setdefault('hookSpecificOutput', {'hookEventName': 'PostToolUse'})
                context['additionalContext'] = context.get('additionalContext', '') + (
                    '\n同轮此前的未启动提示已被本次检查结果取代，最终总结只保留当前检查状态；保留具体风险提示。')
                result.content = [TextContent(type='text', text=json.dumps(payload))]
        if name in {'handle_hook_event', 'handle_readiness_event'}:
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
                        data.pop('reply_plan', None)
                        return CallToolResult(structuredContent=data,
                            content=[TextContent(type='text', text='{}')])
                    # One generic gap per turn, not one per tool invocation.
                    # A later editing turn must still be able to report its own
                    # gap. Real risk/repair feedback never enters this cache.
                    key = gap_key(arguments, event)
                    with gap_notice_lock:
                        duplicate = key in gap_notices
                        gap_notices[key] = None
                        gap_notices.move_to_end(key)
                        while len(gap_notices) > 512:
                            gap_notices.popitem(last=False)
                    if duplicate:
                        data.pop('user_feedback', None)
                        data.pop('reply_plan', None)
                        return CallToolResult(structuredContent=data,
                            content=[TextContent(type='text', text='{}')])
                    if event == 'PostToolUse':
                        if data.get('reason_code') in {'WORKSPACE_INITIALIZING', 'WORKSPACE_DEGRADED', 'WORKSPACE_ERROR'}:
                            message += '本次修改尚未检查。'
                    from .hook_user_feedback import check_gap_feedback
                    data['user_feedback'] = check_gap_feedback(message)
                    data['reply_plan'] = data['user_feedback']['reply_plan']
                    message = data['user_feedback']['message']
                    presentation = (
                        '仅当本轮实际修改了源代码或配置，且该改动的检查在总结时仍未完成，'
                        '才在正常开发总结中简要说明一次本轮检查缺口，不能称检查通过。'
                        '普通聊天、只读操作和未改动文件的操作不展示此提示；'
                        '后续检查完成时不保留旧的未完成提示，其他轮次不重复沿用。'
                        '这只是检查状态，不是发现了漏洞；没有具体诊断时不要推断连接或配置有误。')
                    payload['systemMessage'] = message
                    previous_context = payload.get('hookSpecificOutput', {}).get('additionalContext', '')
                    payload['hookSpecificOutput'] = {'hookEventName': event, 'additionalContext':
                        (previous_context + '\n' if previous_context else '') +
                        '用户提示\n' + message + '\n\n呈现要求\n'
                        + presentation +
                        '检查未完成不代表文件编辑失败，不要重复编辑、撤销或自行修复。'
                        '不重放检查事件、不补建编辑后的基线，不运行构建测试。'
                        '本提示只说明项目初始检查或本次Hook的状态，不取消当前开发任务核查。'
                        '实际开发任务仍在首次编辑前用本会话路由保存任务记录；已有任务沿用原引用'
                        '在结束时完成检查，无需用户另发继续。已经编辑而缺少原记录时如实说明缺口。'}
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
