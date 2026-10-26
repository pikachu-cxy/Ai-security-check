"""Host-neutral application wiring for task ownership and mandatory impact gates.

Owns connection routing only. Domain stores remain the sole task/evidence and
authority sources; no SDK, tool manager or host presentation is retained here.
"""
from __future__ import annotations

from pathlib import Path

from .tasks.ownership import connection_owner, current_owner
from .workspace import WorkspaceResolver


class WorkspaceApplication:
    def __init__(self, runtime_provider, hooks, *, binding=None, scan_path_provider):
        self.runtime_provider = runtime_provider
        self.hooks = hooks
        self.binding = binding
        self.scan_path_provider = scan_path_provider
        self.connection_owner = connection_owner()
        self.issued_tasks = {}
        self.issued_development_checks = {}
        self.native_session_bindings = set()
        from .tasks.source_cache import TaskSourceCache
        self.task_source_cache = TaskSourceCache()

    def bound_path(self, value: str | None) -> str | None:
        if self.binding is None:
            return value
        candidate = Path(value) if value is not None else Path(self.binding.root)
        if not candidate.is_absolute():
            candidate = Path(self.binding.root) / candidate
        resolved = WorkspaceResolver().resolve(candidate, allow_non_git_explicit=True).path
        if resolved != Path(self.binding.root):
            raise ValueError("Requested workspace is outside this MCP connection")
        return self.binding.root

    def task_service(self, ref=None,session_ref=None,workspace=None):
        from .tasks.security import TaskSecurityService
        owner=current_owner(self.connection_owner)
        if session_ref is not None:
            from .tasks.ownership import verify_session_ref
            root=TaskSecurityService(self.runtime_provider,self.hooks).root(self.bound_path(workspace))
            scoped=verify_session_ref(self.hooks,root,session_ref)
            if owner['host']!='connection' and scoped!=owner:
                from .tasks.ownership import ownership_error
                raise ownership_error(owner, scoped)
            owner=scoped
        prior=self.issued_tasks.get(ref)
        if prior and session_ref is None and (owner['host']=='connection' or prior==self.connection_owner): owner=prior
        from .storage import ReadOnlySQLiteStore
        service=TaskSecurityService(self.runtime_provider,self.hooks,owner=owner,
            read_only_scan_store_provider=lambda: ReadOnlySQLiteStore(self.scan_path_provider()),
            source_cache=self.task_source_cache)
        if ref is not None and session_ref is not None:
            service.load_header(root,ref)  # Reject before routing, without loading source pages.
            if len(self.issued_tasks)>=64: self.issued_tasks.pop(next(iter(self.issued_tasks)))
            self.issued_tasks[ref]=owner
        return service

    def development_service(self, ref=None, session_ref=None, workspace=None):
        """Reuse session verification without entering strict snapshot storage."""
        from .development_check import DevelopmentCheckService
        self.native_binding_required(workspace, session_ref)
        owner = self.task_service(session_ref=session_ref, workspace=workspace)._owner()
        prior = self.issued_development_checks.get(ref)
        if prior and session_ref is None and (owner['host'] == 'connection' or prior == self.connection_owner):
            owner = prior
        return DevelopmentCheckService(self.runtime_provider, self.hooks, owner=owner,
                                       scan_path_provider=self.scan_path_provider)

    def remember_development_check(self, result, owner):
        if result.get('check_ref'):
            if len(self.issued_development_checks) >= 64:
                self.issued_development_checks.pop(next(iter(self.issued_development_checks)))
            self.issued_development_checks[result['check_ref']] = owner

    def scan(self, workspace=None, mode='quick', *, staged=False, rules_path=None, progress=None):
        from .explicit_scan import run_explicit_scan
        runtime=self.runtime_provider() if callable(self.runtime_provider) else self.runtime_provider
        return run_explicit_scan(runtime,self.bound_path(workspace),mode=mode,staged=staged,
                                 rules_path=rules_path,progress=progress,hooks=self.hooks)

    def scan_project(self, workspace=None, *, force_rescan=False, progress=None):
        """Revalidate immutable evidence before reusing a whole-project result."""
        from .explicit_scan import run_explicit_scan
        from .scan_reuse import try_reuse
        if type(force_rescan) is not bool:
            raise ValueError('Invalid force_rescan value')
        runtime=self.runtime_provider() if callable(self.runtime_provider) else self.runtime_provider
        root=self.bound_path(workspace)
        decision=None
        if not force_rescan:
            if progress is not None:
                progress.checkpoint()
                progress.emit('SCAN_REUSE_CHECK_STARTED',message='正在核对源码、范围、规则及引擎数据是否仍适用。')
            decision=try_reuse(runtime,root,hooks=self.hooks)
            if decision.reused:
                if progress is not None:
                    progress.checkpoint()
                    progress.emit('SCAN_RESULT_REUSED',message='当前证据已重新核验，复用上次扫描结果。')
                return dict(decision.scan,result_reuse=decision.receipt)
        result=run_explicit_scan(runtime,root,mode='release',progress=progress,hooks=self.hooks, force_rescan=force_rescan)
        result.scanner_diagnostics['reuse_check']=(decision.receipt if decision is not None else
            dict(reused=False,reason_code='FORCE_RESCAN_REQUESTED',scanner_run=True))
        return result

    def scan_files(self, workspace, files, *, progress=None):
        """Check an explicit bounded worktree selection, without Git diff scope."""
        from .explicit_scan import run_explicit_scan
        from .scan_request import ScanInputError
        if files is None:
            raise ScanInputError('SCAN_FILES_SELECTION_INVALID')
        runtime=self.runtime_provider() if callable(self.runtime_provider) else self.runtime_provider
        return run_explicit_scan(runtime,self.bound_path(workspace),mode='feature',files=files,
                                 progress=progress,hooks=self.hooks)

    def impact_owner(self, workspace, session_ref=None):
        # Session routing is verified by the same boundary as development tasks;
        # a model-supplied owner is never accepted by an impact tool.
        return self.task_service(session_ref=session_ref, workspace=workspace)._owner()

    def impact_service(self, workspace, session_ref=None, *, owner=None):
        from .repair_impact import RepairImpactService
        from .repair_impact_sources import resolve_impact_source
        from .storage import ReadOnlySQLiteStore
        root = Path(self.bound_path(workspace)).resolve()
        resolved_owner = owner if owner is not None else self.impact_owner(str(root), session_ref)
        tasks = self.task_service(session_ref=session_ref, workspace=str(root))
        scan_path = self.scan_path_provider()
        scans = ReadOnlySQLiteStore(scan_path)
        return RepairImpactService(root, self.hooks.workspace_directory(root) / 'repair-impact',
            resolved_owner, lambda source: resolve_impact_source(source, root, scans, tasks))

    def impact_required(self, root, task_ref, record=None):
        from .tasks.fix import TaskFixService
        from .storage import ReadOnlySQLiteStore, SQLiteStore
        scans = ReadOnlySQLiteStore(self.scan_path_provider())
        packet = TaskFixService(scans).prepare(task_ref, root, bound_workspace=root)
        proposal = dict(summary=packet.get('security_goal', '评估选定修复方案对正常业务的影响'),
            security_goal=packet.get('security_goal', '保留正常业务并修复选定问题'),
            preserve=[v['requirement'] for v in packet.get('fix_constraints', [])],
            changes=[dict(file_path=m['file'], start_line=m['line'], end_line=m['line'],
                          reason='选定问题的拟修改位置') for m in packet.get('affected_findings', [])])
        if record is not None:
            members = packet.get('affected_findings', [])
            if len(members) != 1 or members[0]['file'] != record['target']:
                raise ValueError('IMPACT_PROPOSAL_MISMATCH')
            proposal = dict(summary='删除已定位的独立主机名校验覆盖语句，恢复平台校验，保持其他字节不变。',
                security_goal='恢复平台主机名校验，不改变其余代码或文件。',
                preserve=['除该独立语句外，其他字节和文件保持不变。', '保留证书和主机名均有效的正常请求。'],
                changes=[dict(file_path=record['target'], start_line=members[0]['line'],
                    end_line=members[0]['line'], reason='只删除该独立覆盖语句；不修改其他字节或文件。')])
        return dict(status='IMPACT_REQUIRED', gate='REASSESS_REQUIRED',
            repair_authorized=False, automatic_execution=False, scanner_run=False,
            message='先完成选定方案的功能影响分析，再沿用已有具体修复意图继续；无需重复批准同一修复。',
            next_action=dict(tool='prepare_repair_impact', arguments=dict(
                workspace_path=str(root), source=dict(kind='SCANNER_TASK_GROUP', task_ref=task_ref),
                proposal=proposal)))

    def impact_check(self, root, task_ref, assessment_ref, owner=None, *, record=None):
        from .repair_impact_contract import impact_failure
        if not assessment_ref:
            return self.impact_required(root, task_ref, record)
        try:
            checked = self.impact_service(str(root), owner=owner).validate_for_fix(
                assessment_ref, dict(kind='SCANNER_TASK_GROUP', task_ref=task_ref))
            if record is not None and checked.get('gate') == 'READY_FOR_EXISTING_AUTH':
                from .repair_impact_models import digest, proposal as normalize_proposal
                required = self.impact_required(root, task_ref, record)
                expected = digest(normalize_proposal(required['next_action']['arguments']['proposal']))
                if checked.get('proposal_revision') != expected:
                    return impact_failure('IMPACT_PROPOSAL_MISMATCH')
            return checked
        except Exception as exc:
            return impact_failure(exc)

    def native_intents(self, service, workspace):
        from .native_repair_intent import NativeRepairIntents
        return NativeRepairIntents(self.hooks, service.root(self.bound_path(workspace)), service._owner())

    def native_binding_required(self, workspace, session_ref):
        root = str(Path(self.bound_path(workspace)).resolve())
        # An explicit session must not silently become a new connection owner
        # after a failed native repair preparation. This latch chooses no owner.
        if (root in self.native_session_bindings and session_ref is None and
                current_owner(self.connection_owner)['host'] == 'connection'):
            from .tasks.ownership import TaskOwnershipError
            raise TaskOwnershipError('TASK_SESSION_BINDING_REQUIRED')
