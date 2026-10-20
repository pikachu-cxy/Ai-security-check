"""Host-neutral explicit scanning with the existing workspace execution lane.

This use case has no development baseline, task ownership or repair authority.
Low-level Runtime embeddings may omit it; shipped CLI/MCP entry points use it.
"""
from __future__ import annotations

from pathlib import Path
import time
import uuid

from .hook_state import HookStateStore
from .progress import ScanCancelled
from .scan_attempt import ScanAttemptStore, ScanAttemptExecution, ScanAttemptLost, source_binding
from .workspace import WorkspaceResolver


class ExplicitScanBusy(ValueError):
    def __init__(self):
        super().__init__('本项目已有安全检查正在执行；当前请求未执行，请稍后重试。')

    def to_dict(self):
        return dict(status='BUSY', reason_code='SCAN_ATTEMPT_BUSY', coverage='UNKNOWN',
            scanner_run=False, source_modified=False, repair_authorized=False, message=str(self))


def cancelled_scan():
    return dict(status='CANCELLED', reason_code='SCAN_CANCELLED', coverage='UNKNOWN',
                check_completed=False, source_modified=False, repair_authorized=False,
                message='安全检查已取消，未确认检查完成；原任务和修复授权保持原状态。')


def run_explicit_scan(runtime, workspace=None, *, mode='quick', staged=False,
                      rules_path=None, progress=None, hooks=None, now=time.time, files=None):
    if mode not in {'quick','feature','release'} or type(staged) is not bool:
        raise ValueError('Invalid explicit scan mode')
    root=WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True, allow_non_git_source=True).path
    request=None
    if files is not None:
        from .selected_scan import selected_request
        if mode!='feature' or staged:
            raise ValueError('Explicit file scans require feature mode and the worktree')
        request=selected_request(root,files)
    hooks=hooks or HookStateStore(Path(runtime.store.path).parent/'hooks')
    attempts=ScanAttemptStore(hooks,root,now=now)
    attempts.recover_cleanup(limit=2)
    with hooks.lock(root,wait_seconds=1) as acquired:
        if not acquired: raise ExplicitScanBusy()
        # Request metadata describes only this explicit request. It never
        # fabricates a before-edit snapshot or resets a development task.
        lease=attempts.claim('MANUAL','explicit-'+uuid.uuid4().hex,source_binding(dict(
            contract='explicit-scan-request-v1', mode=mode, staged=staged,
            requested_files=list(request.files) if request is not None else None,
            rules_path=str(rules_path) if rules_path is not None else None,
            baseline='NONE_EXPLICIT_REQUEST'),source_kind='INDEX' if staged else 'WORKTREE'))
        if lease is None: raise ExplicitScanBusy()

    def publish(view,result):
        # Still inside the exact fixed-input lifetime; no live workspace is
        # substituted after Runtime has disposed of its private source view.
        applicability=view.check_current()
        with hooks.lock(root,wait_seconds=2) as acquired:
            if not acquired or not attempts.is_current(lease,view.input_id):
                raise ScanAttemptLost('SCAN_ATTEMPT_PUBLICATION_LOST')
            outcome='COMPLETED' if applicability.state=='CURRENT' else 'STALE'
            if not attempts.finish(lease,input_id=view.input_id,scan_id=result.scan_id,outcome=outcome):
                raise ScanAttemptLost('SCAN_ATTEMPT_PUBLICATION_LOST')
        receipt=dict(execution.receipt,publication='COMMITTED' if outcome=='COMPLETED' else 'STALE',
                     source_applicability=applicability.state)
        result.scanner_diagnostics['execution_publication']=receipt
        if outcome=='STALE' and result.scan_context.get('fixed_input',{}).get('applicability')=='CURRENT':
            result.status,result.coverage,result.release_status='PARTIAL','UNKNOWN','REVIEW'
            result.summary+='\n检查对应已捕获的版本；最新来源已变化或无法核验，仍需检查。'

    validator=None
    if request is not None:
        from .selected_scan import selection_captured
        validator=lambda view:selection_captured(view,request.files)
    execution=ScanAttemptExecution(attempts,lease,after_scan=publish,progress=progress,validator=validator)
    try:
        arguments=dict(staged=staged,rules_path=rules_path,execution=execution)
        if request is not None:
            from dataclasses import replace
            request=replace(request,rules_path=Path(rules_path) if rules_path is not None else None)
            arguments['request']=request
        result=runtime.scan(root,mode,**arguments)
        if execution.input_id is None:
            raise ScanAttemptLost('SCAN_ATTEMPT_INPUT_NOT_BOUND')
        if request is not None:
            from .selected_scan import selection_scope
            result.scanner_diagnostics['selected_scope']=selection_scope(result,request.files)
        return result
    except (ScanCancelled,KeyboardInterrupt):
        with hooks.lock(root,wait_seconds=2) as acquired:
            if acquired: attempts.cancel(lease)
        raise
    except BaseException:
        with hooks.lock(root,wait_seconds=2) as acquired:
            if acquired: attempts.finish(lease,input_id=execution.input_id,outcome='FAILED')
        raise
