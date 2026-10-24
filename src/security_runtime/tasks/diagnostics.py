"""Bounded task execution diagnostics; never echo arbitrary source or SDK input."""
from __future__ import annotations


class TaskRuntimeRestartRequired(ValueError):
    """Loaded task modules cannot safely execute the newer recovery contract."""
    def __init__(self):
        super().__init__('RUNTIME_RESTART_REQUIRED')


def owned_storage_failure(exc):
    """Keep typed storage admission separate from workspace/session rejection.

    The caller may already have performed work before admission failed, so this
    response deliberately makes no claim that a scanner did or did not run.
    Never return the filesystem report, target paths or arbitrary exception text.
    """
    from ..owned_workspace_storage import OwnedWorkspaceStorageError
    cause = exc
    for _ in range(8):
        if isinstance(cause, OwnedWorkspaceStorageError):
            states = {'BUSY', 'RETRY', 'UPGRADE_INCOMPLETE', 'UNSAFE', 'PLATFORM_UNSUPPORTED'}
            state = cause.report.get('state')
            if state not in states or cause.reason_code != 'OWNED_WORKSPACE_STORAGE_' + state:
                return None
            busy = state in {'BUSY', 'RETRY'}
            # A partial permission upgrade may have tightened some targets.
            # Retry full admission on the original path; never discard frozen
            # inputs or relax those modes to simulate rollback.
            retryable = busy or state == 'UPGRADE_INCOMPLETE'
            return dict(status='BUSY' if busy else 'INCONCLUSIVE',
                reason_code=cause.reason_code, stage='PRIVATE_STORAGE_ADMISSION',
                retryable=retryable, original_records_preserved=True,
                retry_original_request=True, baseline_recreated=False,
                source_modified=False, security_proof=False, repair_authorized=False,
                message=('状态目录暂时繁忙或正在变化，请沿原任务和原参数重试，保留原记录。'
                         if busy else
                         '状态目录权限准入未完成，原记录和已收紧的权限保留；'
                         '请沿原路径处理后重试，不要清空历史或重新建立旧基线。'))
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None


def runtime_compatibility_failure(exc):
    cause = exc
    for _ in range(8):
        if isinstance(cause, TaskRuntimeRestartRequired):
            return dict(status='INCONCLUSIVE', reason_code='RUNTIME_RESTART_REQUIRED',
                scanner_run=False, source_modified=False, security_proof=False, repair_authorized=False,
                original_task_preserved=True, baseline_recreated=False,
                recovery=dict(action='RECONNECT_RUNTIME', resume_tool='prepare_task_security_review',
                              same_task_required=True),
                message='运行中的任务组件与收尾恢复接口不兼容；请重新连接 Runtime 后沿原任务继续，保留原基线与累计额度，不要新建任务。')
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None


def capacity_failure(exc):
    from ..ledger_partitions import LedgerCapacity
    from ..snapshot_store import SnapshotStoreError
    cause = exc
    for _ in range(8):
        if isinstance(cause, SnapshotStoreError) and cause.reason_code == 'SNAPSHOT_WAITING_CAPACITY':
            return dict(status='INCONCLUSIVE', reason_code=cause.reason_code,
                source_modified=False, security_proof=False, repair_authorized=False,
                prior_committed_evidence_preserved=True, baseline_recreated=False,
                capacity=dict(storage='WORKSPACE_SNAPSHOT_PAGES', state='WAITING_CAPACITY'),
                message='快照页存储容量不足，本次操作未完成；已提交的原始证据保留。请检查存储配额，不能清空历史或用当前目录补建旧基线。')
        if isinstance(cause, LedgerCapacity):
            return dict(status='INCONCLUSIVE', reason_code=cause.reason_code,
                scanner_run=False, source_modified=False, security_proof=False, repair_authorized=False,
                message='风险记录容量不足，本次核查未能完成。原任务、修改前记录和历史均已保留；请保留原任务进行容量诊断，不能清空历史或重建基线冒充完成。',
                capacity=dict(observed=cause.count, maximum=cause.limit), original_task_preserved=True)
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None
