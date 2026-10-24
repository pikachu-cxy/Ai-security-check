"""Bounded task execution diagnostics; never echo arbitrary source or SDK input."""
from __future__ import annotations


class TaskRuntimeRestartRequired(ValueError):
    """Loaded task modules cannot safely execute the newer recovery contract."""
    def __init__(self):
        super().__init__('RUNTIME_RESTART_REQUIRED')


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
