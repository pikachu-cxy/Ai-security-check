"""Bounded task execution diagnostics; never echo arbitrary source or SDK input."""
from __future__ import annotations


def capacity_failure(exc):
    from ..ledger_partitions import LedgerCapacity
    cause = exc
    for _ in range(8):
        if isinstance(cause, LedgerCapacity):
            return dict(status='INCONCLUSIVE', reason_code=cause.reason_code,
                scanner_run=False, source_modified=False, security_proof=False, repair_authorized=False,
                message='风险记录容量不足，本次核查未能完成。原任务、修改前记录和历史均已保留；请保留原任务进行容量诊断，不能清空历史或重建基线冒充完成。',
                capacity=dict(observed=cause.count, maximum=cause.limit), original_task_preserved=True)
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None
