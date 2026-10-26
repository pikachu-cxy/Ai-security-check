"""Task B-to-C audits; startup observations never claim a product baseline."""
from datetime import datetime
import time

MODE = 'AI_DEVELOPMENT_TASK_AUDIT'
CONTRACT = 'workspace-task-diff-v1'
BASELINE_MESSAGE = '当前任务审计模式不要求产品启动比较基线。'


def startup_baseline():
    return dict(status='NOT_REQUIRED', required=False, created=False,
                message=BASELINE_MESSAGE)


def saved_scan_preparation():
    """Bounded metadata only; never run version probes, downloads or scanners.

    Saved health is explicitly historical. Actual availability remains the
    independent preparation query and each task's real execution result.
    """
    from .background_preparation import current_preparation
    from .install_readiness import validate_readiness_receipt
    saved = current_preparation()
    receipt = saved.get('receipt') or {}
    result = dict(status='NOT_VERIFIED', verified_now=False, current_ready=None,
                  source='SAVED_PREPARATION_METADATA', components={}, vulnerability_data=None)
    states = {'NOT_STARTED', 'QUEUED', 'PREPARING', 'RESUMING', 'READY', 'PARTIAL',
              'FAILED', 'STALE', 'INTERRUPTED', 'OTHER_BUILD', 'UNKNOWN'}
    result['background_status'] = saved.get('status') if saved.get('status') in states else 'UNKNOWN'
    if result['background_status'] in {'FAILED', 'PARTIAL', 'STALE', 'INTERRUPTED', 'OTHER_BUILD'}:
        result['status'] = 'KNOWN_GAPS'
    if not validate_readiness_receipt(receipt):
        return result
    issues = []
    for name in ('semgrep', 'gitleaks', 'trivy'):
        item = receipt['tools'][name]
        # The validated receipt supplies closed enums; no arbitrary messages,
        # executable paths, arguments or exception text enter Host context.
        result['components'][name] = dict(saved_status=item['status'],
                                        ready_at_observation=item['ready'])
        if not item['ready']:
            issues.append(name)
    database = receipt['vulnerability_db']
    freshness = database['freshness']
    if database.get('next_update'):
        try:
            if datetime.fromisoformat(database['next_update']).timestamp() <= time.time():
                freshness = 'STALE'
        except (TypeError, ValueError, OverflowError):
            freshness = 'UNKNOWN'
    result['vulnerability_data'] = dict(saved_status=database['status'], freshness=freshness)
    if issues or freshness != 'FRESH' or not database['ready']:
        result.update(status='KNOWN_GAPS', affected_components=issues)
    return result


def startup_message(preparation):
    message = 'AI 开发任务审计已连接。' + BASELINE_MESSAGE + '每个任务首次编辑前建立修改前记录，结束后检查实际差异。'
    if preparation['status'] == 'KNOWN_GAPS':
        message += '已保存的扫描组件或漏洞数据状态存在准备缺口；这些问题仍须独立处理。'
        if (preparation.get('vulnerability_data') or {}).get('freshness') == 'STALE':
            message += '漏洞数据已过期。'
    message += '组件及漏洞数据尚未在本次启动中实时核验，就绪状态单独查询。'
    return message


def connection_readiness():
    preparation = saved_scan_preparation()
    return dict(status='CONNECTED', operating_mode=MODE, audit_scope_contract=CONTRACT,
        startup_comparison_baseline=startup_baseline(), scan_preparation=preparation,
        message=startup_message(preparation), project_scan_status='NOT_REQUESTED',
        task_baseline_ready=False, task_baseline_requirement='SYNCHRONOUS_BEFORE_FIRST_EDIT',
        scanner_run=False, source_modified=False, security_proof=False)


def task_activity(hooks, root, host, session, *, paths=(), scope_unknown=True, event_id=None):
    """Append to an original owner-bound task; never create B after a mutation."""
    from .host_event_runtime import inconclusive
    from .tasks.activity import ActivityStore, POLICY, LEGACY
    from .tasks.ownership import record_owner, session_owner
    from .tasks.security_state import TaskSecurityStore
    from .task_review.protocol import require_record_protocol
    owner = session_owner(host, session)
    activity = ActivityStore(hooks, root)
    focus = activity.focus(owner)
    if not focus or not focus.get('task_ref'):
        return inconclusive('TASK_BASELINE_REQUIRED')
    record = TaskSecurityStore(hooks, root).get(focus['task_ref'], headers=True)
    if not record or record_owner(record) != owner:
        return inconclusive('TASK_BASELINE_UNAVAILABLE')
    require_record_protocol(record)
    if record['phase'] in {'COMPLETE', 'NO_CHANGES', 'INCOMPLETE'}:
        return inconclusive('TASK_BASELINE_REQUIRED')
    if focus.get('policy') not in {POLICY, LEGACY}:
        return inconclusive('TASK_BASELINE_UNAVAILABLE')
    row = activity.record(owner, event_id=event_id, paths=paths,
                          scope_unknown=scope_unknown, allow_legacy=True)
    if row is None or row.get('task_ref') != record['task_ref']:
        return inconclusive('TASK_BASELINE_UNAVAILABLE')
    from .hook_observation_contract import TASK_CLOSEOUT_PENDING, deferred_activity_facts
    result = inconclusive(TASK_CLOSEOUT_PENDING)
    result.update(deferred_activity_facts(), security_task_ref=record['task_ref'],
        activity_seq=row['seq'], task_edit_check_policy=record.get('check_policy', LEGACY),
        task_baseline_status='PARTIAL' if record['baseline']['limitations'] else 'CAPTURED',
        next_step='Finish this original task and review its complete workspace B-to-C difference.')
    return result
