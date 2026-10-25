"""Keep readable review work active without changing evidence or allowances."""
from __future__ import annotations

from .plan import _plan, _unit_gaps


DELIVERY_BLOCKERS = frozenset({
    'TASK_CONTEXT_BYTE_BUDGET', 'TASK_CONTEXT_SOURCE_BUDGET',
    'TASK_CONTEXT_NAVIGATION_BUDGET', 'TASK_CONTEXT_CONTROL_BUDGET',
    'TASK_CONTEXT_READ_BUDGET', 'TASK_REVIEW_RECORD_CAPACITY',
    'TASK_REVIEW_CAPACITY_REQUIRED',
})


def retain_delivery_blocker(service, root, record, reason):
    if reason in DELIVERY_BLOCKERS:
        # Refused packets must not save pending evidence, charges or lease
        # renewals. Persist only the actual failure on the last signed record.
        saved = service.load(root, record['task_ref'])
        saved['review_delivery_blocker'] = record['review_delivery_blocker'] = dict(
            reason=reason, review_revision=record.get('review_revision', 1))
        service.store(root).save_review(saved)


def _delivery_blocked(record):
    ledger = record['review_ledger']
    limits = ledger['limits']
    blocker = record.get('review_delivery_blocker') or {}
    return ((blocker.get('reason') in DELIVERY_BLOCKERS
             and blocker.get('review_revision') == record.get('review_revision', 1))
            or ledger['capacity']['status'] != 'READY'
            or ledger['total_bytes'] >= limits['total_bytes']
            or ledger['reads'] >= limits['reads']
            or limits['response_bytes'] < 512
            or any(ledger[key + '_bytes'] >= maximum
                   for key, maximum in ledger['category_limits'].items()))


def _unavailable(record, gap):
    # Only Runtime-recorded source failures excuse a read. Host prose, a
    # scanner failure or a masked literal cannot exempt other readable work.
    version = gap['location_version']
    accepted_versions = {version, 'CURRENT' if version == 'CURRENT_TASK_END' else 'BEFORE_TASK'}
    for failure in [*record.get('limitations', []), *record.get('context_gaps', [])]:
        if (failure.get('path') == gap['path']
                and failure.get('location_version') in accepted_versions
                and (failure.get('reason', '').startswith('TASK_PREIMAGE_')
                     or failure.get('reason') in {'TASK_SOURCE_UNAVAILABLE', 'TASK_CONTEXT_SOURCE_UNAVAILABLE'})):
            return True
    return False


def continuation(record):
    """Return one bounded next step; terminal PARTIAL is for real blockers."""
    plan = _plan(record)
    if _delivery_blocked(record):
        return None
    pending, first = 0, None
    for unit in plan['units']:
        gaps = _unit_gaps(plan, unit)
        unread = next((gap for gap in gaps
                       if gap['reason'] in {'SOURCE_RANGE_UNREAD', 'SOURCE_RANGE_UNKNOWN'}
                       and not _unavailable(record, gap)), None)
        if unread is None and unit['submitted_at'] is not None:
            continue
        pending += 1
        if first is not None:
            continue
        action = dict(task_ref=record['task_ref'], review_session=record['review_session'])
        if unread is not None:
            low = unread['start_line']
            action.update(tool='read_task_review_context', file_path=unread['path'],
                source_version='CURRENT' if unread['location_version'] == 'CURRENT_TASK_END' else 'BEFORE_TASK',
                start_line=low, end_line=min(low + 79, unread.get('end_line') or low + 79))
        else:
            action.update(tool='submit_task_review_batch', unit_ids=[unit['unit_id']])
        first = action
    if first is None:
        return None
    return dict(status='REVIEW_CONTINUE_REQUIRED', task_ref=record['task_ref'],
        review_session=record['review_session'], review_required=True,
        result_saved=False, review_state_changed=False, scanner_run=False,
        source_modified=False, repair_authorized=False, pending_unit_count=pending,
        next_action=first,
        message='仍有可完成的逐文件复核，本次未保存最终结论或结束任务。',
        guidance='沿用原任务、会话、全部计划分页、证据和累计额度，读取剩余窗口并完成推理及逐项提交，再重新提交最终结论。脱敏或静态检查受限不免除其他可读范围；不要重新扫描、重建基线或要求用户再次确认继续。')
