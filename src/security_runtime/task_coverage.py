"""Presentation of before-body gaps; persisted coverage gates stay unchanged."""

BODY_REASONS = frozenset({
    'SNAPSHOT_INLINE_TEXT_BYTE_BUDGET', 'TASK_PREIMAGE_FILE_BUDGET',
    'TASK_PREIMAGE_FILE_COUNT_BUDGET', 'TASK_PREIMAGE_TASK_BYTE_BUDGET',
    'TASK_PREIMAGE_WORKSPACE_BYTE_BUDGET', 'TASK_PREIMAGE_DATABASE_BUDGET',
    'TASK_PREIMAGE_STORE_UNAVAILABLE', 'TASK_PREIMAGE_REFERENCE_BUDGET',
    'TASK_PREIMAGE_SOURCE_REJECTED', 'TASK_PREIMAGE_CONTENT_UNVERIFIED',
})
CAPTURE_GAP = 'TASK_BEFORE_SOURCE_CAPTURE_INCOMPLETE'
CAPTURE_LABEL = '工作区修改前正文未完整留存，核查仍保留覆盖限制'


def capture_gap_note(value):
    if any(type(value.get(key)) is not int or value[key] < 0
           for key in ('count', 'affected_file_count')):
        return CAPTURE_LABEL
    return (f"工作区有 {value['count']} 个文件未留存修改前正文；"
            f"本次改动中有 {value['affected_file_count']} 个文件缺少修改前正文，核查仍保留覆盖限制。")


def display_limitations(record, values):
    """Do not mistake the first 100 workspace failures for the task's scope.

    Keep original signed limitations for coverage/closure, and keep inventory,
    hash, unknown and unrelated-source errors visible. The full per-path body
    map can locate a changed file even beyond the bounded diagnostic list.
    """
    baseline = record.get('baseline') or {}
    unavailable = baseline.get('text_unavailable') or {}
    body_gaps = [item for item in values if isinstance(item, dict)
                 and item.get('reason') in BODY_REASONS and item.get('path')]
    if not body_gaps:
        return values
    missing = {item['path'] for item in body_gaps} | {
        path for path, reason in unavailable.items() if reason in BODY_REASONS}
    changed = {item['path'] for item in record.get('changes', ())}
    affected = sorted(missing & changed)
    summary = dict(reason=CAPTURE_GAP, count=len(missing), paths=affected,
                   affected_file_count=len(affected), workspace_capture_only=True)
    # Never silently drop unknown limitation types or mutate historical records.
    remaining = [item for item in values if item not in body_gaps]
    return [summary, *remaining]
