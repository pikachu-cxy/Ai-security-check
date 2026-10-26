"""Shared closed facts for edit activity deferred to the original task."""
RECORDED_PENDING = 'RECORDED_PENDING'
TASK_CLOSEOUT_PENDING = 'TASK_CLOSEOUT_PENDING'
DEFERRED_TO_TASK_CLOSEOUT = 'DEFERRED_TO_TASK_CLOSEOUT'
ACTIVITY_STATUSES = frozenset({RECORDED_PENDING})
ACTIVITY_REASONS = frozenset({TASK_CLOSEOUT_PENDING, DEFERRED_TO_TASK_CLOSEOUT})


def deferred_activity_facts():
    return dict(status=RECORDED_PENDING, reason=TASK_CLOSEOUT_PENDING,
        scanner_skipped_reason=DEFERRED_TO_TASK_CLOSEOUT,
        task_activity_recorded=True, task_audit_complete=False)
