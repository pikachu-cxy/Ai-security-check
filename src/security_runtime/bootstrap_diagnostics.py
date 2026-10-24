"""Closed preparation diagnostics; never retain exception text or source paths."""
from __future__ import annotations


BASELINE_REASONS = frozenset({
    'BASELINE_BUSY', 'BASELINE_DEADLINE_EXCEEDED',
    'BASELINE_FILE_BUDGET_EXCEEDED', 'BASELINE_CONTENT_BUDGET_EXCEEDED',
    'BASELINE_SOURCE_CHANGED', 'BASELINE_COVERAGE_INSUFFICIENT',
    'BASELINE_STATE_PERMISSION_DENIED', 'BASELINE_GIT_SNAPSHOT_UNAVAILABLE',
    'BASELINE_CHECK_INCONCLUSIVE', 'INITIALIZATION_INCONCLUSIVE',
    'BASELINE_CAPACITY_WAIT', 'BASELINE_PROGRESS_WAIT',
    'BASELINE_HISTORY_UNAVAILABLE', 'BASELINE_PLATFORM_UNSUPPORTED',
})


class BaselinePreparationError(ValueError):
    def __init__(self, code):
        self.code = code if code in BASELINE_REASONS else 'BASELINE_CHECK_INCONCLUSIVE'
        super().__init__(self.code)


def baseline_failure_reason(error):
    if isinstance(error, BaselinePreparationError):
        return error.code
    if isinstance(error, PermissionError):
        return 'BASELINE_STATE_PERMISSION_DENIED'
    product_reason = getattr(error, 'reason_code', None)
    if product_reason in {'PRODUCT_EPOCH_HISTORY_UNAVAILABLE', 'PRODUCT_EPOCH_WAITING_CAPACITY',
                          'PRODUCT_EPOCH_NO_PROGRESS',
                          'PRODUCT_EPOCH_PLATFORM_UNSUPPORTED', 'PLATFORM_UNSUPPORTED'}:
        return {'PRODUCT_EPOCH_HISTORY_UNAVAILABLE': 'BASELINE_HISTORY_UNAVAILABLE',
                'PRODUCT_EPOCH_WAITING_CAPACITY': 'BASELINE_CAPACITY_WAIT',
                'PRODUCT_EPOCH_NO_PROGRESS': 'BASELINE_PROGRESS_WAIT',
                'PRODUCT_EPOCH_PLATFORM_UNSUPPORTED': 'BASELINE_PLATFORM_UNSUPPORTED',
                'PLATFORM_UNSUPPORTED': 'BASELINE_PLATFORM_UNSUPPORTED'}[product_reason]
    # Older snapshot helpers retain their public ValueError contract. Match
    # only complete fixed messages; arbitrary exception text is never copied.
    return {
        'Unable to read bounded Git hook snapshot': 'BASELINE_GIT_SNAPSHOT_UNAVAILABLE',
        'Hook snapshot file count budget exceeded': 'BASELINE_FILE_BUDGET_EXCEEDED',
        'Hook snapshot file budget exceeded': 'BASELINE_CONTENT_BUDGET_EXCEEDED',
        'Hook comparison file budget exceeded': 'BASELINE_FILE_BUDGET_EXCEEDED',
        'Hook snapshot content budget exceeded': 'BASELINE_CONTENT_BUDGET_EXCEEDED',
        'Hook comparison content budget exceeded': 'BASELINE_CONTENT_BUDGET_EXCEEDED',
        'SNAPSHOT_CHANGED': 'BASELINE_SOURCE_CHANGED',
    }.get(str(error), 'BASELINE_CHECK_INCONCLUSIVE')
