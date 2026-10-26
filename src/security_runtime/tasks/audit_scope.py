"""New results audit workspace differences, not the authors of those changes."""
from ..task_audit_mode import CONTRACT

LEGACY_ATTRIBUTION_REASON = 'CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE'


def apply(record):
    """Only a new finish/submission calls this; historical reads never rewrite."""
    old = [item for item in record.get('limitations', ())
           if item.get('reason') == LEGACY_ATTRIBUTION_REASON]
    if old:
        history = list(record.get('historical_attribution_observations', ()))
        for item in old:
            if item not in history:
                history.append(dict(item))
        record['historical_attribution_observations'] = history
        record['limitations'] = [item for item in record['limitations']
                                 if item.get('reason') != LEGACY_ATTRIBUTION_REASON]
    record['audit_scope_contract'] = CONTRACT
    return record
