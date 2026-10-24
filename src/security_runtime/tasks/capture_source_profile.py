"""Birth-only capture-source fencing; no source publisher is enabled here.

The new policy makes older task readers reject these fresh opt-in records.
Original donor pages retain their existing GC domain and all task accounting.
"""
from .ownership import record_owner, valid_owner


POLICY = 'BATCHED_FILES_GC_SOURCE_V2'
PROFILE = 'CAPTURE_SOURCES_V2'
PROFILE_FIELD = 'capture_source_profile'
DESCRIPTOR_FIELD = 'capture_source'
_SINGLES = ('baseline', 'end', 'snapshot')
_HISTORIES = ('previous_reviews', 'review_history', 'previous_snapshots')


class CaptureSourceProfileError(ValueError):
    def __init__(self, suffix='INVALID'):
        self.reason_code = 'CAPTURE_SOURCE_PROFILE_' + suffix
        super().__init__(self.reason_code)


def _no_descriptors(record):
    # Inspect only control/snapshot containers, never user map or preimage
    # values. This reserve does not interpret source JSON as a new contract.
    pending, count = [record], 0
    while pending:
        value = pending.pop()
        count += 1
        if count > 4096:
            raise CaptureSourceProfileError()
        if not isinstance(value, dict):
            continue
        if DESCRIPTOR_FIELD in value:
            raise CaptureSourceProfileError('PUBLISHER_UNAVAILABLE')
        pending.extend(value[name] for name in _SINGLES if isinstance(value.get(name), dict))
        for name in _HISTORIES:
            history = value.get(name)
            if isinstance(history, list):
                pending.extend(item for item in history if isinstance(item, dict))


def validate_record(record):
    """Check the signed control combination without reading source or time."""
    if not isinstance(record, dict):
        raise CaptureSourceProfileError()
    _no_descriptors(record)
    present = PROFILE_FIELD in record
    if not present and record.get('capture_policy') != POLICY:
        return
    from .activity import POLICY as CLOSEOUT_POLICY
    from .frozen_body_context import (CONTRACT as BODY_CONTRACT, PROFILE as BODY_PROFILE,
                                    PROFILE_FIELD as BODY_FIELD, CONTEXT_FIELD)
    from .snapshot_pages import GC_CONTRACT
    baseline = record.get('baseline')
    context = baseline.get(CONTEXT_FIELD) if isinstance(baseline, dict) else None
    payload = context.get('payload') if isinstance(context, dict) else None
    if (not present or record[PROFILE_FIELD] != PROFILE
            or record.get('contract') != GC_CONTRACT or record.get('capture_policy') != POLICY
            or record.get('check_policy') != CLOSEOUT_POLICY
            or record.get('native_repair') is not None or not valid_owner(record_owner(record))
            or record.get(BODY_FIELD) != BODY_PROFILE or not isinstance(payload, dict)
            or payload.get('contract') != BODY_CONTRACT or payload.get('profile') != BODY_PROFILE
            or payload.get('task_ref') != record.get('task_ref')
            or payload.get('preimage_task_ref') != record.get('task_ref')
            or payload.get('owner') != record_owner(record) or payload.get('workspace') != record.get('workspace')
            or payload.get('field') != 'baseline' or payload.get('preimage_namespace') != 'closeout'
            or payload.get('representation_version') != baseline.get('redaction_version')):
        raise CaptureSourceProfileError()


def validate_transition(old, record, *, new):
    """Apply under the existing task CAS; never adopt or downgrade a task."""
    validate_record(record)
    if new:
        return
    if not isinstance(old, dict):
        raise CaptureSourceProfileError()
    for name in (PROFILE_FIELD, 'capture_policy'):
        # Missing and explicit None are distinct persisted contracts.
        if (name in old, old.get(name)) != (name in record, record.get(name)):
            raise CaptureSourceProfileError()
