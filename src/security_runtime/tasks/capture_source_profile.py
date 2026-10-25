"""Birth-only capture-source fencing with an explicit publication marker.

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
        if (DESCRIPTOR_FIELD in value
                and not (value is record.get('baseline') and 'capture_publication' in record)):
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
        if 'capture_publication' in record:
            raise CaptureSourceProfileError()
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
    marker = record.get('capture_publication')
    if 'capture_publication' in record:
        import re
        if (not isinstance(marker, dict) or set(marker) != {'payload', 'mac'}
                or not isinstance(marker.get('mac'), str)
                or re.fullmatch('[a-f0-9]{64}', marker['mac']) is None
                or not isinstance(marker.get('payload'), dict)):
            raise CaptureSourceProfileError()
        identity = marker['payload']
        if (set(identity) != {'contract', 'task_ref', 'request_id', 'identity_digest'}
                or identity.get('contract') != 'task-baseline-capture-publication-v1'
                or identity.get('task_ref') != record.get('task_ref')
                or not isinstance(identity.get('request_id'), str)
                or re.fullmatch('cp1-[a-f0-9]{64}', identity['request_id']) is None
                or not isinstance(identity.get('identity_digest'), str)
                or re.fullmatch('[a-f0-9]{64}', identity['identity_digest']) is None):
            raise CaptureSourceProfileError()
    if DESCRIPTOR_FIELD in baseline:
        from ..task_review.capture_source_binding import (CaptureSourceBinding,
            CaptureSourceBindingError, validate_descriptor)
        try:
            scope = CaptureSourceBinding(record['task_ref'], record_owner(record), 'baseline',
                record['task_ref'], baseline['redaction_version'])
            descriptor = validate_descriptor(scope, {DESCRIPTOR_FIELD: baseline[DESCRIPTOR_FIELD]})
            if descriptor['source'] != baseline.get('paged_entries', {}).get('source'):
                raise CaptureSourceProfileError()
        except (CaptureSourceBindingError, ValueError, TypeError, KeyError, AttributeError):
            raise CaptureSourceProfileError() from None


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
