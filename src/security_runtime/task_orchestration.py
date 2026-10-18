"""Shared task selection and handoff facts; existing services own all state.

No host payloads, scanner dispatch, baseline capture, leases or repair grants live
here. Delivery facts describe this response, not a durable receipt or user read.
"""
from .task_ownership import record_owner
from .task_review_protocol import is_v3_record, require_record_protocol


class TaskSelectionError(ValueError):
    def __init__(self):
        super().__init__('TASK_OWNER_MISMATCH')


def require_task_owner(record, owner, *, allow_unowned=False):
    if record and record_owner(record) != owner:
        if not (allow_unowned and record_owner(record) is None):
            raise TaskSelectionError()


def historical_tasks(store, owner):
    """Return owned non-executable active history, without selecting a newest row."""
    return [item for item in store.records(active=True)
            if record_owner(item) == owner and not is_v3_record(item)]


def select_task(store, owner, *, task_key=None, task_ref=None, hook=False, include_historical=False):
    """Select an exact task without adopting another owner or a newest record.

    Only the existing Hook lookup may retain its single unowned v3 task.
    An explicit reference is still checked against the requesting Hook owner.
    A unique owned historical task may be returned only for a read-only notice.
    """
    if task_ref is not None:
        record = store.get(task_ref)
    elif hook:
        record = store.for_hook(owner.get('host'), owner.get('session'))
    else:
        record = store.get(active=True, owner=owner)
        if record is None and task_key is not None:
            record = store.get(task_key=task_key)
            if record and record_owner(record) != owner:
                return None
        if record is None and include_historical:
            historical = historical_tasks(store, owner)
            if len(historical) == 1:
                record = historical[0]
    require_task_owner(record, owner, allow_unowned=hook)
    return record


def review_protocol(record):
    """Executable handoffs require an explicit v3 record, never a legacy default."""
    return require_record_protocol(record)


def task_needs_handoff(record):
    return bool(record and is_v3_record(record) and record.get('phase') not in {'COMPLETE', 'NO_CHANGES'})


def task_allows_followup(record):
    # Preserve the bounded report continuation policy; a running check is not a
    # second scan/continuation opportunity and a closed task is not reopened.
    return bool(record and is_v3_record(record) and record.get('phase') in {'ACTIVE', 'READY', 'REVIEWING'})


def followup_identity(record, version):
    """Existing version/phase dedup key, never a synthetic invocation identity."""
    from .task_security import digest_value
    return digest_value(dict(hashes=version['hashes'], phase=record['phase']))


def task_delivery_facts(record, *, scanner_run=None, recording='UNKNOWN',
                        context_returned=False, intent='TASK_FINAL_SUMMARY', delivery_receipt=None):
    """Project known facts without claiming persistence, host consumption or consent."""
    from .task_projection import status as projection_status
    if type(context_returned) is not bool or scanner_run is not None and type(scanner_run) is not bool:
        raise ValueError('Invalid task delivery observation')
    if intent not in {'TASK_FINAL_SUMMARY', 'TASK_CLOSEOUT'}:
        raise ValueError('Invalid task delivery intent')
    if recording not in {'UNKNOWN', 'RECORDED', 'ALREADY_RECORDED', 'FAILURE_MARKER_RECORDED', 'UNAVAILABLE',
                         'NO_MUTATION', 'NOT_APPLICABLE', 'TASK_CLOSED',
                         'TASK_OWNER_MISMATCH', 'TASK_CHANGED'}:
        raise ValueError('Invalid task recording observation')
    # Facts retain the recorded protocol without treating history as executable.
    protocol = record.get('review_protocol')
    if type(protocol) is not int or protocol not in {1, 2, 3}:
        protocol = None
    result = dict(contract='task-delivery-v1', observation_scope='CURRENT_EVENT', task_ref=record['task_ref'],
        phase=record['phase'], review_protocol=protocol,
        task_pending=task_needs_handoff(record), delivery_intent=intent,
        risk_ledger_sync=projection_status(record),
        check_execution='EXECUTED' if scanner_run is True else
            'NOT_EXECUTED' if scanner_run is False else 'UNKNOWN',
        task_recording=recording, context_returned=context_returned,
        host_report_submitted='NOT_OBSERVED', user_consumption='UNKNOWN',
        repair_authorized=False)
    if delivery_receipt is not None:
        import re
        fields = {'contract', 'delivery_ref', 'result_version', 'response_prepared',
            'transport_written', 'host_report_submitted', 'user_consumption', 'recording'}
        if (not isinstance(delivery_receipt, dict) or set(delivery_receipt) != fields
                or delivery_receipt['contract'] != 'task-delivery-receipt-v1'
                or delivery_receipt['recording'] not in {'RECORDED', 'UNAVAILABLE'}
                or any(type(delivery_receipt[field]) is not bool for field in
                       ('response_prepared', 'transport_written'))
                or delivery_receipt['user_consumption'] != 'UNKNOWN'
                or delivery_receipt['host_report_submitted'] not in {'NOT_OBSERVED', 'REPORTED'}):
            raise ValueError('Invalid task delivery receipt facts')
        if delivery_receipt['recording'] == 'RECORDED':
            if (not re.fullmatch(r'tdr1-[a-f0-9]{64}', delivery_receipt['delivery_ref'] or '')
                    or not re.fullmatch(r'[a-f0-9]{64}', delivery_receipt['result_version'] or '')):
                raise ValueError('Invalid task delivery receipt identity')
        elif (delivery_receipt['delivery_ref'] is not None or delivery_receipt['result_version'] is not None
                or delivery_receipt['response_prepared'] or delivery_receipt['transport_written']
                or delivery_receipt['host_report_submitted'] != 'NOT_OBSERVED'):
            raise ValueError('Unavailable delivery receipt cannot claim delivery')
        result['delivery_receipt'] = dict(delivery_receipt)
        result['host_report_submitted'] = delivery_receipt['host_report_submitted']
    return result
