"""One executable task-review protocol; historical records stay unchanged."""
from __future__ import annotations


PROTOCOL_VERSION = 3


class UnsupportedTaskReviewProtocol(ValueError):
    """Safe rejection without echoing an untrusted protocol value."""

    reason_code = 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'

    def __init__(self, value):
        self.received_protocol = (value if type(value) is int and value in {1, 2, PROTOCOL_VERSION}
                                  else 'MISSING' if value is None else 'INVALID')
        super().__init__('Only task review protocol 3 can execute; older task records remain read-only')

    def response(self, task_ref=None, review_session=None):
        result = dict(status=self.reason_code, reason_code=self.reason_code,
            protocol_version=PROTOCOL_VERSION, received_protocol=self.received_protocol,
            read_only_supported=True, recoverable=False, scanner_run=False,
            repair_authorized=False, message=str(self),
            guidance='Keep the original history and risks. Do not migrate its baseline or reset its budgets. Begin protocol 3 only for new work before editing.')
        if task_ref is not None:
            result['task_ref'] = task_ref
        if review_session is not None:
            result['review_session'] = review_session
        return result


def validate_protocol(value):
    if type(value) is not int or value != PROTOCOL_VERSION:
        raise UnsupportedTaskReviewProtocol(value)
    return PROTOCOL_VERSION


def is_v3_record(record):
    value = record.get('review_protocol')
    return type(value) is int and value == PROTOCOL_VERSION


def require_record_protocol(record):
    return validate_protocol(record.get('review_protocol'))
