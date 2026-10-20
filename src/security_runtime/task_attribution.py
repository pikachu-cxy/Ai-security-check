"""Conservative pre-baseline witnesses for disconnected connection-only tasks.

This never closes, adopts or rewrites another task. Host sessions can reconnect;
their MCP/Hook process exiting is not evidence that editing has ended.
"""
import math

from .task_ownership import LEASE_SECONDS, record_owner, valid_owner, writer_gone
from .task_review_protocol import is_v3_record

CONTRACT = 'task-attribution-start-v1'


def _expired_connection(record, instant):
    owner = record_owner(record)
    writer = record.get('writer')
    times = [record.get(key) for key in ('created_at', 'activity_at', 'lease_until')]
    return (is_v3_record(record) and record.get('phase') == 'ACTIVE'
        and type(record.get('static_attempts')) is int and record['static_attempts'] == 0
        and not any(record.get(key) for key in ('end', 'static', 'review_plan', 'review'))
        and valid_owner(owner) and owner['host'] == 'connection'
        and not record.get('connector_owner')
        and type(record.get('generation')) is int and record['generation'] > 0
        and all(type(value) in (int, float) and math.isfinite(value) for value in times)
        and times[0] <= times[1] < times[2] <= instant
        and times[2] >= times[1] + LEASE_SECONDS
        and isinstance(writer, dict) and type(writer.get('pid')) is int and writer['pid'] > 0
        and isinstance(writer.get('stamp'), str) and bool(writer['stamp'])
        and writer_gone(writer))


def observe_start(records, instant):
    """Call under the workspace lock BEFORE capturing a new task's baseline."""
    return dict(contract=CONTRACT, observed_at=instant, disconnected={
        item['task_ref']: dict(generation=item['generation'], owner=record_owner(item),
                              writer=item['writer'], created_at=item['created_at'])
        for item in records if _expired_connection(item, instant)})


def overlapping_tasks(record, records, instant):
    """Absence first observed at finish cannot erase an earlier editing overlap."""
    start = record.get('attribution_start')
    if not isinstance(start, dict):
        start = {}
    witnesses = (start.get('disconnected', {})
        if start.get('contract') == CONTRACT and start.get('observed_at') == record['created_at'] else {})
    if not isinstance(witnesses, dict):
        witnesses = {}
    overlaps = []
    for other in records:
        if (other['task_ref'] == record['task_ref'] or other['created_at'] > instant
                or other.get('closed_at', float('inf')) <= record['created_at']):
            continue
        witness = witnesses.get(other['task_ref'])
        if (witness == dict(generation=other.get('generation'), owner=record_owner(other),
                            writer=other.get('writer'), created_at=other['created_at'])
                and _expired_connection(other, record['created_at'])):
            continue
        overlaps.append(other)
    return overlaps
