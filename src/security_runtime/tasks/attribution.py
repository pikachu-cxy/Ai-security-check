"""Conservative pre-baseline witnesses for idle sessions and dead connections.

This never closes, adopts or rewrites another task. Host sessions can reconnect;
their MCP/Hook process exiting is not evidence that editing has ended.
"""
import math
import time

from .ownership import LEASE_SECONDS, record_owner, valid_owner, writer_gone
from ..task_review.protocol import is_v3_record

CONTRACT = 'task-attribution-start-v1'


def session_activity(hooks, root, owner, *, idle=False, now=time.time):
    """Validated host events checkpoint activity, never verdicts or risk state.

    Stop is only an idle boundary. Reconnect/activity invalidates it; any task
    save also invalidates it. Unknown history is never backfilled from a PID.
    """
    from .security_state import TaskSecurityStore
    if not valid_owner(owner) or owner['host'] not in {'codex', 'cursor'}:
        return
    store = TaskSecurityStore(hooks, root, now=now)
    def applicable(record):
        if record_owner(record) != owner:
            return False
        if not idle:
            return bool(record.get('session_idle'))
        return (record['phase'] == 'ACTIVE' and record.get('static_attempts') == 0 and not any(
            record.get(key) for key in ('end', 'static', 'review_plan', 'review')))
    # Ordinary read-only events/Stop must not create task state or enter a
    # write lock when there is no existing checkpoint to update.
    if not any(applicable(record) for record in store.records(active=True)):
        return
    with hooks.lock(root, wait_seconds=2) as acquired:
        if not acquired:
            raise ValueError('Task session activity lock unavailable')
        for record in store.records(active=True):
            if not applicable(record):
                continue
            if idle:
                store.save(record, session_idle=True)
            else:
                store.save(record)


def _idle_session(record, instant):
    owner, checkpoint = record_owner(record), record.get('session_idle')
    return (is_v3_record(record) and record.get('phase') == 'ACTIVE'
        and type(record.get('static_attempts')) is int and record['static_attempts'] == 0
        and not any(record.get(key) for key in ('end', 'static', 'review_plan', 'review'))
        and valid_owner(owner) and owner['host'] in {'codex', 'cursor'}
        and isinstance(checkpoint, dict) and set(checkpoint) == {'contract', 'observed_at', 'generation'}
        and checkpoint['contract'] == 'task-session-idle-v1'
        and type(checkpoint['generation']) is int and checkpoint['generation'] == record.get('generation')
        and type(checkpoint['observed_at']) in (int, float) and math.isfinite(checkpoint['observed_at'])
        and checkpoint['observed_at'] == record.get('activity_at')
        and type(record.get('created_at')) in (int, float) and math.isfinite(record['created_at'])
        and record['created_at'] <= checkpoint['observed_at'] <= instant)


def _witness(record):
    return dict(generation=record.get('generation'), owner=record_owner(record),
                writer=record.get('writer'), created_at=record['created_at'],
                session_idle=record.get('session_idle'))


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
    return dict(contract=CONTRACT, observed_at=instant, idle_sessions={
        item['task_ref']: _witness(item) for item in records if _idle_session(item, instant)}, disconnected={
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
    idle = start.get('idle_sessions', {}) if (
        start.get('contract') == CONTRACT and start.get('observed_at') == record['created_at']) else {}
    if not isinstance(idle, dict):
        idle = {}
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
        if idle.get(other['task_ref']) == _witness(other) and _idle_session(other, record['created_at']):
            continue
        overlaps.append(other)
    return overlaps
