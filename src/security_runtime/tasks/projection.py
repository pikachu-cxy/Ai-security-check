"""Recoverable task-to-ledger projection, separate from task/review completion.

The intent is part of the existing signed task transaction. Reads never replay
it; callers must own the workspace lock and the original task before draining.
This does not migrate the ledger or confer repair authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sqlite3


CONTRACT = 'task-ledger-projection-v1'
_OWNER_UNSET = object()


def _basis(record):
    value = {key: record.get(key) for key in
             ('task_ref', 'review_revision', 'static', 'review')}
    value['end_hashes'] = (record.get('end') or {}).get('hashes', {})
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def enqueue(record, updates=None, expected_versions=None):
    """Return a candidate; TaskSecurityStore.save signs it with the result."""
    result = dict(record)
    projection = dict(contract=CONTRACT, state='PENDING', basis=_basis(record),
        host_updates=copy.deepcopy(updates or {}),
        expected_versions=dict(expected_versions or {}))
    projection['projection_id'] = hashlib.sha256(json.dumps(projection,
        sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    result['ledger_projection'] = projection
    return result


def status(record):
    projection = record.get('ledger_projection')
    if projection is None:
        return dict(state='LEGACY_NOT_RECORDED', pending=False)
    if not isinstance(projection, dict) or projection.get('contract') != CONTRACT:
        return dict(state='UNAVAILABLE', pending=True)
    state = projection.get('state')
    if state not in {'PENDING', 'APPLIED', 'SUPERSEDED'}:
        return dict(state='UNAVAILABLE', pending=True)
    result = dict(state=state, pending=state == 'PENDING')
    failure = projection.get('sync_failure')
    if state == 'PENDING' and isinstance(failure, dict):
        result['capacity_failure'] = copy.deepcopy(failure)
    return result


def drain(service, root, record):
    """Replay deterministic ledger writes, never scanners or host reasoning.

    Must run under the existing workspace lock. If acknowledgement fails after
    applying the projection, the signed intent remains pending and can replay.
    Register is an upsert; host updates are assignments already validated at
    submission. They touch neither user dispositions nor repair intents.
    """
    if not service.hooks.lock_held(root):
        raise ValueError('Projection workspace lock required')
    projection = record.get('ledger_projection')
    if not status(record)['pending']:
        return record
    if not isinstance(projection, dict) or projection.get('contract') != CONTRACT:
        return record
    candidate = copy.deepcopy(record)
    try:
        if projection.get('basis') != _basis(record):
            candidate['ledger_projection']['state'] = 'SUPERSEDED'
        else:
            from .risk_ledger import TaskRiskLedger, current_hashes
            updates = projection.get('host_updates', {})
            if not isinstance(updates, dict):
                return record
            for update in updates.values():
                hashes = update.get('proof_hashes', {})
                if not hashes or current_hashes(root, hashes) != hashes:
                    return record  # Never apply an old resolution to new code.
            ledger = TaskRiskLedger(service.hooks, root)
            ledger.register(record)
            if updates:
                ledger.record_host(updates,
                    expected_versions=projection.get('expected_versions', {}),
                    projection_id=projection.get('projection_id'))
            candidate['ledger_projection']['state'] = 'APPLIED'
        candidate['ledger_projection'].pop('host_updates', None)
        candidate['ledger_projection'].pop('expected_versions', None)
        store = service.store(root)
        if record.get('retained_for_projection') is True:
            return store.ack_retained_projection(candidate)
        return store.save(candidate)
    except (OSError, ValueError, sqlite3.DatabaseError) as exc:
        # The source result was committed first. Preserve its pending intent,
        # rather than pretending a failed projection means no risks were found.
        from .diagnostics import capacity_failure
        failure = capacity_failure(exc)
        if failure is not None:
            current = copy.deepcopy(record)
            current['ledger_projection']['sync_failure'] = dict(
                reason_code=failure['reason_code'], capacity=failure['capacity'],
                source_result_saved=True, original_task_preserved=True,
                message='原检查结果已保存；风险账本投影容量不足，待按原任务恢复。')
            return current  # Attempt diagnostic only: do not rewrite source/history.
        return record


def reconcile_pending(service, root, limit=8, *, owner=_OWNER_UNSET):
    """Drain owned retained facts under the caller's workspace lock, never tasks.

    The caller must already hold the workspace lock. Historical query paths must
    not call this function. Expired source bodies and task execution stay expired.
    """
    from .ownership import record_owner, valid_owner
    if not service.hooks.lock_held(root): raise ValueError('Projection workspace lock required')
    if type(limit) is not int or not 1 <= limit <= 32: raise ValueError('Invalid projection limit')
    selected_owner = service._owner() if owner is _OWNER_UNSET else owner
    if selected_owner is not None and not valid_owner(selected_owner):
        raise ValueError('Projection owner cannot be verified')
    selected = service.store(root).pending_projections(32)
    applied, pending, foreign = 0, 0, 0
    for record in selected:
        if record_owner(record) != selected_owner:
            foreign += 1
            continue
        if applied + pending >= limit: break
        result = drain(service, root, record)
        if status(result)['pending']:
            pending += 1
        else:
            applied += 1
    return dict(applied=applied, pending=pending, foreign=foreign,
                scanner_run=False, repair_authorized=False)
