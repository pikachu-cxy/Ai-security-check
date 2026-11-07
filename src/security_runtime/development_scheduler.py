"""Live product supervisor for previously submitted observed-file checks only."""
from __future__ import annotations

import threading
import time

from .development_check import DevelopmentCheckStore, root_identity

_lock = threading.Lock()
_watchers = set()
MAX_LAUNCH_FAILURES = 3


def recover_once(hooks, root, *, launcher=None):
    """No inventory/admission/new task. Failed launches have a durable budget."""
    from .development_check_worker import launch_worker
    store = DevelopmentCheckStore(hooks, root)
    identity = root_identity(store.root)
    rows = [r for r in store.rows() if r.get('kind') == 'check'
            and r.get('root_identity') == identity
            and r.get('finish_requested') and r['state'] in {'QUEUED', 'RUNNING'}]
    if not rows:
        return False
    worker = store.read('$worker')
    if worker and worker.get('lease_until', 0) > store.now():
        if not retire_dead_worker(store, worker, rows):
            return True
    eligible = [r for r in rows if r.get('launch_retry_seq') != r['dirty_seq']
                or r.get('launch_retry_at', 0) <= store.now()]
    if not eligible:
        return True
    try:
        (launcher or launch_worker)(hooks, store.root)
    except (OSError, ValueError):
        from .development_delivery import publish
        with store.transaction() as db:
            for original in eligible:
                row = store._get(db, original['check_ref'])
                if not row['finish_requested'] or row['dirty_seq'] != original['dirty_seq']:
                    continue
                count = (row.get('launch_failures', 0) if row.get('launch_retry_seq') == row['dirty_seq'] else 0) + 1
                changes = dict(launch_failures=count, launch_retry_seq=row['dirty_seq'],
                               launch_retry_at=store.now()+min(2**count, 30),
                               reason_code='DEVELOPMENT_WORKER_START_FAILED')
                if count >= MAX_LAUNCH_FAILURES:
                    changes.update(state='FAILED', failed_seq=row['dirty_seq'])
                current = store._put(db, row['check_ref'], dict(row, **changes))
                if current['state'] == 'FAILED':
                    publish(store, db, dict(current, scanned_seq=row['dirty_seq'], scan_id=None, result=None))
    return True


def retire_dead_worker(store, worker, rows):
    """Only a definitively absent PID may shortcut a lease; unknown stays live.

    A reused PID is conservatively live. Never signal/kill a process. This check
    runs in recovery/supervision, not the normal scanning or Stop caller.
    """
    import os
    pids = {r.get('worker_pid') for r in rows if r.get('worker_ticket') == worker.get('ticket')}
    if len(pids) != 1:
        return False
    pid = pids.pop()
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        pass
    except OSError:
        return False
    with store.transaction() as db:
        current = store._get(db, '$worker')
        if current != worker:
            return False
        store._put(db, '$worker', dict(current, lease_until=0))
    # Only release the attempt belonging to this dead worker's recorded batch.
    from .scan_attempt import ScanAttemptStore, AttemptLease
    attempts = ScanAttemptStore(store.hooks, store.root)
    with store.hooks.lock(store.root, wait_seconds=0) as acquired:
        if acquired:
            lane = attempts.read().get('lane') or {}
            owned = any(r['check_ref'] == lane.get('scope_key') and r['owner'] == lane.get('owner')
                        for r in rows if r.get('worker_ticket') == worker['ticket'])
            if owned and lane.get('state') == 'ACTIVE':
                attempts.retire(AttemptLease(**{k: lane[k] for k in
                    ('attempt_id', 'generation', 'lease_owner', 'cancel_generation')}))
    from .development_check_worker import _release_capacity
    _release_capacity(store.hooks, worker['ticket'], dispatch=False)
    return True


def supervise(hooks, root):
    """Registered only by submission or recovery of an existing admitted queue.

    Reads and edit hooks never register this watchdog. One daemon per queue;
    detached workers survive a cancelled tool wait. A new product connection
    recovers saved submissions, without adopting them into another session.
    """
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return
    identity = (str(hooks.directory), str(store.root))
    with _lock:
        if identity in _watchers:
            return
        _watchers.add(identity)

    def watch():
        try:
            delay = 1
            while True:
                time.sleep(delay)
                if not recover_once(hooks, store.root):
                    return
                delay = min(delay * 2, 8)
        except (OSError, ValueError):
            # Saved requests/outbox remain authoritative and recoverable.
            return
        finally:
            with _lock:
                _watchers.discard(identity)

    threading.Thread(target=watch, daemon=True, name='development-check-supervisor').start()
