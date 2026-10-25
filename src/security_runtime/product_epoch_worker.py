"""Durable scheduling of an already admitted finite product observation.

The queue is a scheduling hint, never a source authority. Every worker verifies
the original epoch/root/policy before stepping it. Missing history is terminal.
Closing an MCP connection stops polling, not the independently running worker.
"""
from pathlib import Path
import os
import sqlite3
import subprocess
import threading
import time
import uuid

from .hook_state import HookStateStore, no_links
from .product_epoch_jobs import TERMINAL, _progress_watermark, MAX_NO_PROGRESS_TURNS
from .product_epoch_service import ProductEpochService
from .tasks.durable import SignedRecords
from .tasks.ownership import valid_owner


PENDING = frozenset({'QUEUED', 'RUNNING'})


class EpochWorkerUnavailable(ValueError):
    """The original saved request survives a failed process launch."""


class EpochQueue(SignedRecords):
    max_rows = 2
    max_record_bytes = 16000

    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'product-epoch-jobs.db', **kwargs)

    @staticmethod
    def verify(service, job):
        current = service.status(epoch_ref=job['epoch_ref'])
        if any(current.get(key) != job[key] for key in
               ('epoch_ref', 'policy_digest', 'root_identity', 'workspace_id')):
            raise ValueError('Original product observation is unavailable')
        return current

    def submit(self, service, owner, observed):
        if not valid_owner(owner) or not observed.get('epoch_ref'):
            raise ValueError('Original product observation required')
        current = self.verify(service, observed)
        with self.transaction() as db:
            previous = self._get(db, '$job')
            if previous:
                if any(previous[key] != current[key] for key in
                       ('epoch_ref', 'policy_digest', 'root_identity', 'workspace_id')):
                    raise ValueError('Cannot replace the original product observation')
                if previous['state'] in PENDING or previous['state'] == 'SEALED':
                    return previous
                if previous['state'] not in {'BUSY', 'WAITING_CAPACITY', 'WAITING_PROGRESS'}:
                    return previous
            return self._put(db, '$job', dict(
                contract='product-epoch-job-v1', owner=dict(owner), policy=service.policy,
                **{key: current[key] for key in ('epoch_ref', 'policy_digest', 'root_identity', 'workspace_id')},
                state='SEALED' if current['state'] == 'SEALED' else 'QUEUED',
                created_at=previous['created_at'] if previous else self.now(), reason=None))

    def pending(self):
        job = self.read('$job')
        return bool(job and job['state'] in PENDING)


def launch(hooks, root):
    from .background_preparation import runtime_command
    from .task_dispatcher import register
    queue = EpochQueue(hooks, root)
    if not queue.pending():
        return False
    register(hooks, root)
    with queue.transaction() as db:
        current = queue._get(db, '$worker')
        if current and current['lease_until'] > queue.now():
            return False
        ticket = uuid.uuid4().hex
        queue._put(db, '$worker', dict(ticket=ticket, lease_until=queue.now()+60))
    argv = runtime_command()+['product-epoch-worker', '--workspace', str(root),
        '--hooks', str(Path(hooks.directory).resolve()), '--ticket', ticket]
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    try:
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, cwd=str(queue.path.parent), **options)
    except OSError:
        with queue.transaction() as db:
            current = queue._get(db, '$worker')
            if current and current['ticket'] == ticket:
                queue._put(db, '$worker', dict(current, lease_until=0))
        raise EpochWorkerUnavailable('Product observation request retained; worker launch unavailable') from None
    return True


def run_worker(workspace, hooks_path, ticket):
    from .task_dispatcher import execution_slot
    root, directory = Path(workspace).absolute(), Path(hooks_path).absolute()
    no_links(root)
    no_links(directory)
    hooks = HookStateStore(directory)
    queue = EpochQueue(hooks, root)
    stop = threading.Event()

    def owned(*, finish=False):
        # Never allocate/rebuild a missing scheduling database on recovery.
        if not queue.path.is_file():
            return False
        with queue.transaction() as db:
            row = queue._get(db, '$worker')
            if not row or row['ticket'] != ticket or row['lease_until'] <= queue.now():
                return False
            queue._put(db, '$worker', dict(row, lease_until=0 if finish else queue.now()+60))
            return True

    if not owned():
        return 2

    def heartbeat():
        while not stop.wait(15):
            try:
                if not owned():
                    stop.set()
            except (OSError, ValueError, sqlite3.DatabaseError):
                stop.set()

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    service = None
    try:
        job = queue.read('$job')
        if not job or job['state'] not in PENDING:
            return 0
        service = ProductEpochService(hooks, root, policy=job['policy'])
        previous, stalled = None, 0
        while not stop.is_set() and owned():
            # status(ref) must succeed before step; step must never get an
            # opportunity to fall back to ensure after missing original state.
            queue.verify(service, job)
            with execution_slot() as available:
                if not available:
                    stop.wait(.25)
                    continue
                result = service.step(job['owner'], epoch_ref=job['epoch_ref'])
            state = result['state']
            watermark = _progress_watermark(result)
            stalled = stalled+1 if watermark == previous else 0
            previous = watermark
            if stalled >= MAX_NO_PROGRESS_TURNS and state not in TERMINAL:
                state = 'WAITING_PROGRESS'
            with queue.transaction() as db:
                worker = queue._get(db, '$worker')
                current = queue._get(db, '$job')
                if (not worker or worker['ticket'] != ticket or worker['lease_until'] <= queue.now()
                        or not current or current['epoch_ref'] != job['epoch_ref']
                        or current['state'] not in PENDING):
                    return 2
                queue._put(db, '$job', dict(current,
                    state=state if state in TERMINAL or state == 'WAITING_PROGRESS' else 'RUNNING',
                    reason=result.get('reason')))
            if state in TERMINAL or state == 'WAITING_PROGRESS':
                return 0
            stop.wait(.01)
        return 2
    except (OSError, ValueError, sqlite3.DatabaseError) as error:
        # Retain the original epoch and all accepted observations. Recovery
        # cannot manufacture a missing source or silently create a new epoch.
        if queue.path.is_file():
            with queue.transaction() as db:
                worker, job = queue._get(db, '$worker'), queue._get(db, '$job')
                if worker and worker['ticket'] == ticket and job and job['state'] in PENDING:
                    busy = isinstance(error, sqlite3.OperationalError) and getattr(error, 'sqlite_errorcode', None) in {
                        sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                    full = isinstance(error, sqlite3.OperationalError) and getattr(error, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL
                    queue._put(db, '$job', dict(job,
                        state='BUSY' if busy else 'WAITING_CAPACITY' if full else 'HISTORY_UNAVAILABLE',
                        reason='PRODUCT_EPOCH_BUSY' if busy else 'PRODUCT_EPOCH_WAITING_CAPACITY' if full else 'ORIGINAL_EPOCH_UNAVAILABLE'))
        return 2
    finally:
        stop.set()
        thread.join(timeout=1)
        if service is not None:
            service.close()
        try:
            owned(finish=True)
        except (OSError, ValueError, sqlite3.DatabaseError):
            pass  # A failed lease release cannot replace the original result.
