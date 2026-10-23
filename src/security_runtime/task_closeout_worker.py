"""Detached closeout dispatcher. No model calls, task creation or source edits."""
from pathlib import Path
import os
import subprocess
import sqlite3
import threading
import time
import uuid

from .tasks.closeout_queue import CloseoutQueue, PENDING
from .hook_state import HookStateStore, no_links


def launch_worker(hooks, root):
    from .background_preparation import runtime_command
    from .task_dispatcher import register
    register(hooks, root)
    queue = CloseoutQueue(hooks, root)
    supervise(hooks, root)
    with queue.transaction() as db:
        previous = queue._get(db, '$worker')
        if previous and previous['lease_until'] > queue.now():
            return False
        ticket = uuid.uuid4().hex
        queue._put(db, '$worker', dict(ticket=ticket, lease_until=queue.now()+60))
    argv = runtime_command() + ['task-closeout-worker', '--workspace', str(root),
        '--hooks', str(Path(hooks.directory).resolve()), '--ticket', ticket]
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    try:
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, cwd=str(queue.path.parent), **options)
    except OSError:
        with queue.transaction() as db:
            row = queue._get(db, '$worker')
            if row and row['ticket'] == ticket:
                queue._put(db, '$worker', dict(row, lease_until=0))
        raise ValueError('Closeout worker could not start; saved request retained') from None
    supervise(hooks, root)
    return True


_watchers = set()
_watch_lock = threading.Lock()


def supervise(hooks, root):
    """Live runtime watchdog; recovery only inspects this registered queue."""
    key = (str(hooks.directory), str(root))
    with _watch_lock:
        if key in _watchers:
            return
        _watchers.add(key)

    def watch():
        try:
            while True:
                time.sleep(10)
                queue = CloseoutQueue(hooks, root)
                if not any(row.get('state') in PENDING for row in queue.rows()):
                    return
                launch_worker(hooks, root)
        except (OSError, ValueError, sqlite3.DatabaseError):
            return
        finally:
            with _watch_lock:
                _watchers.discard(key)
    threading.Thread(target=watch, daemon=True, name='closeout-watchdog').start()


def recover(hooks, root):
    queue = CloseoutQueue(hooks, root)
    if any(row.get('state') in PENDING for row in queue.rows()):
        launch_worker(hooks, root)
        supervise(hooks, root)


def run_worker(workspace, hooks_path, ticket, *, service_factory=None, idle_wait=1):
    from .runtime import SecurityRuntime
    from .storage import SQLiteStore
    from .tasks.security import TaskSecurityService
    from .tasks.queued_closeout import execute_one
    from .workspace import WorkspaceResolver
    root = WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True).path
    no_links(Path(hooks_path))
    hooks = HookStateStore(Path(hooks_path))
    queue = CloseoutQueue(hooks, root)

    def owned(*, finish=False):
        with queue.transaction() as db:
            row = queue._get(db, '$worker')
            if not row or row['ticket'] != ticket or row['lease_until'] <= queue.now():
                return False
            if finish and any(r.get('state') in PENDING for r in queue._all(db)):
                return False
            queue._put(db, '$worker', dict(row, lease_until=0 if finish else queue.now()+60))
            return True

    if not owned():
        return 2
    stop = threading.Event()

    def heartbeat():
        while not stop.wait(15):
            try:
                if not owned():
                    return
            except (OSError, ValueError, sqlite3.DatabaseError):
                return
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        from .tasks.baseline_inputs import BaselineInputs
        try:
            BaselineInputs(hooks, root).collect_expired()
        except (OSError, ValueError, sqlite3.DatabaseError):
            pass  # Failed cleanup cannot recapture originals or block another task.
        while owned():
            pending = [r for r in queue.rows() if r.get('state') in PENDING]
            if not pending:
                if owned(finish=True):
                    return 0
                continue
            for row in sorted(pending, key=lambda r:(r['next_attempt_at'], r['created_at'])):
                if not owned():
                    return 2
                if service_factory:
                    service = service_factory(row['owner'])
                else:
                    scan_path = row['configuration'].get('scan_store')
                    engine = SecurityRuntime(store=SQLiteStore(Path(scan_path) if scan_path else None))
                    service = TaskSecurityService(engine, hooks, owner=row['owner'])
                from .task_dispatcher import execution_slot
                with execution_slot() as available:
                    if available:
                        execute_one(service, root, row['task_ref'], worker=ticket)
            stop.wait(idle_wait)
        return 2
    finally:
        stop.set()
        thread.join(timeout=1)
