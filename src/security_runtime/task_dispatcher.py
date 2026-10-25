"""User-level queue discovery and bounded execution; only registered workspaces."""
from contextlib import contextmanager
from pathlib import Path
import os
import subprocess
import sqlite3
import time

from .hook_state import HookStateStore, no_links
from .storage import SQLiteStore
from .tasks.durable import SignedRecords
from .tasks.closeout_queue import fingerprint, CloseoutQueue, PENDING


def index():
    base = SQLiteStore.default_path().parent/'task-dispatcher'
    return SignedRecords(HookStateStore(base/'keys'), base, 'registered-workspaces.db')


def register(hooks, root):
    store = index()
    store.hooks.key(store.root)
    value = dict(execution_root=str(Path(root).resolve()), hooks=str(Path(hooks.directory).resolve()))
    with store.transaction() as db:
        store._put(db, fingerprint(value), dict(value, registered_at=store.now()))


@contextmanager
def execution_slot():
    """OS locks release automatically on a crashed process; max two user jobs."""
    base = SQLiteStore.default_path().parent/'task-dispatcher'
    hooks = HookStateStore(base/'slots')
    for slot in range(2):
        with hooks.lock(base/str(slot)) as acquired:
            if acquired:
                yield True
                return
    yield False


def recover_registered():
    from .task_closeout_worker import recover
    from .tasks.queued_inputs import QueuedInputs
    restored = 0
    for row in index().rows():
        if 'execution_root' not in row:
            continue
        try:
            root, hooks_path = Path(row['execution_root']), Path(row['hooks'])
            no_links(root)
            no_links(hooks_path)
            if not root.is_dir():
                continue  # Missing directory is never rebuilt from another checkout.
            hooks = HookStateStore(hooks_path)
            queue = CloseoutQueue(hooks, root)
            rows = queue.rows()
            inputs = QueuedInputs(hooks, root)
            active = {r.get('input_ref') for r in rows if r.get('state') in PENDING}
            inputs.collect(active)
            from .product_epoch_worker import EpochQueue, launch
            epoch_pending = EpochQueue(hooks, root).pending()
            if epoch_pending:
                launch(hooks, root)
                restored += 1
            if any(r.get('state') in PENDING for r in rows):
                recover(hooks, root)
                restored += 1
            elif not epoch_pending and row['registered_at']+86400 < store_now():
                store = index()
                with store.transaction() as db:
                    current = store._get(db, row['key'])
                    if current == row:
                        db.execute('DELETE FROM records WHERE key=?', (row['key'],))
        except (OSError, ValueError, sqlite3.DatabaseError):
            continue  # An invalid workspace cannot prevent other queues recovering.
    return restored


def store_now():
    return time.time()


def run(*, once=False):
    store = index()
    with store.hooks.lock(store.root/'supervisor') as acquired:
        if not acquired:
            return 0
        while True:
            try:
                recover_registered()
            except (OSError, ValueError, sqlite3.DatabaseError):
                if once:
                    return 2
            if once:
                return 0
            time.sleep(5)


def autostart(action='status', *, registry_api=None):
    """Explicit Windows user login registration; never changes unrelated values."""
    from .background_preparation import runtime_command
    if os.name != 'nt' and registry_api is None:
        return dict(status='UNSUPPORTED_PLATFORM', configured=False)
    if registry_api is None:
        import winreg as registry_api
    api = registry_api
    path = r'Software\Microsoft\Windows\CurrentVersion\Run'
    name = 'AISecurityTaskCloseoutDispatcher'
    command = subprocess.list2cmdline(runtime_command()+['task-closeout-dispatcher'])
    store = index()
    old = store.read('$autostart')
    try:
        with api.OpenKey(api.HKEY_CURRENT_USER, path, 0, api.KEY_READ) as key:
            actual = api.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        actual = None
    if action == 'status':
        return dict(status='CONFIGURED' if old and actual == old['command'] else 'NOT_CONFIGURED',
                    configured=bool(old and actual == old['command']))
    if action not in {'install', 'remove'}:
        raise ValueError('Unknown dispatcher startup action')
    if actual is not None and (not old or actual not in {old['command'], old.get('previous_command')}):
        raise ValueError('Unowned dispatcher startup configuration')
    if action == 'install':
        store.hooks.key(store.root)
        # Receipt first: an interrupted registration can be retried safely.
        with store.transaction() as db:
            store._put(db, '$autostart', dict(command=command, previous_command=actual))
        with api.CreateKeyEx(api.HKEY_CURRENT_USER, path, 0, api.KEY_SET_VALUE) as key:
            api.SetValueEx(key, name, 0, api.REG_SZ, command)
        with store.transaction() as db:
            store._put(db, '$autostart', dict(command=command))
        return dict(status='CONFIGURED', configured=True, effective='NEXT_USER_LOGIN')
    if actual is not None:
        with api.OpenKey(api.HKEY_CURRENT_USER, path, 0, api.KEY_SET_VALUE) as key:
            api.DeleteValue(key, name)
    return dict(status='REMOVED', configured=False)
