"""Task-window path notifications. No Git, content inventory, scan or writer claim.

The pinned watchfiles backend registers synchronously before PreToolUse returns.
Python collects bounded paths in the existing MCP process; a lost connection is
a saved coverage gap, never a reconstructed observation of past writes.
"""
from __future__ import annotations

import atexit
import os
from pathlib import Path
import threading
import time
import uuid

from .hook_state import no_links

CONTRACT = 'development-file-watch-v1'
MAX_WINDOWS = 16
IDLE_SECONDS = 1800
HEARTBEAT_SECONDS = 5
LEASE_SECONDS = 20
SETTLE_SECONDS = 2
_lock = threading.RLock()
_windows = {}


def _key(store, ref):
    return str(store.path), ref


def _backend(root):
    # Publicly documented low-level API, pinned to avoid an implicit startup
    # timeout before we can acknowledge that notifications are registered.
    from watchfiles._rust_notify import RustNotify
    return RustNotify([str(root)], False, False, 300, True, False)


def _gap(store, ref, reason, *, watch_id=None, status='FAILED'):
    with store.transaction() as db:
        row = store._get(db, ref)
        if row is None or watch_id and row.get('file_watch', {}).get('id') != watch_id:
            return
        gaps = list(dict.fromkeys([*row.get('file_watch_gaps', []), reason]))
        watch = dict(row.get('file_watch', {}), status=status, ended_at=store.now())
        # A newly discovered observation gap invalidates an earlier clean result.
        if reason not in row.get('file_watch_gaps', []):
            row, _ = store.append(db, row, [], True, None)
        store._put(db, ref, dict(row, file_watch=watch, file_watch_gaps=gaps))


class _Window:
    def __init__(self, store, ref, owner, backend_factory):
        self.store, self.ref, self.owner = store, ref, dict(owner)
        self.id = uuid.uuid4().hex
        self.closing = threading.Event()
        self.done = threading.Event()
        self.seen = set()
        self.last_activity = time.monotonic()
        self.close_at = None
        from .target import TargetDetector
        self.ignored = {os.path.normcase(p) for p in TargetDetector().ignored}
        self.private = store.path.parent
        started = time.monotonic()
        self.backend = backend_factory(store.root)
        self.registration_slow = time.monotonic()-started > 10
        self.thread = threading.Thread(target=self.run, daemon=True, name='development-file-watch')

    def paths(self, changes):
        from .development_check import MAX_PATHS, MAX_PATH_BYTES, clean_paths
        names, uncertain, size = [], False, 0
        for _kind, raw in changes:
            path = Path(raw)
            if not path.is_absolute():
                uncertain = True
                continue
            try:
                name = path.relative_to(self.store.root).as_posix()
                from .development_scope import excluded_artifact
                if excluded_artifact(name):
                    continue
                if any(os.path.normcase(p) in self.ignored for p in Path(name).parts):
                    continue
                if path.is_relative_to(self.private):
                    continue
                no_links(path)
                if path.is_dir():
                    continue
            except (OSError, ValueError):
                uncertain = True
                continue
            size += len(name.encode('utf-8', errors='replace'))
            if len(names) >= MAX_PATHS or size > MAX_PATH_BYTES:
                uncertain = True
                break
            names.append(name)
        names, invalid = clean_paths(names, tolerant=True)
        return names, uncertain or invalid

    def record(self, changes):
        names, uncertain = self.paths(changes)
        fresh = [p for p in names if p not in self.seen]
        if not fresh and not uncertain:
            return
        with self.store.transaction() as db:
            row = self.store._get(db, self.ref)
            if (row is None or row['owner'] != self.owner
                    or row.get('file_watch', {}).get('id') != self.id
                    or row['file_watch']['status'] != 'ACTIVE'):
                self.closing.set()
                return
            from .development_check import clean_paths
            _, overflow = clean_paths(list(dict.fromkeys([*row['observed_paths'], *fresh])), tolerant=True)
            uncertain = uncertain or overflow
            row, _ = self.store.append(db, row, fresh, uncertain, None, explicit=False)
            if uncertain:
                row = dict(row, file_watch_gaps=list(dict.fromkeys([
                    *row.get('file_watch_gaps', []), 'FILE_WATCH_PATHS_INCOMPLETE'])))
            self.store._put(db, self.ref, row)
        from .development_check import MAX_PATHS
        self.seen.update(fresh[:max(0, MAX_PATHS-len(self.seen))])

    def run(self):
        heartbeat = 0
        try:
            while True:
                # An unset stop event permits a final native batch to drain.
                changes = self.backend.watch(50, 10, 100, None)
                if changes == 'signal' or changes == 'stop':
                    raise RuntimeError('Watcher interrupted')
                if changes != 'timeout':
                    self.record(changes)
                now = time.monotonic()
                if self.closing.is_set():
                    if changes == 'timeout':
                        break
                    if self.close_at is not None and now >= self.close_at:
                        _gap(self.store, self.ref, 'FILE_WATCH_SETTLEMENT_TIMEOUT', watch_id=self.id)
                        break
                if now - self.last_activity > IDLE_SECONDS:
                    _gap(self.store, self.ref, 'FILE_WATCH_IDLE_EXPIRED', watch_id=self.id, status='EXPIRED')
                    break
                if now - heartbeat >= HEARTBEAT_SECONDS:
                    with self.store.transaction() as db:
                        row = self.store._get(db, self.ref)
                        if (row is None or row.get('file_watch', {}).get('id') != self.id
                                or row['file_watch']['status'] != 'ACTIVE'):
                            break
                        watch = dict(row['file_watch'], lease_until=self.store.now()+LEASE_SECONDS)
                        self.store._put(db, self.ref, dict(row, file_watch=watch))
                    heartbeat = now
        except Exception:
            # Exceptions can contain private absolute paths; keep a fixed reason.
            try:
                _gap(self.store, self.ref, 'FILE_WATCH_INTERRUPTED', watch_id=self.id)
            except (OSError, ValueError):
                pass
        finally:
            try:
                self.backend.close()
            except Exception:
                pass
            try:
                with self.store.transaction() as db:
                    row = self.store._get(db, self.ref)
                    if row and row.get('file_watch', {}).get('id') == self.id and row['file_watch']['status'] == 'ACTIVE':
                        watch = dict(row['file_watch'], status='STOPPED', ended_at=self.store.now())
                        self.store._put(db, self.ref, dict(row, file_watch=watch))
            finally:
                self.done.set()
                with _lock:
                    if _windows.get(_key(self.store, self.ref)) is self:
                        _windows.pop(_key(self.store, self.ref), None)


def start_window(store, ref, owner, *, backend_factory=None):
    store.load(ref, owner)
    key = _key(store, ref)
    with _lock:
        current = _windows.get(key)
        if current and current.thread.is_alive() and not current.closing.is_set():
            current.last_activity = time.monotonic()
            return 'ACTIVE'
        if len(_windows) >= MAX_WINDOWS:
            _gap(store, ref, 'FILE_WATCH_CAPACITY_EXCEEDED')
            return 'FAILED'
        old = store.load(ref, owner).get('file_watch', {})
        if old.get('status') == 'ACTIVE':
            _gap(store, ref, 'FILE_WATCH_INTERRUPTED', status='INTERRUPTED')
        window = None
        try:
            window = _Window(store, ref, owner, backend_factory or _backend)
            with store.transaction() as db:
                row = store._get(db, ref)
                watch = dict(contract=CONTRACT, id=window.id, status='ACTIVE',
                             started_at=store.now(), lease_until=store.now()+LEASE_SECONDS,
                             scope='TASK_TIME_WINDOW', attribution='TIME_WINDOW_NOT_WRITER')
                store._put(db, ref, dict(row, file_watch=watch))
            if window.registration_slow:
                _gap(store, ref, 'FILE_WATCH_START_DELAYED', watch_id=window.id, status='ACTIVE')
            _windows[key] = window
            window.thread.start()
            return 'ACTIVE'
        except Exception:
            if window is not None:
                _windows.pop(key, None)
                try:
                    window.backend.close()
                except Exception:
                    pass
            _gap(store, ref, 'FILE_WATCH_START_FAILED')
            return 'FAILED'


def active(store, ref, owner):
    with _lock:
        window = _windows.get(_key(store, ref))
        return bool(window and window.owner == owner and window.thread.is_alive()
                    and not window.closing.is_set())


def stop_window(store, ref, owner):
    row = store.load(ref, owner)
    with _lock:
        window = _windows.get(_key(store, ref))
        if window is not None:
            window.close_at = time.monotonic()+SETTLE_SECONDS
            window.closing.set()
    if window is not None:
        # No workspace lock is held while waiting for the last persisted batch.
        if not window.done.wait(SETTLE_SECONDS+1):
            _gap(store, ref, 'FILE_WATCH_SETTLEMENT_TIMEOUT', watch_id=window.id)
    elif row.get('file_watch', {}).get('status') == 'ACTIVE':
        _gap(store, ref, 'FILE_WATCH_INTERRUPTED', status='INTERRUPTED')


def close_store(store):
    """Trusted connection teardown: keep an unfinished observation gap."""
    with _lock:
        windows = [w for w in _windows.values() if w.store.path == store.path]
    _close(windows)


def _close(windows):
    for window in windows:
        try:
            _gap(window.store, window.ref, 'FILE_WATCH_INTERRUPTED',
                 watch_id=window.id, status='INTERRUPTED')
        except (OSError, ValueError):
            pass
        window.close_at = time.monotonic()+SETTLE_SECONDS
        window.closing.set()
    for window in windows:
        window.done.wait(SETTLE_SECONDS+1)


def _shutdown():
    with _lock:
        windows = list(_windows.values())
    _close(windows)


atexit.register(_shutdown)
