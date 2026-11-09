"""Task-window path notifications. No Git, content inventory, scan or writer claim.

The pinned watchfiles backend registers synchronously before PreToolUse returns.
Python collects bounded paths in the existing MCP process; a lost connection is
a saved coverage gap, never a reconstructed observation of past writes.
"""
from __future__ import annotations

import atexit
import logging
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
        watch = dict(row.get('file_watch', {}), status=status)
        if status != 'ACTIVE':
            watch['ended_at'] = store.now()
        watch['diagnostic'] = dict(reason=reason, at=store.now(), reporter_pid=os.getpid())
        # A watcher diagnostic is not an observed edit. Preserve uncertainty,
        # but do not advance the input version or reopen an already saved batch.
        store._put(db, ref, dict(row, scope_unknown=True,
                                file_watch=watch, file_watch_gaps=gaps,
                                file_watch_diagnostic=dict(watch['diagnostic'], watch_id=watch.get('id'),
                                    owner_pid=(watch.get('control') or {}).get('pid'))))


class _Window:
    def __init__(self, store, ref, owner, backend_factory, prewarm=None):
        self.prewarm = prewarm
        self.store, self.ref, self.owner = store, ref, dict(owner)
        self.id = uuid.uuid4().hex
        self.control = None
        self.closing = threading.Event()
        self.done = threading.Event()
        self.seen = set()
        self.last_activity = time.monotonic()
        self.pending_tools = set()
        self.quiet_since = None
        self.close_at = None
        from .target import TargetDetector
        self.ignored = {os.path.normcase(p) for p in TargetDetector().ignored}
        self.private = store.path.parent
        started = time.monotonic()
        self.backend = backend_factory(store.root)
        self.registration_slow = time.monotonic()-started > 10
        self.thread = threading.Thread(target=self.run, daemon=True, name='development-file-watch')

    def paths(self, changes):
        from .development_check import clean_paths
        names, uncertain = [], False
        for _kind, raw in changes:
            path = Path(raw)
            if not path.is_absolute():
                uncertain = True
                continue
            # An unrelated notification is not a gap in this project's
            # coverage. Compare directory components, not string prefixes;
            # normalize traversal before containment, but validate links on
            # the original spelling below so normalization cannot hide one.
            lexical = Path(os.path.abspath(path))
            if not lexical.is_relative_to(self.store.root):
                continue
            try:
                name = lexical.relative_to(self.store.root).as_posix()
                from .development_scope import excluded_artifact
                if excluded_artifact(name):
                    continue
                if any(os.path.normcase(p) in self.ignored for p in Path(name).parts):
                    continue
                if lexical.is_relative_to(self.private):
                    continue
                no_links(path)
                if path.is_dir():
                    continue
                from .scope_policy import is_compiled_artifact
                if is_compiled_artifact(path):
                    continue
            except (OSError, ValueError):
                uncertain = True
                continue
            names.append(name)
        names, invalid = clean_paths(names, tolerant=True)
        return names, uncertain or invalid

    def record(self, changes):
        names, uncertain = self.paths(changes)
        if names or uncertain:
            # Rewrites of a path already recorded still interrupt quiet time.
            self.quiet_since = time.monotonic()
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
        self.seen.update(fresh)
        if fresh and not self.closing.is_set() and self.prewarm and os.getenv('SECURITY_RUNTIME_WATCH_PREWARM') != '0':
            try:
                self.prewarm(self.store.root, fresh, batch=(self.ref, row['scanned_seq']))
            except Exception:
                # Optional scheduling must never interrupt the observation window.
                logging.getLogger(__name__).debug('Watch prewarm scheduling unavailable')

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
                    if self.close_at is None:
                        break
                    if changes == 'timeout' and now - self.quiet_since >= SETTLE_SECONDS:
                        break
                    if now >= self.close_at:
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


def _reuse_remote(store, ref, owner, watch, invocation):
    from .watch_control import request, owner_lost
    if request(watch, 'touch', invocation=invocation) is True:
        return 'ACTIVE'
    current = store.load(ref, owner).get('file_watch', {})
    if current.get('id') != watch.get('id') or current.get('status') != 'ACTIVE':
        return None
    if owner_lost(current, store.now()):
        _gap(store, ref, 'FILE_WATCH_INTERRUPTED', watch_id=current.get('id'), status='INTERRUPTED')
        return None
    # A fresh owner that cannot be contacted is not proven dead. Do not steal
    # its watcher or discard queued notifications; retain the diagnostic.
    _gap(store, ref, 'FILE_WATCH_OWNER_UNAVAILABLE', watch_id=current.get('id'), status='ACTIVE')
    return 'FAILED'


def start_window(store, ref, owner, *, backend_factory=None, invocation=None, prewarm=None):
    store.load(ref, owner)
    key = _key(store, ref)
    with _lock:
        current = _windows.get(key)
        if current and current.thread.is_alive() and not current.closing.is_set():
            current.last_activity = time.monotonic()
            current.pending_tools.add(invocation)
            return 'ACTIVE'
    # Never hold this process's window lock while contacting another owner:
    # two MCP connections can be handling each other's workspaces concurrently.
    old = store.load(ref, owner).get('file_watch', {})
    if old.get('status') == 'ACTIVE':
        reused = _reuse_remote(store, ref, owner, old, invocation)
        if reused is not None:
            return reused
    with _lock:
        current = _windows.get(key)
        if current and current.thread.is_alive() and not current.closing.is_set():
            current.last_activity = time.monotonic()
            current.pending_tools.add(invocation)
            return 'ACTIVE'
        if len(_windows) >= MAX_WINDOWS:
            _gap(store, ref, 'FILE_WATCH_CAPACITY_EXCEEDED')
            return 'FAILED'
        window = None
        try:
            window = _Window(store, ref, owner, backend_factory or _backend, prewarm)
            from .watch_control import endpoint
            try:
                window.control = endpoint()
            except OSError:
                # Local watching must still work where loopback binding is
                # restricted. Other connections cannot claim this as dead.
                window.control = dict(pid=os.getpid())
            window.pending_tools.add(invocation)
            with store.transaction() as db:
                row = store._get(db, ref)
                # Simultaneous starts in separate MCP processes elect a single
                # owner in the existing transaction, after native registration.
                winner = row.get('file_watch', {})
                if winner.get('status') != 'ACTIVE':
                    winner = None
                    watch = dict(contract=CONTRACT, id=window.id, status='ACTIVE',
                                 control=window.control,
                                 started_at=store.now(), lease_until=store.now()+LEASE_SECONDS,
                                 scope='TASK_TIME_WINDOW', attribution='TIME_WINDOW_NOT_WRITER')
                    store._put(db, ref, dict(row, file_watch=watch))
                    _windows[key] = window
                    window.thread.start()
            if winner is not None:
                window.backend.close()
                window = None
            else:
                if window.registration_slow:
                    _gap(store, ref, 'FILE_WATCH_START_DELAYED', watch_id=window.id, status='ACTIVE')
                return 'ACTIVE'
        except Exception:
            if window is not None:
                _windows.pop(key, None)
                try:
                    window.backend.close()
                except Exception:
                    pass
            if window is not None or store.load(ref, owner).get('file_watch', {}).get('status') != 'ACTIVE':
                _gap(store, ref, 'FILE_WATCH_START_FAILED', watch_id=window.id if window else None)
            return 'FAILED'
    return _reuse_remote(store, ref, owner, winner, invocation) or 'FAILED'


def active(store, ref, owner, *, completed=None, resolve_remote=True):
    with _lock:
        window = _windows.get(_key(store, ref))
        if not (window and window.owner == owner and window.thread.is_alive()
                and not window.closing.is_set()):
            window = None
        if window is not None:
            if completed is not None and completed in window.pending_tools:
                window.pending_tools.remove(completed)
                window.quiet_since = time.monotonic()
            return True
    if not resolve_remote:
        return False
    watch = store.load(ref, owner).get('file_watch', {})
    if watch.get('status') == 'ACTIVE':
        from .watch_control import request
        return request(watch, 'complete', invocation=completed) is True
    return False


def stop_window(store, ref, owner, *, deadline=None):
    row = store.load(ref, owner)
    with _lock:
        window = _windows.get(_key(store, ref))
        if window is not None:
            if window.close_at is None:
                now = time.monotonic()
                if window.pending_tools or window.quiet_since is None:
                    window.quiet_since = now
                window.close_at = deadline if deadline is not None else now + 2 * SETTLE_SECONDS
            window.closing.set()
    if window is not None:
        # No workspace lock is held while waiting for the last persisted batch.
        if not window.done.wait(max(0, window.close_at - time.monotonic())):
            _gap(store, ref, 'FILE_WATCH_SETTLEMENT_TIMEOUT', watch_id=window.id)
    elif row.get('file_watch', {}).get('status') == 'ACTIVE':
        from .watch_control import request, owner_lost
        watch = row['file_watch']
        remaining = max(0, deadline-time.monotonic()) if deadline is not None else 2*SETTLE_SECONDS
        request(watch, 'stop', budget=remaining)
        current = store.load(ref, owner).get('file_watch', {})
        if current.get('id') == watch.get('id') and current.get('status') == 'ACTIVE':
            if owner_lost(current, store.now()):
                _gap(store, ref, 'FILE_WATCH_INTERRUPTED', watch_id=watch.get('id'), status='INTERRUPTED')
                return
            # Keep the original watcher running to drain its last events, but
            # do not certify a flush that failed to acknowledge within budget.
            _gap(store, ref, 'FILE_WATCH_SETTLEMENT_TIMEOUT', watch_id=watch.get('id'))


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
        window.closing.set()
    for window in windows:
        window.done.wait(SETTLE_SECONDS+1)


def _shutdown():
    with _lock:
        windows = list(_windows.values())
    _close(windows)


atexit.register(_shutdown)
