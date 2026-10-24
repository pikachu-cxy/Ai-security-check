"""Bounded local hook metadata and OS-owned cross-process workspace locks."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import uuid
import stat
import threading
from contextlib import contextmanager
from contextlib import closing
from pathlib import Path

from .storage import SQLiteStore

MAX_STATE_BYTES = 2_000_000
MAX_SESSIONS = 64
_is_reserved = getattr(os.path, 'isreserved', lambda name: Path(name).is_reserved())
_held_workspace_locks = threading.local()


def identity(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def hook_session_paths(directory: Path) -> list[Path]:
    """Enumerate only Hook-owned filenames; other stores share this directory.

    A path inside the Hook namespace must still be a regular, unlinked file.
    Product ledger files and writer-fence directories never consume session TTL.
    """
    no_links(directory)
    paths = []
    for path in directory.glob('*.json'):
        if re.fullmatch(r'[a-f0-9]{64}\.json', path.name) is None:
            continue
        no_links(path)
        if not path.is_file():
            raise ValueError('Hook session path cannot be verified')
        paths.append(path)
    return paths


def native_io_path(path: Path) -> Path:
    """Represent the same state location for Windows IO, never its identity.

    Win32's legacy path limit also applies to atomic renames. Keep logical
    directories/root comparisons unchanged, and use an absolute extended path
    only for filesystem operations. Do not resolve or follow links here.
    """
    path = Path(path)
    if os.name != 'nt':
        return path
    def valid_components(parts):
        for name in parts:
            if name not in ('', '.', '..') and (
                    name.endswith(('.', ' ')) or ':' in name or _is_reserved(name)):
                raise ValueError('Hook state path spelling is not supported')
    def checked_unc(tail):
        parts = tail.split('\\')
        if len(parts) < 2 or any(name in ('', '.', '..', '?') for name in parts[:2]):
            raise ValueError('Hook state device paths are not supported')
        if any(name.endswith(('.', ' ')) or ':' in name for name in parts[:2]):
            raise ValueError('Hook state path spelling is not supported')
        valid_components(parts[2:])
    def validate_shape(raw):
        if raw.startswith('\\\\.\\'):
            raise ValueError('Hook state device paths are not supported')
        if raw.startswith('\\\\?\\'):
            tail = raw[4:]
            if tail.startswith('UNC\\'):
                checked_unc(tail[4:])
                return
            if len(tail) >= 3 and tail[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' and tail[1:3] == ':\\':
                valid_components(tail[3:].split('\\'))
                return
            raise ValueError('Hook state device paths are not supported')
        if raw.startswith('\\\\'):
            checked_unc(raw[2:])
            return
        drive, tail = os.path.splitdrive(raw)
        if drive and (len(drive) != 2 or drive[0] not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' or drive[1] != ':'):
            raise ValueError('Hook state device paths are not supported')
        valid_components(tail.split('\\'))
    # GetFullPathName can strip a trailing dot/space or a UNC dot server.
    # Validate the original spelling before normalization can erase it.
    validate_shape(str(path))
    raw = os.path.abspath(path)
    validate_shape(raw)
    if raw.startswith('\\\\?\\'):
        return Path(raw)
    if raw.startswith('\\\\'):
        return Path('\\\\?\\UNC\\' + raw[2:])
    return Path('\\\\?\\' + raw)


def no_links(path: Path) -> None:
    # Check the original lexical parents as well: normalizing '..' for native
    # IO must not hide a linked ancestor from the existing fail-closed gate.
    for p in (path, *path.parents):
        native = native_io_path(p)
        try:
            info = native.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Hook state/configuration links are not supported')


def atomic_bytes(path: Path, content: bytes) -> None:
    no_links(path)
    path = native_io_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.hook-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class HookStateStore:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or SQLiteStore.default_path().parent / 'hooks'

    def workspace_directory(self, root: Path) -> Path:
        directory = self.directory / identity(os.path.normcase(str(root)))
        no_links(directory)
        return native_io_path(directory)

    def path(self, root: Path, host: str, session_id: str | None) -> Path:
        return self.workspace_directory(root) / (identity(host + '\0' + (session_id or 'default')) + '.json')

    def scan_path(self, root: Path, host: str, session_id: str | None) -> Path:
        """A strict scanner cache cannot replace a product observation binding.

        The separate directory prevents any caller-controlled session name from
        colliding with the main session's namespace.
        """
        return self.workspace_directory(root) / 'scan-sessions' / self.path(root, host, session_id).name

    def pending_activity(self, root, host, session_id, *, mark=False, completed=None):
        """Bounded reconciliation intent, not finding/proof/authorization state.

        This separate SQLite transaction can record an arrival while the OS
        workspace lock is held. Conditional completion cannot erase a newer
        arrival. A future activity retries the real filesystem delta.
        """
        path = self.workspace_directory(root) / 'pending-activity.db'
        no_links(path)
        sid = identity(host + '\0' + (session_id or 'default'))
        if not mark and completed is None:
            if not path.is_file():
                return None
            from .closeout_state import readonly_uri
            with closing(sqlite3.connect(readonly_uri(path), uri=True)) as db:
                db.execute('PRAGMA query_only=ON')
                if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pending_activity'").fetchone():
                    return None
                row = db.execute('SELECT sequence FROM pending_activity WHERE session=?', (sid,)).fetchone()
                return row[0] if row else None
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=1)) as db:
            with db:
                db.execute('PRAGMA secure_delete=ON')
                db.execute('CREATE TABLE IF NOT EXISTS pending_activity '
                           '(session TEXT PRIMARY KEY, sequence TEXT NOT NULL)')
                if mark:
                    db.execute('BEGIN IMMEDIATE')
                    old = db.execute('SELECT sequence FROM pending_activity WHERE session=?', (sid,)).fetchone()
                    if old is None and db.execute('SELECT count(*) FROM pending_activity').fetchone()[0] >= MAX_SESSIONS:
                        raise ValueError('Pending activity budget exceeded')
                    db.execute('INSERT INTO pending_activity VALUES(?,?) ON CONFLICT(session) '
                               'DO UPDATE SET sequence=excluded.sequence', (sid, uuid.uuid4().hex))
                if completed is not None:
                    db.execute('DELETE FROM pending_activity WHERE session=? AND sequence=?', (sid, completed))
                row = db.execute('SELECT sequence FROM pending_activity WHERE session=?', (sid,)).fetchone()
                return row[0] if row else None

    @contextmanager
    def lock(self, root: Path, *, wait_seconds: float = 0):
        directory = self.workspace_directory(root)
        no_links(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / 'workspace.lock'
        no_links(path)
        # The file is never unlinked: deleting an allegedly stale lock permits
        # two owners of different inodes. OS locks release on process death.
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        acquired = False
        deadline = time.monotonic() + wait_seconds
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(min(.025, max(0, deadline - time.monotonic())))
            if acquired:
                held = getattr(_held_workspace_locks, 'paths', None)
                if held is None:
                    held = _held_workspace_locks.paths = {}
                held[os.path.normcase(os.path.abspath(path))] = (os.getpid(), fd)
            yield acquired
        finally:
            if acquired:
                held = getattr(_held_workspace_locks, 'paths', {})
                marker = os.path.normcase(os.path.abspath(path))
                if held.get(marker) == (os.getpid(), fd): held.pop(marker, None)
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def lock_held(self, root: Path) -> bool:
        """This thread owns the actual workspace OS lock; never authorization."""
        path = self.workspace_directory(root) / 'workspace.lock'
        marker = getattr(_held_workspace_locks, 'paths', {}).get(os.path.normcase(os.path.abspath(path)))
        return marker is not None and marker[0] == os.getpid()

    def key(self, root: Path) -> bytes:
        path = self.workspace_directory(root) / 'snapshot.key'
        no_links(path)
        if not path.exists():
            # Session routing can precede the initial scan. Publish a complete
            # key exactly once, without replacing a concurrent creator's key or
            # exposing an empty/partially-written key to another connection.
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix='.key-', dir=path.parent)
            temporary = Path(name)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(os.urandom(32))
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    if os.name == 'nt':
                        # Windows rename fails when the destination exists.
                        os.rename(temporary, path)
                    else:
                        os.link(temporary, path, follow_symlinks=False)
                except FileExistsError:
                    pass  # The fully-published winner is the only valid key.
            finally:
                temporary.unlink(missing_ok=True)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Invalid local hook snapshot key')
        return key

    def load(self, path: Path) -> tuple[dict | None, bool]:
        no_links(path)
        if not path.exists():
            return None, False
        try:
            if path.stat().st_size > MAX_STATE_BYTES:
                return None, True
            value = json.loads(path.read_bytes())
            from .hook_runtime import validate_state
            value = validate_state(value)
            if value.get('schema_version') == 'hook-product-epoch-v1':
                from .product_epoch_hooks import verify_epoch_state
                verify_epoch_state(value, path)
            return value, False
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            # Do not copy corrupt/oversized content to logs or quarantine files.
            return None, True

    def save(self, path: Path, value: dict) -> None:
        from .hook_runtime import validate_state
        validate_state(value)
        if value.get('schema_version') == 'hook-product-epoch-v1':
            from .product_epoch_hooks import verify_epoch_state
            verify_epoch_state(value, path)
        content = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()
        if len(content) > MAX_STATE_BYTES:
            raise ValueError('Hook state budget exceeded')
        atomic_bytes(path, content)
        # Workspace lock protects both state updates and bounded retention.
        states = sorted(hook_session_paths(path.parent),
                        key=lambda p: p.stat().st_mtime, reverse=True)
        for old in states[MAX_SESSIONS:]:
            no_links(old)
            old.unlink()
