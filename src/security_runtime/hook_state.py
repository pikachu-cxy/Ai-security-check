"""Bounded local hook metadata and OS-owned cross-process workspace locks."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from .storage import SQLiteStore

MAX_STATE_BYTES = 2_000_000
MAX_SESSIONS = 64


def identity(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def no_links(path: Path) -> None:
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError('Hook state/configuration links are not supported')


def atomic_bytes(path: Path, content: bytes) -> None:
    no_links(path)
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
        return self.directory / identity(os.path.normcase(str(root)))

    def path(self, root: Path, host: str, session_id: str | None) -> Path:
        return self.workspace_directory(root) / (identity(host + '\0' + (session_id or 'default')) + '.json')

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
            yield acquired
        finally:
            if acquired:
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def key(self, root: Path) -> bytes:
        path = self.workspace_directory(root) / 'snapshot.key'
        no_links(path)
        if not path.exists():
            atomic_bytes(path, os.urandom(32))
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
            return validate_state(value), False
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            # Do not copy corrupt/oversized content to logs or quarantine files.
            return None, True

    def save(self, path: Path, value: dict) -> None:
        from .hook_runtime import validate_state
        validate_state(value)
        content = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()
        if len(content) > MAX_STATE_BYTES:
            raise ValueError('Hook state budget exceeded')
        atomic_bytes(path, content)
        # Workspace lock protects both state updates and bounded retention.
        states = sorted(path.parent.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in states[MAX_SESSIONS:]:
            no_links(old)
            old.unlink()
