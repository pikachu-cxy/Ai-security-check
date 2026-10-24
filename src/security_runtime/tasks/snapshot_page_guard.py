"""Coordinate page publication/readers with collection; never an owner grant.

The fixed lock inode is never unlinked. Process death releases its OS lock.
Windows conservatively serializes readers as well as collectors.
"""
from contextlib import contextmanager
from functools import wraps
import json
import os
from pathlib import Path
import stat
import threading
import time

from ..hook_state import no_links
from ..snapshot_store import SnapshotStoreError


_local = threading.local()
_descriptors = set()


def guard_held(directory):
    path = Path(directory)/'snapshot-pages.gc.lock'
    return os.path.normcase(os.path.abspath(path)) in getattr(_local, 'held', {})


def _after_fork():
    global _local, _descriptors
    # Do not LOCK_UN a description shared with the parent through fork.
    for fd in _descriptors:
        try:
            os.close(fd)
        except OSError:
            pass
    _local, _descriptors = threading.local(), set()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork)


@contextmanager
def page_guard(directory, *, exclusive=False, create=False, wait_seconds=2):
    directory = Path(directory)
    path = directory/'snapshot-pages.gc.lock'
    identity = directory/'snapshot-pages.gc.identity'
    marker = os.path.normcase(os.path.abspath(path))
    held = getattr(_local, 'held', None)
    if held is None:
        held = _local.held = {}
    current = held.get(marker)
    if current is not None:
        if exclusive and not current['exclusive']:
            raise SnapshotStoreError('SNAPSHOT_GC_LOCK_UPGRADE_REJECTED')
        yield
        return
    no_links(path)
    no_links(identity)
    if identity.exists() and not path.exists():
        raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
    if not create and not path.exists():
        # Legacy-only state is never collected. Do not create state on reads.
        yield
        return
    if create:
        no_links(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    if create:
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    acquiring_pid = os.getpid()
    _descriptors.add(fd)
    acquired = False
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (os.name != 'nt' and info.st_mode & 0o077)):
            raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
        if info.st_size == 0:
            if not create:
                raise SnapshotStoreError('SNAPSHOT_PAGE_STORE_BUSY')
            os.write(fd, b'0')
        deadline = time.monotonic()+wait_seconds
        while True:
            try:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    initialize = create and not identity.exists()
                    fcntl.flock(fd, (fcntl.LOCK_EX if exclusive or initialize else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise SnapshotStoreError('SNAPSHOT_PAGE_STORE_BUSY') from None
                time.sleep(min(.01, max(0, deadline-time.monotonic())))
        no_links(path)
        actual = path.stat()
        if (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino):
            raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
        expected = dict(contract='snapshot-page-guard-v1', device=info.st_dev, inode=info.st_ino)
        if not identity.exists():
            if not create:
                raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
            marker_fd = os.open(identity, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(marker_fd, 'wb') as stream:
                stream.write(json.dumps(expected, sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
        no_links(identity)
        marker_info = identity.stat()
        if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_nlink != 1
                or marker_info.st_size > 512 or (os.name != 'nt' and marker_info.st_mode & 0o077)):
            raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
        with identity.open('rb') as stream:
            if json.loads(stream.read(513)) != expected:
                raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
        held[marker] = dict(exclusive=exclusive, fd=fd)
        yield
    finally:
        if os.getpid() == acquiring_pid:
            held.pop(marker, None)
            if acquired:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            _descriptors.discard(fd)
            os.close(fd)


def guarded_read(function):
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with page_guard(self.path.parent):
            return function(self, *args, **kwargs)
    return wrapped


def guarded_queue_publication(function):
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with page_guard(self.path.parent):
            from .snapshot_pages import managed
            record = args[0] if args else kwargs.get('record', {})
            if isinstance(record, dict) and managed(record) and not guard_held(self.path.parent):
                raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
            return function(self, *args, **kwargs)
    return wrapped
