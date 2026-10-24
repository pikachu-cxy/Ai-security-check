"""Bounded POSIX observations; no source body is persisted or decoded."""
import hashlib
import hmac
import os
from pathlib import Path
import stat
import time

from .hook_state import no_links


class ObservationError(ValueError):
    def __init__(self, reason):
        self.reason_code = reason
        super().__init__(reason)


def identity(info):
    return [info.st_dev, info.st_ino]


def revision(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def platform_supported():
    return (os.name != 'nt' and hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks)


def open_directory(root, relative='', expected=None, *, expected_root_identity=None):
    if not platform_supported():
        raise ObservationError('PLATFORM_UNSUPPORTED')
    no_links(Path(root))
    if expected_root_identity is None:
        expected_root_identity = identity(os.stat(root, follow_symlinks=False))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        # Bind the descriptor before resolving any child. A path stat before
        # and after IO cannot detect a foreign root substituted and restored
        # between those checks. All following opens derive from this root fd.
        if identity(os.fstat(fd)) != expected_root_identity:
            raise ObservationError('ROOT_CHANGED')
        for part in relative.split('/') if relative else ():
            if part in {'', '.', '..'} or '\\' in part or '\0' in part:
                raise ObservationError('PATH_UNSUPPORTED')
            following = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = following
        if expected is not None and identity(os.fstat(fd)) != expected:
            raise ObservationError('DIRECTORY_CHANGED')
        return fd
    except BaseException:
        os.close(fd)
        raise


class DirectoryObservation:
    def __init__(self, root, path, expected, *, expected_root_identity=None):
        self.root, self.path, self.expected = root, path, expected
        self.root_identity = (list(expected_root_identity) if expected_root_identity is not None
                              else identity(os.stat(root, follow_symlinks=False)))
        self.fd = open_directory(root, path, expected, expected_root_identity=self.root_identity)
        try:
            self.iterator = os.scandir(self.fd)
        except BaseException:
            os.close(self.fd)
            raise

    def verify(self):
        fd = open_directory(self.root, self.path, self.expected, expected_root_identity=self.root_identity)
        os.close(fd)

    def next(self):
        entry = next(self.iterator)
        info = os.stat(entry.name, dir_fd=self.fd, follow_symlinks=False)
        return entry.name, info

    def close(self):
        self.iterator.close()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class StableHashReader:
    """One file's first stable, possibly multi-step keyed hash observation."""
    def __init__(self, root, key, path, *, expected_root_identity=None):
        self.root, self.path = root, path
        self.root_identity = (list(expected_root_identity) if expected_root_identity is not None
                              else identity(os.stat(root, follow_symlinks=False)))
        self.parent, _, self.name = path.rpartition('/')
        self.directory_fd = open_directory(root, self.parent, expected_root_identity=self.root_identity)
        self.directory_identity = identity(os.fstat(self.directory_fd))
        self.fd = None
        try:
            self.fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0),
                              dir_fd=self.directory_fd)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode):
                raise ObservationError('NOT_REGULAR_FILE')
            self.before = revision(info)
            self.size, self.read_bytes = info.st_size, 0
            self.digest = hmac.new(key, b'hook-file-v1', hashlib.sha256)
        except BaseException:
            self.close()
            raise

    def _read_chunk(self, size):
        return os.read(self.fd, size)

    def _stable(self):
        fd = open_directory(self.root, self.parent, self.directory_identity,
                            expected_root_identity=self.root_identity)
        try:
            current = os.stat(self.name, dir_fd=fd, follow_symlinks=False)
            return stat.S_ISREG(current.st_mode) and revision(current) == self.before == revision(os.fstat(self.fd))
        finally:
            os.close(fd)

    def advance(self, byte_budget, deadline):
        consumed = 0
        try:
            if not self._stable():
                return dict(state='UNSTABLE', reason='SOURCE_CHANGED', bytes_read=0)
            while consumed < byte_budget and time.monotonic() < deadline:
                raw = self._read_chunk(min(65536, byte_budget-consumed))
                consumed += len(raw)
                self.read_bytes += len(raw)
                if not raw:
                    if self.read_bytes != self.size or not self._stable():
                        return dict(state='UNSTABLE', reason='SOURCE_CHANGED', bytes_read=consumed)
                    return dict(state='OBSERVED', hash=self.digest.hexdigest(), size=self.size,
                                bytes_read=consumed)
                self.digest.update(raw)
            if not self._stable():
                return dict(state='UNSTABLE', reason='SOURCE_CHANGED', bytes_read=consumed)
            return dict(state='PENDING', bytes_read=consumed)
        except (OSError, ObservationError, ValueError):
            return dict(state='UNSTABLE', reason='SOURCE_UNAVAILABLE', bytes_read=consumed)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None
