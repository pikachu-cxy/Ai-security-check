"""One authenticated, bounded scratch slot per explicitly selected private parent.

The fixed registration/lock survives normal use. A dead writer's registered job
is removed only by a later holder after every known target has been checked.
An incomplete registration or unknown file fails closed instead of creating a
second slot or deleting caller data. No parent permission is ever repaired.
"""
from contextlib import ExitStack
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import threading

from ..hook_state import no_links
from ..closeout_state import encode

LOCK_NAME = 'typed-source-v1.lock'
SLOT_NAME = 'typed-source-v1.job'
DATABASE_NAME = 'scratch.db'
CONTRACT = 'typed-source-scratch-v1'
_KNOWN_FILES = frozenset({DATABASE_NAME, DATABASE_NAME + '-journal'})
_fds, _mutex = set(), threading.Lock()


class TypedSnapshotSourceError(ValueError):
    def __init__(self, suffix):
        self.reason_code = 'TYPED_SOURCE_' + suffix
        super().__init__(self.reason_code)


def fail(suffix):
    raise TypedSnapshotSourceError(suffix)


def _fork_before():
    _mutex.acquire()


def _fork_parent():
    _mutex.release()


def _fork_child():
    global _fds, _mutex
    for fd in _fds:
        try:
            os.close(fd)
        except OSError:
            pass
    # Closing inherited descriptions must never LOCK_UN the parent's flock.
    _fds, _mutex = set(), threading.Lock()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(before=_fork_before, after_in_parent=_fork_parent,
                       after_in_child=_fork_child)


def _open(*args, **kwargs):
    with _mutex:
        fd = os.open(*args, **kwargs)
        _fds.add(fd)
        return fd


def _close(fd, pid):
    if pid != os.getpid():
        return
    with _mutex:
        if fd in _fds:
            _fds.remove(fd)
            try:
                os.close(fd)
            except OSError:
                pass


def _identity(info):
    return [info.st_dev, info.st_ino]


def _valid(info, *, directory=False):
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        fail('SCRATCH_UNSAFE')


def _directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd, pid = _open(path.anchor, flags), os.getpid()
    try:
        for part in path.parts[1:]:
            child = _open(part, flags, dir_fd=fd)
            _close(fd, pid)
            fd = child
        return fd
    except BaseException:
        _close(fd, pid)
        raise


class ScratchSlot:
    def __init__(self, store, directory):
        self.store, self.original = store, Path(directory)
        self.parent = Path(os.path.abspath(self.original))
        self.directory, self.path = self.parent / SLOT_NAME, self.parent / SLOT_NAME / DATABASE_NAME
        self._stack, self._parent_fd, self._lock_fd = None, None, None
        self._owned, self._pid = False, os.getpid()

    def _stable(self):
        no_links(self.original)
        no_links(self.parent)
        actual = self.parent.lstat()
        _valid(actual, directory=True)
        if _identity(actual) != self._base['parent_identity']:
            fail('SCRATCH_UNSAFE')
        for name, fd, expected in [(LOCK_NAME, self._lock_fd, self._lock_identity)]:
            value = os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            pinned = os.fstat(fd)
            _valid(value)
            _valid(pinned)
            if _identity(value) != expected or _identity(pinned) != expected:
                fail('SCRATCH_UNSAFE')

    def _read_registration(self):
        self._stable()
        os.lseek(self._lock_fd, 0, os.SEEK_SET)
        raw = os.read(self._lock_fd, 32769)
        try:
            if not 0 < len(raw) <= 32768:
                raise ValueError()
            packet = json.loads(raw)
            value = packet['value']
            if (set(packet) != {'value', 'mac'} or not isinstance(value, dict)
                    or set(value) != {*self._base, 'slot_identity', 'database_identity'}
                    or any(value[key] != item for key, item in self._base.items())
                    or not isinstance(packet['mac'], str)
                    or not hmac.compare_digest(packet['mac'], self.store._mac(value))):
                raise ValueError()
            for key in ('slot_identity', 'database_identity'):
                identity = value[key]
                if identity is not None and (not isinstance(identity, list) or len(identity) != 2
                        or any(type(item) is not int or item < 0 for item in identity)):
                    raise ValueError()
            if value['slot_identity'] is None and value['database_identity'] is not None:
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, RecursionError):
            fail('SCRATCH_UNSAFE')

    def _register(self, value):
        self._stable()
        raw = encode(dict(value=value, mac=self.store._mac(value)))
        if len(raw) > 32768:
            fail('SCRATCH_REGISTRATION_INCOMPLETE')
        try:
            os.lseek(self._lock_fd, 0, os.SEEK_SET)
            os.ftruncate(self._lock_fd, 0)
            offset = 0
            while offset < len(raw):
                written = os.write(self._lock_fd, raw[offset:])
                if written <= 0:
                    raise OSError('Incomplete scratch registration')
                offset += written
            os.fsync(self._lock_fd)
        except OSError:
            fail('SCRATCH_REGISTRATION_INCOMPLETE')

    def __enter__(self):
        if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
            fail('PLATFORM_UNSUPPORTED')
        import fcntl
        self._stack = ExitStack()
        try:
            no_links(self.original)
            no_links(self.parent)
            if (self.parent == self.store.root or self.parent.is_relative_to(self.store.root)
                    or self.parent == self.store.directory or self.parent.is_relative_to(self.store.directory)):
                fail('SCRATCH_UNSAFE')
            self._parent_fd = _directory(self.parent)
            self._stack.callback(_close, self._parent_fd, self._pid)
            info = os.fstat(self._parent_fd)
            _valid(info, directory=True)
            self._base = dict(contract=CONTRACT, parent=str(self.parent), parent_identity=_identity(info),
                owner_uid=os.getuid(), store_identity=hashlib.sha256(encode(self.store._store_identity())).hexdigest())
            # Serialize even the first O_EXCL/registration interval. A second
            # writer must not observe the first writer's unpublished empty lock
            # record and mistake it for damaged durable ownership evidence.
            try:
                fcntl.flock(self._parent_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fail('WAITING_SCRATCH_BUSY')
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            created = False
            try:
                self._lock_fd = _open(LOCK_NAME, flags | os.O_CREAT | os.O_EXCL, 0o600,
                                      dir_fd=self._parent_fd)
                created = True
            except FileExistsError:
                self._lock_fd = _open(LOCK_NAME, flags, dir_fd=self._parent_fd)
            self._stack.callback(_close, self._lock_fd, self._pid)
            lock_info = os.fstat(self._lock_fd)
            _valid(lock_info)
            self._lock_identity = _identity(lock_info)
            self._stable()
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                fail('WAITING_SCRATCH_BUSY')
            if created:
                # Never adopt a pre-existing slot by adding a fresh signature.
                if os.path.lexists(self.directory):
                    fail('SCRATCH_UNSAFE')
                self._register(dict(self._base, slot_identity=None, database_identity=None))
            registration = self._read_registration()
            self._cleanup(registration)
            os.mkdir(SLOT_NAME, mode=0o700, dir_fd=self._parent_fd)
            slot = _open(SLOT_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._parent_fd)
            try:
                slot_info = os.fstat(slot)
                _valid(slot_info, directory=True)
                registration = dict(self._base, slot_identity=_identity(slot_info), database_identity=None)
                self._register(registration)
                database = _open(DATABASE_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=slot)
                try:
                    info = os.fstat(database)
                    _valid(info)
                    registration['database_identity'] = _identity(info)
                    self._register(registration)
                    self._owned = True
                finally:
                    _close(database, self._pid)
            finally:
                _close(slot, self._pid)
            return self
        except BaseException:
            self._stack.close()
            self._stack = None
            raise

    def _cleanup(self, registration):
        """Verify the entire fixed job first; never recurse through caller data."""
        self._stable()
        try:
            info = os.stat(SLOT_NAME, dir_fd=self._parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if registration['slot_identity'] is not None:
                self._register(dict(self._base, slot_identity=None, database_identity=None))
            return
        _valid(info, directory=True)
        if registration['slot_identity'] != _identity(info):
            fail('SCRATCH_UNSAFE')
        slot = _open(SLOT_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._parent_fd)
        try:
            if _identity(os.fstat(slot)) != _identity(info):
                fail('SCRATCH_UNSAFE')
            names = set(os.listdir(slot))
            if not names <= _KNOWN_FILES:
                fail('SCRATCH_UNSAFE')
            original = {}
            with ExitStack() as pins:
                for name in sorted(names):
                    actual = os.stat(name, dir_fd=slot, follow_symlinks=False)
                    _valid(actual)
                    if name == DATABASE_NAME and registration['database_identity'] != _identity(actual):
                        fail('SCRATCH_UNSAFE')
                    if registration['database_identity'] is None:
                        fail('SCRATCH_UNSAFE')
                    fd = _open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=slot)
                    pins.callback(_close, fd, self._pid)
                    pinned = os.fstat(fd)
                    _valid(pinned)
                    if _identity(pinned) != _identity(actual):
                        fail('SCRATCH_UNSAFE')
                    original[name] = (fd, _identity(actual))
                self._stable()
                if set(os.listdir(slot)) != names:
                    fail('SCRATCH_UNSAFE')
                for name, (fd, identity) in original.items():
                    actual = os.stat(name, dir_fd=slot, follow_symlinks=False)
                    _valid(actual)
                    if _identity(actual) != identity or _identity(os.fstat(fd)) != identity:
                        fail('SCRATCH_UNSAFE')
                # All target identities are known before the first unlink.
                for name in names:
                    self._stable()
                    if _identity(os.stat(SLOT_NAME, dir_fd=self._parent_fd, follow_symlinks=False)) != registration['slot_identity']:
                        fail('SCRATCH_UNSAFE')
                    if _identity(os.stat(name, dir_fd=slot, follow_symlinks=False)) != original[name][1]:
                        fail('SCRATCH_UNSAFE')
                    os.unlink(name, dir_fd=slot)
            if os.listdir(slot):
                fail('SCRATCH_UNSAFE')
            self._stable()
            if _identity(os.stat(SLOT_NAME, dir_fd=self._parent_fd, follow_symlinks=False)) != registration['slot_identity']:
                fail('SCRATCH_UNSAFE')
            os.rmdir(SLOT_NAME, dir_fd=self._parent_fd)
            self._register(dict(self._base, slot_identity=None, database_identity=None))
        finally:
            _close(slot, self._pid)

    def close(self):
        if self._stack is None or self._pid != os.getpid():
            return
        try:
            if self._owned:
                self._cleanup(self._read_registration())
        finally:
            self._stack.close()
            self._stack = None

    def __exit__(self, kind, error, traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if error is None:
                raise
            if hasattr(error, 'add_note'):
                error.add_note('Typed source scratch cleanup failed: ' + type(cleanup_error).__name__)
        return False
