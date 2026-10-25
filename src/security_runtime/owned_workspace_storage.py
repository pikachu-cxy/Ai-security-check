"""Explicit POSIX permission admission for one Hook-owned workspace namespace.

Inspection performs no writes and does not open SQLite or read state bodies.
Admission only removes mode bits from pre-existing, current-UID owned targets;
missing owner access is never repaired. The directory-FD lock serializes this
admission API only, not legacy SQLite or page writers. Concurrent namespace
changes fail closed, retaining any permissions already tightened for retry.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import errno
import math
import os
from pathlib import Path
import stat
import threading
import time

_descriptors = set()
_descriptor_lock = threading.Lock()


def _before_fork():
    _descriptor_lock.acquire()


def _after_fork_parent():
    _descriptor_lock.release()


def _after_fork_child():
    global _descriptors, _descriptor_lock
    # Never LOCK_UN: fork shares the parent's open-file descriptions. Closing
    # only this child's copies leaves the active parent's directory lock intact.
    for fd in _descriptors:
        try:
            os.close(fd)
        except OSError:
            pass
    _descriptors, _descriptor_lock = set(), threading.Lock()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_parent,
                       after_in_child=_after_fork_child)


def _open(*args, **kwargs):
    # Serialize open/registration with fork so a child cannot inherit an
    # unregistered descriptor that becomes locked after it forked.
    with _descriptor_lock:
        fd = os.open(*args, **kwargs)
        _descriptors.add(fd)
        return fd


def _close(fd, owner_pid):
    if owner_pid != os.getpid():
        return
    with _descriptor_lock:
        if fd in _descriptors:
            _descriptors.remove(fd)
            try:
                os.close(fd)
            except OSError:
                pass


DATABASES = ('task-security.db', 'pending-activity.db')
FILES = ('snapshot.key', 'task-security.db.review-metadata.identity', 'workspace.lock',
         'task-security.db.capture-publication.identity',
         'task-security.db.capture-publication.identity.next',
         'snapshot-pages.gc.lock', 'snapshot-pages.gc.identity',
         *(name + suffix for name in DATABASES for suffix in ('', '-journal', '-wal', '-shm')))


class OwnedWorkspaceStorageError(ValueError):
    def __init__(self, report):
        self.report = report
        self.reason_code = report['reason_code']
        super().__init__(self.reason_code)


class _CheckFailure(Exception):
    def __init__(self, detail):
        self.detail = detail
        super().__init__(detail)


def _supported():
    return (os.name == 'posix' and hasattr(os, 'getuid') and hasattr(os, 'fchmod')
            and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks)


def _identity(info):
    return (info.st_dev, info.st_ino)


def _mode(info):
    return stat.S_IMODE(info.st_mode)


def _directory(path, *, create=False, created=None):
    """Walk from the filesystem root using an independent NOFOLLOW FD chain."""
    path = Path(os.path.abspath(path))
    owner_pid = os.getpid()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = _open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            try:
                child = _open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                    if created is not None:
                        created.append(component)
                except FileExistsError:
                    pass
                child = _open(component, flags, dir_fd=fd)
            _close(fd, owner_pid)
            fd = child
        return fd
    except BaseException:
        _close(fd, owner_pid)
        raise


class OwnedWorkspaceStorage:
    _scope = 'KNOWN_WORKSPACE_STATE_V1'
    _source_workspace = True

    def __init__(self, hooks, root):
        # Import lazily: HookStateStore's explicit writers call this module.
        from .hook_state import HookStateStore, identity, native_io_path
        if not isinstance(hooks, HookStateStore):
            raise OwnedWorkspaceStorageError(self._report('UNSAFE', detail='HOOK_STORE_REQUIRED'))
        self.hooks, self.root = hooks, Path(root)
        self._initial_error = None
        try:
            # Preserve the product's original root spelling/namespace. A
            # subclass cannot redirect this operation to an arbitrary path.
            self.original_directory = HookStateStore.workspace_directory(hooks, root)
        except (OSError, ValueError):
            self._initial_error = 'PATH_UNSAFE'
            self.original_directory = native_io_path(hooks.directory / identity(os.path.normcase(str(root))))
        self.directory = Path(os.path.abspath(self.original_directory))

    @classmethod
    def _report(cls, state, *, detail=None, targets=None, changed=None, created=0):
        return dict(state=state, reason_code='OWNED_WORKSPACE_STORAGE_' + state,
                    detail_code=detail, scope=cls._scope,
                    source_workspace_verified=(cls._source_workspace and state in {
                        'ABSENT', 'PRIVATE', 'UPGRADE_REQUIRED'}),
                    permission_model='POSIX_MODE_BITS', content_verified=False,
                    targets=targets or [], changed=list(changed or []), created_directories=created)

    def _roots(self):
        from .hook_state import no_links
        if self._initial_error is not None:
            raise _CheckFailure(self._initial_error)
        no_links(self.root)
        no_links(self.original_directory)
        fd = _directory(self.root)
        owner_pid = os.getpid()
        try:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise _CheckFailure('ROOT_NOT_DIRECTORY')
            return _identity(info)
        finally:
            _close(fd, owner_pid)

    def _valid(self, info, *, directory=False, device=None):
        target = 0o700 if directory else 0o600
        if info.st_uid != os.getuid():
            raise _CheckFailure('OWNER_MISMATCH')
        if (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)):
            raise _CheckFailure('TYPE_MISMATCH')
        if not directory and info.st_nlink != 1:
            raise _CheckFailure('MULTIPLE_LINKS')
        if device is not None and info.st_dev != device:
            raise _CheckFailure('DEVICE_MISMATCH')
        if _mode(info) & target != target:
            raise _CheckFailure('OWNER_ACCESS_MISSING')

    def _inventory(self, fd):
        directory = os.fstat(fd)
        self._valid(directory, directory=True)
        values = {'.': directory}
        for name in FILES:
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            self._valid(info, device=directory.st_dev)
            values[name] = info
        return values

    def _targets(self, values):
        return [dict(name=name, kind='DIRECTORY' if name == '.' else 'FILE',
                     mode=_mode(info), target_mode=0o700 if name == '.' else 0o600,
                     device=info.st_dev, inode=info.st_ino, owner_uid=info.st_uid)
                for name, info in values.items()]

    def inspect(self):
        if not _supported():
            return self._report('PLATFORM_UNSUPPORTED')
        try:
            root_identity = self._roots()
            try:
                fd = _directory(self.directory)
            except FileNotFoundError:
                return self._report('ABSENT')
            with ExitStack() as stack:
                stack.callback(_close, fd, os.getpid())
                values = self._inventory(fd)
                self._live(fd, values, {}, root_identity)
                state = 'PRIVATE' if all(_mode(v) == (0o700 if n == '.' else 0o600)
                                         for n, v in values.items()) else 'UPGRADE_REQUIRED'
                return self._report(state, targets=self._targets(values))
        except _CheckFailure as error:
            return self._report('UNSAFE', detail=error.detail)
        except (OSError, ValueError):
            return self._report('UNSAFE', detail='PATH_OR_ACCESS_UNSAFE')

    def _live(self, fd, original, changed, root_identity, handles=None):
        if self._roots() != root_identity:
            raise _CheckFailure('ROOT_CHANGED')
        current_fd = _directory(self.directory)
        owner_pid = os.getpid()
        try:
            if _identity(os.fstat(current_fd)) != _identity(original['.']):
                raise _CheckFailure('DIRECTORY_CHANGED')
        finally:
            _close(current_fd, owner_pid)
        actual = self._inventory(fd)
        if set(actual) != set(original):
            raise _CheckFailure('TARGET_SET_CHANGED')
        for name, info in actual.items():
            expected = original[name]
            mode = (0o700 if name == '.' else 0o600) if name in changed else _mode(expected)
            if _identity(info) != _identity(expected) or _mode(info) != mode:
                raise _CheckFailure('TARGET_CHANGED')
            if handles is not None:
                opened = os.fstat(handles[name])
                self._valid(opened, directory=name == '.', device=expected.st_dev)
                if _identity(opened) != _identity(expected) or _mode(opened) != mode:
                    raise _CheckFailure('OPEN_TARGET_CHANGED')
        return actual

    def _lock(self, fd, wait_seconds):
        import fcntl
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise
                if time.monotonic() >= deadline:
                    raise _CheckFailure('LOCK_BUSY')
                time.sleep(min(.01, max(0, deadline - time.monotonic())))

    @contextmanager
    def admitted(self, *, wait_seconds=2):
        """Hold the verified state-directory admission lock for a writer.

        Only admission failures receive admission reason codes. The writer's
        own errors after entry propagate unchanged, with all pinned handles
        and the lock still released on exit.
        """
        with ExitStack() as stack:
            report = self._admit_into(stack, wait_seconds=wait_seconds)
            yield report

    def admit(self, *, wait_seconds=2):
        with self.admitted(wait_seconds=wait_seconds) as report:
            return report

    def _admit_into(self, stack, *, wait_seconds):
        if not _supported():
            raise OwnedWorkspaceStorageError(self._report('PLATFORM_UNSUPPORTED'))
        if type(wait_seconds) not in {int, float} or not math.isfinite(wait_seconds) or not 0 <= wait_seconds <= 10:
            raise OwnedWorkspaceStorageError(self._report('UNSAFE', detail='INVALID_WAIT'))
        changed, created, values, began = [], [], {}, False
        try:
            root_identity = self._roots()
            fd = _directory(self.directory, create=True, created=created)
            stack.callback(_close, fd, os.getpid())
            self._valid(os.fstat(fd), directory=True)
            self._lock(fd, wait_seconds)
            # Closing the pinned FD releases flock on all exit paths.
            values = self._inventory(fd)
            handles = {'.': fd}
            for name in values:
                if name == '.':
                    continue
                # A regular file can become a FIFO after lstat. NONBLOCK
                # ensures fstat can reject that replacement without waiting
                # indefinitely for a peer to open the pipe.
                opened = _open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                               getattr(os, 'O_CLOEXEC', 0), dir_fd=fd)
                stack.callback(_close, opened, os.getpid())
                handles[name] = opened
                info = os.fstat(opened)
                self._valid(info, device=values['.'].st_dev)
                if _identity(info) != _identity(values[name]) or _mode(info) != _mode(values[name]):
                    raise _CheckFailure('OPEN_TARGET_CHANGED')
            # All known targets are pinned and checked before any chmod.
            self._live(fd, values, changed, root_identity, handles)
            for name, info in values.items():
                target = 0o700 if name == '.' else 0o600
                if _mode(info) == target:
                    continue
                self._live(fd, values, changed, root_identity, handles)
                began = True
                os.fchmod(handles[name], target)
                changed.append(name)
            actual = self._live(fd, values, changed, root_identity, handles)
            return self._report('PRIVATE', targets=self._targets(actual), changed=changed, created=len(created))
        except _CheckFailure as error:
            transient = {'ROOT_CHANGED', 'DIRECTORY_CHANGED', 'TARGET_SET_CHANGED', 'TARGET_CHANGED', 'OPEN_TARGET_CHANGED'}
            state = ('UPGRADE_INCOMPLETE' if began or changed or created else
                     'BUSY' if error.detail == 'LOCK_BUSY' else
                     'RETRY' if error.detail in transient else 'UNSAFE')
            raise OwnedWorkspaceStorageError(self._report(state, detail=error.detail,
                targets=self._targets(values), changed=changed, created=len(created))) from None
        except (OSError, ValueError) as error:
            unsupported = isinstance(error, OSError) and error.errno in {errno.ENOSYS, errno.ENOTSUP}
            state = 'UPGRADE_INCOMPLETE' if began or changed or created else 'PLATFORM_UNSUPPORTED' if unsupported else 'UNSAFE'
            raise OwnedWorkspaceStorageError(self._report(state, detail='FILESYSTEM_OPERATION_FAILED',
                targets=self._targets(values), changed=changed, created=len(created))) from None


class OwnedHookNamespaceStorage(OwnedWorkspaceStorage):
    """Protect Hook state for an opaque logical identity, without a source claim.

    Installation targets and coordinator identities can legitimately be absent.
    Only their original Hook-derived state namespace is inspected or created;
    the identity itself is never opened, created, or admitted as a workspace.
    """
    _scope = 'KNOWN_HOOK_NAMESPACE_STATE_V1'
    _source_workspace = False

    def _roots(self):
        from .hook_state import no_links
        if self._initial_error is not None:
            raise _CheckFailure(self._initial_error)
        no_links(self.original_directory)
        return None
