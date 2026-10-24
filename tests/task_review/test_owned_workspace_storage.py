"""Private-storage admission on real isolated POSIX files and descriptors.

Legacy signed rows are store fixtures, not Runtime tasks or native host claims.
Metadata fault injection is labelled separately from native ownership checks.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest
import security_runtime

from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import OwnedWorkspaceStorage, OwnedWorkspaceStorageError
import security_runtime.owned_workspace_storage as storage_module
from test_review_metadata_compatibility import _encoded, _legacy_fixture, _task_row


NATIVE_SQLITE_CONNECT = sqlite3.connect


@contextmanager
def umask(value):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


def tree(directory):
    """No SQLite opens or symlink following; access times are intentionally absent."""
    directory = Path(directory)
    if not directory.exists():
        return None
    result = {}
    for current, directories, files in os.walk(directory, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in directories + files)]:
            info = path.lstat()
            value = dict(mode=stat.S_IMODE(info.st_mode), mtime_ns=info.st_mtime_ns,
                device=info.st_dev, inode=info.st_ino, uid=info.st_uid, links=info.st_nlink,
                kind=stat.S_IFMT(info.st_mode), size=info.st_size)
            if stat.S_ISREG(info.st_mode):
                value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            elif stat.S_ISLNK(info.st_mode):
                value['link'] = os.readlink(path)
            result[str(path.relative_to(directory))] = value
    return result


@pytest.fixture
def sample(tmp_path, monkeypatch):
    if os.name != 'posix':
        pytest.skip('Real POSIX mode/descriptor admission requires a POSIX host')
    fixture = tmp_path / 'legacy'
    fixture.mkdir()
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime'))
    with monkeypatch.context() as scoped:
        # Optional post-commit observation is unrelated to permission admission
        # and must not launch a background writer for this isolated fixture.
        scoped.setattr('security_runtime.product_metrics.task_record_observed', lambda *args: None)
        state, root, legacy = _legacy_fixture(fixture, capacity=True)
    row = _task_row(state, legacy['task_ref'])
    ledger = _encoded(state.get(legacy['task_ref'])['review_ledger'])
    directory = state.path.parent
    key = (directory / 'snapshot.key').read_bytes()
    database = state.path.read_bytes()
    # Preserve the genuine signed fixture, then recreate its same namespace
    # with the old permissions produced by actual umask 022 file creation.
    directory.rename(directory.with_name(directory.name + '.original-fixture'))
    with umask(0o022):
        directory.mkdir()
        (directory / 'snapshot.key').write_bytes(key)
        state.path.write_bytes(database)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(state.path.stat().st_mode) == 0o644
    return SimpleNamespace(root=root, state=state, hooks=state.hooks, directory=directory,
        key=key, database=database, row=row, ledger=ledger, legacy=legacy,
        storage=OwnedWorkspaceStorage(state.hooks, root), temporary=tmp_path)


def assert_legacy(sample):
    assert (sample.directory / 'snapshot.key').read_bytes() == sample.key
    assert sample.state.path.read_bytes() == sample.database
    assert _task_row(sample.state, sample.legacy['task_ref']) == sample.row
    value = sample.state.get(sample.legacy['task_ref'])
    assert value['review_capacity']['status'] == 'CAPACITY_REQUIRED'
    assert _encoded(value['review_ledger']) == sample.ledger


def forbid_sqlite(database, *args, **kwargs):
    name = os.fsdecode(os.fspath(database)).split('?', 1)[0].rsplit('/', 1)[-1]
    # Global observation workers may outlive a preceding unrelated test. Do
    # not turn their independent DB work into a permission-API failure; all
    # connections from this API thread and to either protected DB still fail.
    if threading.current_thread() is not threading.main_thread() and name not in {
            'task-security.db', 'pending-activity.db'}:
        return NATIVE_SQLITE_CONNECT(database, *args, **kwargs)
    pytest.fail('A permission inspection/admission must not open SQLite or recover a journal')


def test_real_old_permissions_tighten_without_rewriting_key_or_signed_capacity(sample, monkeypatch):
    before = tree(sample.directory)
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        result = sample.storage.admit()
    assert result['state'] == 'PRIVATE'
    assert result['content_verified'] is False
    after = tree(sample.directory)
    assert set(after) == set(before)
    for name in before:
        assert {k: v for k, v in after[name].items() if k != 'mode'} == {
            k: v for k, v in before[name].items() if k != 'mode'}
        assert after[name]['mode'] == (0o700 if name == '.' else 0o600)
    assert_legacy(sample)


def test_absent_inspection_is_zero_write_and_admission_only_creates_private_directory(tmp_path, monkeypatch):
    if os.name != 'posix':
        pytest.skip('Native POSIX file-mode creation check')
    root = tmp_path / 'source'
    root.mkdir()
    hooks = HookStateStore(tmp_path / 'state' / 'hooks')
    storage = OwnedWorkspaceStorage(hooks, root)
    before = tree(tmp_path)
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        assert storage.inspect()['state'] == 'ABSENT'
        assert tree(tmp_path) == before
        with umask(0o022):
            assert storage.admit()['state'] == 'PRIVATE'
    directory = hooks.workspace_directory(root)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize('condition', ['broad', 'private', 'partly_tightened', 'malformed_marker'])
def test_readonly_inspection_preserves_every_content_mode_and_mtime(sample, monkeypatch, condition):
    if condition in {'private', 'partly_tightened'}:
        sample.directory.chmod(0o700)
        (sample.directory / 'snapshot.key').chmod(0o600)
        if condition == 'private':
            sample.state.path.chmod(0o600)
    elif condition == 'malformed_marker':
        marker = sample.state.path.with_name(sample.state.path.name + '.review-metadata.identity')
        marker.write_bytes(b'{ordinary malformed marker')
        marker.chmod(0o644)
    before = tree(sample.temporary)
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        report = sample.storage.inspect()
    assert report['changed'] == []
    assert tree(sample.temporary) == before


HOT_JOURNAL_CHILD = r'''
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('PRAGMA cache_size=1')
db.execute('PRAGMA synchronous=FULL')
db.execute('BEGIN IMMEDIATE')
db.execute("UPDATE inspection_probe SET value=?", ('2'*131072,))
os._exit(37)
'''


def test_readonly_inspection_does_not_recover_a_real_hot_sqlite_journal(sample, monkeypatch):
    with sqlite3.connect(sample.state.path) as db:
        db.execute('CREATE TABLE inspection_probe(value TEXT)')
        db.execute('INSERT INTO inspection_probe VALUES(?)', ('1' * 131072,))
    child = subprocess.run([sys.executable, '-c', HOT_JOURNAL_CHILD, str(sample.state.path)],
        cwd=sample.temporary, capture_output=True, text=True, timeout=15)
    assert child.returncode == 37, child.stderr
    journal = Path(str(sample.state.path) + '-journal')
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8] != b'\0' * 8, 'The real journal never became hot'
    before = tree(sample.temporary)
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        report = sample.storage.inspect()
    assert report['changed'] == []
    assert tree(sample.temporary) == before


@pytest.mark.parametrize('link_kind', ['symlink', 'hardlink'])
@pytest.mark.parametrize('target_name', [
    'snapshot.key', 'task-security.db', 'pending-activity.db',
    'task-security.db.review-metadata.identity', 'workspace.lock',
    'snapshot-pages.gc.lock', 'snapshot-pages.gc.identity',
    'task-security.db-journal', 'task-security.db-wal', 'task-security.db-shm',
    'pending-activity.db-journal', 'pending-activity.db-wal', 'pending-activity.db-shm',
])
def test_unsafe_target_link_is_rejected_before_any_chmod_or_external_change(sample, monkeypatch, link_kind, target_name):
    sentinel = sample.temporary / 'outside-sentinel'
    sentinel.write_text('value=1')
    target = sample.directory / target_name
    if not target.exists():
        target.write_text('value=1')
    target.rename(sample.directory / ('original-' + target_name))
    if link_kind == 'symlink':
        target.symlink_to(sentinel)
    else:
        os.link(sentinel, target)
    before, calls = tree(sample.temporary), []
    actual = os.fchmod

    def tracked(fd, mode):
        calls.append(mode)
        return actual(fd, mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(storage_module.os, 'fchmod', tracked)
        with pytest.raises(OwnedWorkspaceStorageError) as unsafe:
            sample.storage.admit()
    assert unsafe.value.report['state'] == 'UNSAFE'
    assert calls == []
    assert tree(sample.temporary) == before
    assert sentinel.read_text() == 'value=1'


def test_foreign_uid_metadata_fault_is_rejected_before_chmod(sample, monkeypatch):
    """Injected descriptor metadata, explicitly not native chown acceptance."""
    target = sample.state.path.stat()
    actual_stat, actual_chmod, calls = os.fstat, os.fchmod, []

    class ForeignUID:
        def __init__(self, info):
            self.info = info

        def __getattr__(self, name):
            return self.info.st_uid + 1 if name == 'st_uid' else getattr(self.info, name)

    def changed_stat(fd):
        info = actual_stat(fd)
        return ForeignUID(info) if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino) else info

    def tracked_chmod(fd, mode):
        calls.append(mode)
        return actual_chmod(fd, mode)

    before = tree(sample.temporary)
    with monkeypatch.context() as scoped:
        scoped.setattr(storage_module.os, 'fstat', changed_stat)
        scoped.setattr(storage_module.os, 'fchmod', tracked_chmod)
        with pytest.raises(OwnedWorkspaceStorageError) as unsafe:
            sample.storage.admit()
    assert unsafe.value.report['state'] == 'UNSAFE'
    assert calls == []
    assert tree(sample.temporary) == before


def test_native_foreign_uid_target_is_rejected_without_chmod(sample, monkeypatch):
    try:
        os.chown(sample.state.path, os.getuid() + 1, -1)
    except PermissionError:
        pytest.skip('Native foreign-owner fixture requires chown privilege; injected UID boundary is tested separately')
    before, calls = tree(sample.temporary), []
    actual = os.fchmod

    def tracked(fd, mode):
        calls.append(mode)
        return actual(fd, mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(storage_module.os, 'fchmod', tracked)
        with pytest.raises(OwnedWorkspaceStorageError) as unsafe:
            sample.storage.admit()
    assert unsafe.value.report['state'] == 'UNSAFE'
    assert calls == []
    assert tree(sample.temporary) == before


def test_target_replaced_after_descriptor_open_is_refused_before_first_chmod(sample, monkeypatch):
    actual_open, actual_chmod = os.open, os.fchmod
    replaced, calls = [], []

    def raced_open(path, flags, *args, **kwargs):
        fd = actual_open(path, flags, *args, **kwargs)
        if not replaced and os.path.basename(os.fsdecode(path)) == sample.state.path.name:
            sample.state.path.rename(sample.directory / 'race-original-database')
            sample.state.path.write_bytes(b'value=2')
            replaced.append(tree(sample.temporary))
        return fd

    def tracked_chmod(fd, mode):
        calls.append(mode)
        return actual_chmod(fd, mode)

    with monkeypatch.context() as scoped:
        # This transparent wrapper preserves the native dir_fd argument.
        # Register that actual capability rather than disabling detection.
        scoped.setattr(storage_module.os, 'supports_dir_fd', {*os.supports_dir_fd, raced_open})
        scoped.setattr(storage_module.os, 'open', raced_open)
        scoped.setattr(storage_module.os, 'fchmod', tracked_chmod)
        with pytest.raises(OwnedWorkspaceStorageError) as unsafe:
            sample.storage.admit()
    assert replaced, 'The actual target descriptor was never opened'
    assert unsafe.value.report['state'] == 'RETRY'
    assert calls == []
    assert tree(sample.temporary) == replaced[0]


def test_second_fchmod_failure_never_writes_sqlite_or_relaxes_partial_permissions(sample, monkeypatch):
    before, actual, calls = tree(sample.directory), os.fchmod, []

    def fail_second(fd, mode):
        calls.append((fd, mode))
        if len(calls) == 2:
            # Real fchmod produces EBADF; the original owned descriptor stays
            # open so failure cleanup cannot accidentally damage another FD.
            return actual(-1, mode)
        return actual(fd, mode)

    with monkeypatch.context() as scoped:
        scoped.setattr(storage_module.os, 'fchmod', fail_second)
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        with pytest.raises(OwnedWorkspaceStorageError) as incomplete:
            sample.storage.admit()
    assert len(calls) == 2
    assert incomplete.value.report['state'] == 'UPGRADE_INCOMPLETE'
    partial = tree(sample.directory)
    assert set(partial) == set(before)
    assert partial['.']['mode'] == 0o700
    assert any(partial[name]['mode'] != before[name]['mode'] for name in before)
    for name in before:
        assert partial[name]['mode'] & ~before[name]['mode'] == 0
        assert {k: v for k, v in partial[name].items() if k != 'mode'} == {
            k: v for k, v in before[name].items() if k != 'mode'}
    assert sample.state.path.read_bytes() == sample.database
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        assert sample.storage.inspect()['changed'] == []
        assert tree(sample.directory) == partial
        assert sample.storage.admit()['state'] == 'PRIVATE'
    assert_legacy(sample)


ADMIT_CHILD = r'''
import json, sys, time
from pathlib import Path
from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import OwnedWorkspaceStorage
import security_runtime.owned_workspace_storage as module
hooks, root, gates = map(Path, sys.argv[1:])
actual, paused = module.os.fchmod, []
def pause_first(fd, mode):
    if not paused:
        paused.append(True)
        (gates/'ready').write_text('ready')
        deadline = time.monotonic()+10
        while not (gates/'release').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('The isolated permission gate was not released')
            time.sleep(.005)
    return actual(fd, mode)
module.os.fchmod = pause_first
print(json.dumps(OwnedWorkspaceStorage(HookStateStore(hooks), root).admit()), flush=True)
'''


def child_environment():
    environment = dict(os.environ)
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    source = str(Path(security_runtime.__file__).resolve().parent.parent)
    environment['PYTHONPATH'] = source + os.pathsep + environment.get('PYTHONPATH', '')
    return environment


def test_directory_descriptor_guard_serializes_real_processes_without_sqlite_or_file_lock(sample, monkeypatch):
    gates = sample.temporary / 'gates'
    gates.mkdir()
    child = subprocess.Popen([sys.executable, '-c', ADMIT_CHILD,
        str(sample.hooks.directory), str(sample.root), str(gates)], cwd=sample.temporary,
        env=child_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual, calls = os.fchmod, []

    def tracked(fd, mode):
        calls.append(mode)
        return actual(fd, mode)

    try:
        deadline = time.monotonic() + 10
        while not (gates / 'ready').exists():
            assert child.poll() is None, 'The permission writer exited before its native guard gate'
            assert time.monotonic() < deadline, 'The permission writer did not reach its first fchmod'
            time.sleep(.005)
        before = tree(sample.directory)
        with monkeypatch.context() as scoped:
            scoped.setattr(storage_module.os, 'fchmod', tracked)
            scoped.setattr(sqlite3, 'connect', forbid_sqlite)
            assert sample.storage.inspect()['changed'] == []
            with pytest.raises(OwnedWorkspaceStorageError) as busy:
                sample.storage.admit(wait_seconds=.05)
        assert busy.value.report['state'] == 'BUSY'
        assert calls == []
        assert tree(sample.directory) == before
    finally:
        (gates / 'release').write_text('release')
        try:
            output, error = child.communicate(timeout=15)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
    assert child.returncode == 0, error
    assert json.loads(output)['state'] == 'PRIVATE'
    assert sample.storage.admit()['state'] == 'PRIVATE'
    assert sample.storage.inspect()['state'] == 'PRIVATE'
    assert not (sample.directory / 'workspace.lock').exists()
    assert_legacy(sample)


def test_unsupported_descriptor_capability_is_explicit_and_zero_write(sample, monkeypatch):
    before = tree(sample.temporary)
    with monkeypatch.context() as scoped:
        scoped.setattr(storage_module, '_supported', lambda: False)
        scoped.setattr(sqlite3, 'connect', forbid_sqlite)
        report = sample.storage.inspect()
        assert report['state'] == 'PLATFORM_UNSUPPORTED'
        assert report['changed'] == []
        with pytest.raises(OwnedWorkspaceStorageError) as unsupported:
            sample.storage.admit()
    assert unsupported.value.report['state'] == 'PLATFORM_UNSUPPORTED'
    assert tree(sample.temporary) == before


FIFO_CHILD = r'''
import hashlib, json, os, stat, sys
from pathlib import Path
from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import OwnedWorkspaceStorage, OwnedWorkspaceStorageError
import security_runtime.owned_workspace_storage as module
hooks, root = map(Path, sys.argv[1:])
storage = OwnedWorkspaceStorage(HookStateStore(hooks), root)
directory, actual_open, actual_chmod = storage.directory, os.open, os.fchmod
changed, calls = [], []
def snapshot():
    result = {}
    for path in [directory, *directory.iterdir()]:
        info = path.lstat()
        value = dict(mode=stat.S_IMODE(info.st_mode),mtime_ns=info.st_mtime_ns,
            device=info.st_dev,inode=info.st_ino,uid=info.st_uid,links=info.st_nlink,
            kind=stat.S_IFMT(info.st_mode),size=info.st_size)
        if stat.S_ISREG(info.st_mode):
            value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[str(path.relative_to(directory))] = value
    return result
def raced_open(path, flags, *args, **kwargs):
    if not changed and os.path.basename(os.fsdecode(path)) == 'task-security.db':
        target = directory/'task-security.db'
        target.rename(directory/'fifo-original-database')
        os.mkfifo(target,0o600)
        changed.append(snapshot())
    return actual_open(path, flags, *args, **kwargs)
def tracked_chmod(fd, mode):
    calls.append(mode)
    return actual_chmod(fd, mode)
module.os.supports_dir_fd = {*module.os.supports_dir_fd, raced_open}
module.os.open = raced_open
module.os.fchmod = tracked_chmod
try:
    report = storage.admit()
except OwnedWorkspaceStorageError as error:
    report = error.report
assert changed, 'The actual descriptor race was not reached'
print(json.dumps(dict(report=report,calls=calls,checkpoint=changed[0])),flush=True)
'''


def test_regular_target_replaced_by_real_fifo_cannot_block_admission_or_chmod(sample):
    try:
        child = subprocess.run([sys.executable, '-c', FIFO_CHILD,
            str(sample.hooks.directory), str(sample.root)], cwd=sample.temporary,
            env=child_environment(), capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        pytest.fail('Opening the concurrently substituted FIFO blocked admission')
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert result['report']['state'] == 'UNSAFE'
    assert result['calls'] == []
    assert stat.S_ISFIFO(sample.state.path.lstat().st_mode)
    assert tree(sample.directory) == result['checkpoint']
    assert (sample.directory / 'fifo-original-database').read_bytes() == sample.database


LOCK_PROBE_CHILD = r'''
import json, sys
from pathlib import Path
from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import OwnedWorkspaceStorage, OwnedWorkspaceStorageError
hooks, root = map(Path,sys.argv[1:])
try:
    report = OwnedWorkspaceStorage(HookStateStore(hooks),root).admit(wait_seconds=.05)
except OwnedWorkspaceStorageError as error:
    report = error.report
print(json.dumps(report),flush=True)
'''


def test_live_fork_child_neither_unlocks_parent_nor_retains_its_directory_guard(sample, monkeypatch):
    if not hasattr(os, 'fork') or not hasattr(os, 'register_at_fork'):
        pytest.skip('Native fork-only descriptor inheritance requires fork and at-fork support')
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    parent_pipes = {ready_read, ready_write, release_read, release_write}
    actual, forked, acknowledged = os.fchmod, [], []

    def close_pipe(fd):
        if fd in parent_pipes:
            parent_pipes.remove(fd)
            os.close(fd)

    def probe():
        child = subprocess.run([sys.executable, '-c', LOCK_PROBE_CHILD,
            str(sample.hooks.directory), str(sample.root)], cwd=sample.temporary,
            env=child_environment(), capture_output=True, text=True, timeout=5)
        assert child.returncode == 0, child.stderr
        return json.loads(child.stdout)

    def fork_while_locked(fd, mode):
        if not forked:
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(ready_read)
                    os.close(release_write)
                    os.write(ready_write, b'r')
                    os.read(release_read, 1)
                finally:
                    os._exit(0)
            forked.append(pid)
            close_pipe(ready_write)
            close_pipe(release_read)
            assert select.select([ready_read], [], [], 5)[0], 'Fork child did not acknowledge its live gate'
            assert os.read(ready_read, 1) == b'r'
            acknowledged.append(True)
            assert os.waitpid(pid, os.WNOHANG) == (0, 0)
            # Child cleanup must close its copy, never LOCK_UN the parent's
            # shared open description while the parent is still admitting.
            assert probe()['state'] == 'BUSY'
        return actual(fd, mode)

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(storage_module.os, 'fchmod', fork_while_locked)
            assert sample.storage.admit()['state'] == 'PRIVATE'
        assert forked
        assert os.waitpid(forked[0], os.WNOHANG) == (0, 0)
        # The non-exec child is still alive. A separate process must acquire
        # the guard after the parent closes its original directory descriptor.
        assert probe()['state'] == 'PRIVATE'
        assert os.waitpid(forked[0], os.WNOHANG) == (0, 0)
    finally:
        if forked:
            if not acknowledged:
                try:
                    os.kill(forked[0], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                os.write(release_write, b'x')
            except OSError:
                pass
            try:
                os.waitpid(forked[0], 0)
            except ChildProcessError:
                pass
        for fd in list(parent_pipes):
            try:
                close_pipe(fd)
            except OSError:
                pass
    assert_legacy(sample)
