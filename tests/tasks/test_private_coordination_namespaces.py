"""Logical Hook coordination protects state without admitting a source path.

These real POSIX files/locks model installation and supervisor identities; no
Runtime task, scanner, source baseline, or native host attestation is created.
"""
import hashlib
import os
from pathlib import Path
import select
import stat
import subprocess
import sys

import pytest
import security_runtime

from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import (
    OwnedHookNamespaceStorage, OwnedWorkspaceStorage, OwnedWorkspaceStorageError,
)
from security_runtime import task_dispatcher


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Real POSIX descriptor/mode/flock checks')


def mode(path):
    return stat.S_IMODE(path.lstat().st_mode)


def fingerprint(path):
    info = path.lstat()
    return (info.st_mode, info.st_uid, info.st_dev, info.st_ino, info.st_nlink,
            info.st_size, info.st_mtime_ns,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None)


@pytest.mark.parametrize('kind', ['missing', 'file', 'symlink'])
def test_namespace_inspection_and_admission_never_access_or_create_source_identity(tmp_path, kind):
    identity = tmp_path / 'logical' / 'installation-target'
    identity.parent.mkdir()
    if kind == 'file':
        identity.write_bytes(b'user-owned installation artifact')
    elif kind == 'symlink':
        identity.symlink_to(tmp_path / 'missing-target', target_is_directory=True)
    existed = os.path.lexists(identity)
    original = fingerprint(identity) if existed else None
    hooks = HookStateStore(tmp_path / 'runtime' / 'hook-locks')
    storage = OwnedHookNamespaceStorage(hooks, identity)
    assert not hooks.directory.exists()
    report = storage.inspect()
    assert report['state'] == 'ABSENT'
    assert report['scope'] == 'KNOWN_HOOK_NAMESPACE_STATE_V1'
    assert report['source_workspace_verified'] is False
    assert not hooks.directory.exists()
    report = storage.admit()
    assert report['state'] == 'PRIVATE'
    assert report['source_workspace_verified'] is False
    assert report['content_verified'] is False
    assert list(storage.directory.iterdir()) == []
    assert mode(storage.directory) == 0o700
    assert os.path.lexists(identity) == existed
    assert (fingerprint(identity) if existed else None) == original


def test_strict_workspace_writer_rejects_missing_identity_without_namespace_fallback(tmp_path):
    root = tmp_path / 'not-a-project'
    hooks = HookStateStore(tmp_path / 'strict-state')
    storage = OwnedWorkspaceStorage(hooks, root)
    report = storage.inspect()
    assert report['state'] == 'UNSAFE'
    assert report['scope'] == 'KNOWN_WORKSPACE_STATE_V1'
    assert report['source_workspace_verified'] is False
    with pytest.raises(OwnedWorkspaceStorageError) as caught:
        storage.admit()
    assert caught.value.reason_code == 'OWNED_WORKSPACE_STORAGE_UNSAFE'
    assert not hooks.directory.exists()
    assert not root.exists()
    with pytest.raises(OwnedWorkspaceStorageError):
        hooks.prepare_private_writer(root)
    with pytest.raises(OwnedWorkspaceStorageError):
        hooks.prepare_database(root, 'pending-activity.db')
    assert not hooks.directory.exists()


def test_namespace_keeps_original_hash_and_only_tightens_derived_state(tmp_path):
    # The logical spelling is an identity, even when its lexical parent is
    # absent. Canonicalizing it before hashing would break legacy coordination.
    identity = tmp_path / 'absent' / '..' / 'component-version'
    hooks = HookStateStore(tmp_path / 'state')
    expected = hooks.directory / hashlib.sha256(os.path.normcase(str(identity)).encode()).hexdigest()
    expected.mkdir(parents=True, mode=0o755)
    expected.chmod(0o755)
    key = expected / 'snapshot.key'
    key.write_bytes(b'k' * 32)
    key.chmod(0o644)
    before = fingerprint(key)
    unknown = expected / 'other-provider.db'
    unknown.write_bytes(b'other provider state')
    unknown.chmod(0o644)
    other_before = fingerprint(unknown)
    storage = OwnedHookNamespaceStorage(hooks, identity)
    assert storage.directory == expected
    assert storage.inspect()['state'] == 'UPGRADE_REQUIRED'
    assert storage.admit()['changed'] == ['.', 'snapshot.key']
    assert mode(expected) == 0o700 and mode(key) == 0o600
    assert fingerprint(key)[1:] == before[1:]
    assert fingerprint(unknown) == other_before
    assert not (tmp_path / 'component-version').exists()
    assert not (tmp_path / 'absent').exists()


def test_namespace_state_symlink_preflight_rejects_before_any_chmod(tmp_path):
    identity = tmp_path / 'virtual-target'
    hooks = HookStateStore(tmp_path / 'state')
    directory = hooks.workspace_directory(identity)
    directory.mkdir(parents=True, mode=0o755)
    directory.chmod(0o755)
    external = tmp_path / 'external-key'
    external.write_bytes(b'x' * 32)
    external.chmod(0o644)
    (directory / 'snapshot.key').symlink_to(external)
    before = fingerprint(directory), fingerprint(external)
    with pytest.raises(OwnedWorkspaceStorageError) as caught:
        OwnedHookNamespaceStorage(hooks, identity).admit()
    assert caught.value.reason_code == 'OWNED_WORKSPACE_STORAGE_UNSAFE'
    assert (fingerprint(directory), fingerprint(external)) == before
    assert not identity.exists()


def test_hook_key_and_lock_coordinate_missing_identity_without_fake_directory(tmp_path):
    identity = tmp_path / 'installation-parent' / 'version-to-install'
    hooks = HookStateStore(tmp_path / 'state')
    key = hooks.key(identity)
    assert len(key) == 32
    assert not identity.parent.exists()
    with hooks.lock(identity) as acquired:
        assert acquired
        path = hooks.workspace_directory(identity) / 'workspace.lock'
        inode = path.stat().st_ino
        assert hooks.lock_held(identity)
    with hooks.lock(identity) as acquired:
        assert acquired
        assert path.stat().st_ino == inode
    assert not identity.parent.exists()
    assert hooks.key(identity) == key


LOCK_CHILD = '''
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX)
print('HELD', flush=True)
sys.stdin.readline()
os.close(fd)
'''


def test_existing_legacy_lock_inode_still_excludes_another_real_process(tmp_path):
    identity = tmp_path / 'virtual-supervisor'
    hooks = HookStateStore(tmp_path / 'locks')
    directory = hooks.workspace_directory(identity)
    directory.mkdir(parents=True)
    directory.chmod(0o755)
    path = directory / 'workspace.lock'
    path.write_bytes(b'0')
    path.chmod(0o644)
    inode = path.stat().st_ino
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', LOCK_CHILD, str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 10)[0], 'child did not acquire real legacy lock'
        assert child.stdout.readline().strip() == 'HELD'
        with hooks.lock(identity) as acquired:
            assert not acquired
        assert path.stat().st_ino == inode
        assert mode(path) == 0o600
        child.stdin.write('release\n')
        child.stdin.flush()
        assert child.wait(timeout=10) == 0
        with hooks.lock(identity) as acquired:
            assert acquired
        assert path.stat().st_ino == inode
        assert not identity.exists()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_dispatcher_readonly_is_absent_and_writers_do_not_create_slot_or_supervisor_targets(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime'))
    base = task_dispatcher.index().root
    assert not base.exists()
    assert task_dispatcher.index().rows() == []
    assert not base.exists()
    with task_dispatcher.execution_slot() as first:
        assert first
        with task_dispatcher.execution_slot() as second:
            assert second
            with task_dispatcher.execution_slot() as third:
                assert not third
    assert not (base / '0').exists()
    assert not (base / '1').exists()
    assert task_dispatcher.run(once=True) == 0
    assert not (base / 'supervisor').exists()


ADMIT_CHILD = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from security_runtime.hook_state import HookStateStore
from security_runtime.owned_workspace_storage import OwnedHookNamespaceStorage, OwnedWorkspaceStorageError
try:
    report = OwnedHookNamespaceStorage(HookStateStore(Path(sys.argv[2])), Path(sys.argv[3])).admit(wait_seconds=0)
    print(report['reason_code'])
except OwnedWorkspaceStorageError as error:
    print(error.reason_code)
'''


def test_admitted_context_keeps_directory_lock_until_writer_exits(tmp_path):
    identity = tmp_path / 'install-target'
    hooks = HookStateStore(tmp_path / 'state')
    storage = OwnedHookNamespaceStorage(hooks, identity)
    source = str(Path(security_runtime.__file__).resolve().parent.parent)

    def other_process():
        child = subprocess.run([sys.executable, '-I', '-B', '-c', ADMIT_CHILD,
            source, str(hooks.directory), str(identity)], capture_output=True, text=True, timeout=10)
        assert child.returncode == 0, child.stderr
        return child.stdout.strip()

    with storage.admitted() as report:
        assert report['state'] == 'PRIVATE'
        assert other_process() == 'OWNED_WORKSPACE_STORAGE_BUSY'
    assert other_process() == 'OWNED_WORKSPACE_STORAGE_PRIVATE'
    assert not identity.exists()


@pytest.mark.parametrize('error', [OSError('caller write failure'), ValueError('caller validation failure')])
def test_admitted_caller_error_propagates_unchanged_and_releases_lock(tmp_path, error):
    hooks = HookStateStore(tmp_path / 'state')
    storage = OwnedHookNamespaceStorage(hooks, tmp_path / 'opaque-identity')
    with pytest.raises(type(error)) as caught:
        with storage.admitted():
            raise error
    assert caught.value is error
    assert storage.admit(wait_seconds=0)['state'] == 'PRIVATE'
