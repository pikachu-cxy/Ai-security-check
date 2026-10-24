"""Root descriptors bind observations even across temporary path replacement."""
from contextlib import contextmanager
import hashlib
import hmac
import inspect
import os
from pathlib import Path
import time

import pytest

from security_runtime.hook_state import HookStateStore, identity
import security_runtime.product_epoch_capture as capture
from security_runtime.product_epoch_hooks import ProductEpochHooks
from security_runtime.product_epoch_service import ProductEpochService


OWNER = dict(host='codex', session=identity('root-identity-fixture'))
pytestmark = pytest.mark.skipif(not capture.platform_supported(), reason='Requires descriptor observations')


@pytest.fixture
def trees(tmp_path):
    root, other = tmp_path.resolve()/'source', tmp_path.resolve()/'replacement'
    for folder, raw in ((root, b'value = 1\n'), (other, b'value = 2\n')):
        (folder/'dir').mkdir(parents=True)
        (folder/'dir'/'source.py').write_bytes(raw)
    hooks = HookStateStore(tmp_path.resolve()/'private')
    return root, other, hooks


@contextmanager
def substituted(root, other, *, graft_original_child=False):
    held, spare = root.with_name('source-held'), other.with_name('replacement-child-held')
    if graft_original_child:
        (other/'dir').rename(spare)
    root.rename(held)
    other.rename(root)
    if graft_original_child:
        (held/'dir').rename(root/'dir')
    try:
        yield
    finally:
        if graft_original_child:
            (root/'dir').rename(held/'dir')
        root.rename(other)
        held.rename(root)
        if graft_original_child:
            spare.rename(other/'dir')


def expected_argument(callable_, root_identity):
    # Keep the same real-IO reproduction runnable against the pre-fix API.
    return ({'expected_root_identity': root_identity}
            if 'expected_root_identity' in inspect.signature(callable_).parameters else {})


def finish(service):
    result = service.ensure(OWNER)
    for _ in range(64):
        if result['state'] == 'SEALED':
            return result
        result = service.step(OWNER)
    pytest.fail('Finite fixture did not seal')


def swap_hash_parent(monkeypatch, root, other):
    original = capture.open_directory
    other_identity = capture.identity((other/'dir').stat())

    def intercepted(folder, relative='', expected=None, **kwargs):
        if Path(folder) == root and relative == 'dir' and expected in (None, other_identity):
            with substituted(root, other):
                return original(folder, relative, expected, **kwargs)
        return original(folder, relative, expected, **kwargs)

    monkeypatch.setattr(capture, 'open_directory', intercepted)


def test_normal_nested_binary_observation_keeps_original_hash(trees):
    root, _, hooks = trees
    original_identity = capture.identity(root.stat())
    reader = capture.StableHashReader(root, hooks.key(root), 'dir/source.py',
        **expected_argument(capture.StableHashReader, original_identity))
    try:
        result = reader.advance(1024, time.monotonic()+1)
        assert result['state'] == 'OBSERVED'
        assert result['hash'] == hmac.new(hooks.key(root), b'hook-file-v1value = 1\n', hashlib.sha256).hexdigest()
    finally:
        reader.close()


def test_product_epoch_rejects_temporarily_substituted_root_hash(trees, monkeypatch):
    root, other, hooks = trees
    service = ProductEpochService(hooks, root)
    original = service.ensure(OWNER)
    swap_hash_parent(monkeypatch, root, other)
    result = finish(service)
    row = service.lookup(original['epoch_ref'], ['dir/source.py'])['results'][0]
    replacement_hash = hmac.new(hooks.key(root), b'hook-file-v1value = 2\n', hashlib.sha256).hexdigest()
    assert row.get('hash') != replacement_hash, 'Replacement source was accepted as the original epoch'
    assert row['status'] == 'GAP' and result['counts']['observed'] == 0
    assert (root/'dir'/'source.py').read_bytes() == b'value = 1\n'
    service.close()


def test_hook_compare_cannot_match_a_temporarily_substituted_root(trees, monkeypatch):
    root, other, hooks = trees
    service = ProductEpochService(hooks, root)
    finish(service)
    adapter = ProductEpochHooks(hooks, root, now=time.time)
    result = dict(workspace_id=identity(os.path.normcase(str(root))), session_id=identity('s'), event='SESSION_START')
    assert adapter.start(result, 'codex', 's')
    state, invalid = hooks.load(hooks.path(root, 'codex', 's'))
    assert not invalid
    (root/'dir'/'source.py').write_bytes(b'value = 2\n')
    (other/'dir'/'source.py').write_bytes(b'value = 1\n')
    swap_hash_parent(monkeypatch, root, other)
    _, compared = adapter.compare(state, 'codex', 's', ['dir/source.py'], False)
    assert compared['product_epoch_comparison_reason'] != 'OBSERVED_HASH_MATCH'
    assert compared['product_epoch_unavailable_path_count'] == 1
    assert compared['product_epoch_comparison_complete'] is False
    service.close()


def test_relative_walk_uses_opened_root_descriptor_after_root_is_renamed(trees, monkeypatch):
    root, other, _ = trees
    original_open, activated = capture.os.open, []
    context = substituted(root, other)
    original_identity = capture.identity(root.stat())

    def intercepted(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if Path(path) == root and 'dir_fd' not in kwargs and not activated:
            context.__enter__()
            activated.append(True)
        return fd

    monkeypatch.setattr(capture.os, 'open', intercepted)
    monkeypatch.setattr(capture, 'platform_supported', lambda: True)
    directory = file_fd = None
    try:
        directory = capture.open_directory(root, 'dir',
            **expected_argument(capture.open_directory, original_identity))
        file_fd = original_open('source.py', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        assert os.read(file_fd, 100) == b'value = 1\n'
        assert (root/'dir'/'source.py').read_bytes() == b'value = 2\n'
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory is not None:
            os.close(directory)
        if activated:
            context.__exit__(None, None, None)


def test_directory_verification_rejects_foreign_root_with_original_child_inode(trees, monkeypatch):
    root, other, _ = trees
    root_identity, child_identity = capture.identity(root.stat()), capture.identity((root/'dir').stat())
    observation = capture.DirectoryObservation(root, 'dir', child_identity,
        **expected_argument(capture.DirectoryObservation, root_identity))
    original = capture.open_directory

    def intercepted(folder, relative='', expected=None, **kwargs):
        if Path(folder) == root and relative == 'dir':
            with substituted(root, other, graft_original_child=True):
                return original(folder, relative, expected, **kwargs)
        return original(folder, relative, expected, **kwargs)

    monkeypatch.setattr(capture, 'open_directory', intercepted)
    try:
        with pytest.raises(capture.ObservationError, match='ROOT_CHANGED'):
            observation.verify()
    finally:
        observation.close()


def test_enumeration_rejects_foreign_root_even_when_child_identity_matches(trees, monkeypatch):
    root, other, hooks = trees
    service = ProductEpochService(hooks, root)
    service.ensure(OWNER)
    original = capture.open_directory

    def intercepted(folder, relative='', expected=None, **kwargs):
        if Path(folder) == root and relative == 'dir':
            with substituted(root, other, graft_original_child=True):
                return original(folder, relative, expected, **kwargs)
        return original(folder, relative, expected, **kwargs)

    monkeypatch.setattr(capture, 'open_directory', intercepted)
    result = finish(service)
    assert result['counts']['gaps'] >= 1
    assert result['counts']['members'] == result['counts']['observed'] == 0
    service.close()
