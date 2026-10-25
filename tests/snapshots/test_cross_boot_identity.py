"""Cross-boot compatibility never replaces signed sources or kernel lock files."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest

from security_runtime import persisted_file_identity as identities
from security_runtime.snapshot_store import SnapshotStoreError
from security_runtime.tasks import snapshot_page_guard as guards
from security_runtime.tasks.diagnostics import capacity_failure
from test_snapshot_store import KEY, sample, store
from test_closeout_queue import setup, private_dispatcher
from test_task_security import service


@pytest.fixture
def previous_mount(sample, monkeypatch, request):
    root, directory, binding = sample
    original_stat = Path.stat
    previous_device = original_stat(root).st_dev + 1000
    private_device = previous_device + (1000 if getattr(request, 'param', None) == 'cross_volume' else 0)
    with guards.page_guard(directory.parent, create=True):
        pass
    hint = directory.parent/'snapshot-pages.gc.identity'
    hint.write_text(json.dumps(dict(json.loads(hint.read_text()), device=private_device)))
    def previous_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == root or path == directory or path.is_relative_to(directory):
            values = {key:getattr(result,key) for key in dir(result) if key.startswith('st_')}
            return SimpleNamespace(**dict(values, st_dev=previous_device if path == root else private_device))
        return result
    with monkeypatch.context() as mounted:
        mounted.setattr(Path, 'stat', previous_stat)
        old = store(sample)
        header = old.create(binding)
        old.append_page(header['ref'], binding, [('one.py', b'original')],
                        expected_cursor=None, cursor='one')
        header = old.seal(header['ref'], binding, expected_files=1, inventory_complete=True)
    monkeypatch.setattr(identities, 'boot_time', lambda:time.time()+60)
    return header


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
def test_reopen_retains_original_signed_namespace_and_bytes(sample, previous_mount):
    _, directory, binding = sample
    before = {p.name:p.read_bytes() for p in directory.iterdir()}
    reopened = store(sample)
    assert reopened.resume(previous_mount['ref'], binding) == previous_mount
    assert reopened.strict_header(previous_mount['ref'], binding) == previous_mount
    assert reopened.read_content(previous_mount['ref'], binding, 'one.py') == b'original'
    reopened.validate_contents()
    assert before == {p.name:p.read_bytes() for p in directory.iterdir()}
    second = replace(binding, task_ref='task-2', source_ref='second-fixed-source')
    assert reopened.create(second)['binding']['root_identity'] == previous_mount['binding']['root_identity']
    assert reopened.resume(previous_mount['ref'], binding) == previous_mount


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
@pytest.mark.parametrize('previous_mount', ['cross_volume'], indirect=True)
def test_different_private_volume_uses_hint_only_with_exact_store_mac(sample, previous_mount):
    _, directory, binding = sample
    reopened = store(sample)
    assert reopened.read_content(previous_mount['ref'], binding, 'one.py') == b'original'
    marker = directory.parent/'snapshot-pages.gc.identity'
    value = json.loads(marker.read_text())
    marker.write_text(json.dumps(dict(value, device=value['device']+1)))
    with pytest.raises(SnapshotStoreError, match='SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH'):
        store(sample).resume(previous_mount['ref'], binding)


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
@pytest.mark.parametrize('invalid', ['key', 'marker', 'root', 'storage', 'boot'])
def test_remount_does_not_adopt_invalid_history(sample, previous_mount, monkeypatch, tmp_path, invalid):
    root, directory, binding = sample
    arguments = {}
    if invalid == 'key':
        arguments['key'] = b'z'*32
    elif invalid == 'marker':
        (directory/'store.identity').write_bytes(b'0'*64)
    elif invalid == 'root':
        root.rename(root.with_name('original-source'))
        root.mkdir()
    elif invalid == 'storage':
        directory.rename(directory.with_name('original-private'))
        import shutil
        shutil.copytree(directory.with_name('original-private'), directory)
        directory.chmod(0o700)
    else:
        monkeypatch.setattr(identities, 'boot_time', lambda:None)
    before = {p.name:p.read_bytes() for p in directory.iterdir()}
    from security_runtime.snapshot_store import SnapshotStore
    candidate = SnapshotStore(directory, workspace_root=root, key=arguments.get('key', KEY))
    with pytest.raises(SnapshotStoreError):
        candidate.resume(previous_mount['ref'], binding)
    assert before == {p.name:p.read_bytes() for p in directory.iterdir()}


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
def test_remounted_guard_retains_same_lock_domain_and_readonly_metadata(tmp_path, monkeypatch):
    directory = tmp_path/'private'
    with guards.page_guard(directory, create=True):
        pass
    marker = directory/'snapshot-pages.gc.identity'
    value = json.loads(marker.read_text())
    marker.write_text(json.dumps(dict(value, device=value['device']+1000)))
    before = {p.name:(p.stat().st_ino,p.read_bytes()) for p in directory.iterdir()}
    monkeypatch.setattr(identities, 'boot_time', lambda:time.time()+60)
    def competing():
        with guards.page_guard(directory, wait_seconds=0):
            pytest.fail('An exclusive lock must exclude a second thread')
    with ThreadPoolExecutor(max_workers=1) as pool:
        with guards.page_guard(directory, exclusive=True):
            with pytest.raises(SnapshotStoreError, match='SNAPSHOT_PAGE_STORE_BUSY'):
                pool.submit(competing).result(timeout=3)
    with guards.page_guard(directory):
        pass
    assert before == {p.name:(p.stat().st_ino,p.read_bytes()) for p in directory.iterdir()}
    lock = directory/'snapshot-pages.gc.lock'
    lock.rename(directory/'original-lock')
    lock.write_bytes(b'0')
    lock.chmod(0o600)
    with pytest.raises(SnapshotStoreError, match='SNAPSHOT_GC_GUARD_UNAVAILABLE'):
        with guards.page_guard(directory):
            pytest.fail('Reboot proof must not adopt a replacement inode')


@pytest.mark.parametrize('case', ['missing_boot', 'recent_anchor', 'new_inode', 'different_owner'])
def test_identity_without_complete_boot_proof_remains_rejected(monkeypatch, case):
    monkeypatch.setattr(identities.sys, 'platform', 'darwin')
    monkeypatch.setattr(identities, 'boot_time', lambda:100)
    item = SimpleNamespace(st_dev=2, st_ino=42, st_uid=os.getuid(), st_birthtime=10, st_mtime=20)
    anchor = SimpleNamespace(**vars(item))
    saved = [1,42]
    if case == 'missing_boot':
        monkeypatch.setattr(identities, 'boot_time', lambda:None)
    elif case == 'recent_anchor':
        anchor.st_mtime = 101
    elif case == 'new_inode':
        item.st_ino = 43
    else:
        item.st_uid += 1
    assert not identities.historical_identity_matches(saved,item,anchor=anchor)


@pytest.mark.parametrize('reason,status', [('SNAPSHOT_GC_GUARD_UNAVAILABLE','INCONCLUSIVE'),
    ('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH','INCONCLUSIVE'), ('SNAPSHOT_PAGE_STORE_BUSY','BUSY')])
def test_snapshot_diagnostic_retains_specific_reason(reason, status):
    response = capacity_failure(SnapshotStoreError(reason))
    assert response['status'] == status and response['reason_code'] == reason
    assert not response['baseline_recreated'] and response['prior_committed_evidence_preserved']


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
def test_original_scanner_directory_reopens_but_modified_content_is_rejected(service, monkeypatch):
    task, root, ref = setup(service)
    from security_runtime.tasks.baseline_inputs import BaselineInputs
    inputs = BaselineInputs(task.hooks, root)
    original = task.load(root, ref)
    pointer = original['before_scan_inputs']['ref']
    with inputs.transaction() as db:
        row = inputs._get(db, pointer)
        inputs._put(db, pointer, dict(row,
            directory_identity=[row['directory_identity'][0]+1000,row['directory_identity'][1]]))
    monkeypatch.setattr(identities, 'boot_time', lambda:time.time()+60)
    before = inputs.path.read_bytes()
    directory = inputs.open(pointer)
    assert before == inputs.path.read_bytes()
    assert task.load(root, ref)['baseline'] == original['baseline']
    (directory/'routes.py').chmod(0o600)
    (directory/'routes.py').write_text('tampered private input\n')
    with pytest.raises(ValueError, match='Queued input modified'):
        inputs.open(pointer)


@pytest.mark.skipif(sys.platform != 'darwin', reason='Historical mount IDs change on macOS')
def test_authenticated_before_and_end_context_keep_old_logical_root_identity(tmp_path, monkeypatch):
    import copy
    import hashlib
    import hmac
    from test_frozen_end_context_producer import _new, _finish, _preserved
    from security_runtime.tasks import frozen_body_context as before
    from security_runtime.tasks import frozen_end_context as after
    sample = _new(tmp_path)
    end = _finish(sample)
    monkeypatch.setattr(identities, 'boot_time', lambda:time.time()+60)
    for packet, verify, error, key_function in (
            (sample.baseline[before.CONTEXT_FIELD], before.verify_context, before.FrozenBodyContextUnavailable, before._key),
            (end[after.END_CONTEXT_FIELD], after.verify_end_context, after.FrozenEndBodyContextUnavailable, after._key)):
        legacy = copy.deepcopy(packet)
        legacy['payload']['root_identity'][0] += 1000
        def sign():
            legacy['mac'] = hmac.new(key_function(sample.state.hooks, sample.root),
                before._encode(legacy['payload']), hashlib.sha256).hexdigest()
        sign()
        assert verify(sample.state.hooks, sample.root, legacy, task_ref=sample.ref,
            owner=sample.owner, now=lambda:sample.clock[0]) == legacy['payload']
        legacy['mac'] = '0'*64
        with pytest.raises(error):
            verify(sample.state.hooks, sample.root, legacy, now=lambda:sample.clock[0])
        legacy['payload']['root_identity'][1] += 1
        sign()
        with pytest.raises(error, match='ROOT_MISMATCH'):
            verify(sample.state.hooks, sample.root, legacy, now=lambda:sample.clock[0])
    _preserved(sample)
