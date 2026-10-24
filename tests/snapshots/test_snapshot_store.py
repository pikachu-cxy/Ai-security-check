"""Paged immutable storage tests; no scanners, live capture or installation."""
from dataclasses import replace
import os
import sqlite3

import pytest

from security_runtime.snapshot_contract import CaptureBatchBudget, SourceConsistency
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError


KEY = b'k' * 32
OWNER = dict(host='codex', session='a' * 64)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    directory = tmp_path / 'private'
    binding = SnapshotBinding('task-1', OWNER, 'immutable-source-1', 3)
    return root, directory, binding


def store(sample, **kwargs):
    root, directory, _ = sample
    return SnapshotStore(directory, workspace_root=root, key=KEY, **kwargs)


def test_1001_entries_cross_pages_resume_and_remain_original(sample):
    root, _, binding = sample
    budget = CaptureBatchBudget(files=128)
    first = store(sample, batch_budget=budget)
    header = first.create(binding)
    ref, cursor = header['ref'], None
    for offset in range(0, 1001, 128):
        entries = [(f'file_{index:04}.py', f'value = {index}\n'.encode(), {'raw_hash': str(index)})
                   for index in range(offset, min(offset+128, 1001))]
        next_cursor = str(offset+len(entries))
        current = store(sample, batch_budget=budget)  # Reopen, never reconstruct the source.
        assert current.resume(ref, binding)['cursor'] == cursor
        header = current.append_page(ref, binding, entries,
                                     expected_cursor=cursor, cursor=next_cursor)
        cursor = next_cursor
    header = current.seal(ref, binding, expected_files=1001, inventory_complete=True)
    assert header['entry_count'] == 1001 and header['coverage_complete']
    assert header['binding']['consistency'] == 'OBSERVED_ONLY'
    assert not header['binding']['captured_before_edit']
    names, after = [], 0
    while True:
        page = current.page(ref, binding, after_seq=after, limit=128)
        names.extend(entry['path'] for entry in page['entries'])
        after = page['next_seq']
        if page['complete']:
            break
    assert names == [f'file_{index:04}.py' for index in range(1001)]
    (root / names[-1]).write_bytes(b'changed live source\n')
    assert current.read_content(ref, binding, names[-1]) == b'value = 1000\n'


def test_page_commit_is_idempotent_and_different_replay_is_rejected(sample):
    _, _, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    entries = [('one.py', b'old', {'representation': 3})]
    first = current.append_page(ref, binding, entries, expected_cursor=None, cursor='page-1')
    assert current.append_page(ref, binding, entries, expected_cursor=None, cursor='page-1') == first
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CURSOR_CONFLICT$'):
        current.append_page(ref, binding, [('one.py', b'other')], expected_cursor=None, cursor='page-1')
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_ENTRY_IMMUTABLE$'):
        current.append_page(ref, binding, [('one.py', b'other')], expected_cursor='page-1', cursor='page-2')
    assert current.read_content(ref, binding, 'one.py') == b'old'


@pytest.mark.parametrize('changes', [dict(source_ref='another-source'),
    dict(owner=dict(host='codex', session='b' * 64)), dict(representation_version=2),
    dict(consistency=SourceConsistency.FROZEN_SOURCE), dict(captured_before_edit=True)])
def test_original_binding_cannot_be_replaced_or_readopted(sample, changes):
    _, _, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    wrong = replace(binding, **changes)
    for operation in (lambda: current.resume(ref, wrong), lambda: current.create(wrong),
                      lambda: current.append_page(ref, wrong, [('one.py', b'x')],
                                                   expected_cursor=None, cursor='one')):
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_BINDING_MISMATCH$'):
            operation()
    assert current.resume(ref, binding)['entry_count'] == 0


def test_key_and_root_boundaries_do_not_replace_original_store(sample, tmp_path):
    root, directory, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    another = tmp_path / 'another-source'
    another.mkdir()
    for invalid in (SnapshotStore(directory, workspace_root=root, key=b'z' * 32),
                    SnapshotStore(directory, workspace_root=another, key=KEY)):
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH$'):
            invalid.resume(ref, binding)
    assert current.resume(ref, binding)['binding']['source_ref'] == binding.source_ref


def test_sealed_snapshot_is_immutable_and_seal_is_idempotent(sample):
    _, _, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'old')], expected_cursor=None, cursor='one')
    sealed = current.seal(ref, binding, expected_files=1, inventory_complete=True)
    assert current.seal(ref, binding, expected_files=1, inventory_complete=True) == sealed
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_IMMUTABLE$'):
        current.append_page(ref, binding, [('two.py', b'new')], expected_cursor='one', cursor='two')
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_IMMUTABLE$'):
        current.seal(ref, binding, expected_files=2, inventory_complete=False)


def test_capacity_wait_retains_prior_page_and_resumes_original_cursor(sample):
    _, _, binding = sample
    current = store(sample, max_storage_bytes=80_000)
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'old')], expected_cursor=None, cursor='one')
    entries = [('two.py', b'x' * 100_000)]
    waiting = current.append_page(ref, binding, entries, expected_cursor='one', cursor='two')
    assert waiting['state'] == 'WAITING_CAPACITY' and waiting['cursor'] == 'one'
    assert waiting['entry_count'] == 1 and waiting['required_storage_bytes'] > 80_000
    assert current.read_content(ref, binding, 'one.py') == b'old'
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_WAITING_CAPACITY$'):
        current.seal(ref, binding, expected_files=1, inventory_complete=True)
    resumed = store(sample, max_storage_bytes=300_000)
    header = resumed.append_page(ref, binding, entries, expected_cursor='one', cursor='two')
    assert header['state'] == 'CAPTURING' and header['entry_count'] == 2
    assert resumed.seal(ref, binding, expected_files=2, inventory_complete=True)['coverage_complete']


def test_objects_are_shared_without_sharing_task_authority(sample):
    _, _, binding = sample
    current = store(sample)
    first = current.create(binding)['ref']
    second_binding = replace(binding, task_ref='task-2', owner=dict(host='cursor', session='b' * 64))
    second = current.create(second_binding)['ref']
    for ref, owner in ((first, binding), (second, second_binding)):
        current.append_page(ref, owner, [('one.py', b'shared')], expected_cursor=None, cursor='one')
    with sqlite3.connect(current.path) as db:
        assert db.execute('SELECT count(*) FROM objects').fetchone()[0] == 1
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_BINDING_MISMATCH$'):
        current.read_content(first, second_binding, 'one.py')
    assert current.read_content(second, second_binding, 'one.py') == b'shared'


def test_missing_original_store_never_recreates_or_reads_current_source(sample):
    root, directory, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'original')], expected_cursor=None, cursor='one')
    current.path.unlink()
    (root / 'one.py').write_bytes(b'current must not become original')
    for operation in (lambda: current.resume(ref, binding), lambda: current.create(binding)):
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
            operation()
    assert not current.path.exists() and (directory / 'store.identity').exists()


def test_bounded_pages_fail_atomically_and_unknown_inventory_stays_partial(sample):
    _, _, binding = sample
    current = store(sample, batch_budget=CaptureBatchBudget(files=2, bytes=1024))
    ref = current.create(binding)['ref']
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_FILE_BUDGET$'):
        current.append_page(ref, binding, [(str(n), b'x') for n in range(3)], expected_cursor=None, cursor='one')
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_BYTE_BUDGET$'):
        current.append_page(ref, binding, [('large.py', b'x' * 1025)], expected_cursor=None, cursor='one')
    assert current.resume(ref, binding)['entry_count'] == 0
    current.append_page(ref, binding, [('one.py', b'x')], expected_cursor=None, cursor='one')
    sealed = current.seal(ref, binding, expected_files=None, inventory_complete=False, gap_count=1)
    assert not sealed['coverage_complete'] and sealed['gap_count'] == 1


def test_sqlite_page_quota_rolls_back_only_uncommitted_page(sample):
    _, _, binding = sample
    current = store(sample, max_database_bytes=65_536)
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'old')], expected_cursor=None, cursor='one')
    entries = [('two.py', b'x' * 100_000)]
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_WAITING_CAPACITY$'):
        current.append_page(ref, binding, entries, expected_cursor='one', cursor='two')
    header = current.resume(ref, binding)
    assert header['entry_count'] == 1 and header['cursor'] == 'one'
    assert current.read_content(ref, binding, 'one.py') == b'old'
    resumed = store(sample)
    assert resumed.append_page(ref, binding, entries, expected_cursor='one', cursor='two')['entry_count'] == 2


def test_damaged_content_is_not_healed_by_deduplication(sample):
    _, _, binding = sample
    current = store(sample)
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'old')], expected_cursor=None, cursor='one')
    with sqlite3.connect(current.path) as db:
        db.execute('UPDATE objects SET body=?', (b'bad',))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        current.read_content(ref, binding, 'one.py')
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        current.append_page(ref, binding, [('two.py', b'old')], expected_cursor='one', cursor='two')
    assert current.resume(ref, binding)['entry_count'] == 1


def test_deleted_entry_is_detected_and_readonly_missing_ref_creates_nothing(sample):
    _, directory, binding = sample
    current = store(sample)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        current.resume('ws2-' + 'b' * 32, binding)
    assert not directory.exists()
    ref = current.create(binding)['ref']
    current.append_page(ref, binding, [('one.py', b'old')], expected_cursor=None, cursor='one')
    with sqlite3.connect(current.path) as db:
        db.execute('DELETE FROM entries')
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        current.page(ref, binding)


def test_reader_page_uses_its_header_boundary_during_concurrent_append(sample, monkeypatch):
    _, _, binding = sample
    reader, writer = store(sample), store(sample)
    ref = reader.create(binding)['ref']
    writer.append_page(ref, binding, [('one.py', b'one')], expected_cursor=None, cursor='one')
    original = reader._get

    def append_after_header(db, reference, owner):
        header = original(db, reference, owner)
        writer.append_page(ref, binding, [('two.py', b'two')], expected_cursor='one', cursor='two')
        return header

    monkeypatch.setattr(reader, '_get', append_after_header)
    page = reader.page(ref, binding)
    assert [entry['path'] for entry in page['entries']] == ['one.py']
    assert page['next_seq'] == 1 and page['complete']
    assert writer.resume(ref, binding)['entry_count'] == 2


@pytest.mark.skipif(os.name == 'nt', reason='POSIX private mode/link assertion')
def test_private_directory_permissions_and_links_are_rejected(sample, tmp_path):
    root, directory, _ = sample
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)  # Exercise public permissions under a private process umask too.
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PRIVATE_STORAGE_UNAVAILABLE$'):
        store(sample).create(sample[2])
    directory.rmdir()
    target = tmp_path / 'linked-private'
    target.mkdir(mode=0o700)
    directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        SnapshotStore(directory, workspace_root=root, key=KEY)
