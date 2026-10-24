"""Frozen body reads stay bounded and avoid a connection for every file."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from security_runtime.snapshot_contract import CaptureBatchBudget
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError, _encode
from security_runtime.tasks.snapshot_pages import pack, unpack


KEY = b'k' * 32
OWNER = dict(host='codex', session='a' * 64)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    binding = SnapshotBinding('body-pages', OWNER, 'original-source', 3)
    current = SnapshotStore(tmp_path.resolve() / 'private', workspace_root=root, key=KEY)
    return current, binding


def capture(current, binding, entries):
    ref = current.create(binding)['ref']
    cursor = None
    for offset in range(0, len(entries), 256):
        page = entries[offset:offset + 256]
        next_cursor = str(offset + len(page))
        current.append_page(ref, binding, page, expected_cursor=cursor, cursor=next_cursor)
        cursor = next_cursor
    current.seal(ref, binding, expected_files=len(entries), inventory_complete=True)
    return ref


def test_body_pages_use_one_connection_per_page_and_keep_original_bytes(sample, monkeypatch):
    current, binding = sample
    entries = [(f'file-{index}.py', f'original={index}\n'.encode()) for index in range(513)]
    ref = capture(current, binding, entries)
    (current.root / entries[-1][0]).write_bytes(b'new live contents')
    opened, original = [], current._db

    @contextmanager
    def counted(**kwargs):
        opened.append(kwargs)
        with original(**kwargs) as db:
            yield db

    monkeypatch.setattr(current, '_db', counted)
    recovered, cursor = [], 0
    while True:
        page = current.page(ref, binding, after_seq=cursor, include_content=True)
        recovered.extend((entry['path'], entry['content']) for entry in page['entries'])
        cursor = page['next_seq']
        if page['complete']:
            break
    assert recovered == entries
    assert len(opened) == 3


def test_body_read_byte_budget_advances_only_returned_entries(sample):
    current, binding = sample
    entries = [(f'file-{index}.py', bytes([index]) * 700) for index in range(3)]
    ref = capture(current, binding, entries)
    reader = SnapshotStore(current.directory, workspace_root=current.root, key=KEY,
                           batch_budget=CaptureBatchBudget(bytes=1000))
    cursor, restored = 0, []
    for expected in range(1, 4):
        page = reader.page(ref, binding, after_seq=cursor, include_content=True)
        assert page['next_seq'] == expected
        assert len(page['entries']) == 1
        assert page['complete'] is (expected == 3)
        assert sum(len(row['content']) + len(_encode({k:v for k,v in row.items() if k != 'content'}))
                   for row in page['entries']) <= 1000
        restored.extend((row['path'], row['content']) for row in page['entries'])
        cursor = page['next_seq']
    assert restored == entries
    # The original metadata-only page API retains its file-count behavior.
    metadata = reader.page(ref, binding)
    assert metadata['complete'] and len(metadata['entries']) == 3
    assert all('content' not in entry for entry in metadata['entries'])
    tiny = SnapshotStore(current.directory, workspace_root=current.root, key=KEY,
                         batch_budget=CaptureBatchBudget(bytes=400))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_BYTE_BUDGET$'):
        tiny.page(ref, binding, include_content=True)


def test_corrupt_body_cannot_return_a_successful_partial_body_page(sample):
    current, binding = sample
    ref = capture(current, binding, [('a.py', b'first'), ('b.py', b'second')])
    with sqlite3.connect(current.path) as db:
        db.execute('UPDATE objects SET body=? WHERE hash=?',
                   (b'broken', hashlib.sha256(b'second').hexdigest()))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_CONTENT_UNAVAILABLE$'):
        current.page(ref, binding, include_content=True)
    assert current.read_content(ref, binding, 'a.py') == b'first'


def test_body_at_original_write_budget_boundary_remains_readable(sample):
    current, binding = sample
    current = SnapshotStore(current.directory, workspace_root=current.root, key=KEY,
                            batch_budget=CaptureBatchBudget(bytes=1000))
    body = b'x' * 884
    ref = capture(current, binding, [('a.py', body)])
    page = current.page(ref, binding, include_content=True)
    assert page['complete'] and page['entries'][0]['content'] == body
    item = {key:value for key,value in page['entries'][0].items() if key != 'content'}
    assert len(body) + len(_encode(item)) > 1000
    payload = {key:value for key,value in item.items() if key not in {'ref', 'seq'}}
    assert len(body) + len(_encode(payload)) == 1000


def test_body_read_groups_across_original_write_pages_without_skipping(sample):
    current, binding = sample
    writer = SnapshotStore(current.directory, workspace_root=current.root, key=KEY,
                           batch_budget=CaptureBatchBudget(bytes=1000))
    ref, cursor = writer.create(binding)['ref'], None
    original = [(f'{index}.py', bytes([index]) * 700) for index in range(3)]
    for index, entry in enumerate(original, 1):
        writer.append_page(ref, binding, [entry], expected_cursor=cursor, cursor=str(index))
        cursor = str(index)
    writer.seal(ref, binding, expected_files=3, inventory_complete=True)
    reader = SnapshotStore(current.directory, workspace_root=current.root, key=KEY,
                           batch_budget=CaptureBatchBudget(bytes=1800))
    first = reader.page(ref, binding, include_content=True)
    assert first['next_seq'] == 2 and not first['complete']
    last = reader.page(ref, binding, after_seq=first['next_seq'], include_content=True)
    assert last['next_seq'] == 3 and last['complete']
    assert [(row['path'], row['content']) for row in first['entries'] + last['entries']] == original


def test_body_page_rejects_foreign_binding_and_invalid_request_without_creation(sample):
    current, binding = sample
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_REQUEST_INVALID$'):
        current.page('missing', binding, include_content='yes')
    assert not current.directory.exists()
    ref = capture(current, binding, [('a.py', b'original')])
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_BINDING_MISMATCH$'):
        current.page(ref, replace(binding, owner=dict(host='codex', session='b' * 64)),
                     include_content=True)


def test_compatibility_unpack_1001_files_opens_by_page_and_keeps_exact_projection(tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    state = SimpleNamespace(path=tmp_path.resolve() / 'private' / 'tasks.db', root=root, key=lambda:KEY)
    names = [f'file-{index:04}.py' for index in range(1001)]
    baseline = dict(hashes={name:hashlib.sha256(name.encode()).hexdigest() for name in names},
                    texts={name:'original ' + name for name in names}, inventory=names)
    record = dict(task_ref='ts1-' + 'a' * 32, task_owner=OWNER,
                  capture_policy='BATCHED_FILES_V1', baseline=baseline)
    packed = pack(state, record)
    opened, original = [], SnapshotStore._db

    @contextmanager
    def counted(self, **kwargs):
        opened.append(kwargs)
        with original(self, **kwargs) as db:
            yield db

    monkeypatch.setattr(SnapshotStore, '_db', counted)
    restored = unpack(state, packed)
    for field, value in baseline.items():
        assert restored['baseline'][field] == value
    assert len(opened) == 5  # One authenticated header and four body pages.
    assert restored['baseline']['inventory'][-1] == names[-1]
