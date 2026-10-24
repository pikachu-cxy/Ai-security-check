"""Opt-in 100000-entry store scale check, not task or scanner end-to-end."""
import json
import os
import sqlite3
import time

import pytest

from security_runtime.snapshot_contract import CaptureBatchBudget
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore


pytestmark = pytest.mark.skipif(
    os.getenv('SECURITY_RUNTIME_SNAPSHOT_SCALE_TEST') != '1',
    reason='Opt in with SECURITY_RUNTIME_SNAPSHOT_SCALE_TEST=1; entry store only, not task end-to-end',
)


def test_100000_store_entries_resume_original_cursor_and_keep_source(tmp_path):
    """Exercise real SQLite pages without creating 100000 live source files."""
    count, batch = 100_000, 256
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    directory = tmp_path.resolve() / 'private'
    binding = SnapshotBinding('scale-task', dict(host='codex', session='a' * 64),
                              'fixed-scale-source', 3)
    key = b's' * 32

    def reopen():
        store = SnapshotStore(directory, workspace_root=root, key=key,
                              batch_budget=CaptureBatchBudget(files=batch))
        assert store.quota == store.database_quota == 128_000_000
        return store

    started = time.perf_counter()
    store = reopen()
    initial = store.create(binding)
    ref, cursor = initial['ref'], initial['cursor']
    written_pages, resumed = 0, False
    for offset in range(0, count, batch):
        stop = min(offset+batch, count)
        entries = [(f'file_{index:06d}.py', f'captured={index}\n'.encode(), {'representation': 3})
                   for index in range(offset, stop)]
        header = store.append_page(ref, binding, entries, expected_cursor=cursor, cursor=str(stop))
        assert header['state'] == 'CAPTURING' and header['entry_count'] == stop
        cursor = header['cursor']
        written_pages += 1
        if written_pages == 196:
            # Continue the committed original capture with a fresh store client.
            store = reopen()
            retained = store.resume(ref, binding)
            assert retained['ref'] == ref and retained['cursor'] == cursor
            assert retained['entry_count'] == stop and stop < count
            resumed = True
    assert resumed
    sealed = store.seal(ref, binding, expected_files=count, inventory_complete=True)
    assert sealed['state'] == 'SEALED' and sealed['entry_count'] == count
    assert sealed['coverage_complete']

    seen, after, read_pages = 0, 0, 0
    while True:
        page = store.page(ref, binding, after_seq=after, limit=batch, include_content=True)
        assert page['state'] == 'SEALED'
        assert len(page['entries']) == min(batch, count-seen)
        for entry in page['entries']:
            assert entry['path'] == f'file_{seen:06d}.py'
            assert entry['seq'] == seen+1
            assert entry['content'] == f'captured={seen}\n'.encode()
            seen += 1
        after = page['next_seq']
        read_pages += 1
        if page['complete']:
            break
    assert seen == after == count
    assert written_pages == read_pages == (count+batch-1)//batch

    # Only this one live file is created. Its later bytes cannot replace the
    # object originally sealed in the entry store.
    last_name = f'file_{count-1:06d}.py'
    (root / last_name).write_bytes(b'changed-live-source\n')
    assert store.read_content(ref, binding, last_name) == f'captured={count-1}\n'.encode()
    with sqlite3.connect(store.path) as db:
        stored_count = db.execute('SELECT count(*) FROM entries WHERE ref=?', (ref,)).fetchone()[0]
    size = store.path.stat().st_size
    assert stored_count == count and size <= 128_000_000
    print(json.dumps(dict(scope='snapshot-entry-store-only', entries=stored_count,
                          write_pages=written_pages, read_pages=read_pages,
                          all_body_bytes_verified=True,
                          elapsed_seconds=round(time.perf_counter()-started, 3),
                          database_bytes=size, quota_bytes=128_000_000), sort_keys=True))
