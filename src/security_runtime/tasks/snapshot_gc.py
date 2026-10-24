"""Bounded task-page collection from authenticated heads and queue pins.

Old/unmanaged pages and unfinished captures are retained. This entry is a write
operation used by task saves; diagnostics and read-only calls never invoke it.
"""
from contextlib import closing
import sqlite3

from ..hook_state import no_links
from ..snapshot_store import SnapshotStoreError
from .snapshot_page_guard import page_guard
from .snapshot_pages import GC_POLICY, POINTER, _binding, _store


def _pointers(value):
    stack, visited = [value], 0
    while stack:
        current = stack.pop()
        visited += 1
        if visited > 250_000:
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_BUDGET')
        if isinstance(current, dict):
            if POINTER in current:
                pointer = current[POINTER]
                if (not isinstance(pointer, dict) or set(pointer) != {'ref', 'source'}
                        or not isinstance(pointer['source'], str) or len(pointer['source']) != 64):
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                yield pointer
            stack.extend(v for key, v in current.items() if key != POINTER)
        elif isinstance(current, list):
            stack.extend(current)


def _protect(store, record, references):
    for pointer in _pointers(record):
        matched = False
        for field in ('baseline', 'end'):
            try:
                header = store.resume(pointer['ref'], _binding(record, field, pointer['source']))
            except SnapshotStoreError as exc:
                if exc.reason_code != 'SNAPSHOT_BINDING_MISMATCH':
                    raise
            else:
                if header['state'] != 'SEALED':
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                matched = True
                break
        if not matched:
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
        references.add(pointer['ref'])


def collect_pages(state, *, prune=False, max_captures=32):
    from .closeout_queue import CloseoutQueue
    from .security_state import MAX_HISTORY_RECORDS, TTL
    directory = state.path.parent
    no_links(state.path)
    page_path = directory/'snapshot-pages'/'snapshots.db'
    no_links(page_path)
    if not state.path.exists() or not page_path.exists():
        return dict(collected_captures=0, released_logical_bytes=0, has_more=False)
    # A collector never invents a missing guard for previously published pages.
    if not (directory/'snapshot-pages.gc.lock').exists():
        # Before the first managed task, all prior pages are legacy and retained.
        legacy_store = _store(state)
        with legacy_store._db() as pages:
            rows = pages.execute('SELECT data,mac FROM captures').fetchall()
            if any(legacy_store._decode(*row)['binding'].get('retention_domain')
                   == 'TASK_PAGES_GC_V1' for row in rows):
                raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
        return dict(collected_captures=0, released_logical_bytes=0, has_more=False)
    with page_guard(directory, exclusive=True):
        store, references = _store(state), set()
        with closing(sqlite3.connect(state.path, timeout=2)) as db, db:
            db.execute('PRAGMA secure_delete=ON')
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT data,mac FROM security_tasks LIMIT ?',
                              (MAX_HISTORY_RECORDS+1,)).fetchall()
            if len(rows) > MAX_HISTORY_RECORDS:
                raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_BUDGET')
            heads = [state.head(row) for row in rows]
            for record in heads:
                _protect(store, record, references)
            queue_refs = set()
            for row in CloseoutQueue(state.hooks, state.root, now=state.now).rows():
                if row.get('key') == '$worker':
                    continue  # Dispatcher lease; it contains no source pointers.
                if row.get('contract') != 'task-closeout-queue-v1':
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                # Running work remains pinned even if its initial queue TTL elapsed.
                if row.get('state') != 'RUNNING' and row.get('expires_at', float('inf')) <= state.now():
                    continue
                baseline_pin = row.get('baseline_pages', {})
                if row.get('snapshot_capture_policy') == GC_POLICY and POINTER not in baseline_pin:
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                surrogate = dict(task_ref=row['task_ref'], task_owner=row['owner'],
                    contract=row.get('snapshot_task_contract'),
                    capture_policy=row.get('snapshot_capture_policy', 'BATCHED_FILES_V1'),
                    baseline=dict(redaction_version=row['end'].get('redaction_version', 1), **baseline_pin),
                    end=row['end'])
                _protect(store, surrogate, queue_refs)
            if prune:
                state._retain_pending(db)
                for ref, raw, mac in db.execute('SELECT ref,data,mac FROM security_tasks WHERE created<?',
                                                (state.now()-TTL,)).fetchall():
                    expired_record = state.decode((raw, mac))
                    if state.expired(expired_record):
                        state.expire_queued_task(expired_record)
                        db.execute('DELETE FROM security_tasks WHERE ref=?', (ref,))
                references = set()
                for row in db.execute('SELECT data,mac FROM security_tasks'):
                    _protect(store, state.head(row), references)
            references.update(queue_refs)
        return store.collect_unreferenced(references, max_captures=max_captures)
