"""Bounded task-page collection from authenticated heads and queue pins.

Old/unmanaged pages and unfinished captures are retained. This entry is a write
operation used by task saves; diagnostics and read-only calls never invoke it.
"""
from contextlib import closing
import sqlite3

from ..hook_state import no_links
from ..snapshot_store import SnapshotStoreError
from .snapshot_page_guard import page_guard
from .snapshot_pages import GC_POLICY, POINTER, REVIEW_CONTRACT, _binding, _store
from .capture_source_profile import POLICY as CAPTURE_SOURCE_POLICY


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


def _protect(store, record, references, *, state=None, db=None):
    if record.get('contract') == REVIEW_CONTRACT:
        # The visible head contains only the current pointers. Historical
        # revisions are rooted in its authenticated, paged source catalog.
        # Never infer that catalog from a partial compatibility projection.
        if state is None or db is None:
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
        from ..task_review.paged_task_store import iter_source_pins
        for pin in iter_source_pins(state, record, db=db):
            header = store.resume(pin['ref'], pin['binding'])
            if header['state'] != 'SEALED':
                raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
            references.add(pin['ref'])
        return
    legacy_record = record
    baseline = record.get('baseline')
    end = record.get('end')
    if isinstance(end, dict) and 'capture_source' in end:
        raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
    if isinstance(baseline, dict) and 'capture_source' in baseline:
        from ..task_review.capture_source_binding import (CaptureSourceBinding,
            CaptureSourceBindingError, raw_source_binding, validate_descriptor)
        from ..source_redaction import task_version
        from .ownership import record_owner
        try:
            scope = CaptureSourceBinding(record['task_ref'], record_owner(record),
                'baseline', record['task_ref'], task_version(record))
            descriptor = validate_descriptor(scope, {'capture_source': baseline['capture_source']})
            if (record.get('capture_policy') != CAPTURE_SOURCE_POLICY
                    or descriptor['source'] != baseline.get(POINTER, {}).get('source')):
                raise ValueError('Capture source does not match its original baseline')
        except (CaptureSourceBindingError, ValueError, TypeError, KeyError, AttributeError):
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID') from None
        header = store.strict_header(descriptor['ref'], raw_source_binding(scope, descriptor['source']))
        if header['state'] != 'SEALED':
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
        references.add(descriptor['ref'])
        # A separately typed V2 descriptor is never an old paged_entries pin.
        legacy_baseline = dict(baseline)
        legacy_baseline.pop('capture_source')
        legacy_record = dict(record, baseline=legacy_baseline)
    for pointer in _pointers(legacy_record):
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


def _protect_publications(store, state, db, references):
    from .capture_publication_store import iter_source_pins
    for pin in iter_source_pins(state, db=db):
        header = store.strict_header(pin['ref'], pin['binding'])
        expected = pin.get('expected_header')
        if (header['state'] not in pin['expected_states']
                or expected is not None and any(header.get(key) != value for key, value in expected.items())):
            raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
        references.add(pin['ref'])


def _missing_pages(state):
    """A missing raw store is benign only without registered source pins."""
    from .capture_publication_store import (MARKER_SUFFIX, TABLES,
        validate_inventory, iter_source_pins)
    from .frozen_body_context import readonly_database
    from .security_state import MAX_HISTORY_RECORDS, MAX_RECORD_BYTES
    marker = state.path.with_name(state.path.name + MARKER_SUFFIX)
    stage = marker.with_name(marker.name + '.next')
    allocated = any(path.exists() or path.is_symlink() for path in (marker, stage))
    if not state.path.exists():
        if allocated:
            raise SnapshotStoreError('SNAPSHOT_HISTORY_UNAVAILABLE')
        return
    if not allocated and state.path.stat().st_size == 0:
        return  # An original writer may have allocated only its empty file.
    with readonly_database(state.path, maximum=MAX_RECORD_BYTES) as db:
        names = {row[0] for row in db.execute('SELECT name FROM sqlite_master '
            "WHERE type='table' AND name IN ('security_tasks', 'cp_registry', "
            "'cp_owners', 'cp_intents', 'cp_receipts')")}
        allocated = allocated or bool(names.intersection(TABLES))
        if not allocated and 'security_tasks' in names:
            rows = db.execute("SELECT CASE WHEN typeof(data)='text' AND "
                'length(CAST(data AS BLOB))<=? THEN data END, '
                "CASE WHEN typeof(mac)='text' AND length(mac)=64 THEN mac END "
                'FROM security_tasks WHERE instr(data,?)>0 OR instr(data,?)>0 LIMIT ?',
                (MAX_RECORD_BYTES, '"capture_publication"', '"capture_source"', MAX_HISTORY_RECORDS + 1))
            for count, row in enumerate(rows, 1):
                if count > MAX_HISTORY_RECORDS:
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_BUDGET')
                try:
                    head = state._authenticated_head(row)
                except (ValueError, TypeError, KeyError):
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID') from None
                if ('capture_publication' in head
                        or 'capture_source' in head.get('baseline', {})):
                    allocated = True
                    break
    if not allocated:
        return
    # Never create a missing fence while diagnosing an allocated domain.
    if not (state.path.parent / 'snapshot-pages.gc.lock').exists():
        raise SnapshotStoreError('SNAPSHOT_GC_GUARD_UNAVAILABLE')
    with page_guard(state.path.parent, exclusive=True):
        with readonly_database(state.path, maximum=MAX_RECORD_BYTES) as db:
            validate_inventory(state, db=db)
            if next(iter_source_pins(state, db=db), None) is not None:
                raise SnapshotStoreError('SNAPSHOT_HISTORY_UNAVAILABLE')


def collect_pages(state, *, prune=False, max_captures=32):
    from .closeout_queue import CloseoutQueue
    from .security_state import MAX_HISTORY_RECORDS, TTL
    directory = state.path.parent
    no_links(state.path)
    page_path = directory/'snapshot-pages'/'snapshots.db'
    no_links(page_path)
    if not state.path.exists() or not page_path.exists():
        _missing_pages(state)
        return dict(collected_captures=0, released_logical_bytes=0, has_more=False)
    # A collector never invents a missing guard for previously published pages.
    if not (directory/'snapshot-pages.gc.lock').exists():
        _missing_pages(state)
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
            # A missing new head is not a retirement grant. Its signed fence
            # and metadata ledger must have one matching published head before
            # this inventory can authorize any pruning or source collection.
            from ..task_review.paged_task_store import validate_head_inventory
            validate_head_inventory(state, db=db)
            from .capture_publication_store import (validate_inventory,
                retire_for_task)
            validate_inventory(state, db=db)
            rows = db.execute('SELECT data,mac FROM security_tasks LIMIT ?',
                              (MAX_HISTORY_RECORDS+1,)).fetchall()
            if len(rows) > MAX_HISTORY_RECORDS:
                raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_BUDGET')
            heads = [state.retention_head(row) for row in rows]
            for record in heads:
                _protect(store, record, references, state=state, db=db)
            _protect_publications(store, state, db, references)
            queue_refs = set()
            for row in CloseoutQueue(state.hooks, state.root, now=state.now).rows():
                if row.get('key') == '$worker':
                    continue  # Dispatcher lease; it contains no source pointers.
                if row.get('contract') not in {'task-closeout-queue-v1', 'task-closeout-queue-v2'}:
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                if row.get('snapshot_task_contract') == REVIEW_CONTRACT:
                    # This foundation has no new-head queue publication path.
                    # A legacy queue row cannot stand in for its full catalog.
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                # Running work remains pinned even if its initial queue TTL elapsed.
                if row.get('state') != 'RUNNING' and row.get('expires_at', float('inf')) <= state.now():
                    continue
                baseline_pin = row.get('baseline_pages', {})
                if (row.get('snapshot_capture_policy') in {GC_POLICY, CAPTURE_SOURCE_POLICY}
                        and POINTER not in baseline_pin):
                    raise SnapshotStoreError('SNAPSHOT_REFERENCE_INVENTORY_INVALID')
                surrogate = dict(task_ref=row['task_ref'], task_owner=row['owner'],
                    contract=row.get('snapshot_task_contract'),
                    capture_policy=row.get('snapshot_capture_policy', 'BATCHED_FILES_V1'),
                    baseline=dict(redaction_version=row['end'].get('redaction_version', 1), **baseline_pin),
                    end=row['end'], source_end_pages=row.get('source_end_pages', {}))
                _protect(store, surrogate, queue_refs)
            # A bad registered source cannot be discovered after task pruning
            # has committed. Validate every raw entry/object, including valid
            # in-flight prefixes, before any control or projection deletion.
            store.validate_contents()
            if prune:
                state._retain_pending(db)
                for ref, raw, mac in db.execute('SELECT ref,data,mac FROM security_tasks WHERE created<?',
                                                (state.now()-TTL,)).fetchall():
                    if state.retention_head((raw, mac)).get('contract') == REVIEW_CONTRACT:
                        # Its projection/TTL integration is not enabled. Keep
                        # the authenticated head and every original source pin.
                        continue
                    expired_record = state.decode((raw, mac))
                    if state.expired(expired_record):
                        state.expire_queued_task(expired_record)
                        retire_for_task(state, expired_record, db=db)
                        db.execute('DELETE FROM security_tasks WHERE ref=?', (ref,))
                references = set()
                for row in db.execute('SELECT data,mac FROM security_tasks'):
                    _protect(store, state.retention_head(row), references, state=state, db=db)
                _protect_publications(store, state, db, references)
            references.update(queue_refs)
        return store.collect_unreferenced(references, max_captures=max_captures)
