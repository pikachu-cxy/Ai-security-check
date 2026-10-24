"""Real SQLite failure/concurrency boundaries for isolated metadata fixtures.

Bindings below are synthetic store inputs, not claims of native host identity.
All state and ordinary metadata values are confined to pytest tmp_path.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import tracemalloc
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataBudget, ReviewMetadataError, ReviewMetadataStore,
)
import security_runtime.task_review.metadata_store as metadata_store


KEY = bytes(range(32))
OWNER = dict(host='codex', session='a' * 64)


def limits(amount=100, reads=100):
    return dict(source_bytes=amount, navigation_bytes=0, control_bytes=0,
                total_bytes=amount, reads=reads)


def charge(amount=1, reads=1):
    return dict(source_bytes=amount, navigation_bytes=0, control_bytes=0,
                total_bytes=amount, reads=reads)


@pytest.fixture
def metadata(tmp_path):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    private = tmp_path.resolve() / 'private'
    private.mkdir(mode=0o700)
    path = private / 'task-security.db'
    binding = ReviewMetadataBinding('ts1-' + 'b' * 32, OWNER, 1, 'c' * 64)
    budget = ReviewMetadataBudget(page_items=2)
    store = ReviewMetadataStore(path, workspace_root=root, key=KEY, budget=budget)
    return SimpleNamespace(root=root, path=path, binding=binding, budget=budget, store=store)


def create(metadata, *, name='plan', allowance=None, request_id='create-plan'):
    generation = metadata.store.ledger(metadata.binding)['generation'] if metadata.path.exists() else 0
    return metadata.store.create(metadata.binding, name, limits=allowance or limits(),
        request_id=request_id, expected_generation=generation)


def reopen(metadata, *, root=None, key=KEY):
    return ReviewMetadataStore(metadata.path, workspace_root=root or metadata.root,
                               key=key, budget=metadata.budget)


@pytest.mark.parametrize('table', ['rm_pages', 'rm_collections', 'rm_ledgers', 'rm_receipts'])
def test_sql_failure_after_real_mutation_rolls_back_page_manifest_charge_and_cas(metadata, monkeypatch, table):
    first = create(metadata)
    ref, binding, store = first['ref'], metadata.binding, metadata.store
    before, before_ledger = store.manifest(ref, binding), store.ledger(binding)
    connect, injected = sqlite3.connect, []

    class FailedPublication(RuntimeError):
        pass

    class FaultConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            statement = sql.lstrip().upper()
            if not injected and table.upper() in statement and statement.startswith(('INSERT', 'UPDATE')):
                injected.append(True)
                raise FailedPublication('Isolated post-SQL failure')
            return result

    def faulty_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=FaultConnection))

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata_store.sqlite3, 'connect', faulty_connect)
        with pytest.raises(FailedPublication):
            store.append(ref, binding, [{'value': 1}], expected_generation=first['generation'],
                         request_id='append-once', charge=charge())
    assert injected, 'The real requested write boundary was never reached'
    assert reopen(metadata).manifest(ref, binding) == before
    assert reopen(metadata).ledger(binding) == before_ledger
    committed = store.append(ref, binding, [{'value': 1}], expected_generation=first['generation'],
                             request_id='append-once', charge=charge())
    assert committed['item_count'] == committed['page_count'] == 1
    assert store.ledger(binding)['spent'] == charge()
    assert store.append(ref, binding, [{'value': 1}], expected_generation=first['generation'],
                        request_id='append-once', charge=charge()) == committed
    assert store.ledger(binding)['spent'] == charge()


def test_same_request_commits_once_across_competing_connections(metadata):
    first = create(metadata)
    gate = threading.Barrier(2)

    def append():
        current = reopen(metadata)
        gate.wait(timeout=10)
        return current.append(first['ref'], metadata.binding, [{'value': 1}],
            expected_generation=first['generation'], request_id='same-append', charge=charge())

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: append(), range(2)))
    assert results[0] == results[1]
    assert metadata.store.manifest(first['ref'], metadata.binding)['item_count'] == 1
    assert metadata.store.ledger(metadata.binding)['spent'] == charge()
    with pytest.raises(ReviewMetadataError) as conflict:
        metadata.store.append(first['ref'], metadata.binding, [{'value': 2}],
            expected_generation=first['generation'], request_id='same-append', charge=charge())
    assert conflict.value.reason_code == 'REVIEW_METADATA_IDEMPOTENCY_CONFLICT'
    assert metadata.store.ledger(metadata.binding)['spent'] == charge()


def test_competing_distinct_requests_cannot_spend_the_last_allowance_twice(metadata):
    first = create(metadata, allowance=limits(1, 1))
    gate = threading.Barrier(2)

    def append(index):
        current = reopen(metadata)
        generation = first['generation']
        gate.wait(timeout=10)
        for _ in range(4):
            try:
                current.append(first['ref'], metadata.binding, [{'value': index}],
                    expected_generation=generation, request_id=f'competing-{index}', charge=charge())
                return 'COMMITTED'
            except ReviewMetadataError as error:
                if error.reason_code == 'REVIEW_METADATA_CAS_CONFLICT':
                    generation = current.ledger(metadata.binding)['generation']
                    continue
                assert error.reason_code == 'REVIEW_METADATA_WAITING_CAPACITY'
                return error.reason_code
        pytest.fail('The finite competing mutation never resolved')

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(append, [1, 2]))
    assert sorted(results) == ['COMMITTED', 'REVIEW_METADATA_WAITING_CAPACITY']
    assert metadata.store.ledger(metadata.binding)['spent'] == charge()
    manifest = metadata.store.manifest(first['ref'], metadata.binding)
    assert manifest['item_count'] == manifest['page_count'] == 1


@pytest.mark.parametrize('next_revision', [False, True])
def test_new_collection_cannot_reset_the_original_task_allowance(metadata, next_revision):
    first = create(metadata, allowance=limits(1, 1))
    store, binding = metadata.store, metadata.binding
    spent = store.append(first['ref'], binding, [{'value': 1}], expected_generation=first['generation'],
                         request_id='spend-original', charge=charge())
    other = replace(binding, revision=2, snapshot_id='d' * 64) if next_revision else binding
    second = store.create(other, 'results', limits=limits(1, 1),
        expected_generation=spent['generation'], request_id='create-second')
    assert store.ledger(other)['spent'] == charge()
    with pytest.raises(ReviewMetadataError) as exhausted:
        store.append(second['ref'], other, [{'value': 2}], expected_generation=second['generation'],
                     request_id='second-spend', charge=charge())
    assert exhausted.value.reason_code == 'REVIEW_METADATA_WAITING_CAPACITY'
    before = store.ledger(binding)
    with pytest.raises(ReviewMetadataError):
        store.create(other, 'expanded', limits=limits(2, 2),
            expected_generation=before['generation'], request_id='expand-original-limits')
    assert store.ledger(binding) == before
    assert store.manifest(second['ref'], other)['item_count'] == 0


def test_new_tables_leave_legacy_and_capacity_task_rows_byte_identical(metadata):
    # Opaque authenticated legacy-row fixtures: metadata storage must neither
    # interpret nor migrate their old task/review contracts.
    with sqlite3.connect(metadata.path) as db:
        db.execute('CREATE TABLE security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, '
                   'phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
        for index, capacity in enumerate([False, True]):
            value = dict(contract='task-security-v1', task_ref='ts1-' + str(index) * 32,
                         workspace=str(metadata.root), review_protocol=3, generation=7,
                         phase='REVIEWING', lifetime_context_bytes=123, review_revision=3)
            if capacity:
                value['review_capacity'] = dict(status='CAPACITY_REQUIRED', source_delivery_started=False)
            db.execute('INSERT INTO security_tasks VALUES(?,?,?,?,?,?)',
                       (value['task_ref'], f'legacy-{index}', value['phase'], 1000,
                        encode(value).decode(), digest(KEY, value)))
        before = db.execute('SELECT * FROM security_tasks ORDER BY ref').fetchall()
    os.chmod(metadata.path, 0o600)
    first = metadata.store.create(metadata.binding, 'plan', limits=limits(),
                                   expected_generation=0, request_id='create-plan')
    updated = metadata.store.append(first['ref'], metadata.binding, [{'value': 1}],
        expected_generation=first['generation'], request_id='append', charge=charge())
    metadata.store.seal(first['ref'], metadata.binding, expected_generation=updated['generation'],
                        expected_items=1, request_id='seal')
    with sqlite3.connect(metadata.path) as db:
        after = db.execute('SELECT * FROM security_tasks ORDER BY ref').fetchall()
    assert before == after


def sealed_two_pages(metadata):
    first = create(metadata)
    second = metadata.store.append(first['ref'], metadata.binding, [{'value': 1}, {'value': 2}],
        expected_generation=first['generation'], request_id='first-page')
    third = metadata.store.append(first['ref'], metadata.binding, [{'value': 3}],
        expected_generation=second['generation'], request_id='second-page')
    return metadata.store.seal(first['ref'], metadata.binding, expected_generation=third['generation'],
                               expected_items=3, request_id='seal')


@pytest.mark.parametrize('damage', ['mac', 'missing_page', 'position_column'])
def test_sealed_manifest_and_read_reject_corrupt_or_missing_page(metadata, damage):
    sealed = sealed_two_pages(metadata)
    with sqlite3.connect(metadata.path) as db:
        if damage == 'mac':
            db.execute('UPDATE rm_pages SET mac=? WHERE ref=? AND page_seq=2', ('0' * 64, sealed['ref']))
        elif damage == 'missing_page':
            db.execute('DELETE FROM rm_pages WHERE ref=? AND page_seq=2', (sealed['ref'],))
        else:
            db.execute('UPDATE rm_pages SET first_item=first_item+1 WHERE ref=? AND page_seq=1', (sealed['ref'],))
    for operation in (metadata.store.manifest, metadata.store.page):
        with pytest.raises(ReviewMetadataError) as invalid:
            operation(sealed['ref'], metadata.binding)
        assert invalid.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'


@pytest.mark.parametrize('field', ['owner', 'task_ref', 'revision', 'snapshot_id'])
def test_collection_cannot_be_read_with_another_binding(metadata, field):
    sealed = sealed_two_pages(metadata)
    replacements = dict(owner=dict(host='codex', session='d' * 64), task_ref='ts1-' + 'e' * 32,
                        revision=2, snapshot_id='f' * 64)
    foreign = replace(metadata.binding, **{field: replacements[field]})
    before = metadata.path.read_bytes()
    for operation in (metadata.store.manifest, metadata.store.page):
        with pytest.raises(ReviewMetadataError):
            operation(sealed['ref'], foreign)
    assert metadata.path.read_bytes() == before


@pytest.mark.parametrize('damage', ['key', 'root', 'root_inode', 'budget'])
def test_wrong_store_identity_never_reinitializes_existing_history(metadata, damage):
    sealed = sealed_two_pages(metadata)
    before = metadata.path.read_bytes()
    root, key, budget = metadata.root, KEY, metadata.budget
    if damage == 'key':
        key = b'Z' * 32
    elif damage == 'root':
        root = metadata.root.with_name('another-source')
        root.mkdir()
    elif damage == 'root_inode':
        metadata.root.rename(metadata.root.with_name('original-source'))
        metadata.root.mkdir()
        with pytest.raises(ReviewMetadataError):
            metadata.store.manifest(sealed['ref'], metadata.binding)
    else:
        budget = replace(budget, logical_bytes=budget.logical_bytes + 1)
    with pytest.raises(ReviewMetadataError):
        other = ReviewMetadataStore(metadata.path, workspace_root=root, key=key, budget=budget)
        other.create(metadata.binding, 'replacement', limits=limits(), expected_generation=0,
                     request_id='replacement')
    assert metadata.path.read_bytes() == before


def test_missing_database_with_existing_identity_cannot_be_rebuilt(metadata):
    first = create(metadata)
    metadata.path.unlink()
    with pytest.raises(ReviewMetadataError) as missing:
        reopen(metadata).create(metadata.binding, 'plan', limits=limits(), expected_generation=0,
                                 request_id='rebuild')
    assert missing.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    assert not metadata.path.exists()


def test_workspace_logical_quota_is_shared_across_distinct_tasks(metadata):
    # The fixed 65536-byte store allowance plus one 40k page fits; a
    # second task cannot spend a fresh independent allowance for another page.
    budget = replace(metadata.budget, logical_bytes=120000)
    store = ReviewMetadataStore(metadata.path, workspace_root=metadata.root, key=KEY, budget=budget)
    first = store.create(metadata.binding, 'plan', limits=limits(), expected_generation=0,
                         request_id='first-create')
    used = store.append(first['ref'], metadata.binding, [{'value': '1' * 40000}],
        expected_generation=first['generation'], request_id='first-large-page')
    other = replace(metadata.binding, task_ref='ts1-' + 'f' * 32)
    second = store.create(other, 'plan', limits=limits(), expected_generation=0,
                          request_id='second-create')
    before = store.ledger(other)
    with pytest.raises(ReviewMetadataError) as full:
        store.append(second['ref'], other, [{'value': '2' * 40000}],
            expected_generation=second['generation'], request_id='second-large-page')
    assert full.value.reason_code == 'REVIEW_METADATA_WAITING_CAPACITY'
    assert store.ledger(other) == before
    assert store.manifest(first['ref'], metadata.binding) == used
    assert store.manifest(second['ref'], other)['item_count'] == 0


@pytest.mark.parametrize('exceptional_exit', [False, True])
def test_reader_keeps_one_snapshot_and_releases_writer_on_exit(metadata, monkeypatch, exceptional_exit):
    sealed = sealed_two_pages(metadata)
    connect, wrote = sqlite3.connect, threading.Event()

    class TrackedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            if sql.lstrip().upper().startswith('INSERT') and 'RM_COLLECTIONS' in sql.upper():
                wrote.set()
            return result

    def tracked_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=TrackedConnection))

    class StopReading(RuntimeError):
        pass

    monkeypatch.setattr(metadata_store.sqlite3, 'connect', tracked_connect)
    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            with metadata.store.reader(sealed['ref'], metadata.binding) as reader:
                first = reader.page()
                future = executor.submit(reopen(metadata).create, metadata.binding, 'sibling',
                    limits=limits(), request_id='reader-sibling', expected_generation=sealed['generation'])
                assert wrote.wait(timeout=10), 'The competing real SQLite mutation never executed'
                assert not future.done(), 'Writer committed while the validated read snapshot remained open'
                second = reader.page(after_page=first['next_cursor'])
                assert first['items'] + second['items'] == [{'value': 1}, {'value': 2}, {'value': 3}]
                assert first['manifest'] == second['manifest'] == sealed
                if exceptional_exit:
                    raise StopReading('Release the isolated reader through its exception path')
        except StopReading:
            assert exceptional_exit
        committed = future.result(timeout=10)
    assert committed['generation'] == sealed['generation'] + 1
    assert metadata.store.ledger(metadata.binding)['generation'] == committed['generation']
    with pytest.raises(ReviewMetadataError) as closed:
        reader.page()
    assert closed.value.reason_code == 'REVIEW_METADATA_INVALID'


def test_real_reader_lock_reports_busy_and_rolls_back_charge_receipt_and_pages(metadata, monkeypatch):
    sealed = sealed_two_pages(metadata)
    sibling = metadata.store.create(metadata.binding, 'sibling', limits=limits(),
        expected_generation=sealed['generation'], request_id='create-sibling')
    before = metadata.store.ledger(metadata.binding)
    connect, observed = sqlite3.connect, []

    class BusyConnection(sqlite3.Connection):
        def commit(self):
            try:
                return super().commit()
            except sqlite3.Error as error:
                observed.append((getattr(error, 'sqlite_errorcode', 0) or 0) & 255)
                raise

    def impatient_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, timeout=.02, factory=BusyConnection))

    with metadata.store.reader(sealed['ref'], metadata.binding) as reader:
        with monkeypatch.context() as scoped:
            scoped.setattr(metadata_store.sqlite3, 'connect', impatient_connect)
            with pytest.raises(ReviewMetadataError) as blocked:
                reopen(metadata).append(sibling['ref'], metadata.binding, [{'value': 1}],
                    expected_generation=sibling['generation'], request_id='busy-append', charge=charge())
        assert blocked.value.reason_code == 'REVIEW_METADATA_BUSY'
        assert observed == [sqlite3.SQLITE_BUSY], 'The test must reach a real SQLite commit lock conflict'
        assert reader.page()['manifest']['generation'] == sibling['generation']
    assert metadata.store.ledger(metadata.binding) == before
    assert metadata.store.manifest(sibling['ref'], metadata.binding) == sibling
    with sqlite3.connect(metadata.path) as db:
        assert db.execute('SELECT count(*) FROM rm_receipts WHERE request_id=?', ('busy-append',)).fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM rm_pages WHERE ref=?', (sibling['ref'],)).fetchone()[0] == 0
    retried = metadata.store.append(sibling['ref'], metadata.binding, [{'value': 1}],
        expected_generation=sibling['generation'], request_id='busy-append', charge=charge())
    assert retried['generation'] == sibling['generation'] + 1
    assert metadata.store.ledger(metadata.binding)['spent'] == charge()


def test_unexpected_page_trigger_is_rejected_before_it_can_change_legacy_task(metadata, monkeypatch):
    first = create(metadata)
    legacy = dict(contract='task-security-v1', task_ref='ts1-' + '0' * 32, value=1)
    with sqlite3.connect(metadata.path) as db:
        db.execute('CREATE TABLE security_tasks (ref TEXT PRIMARY KEY, task_key TEXT NOT NULL, '
                   'phase TEXT NOT NULL, created REAL NOT NULL, data TEXT NOT NULL, mac TEXT NOT NULL)')
        db.execute('INSERT INTO security_tasks VALUES(?,?,?,?,?,?)',
                   (legacy['task_ref'], 'legacy', 'REVIEWING', 1000, encode(legacy).decode(), digest(KEY, legacy)))
        before = db.execute('SELECT * FROM security_tasks').fetchall()
        metadata_before = {table: db.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall()
                           for table in metadata_store.TABLES}
        db.execute("CREATE TRIGGER unexpected_rm_page AFTER INSERT ON rm_pages "
                   "BEGIN UPDATE security_tasks SET data='value=2'; END")
    connect, writes = sqlite3.connect, []

    class TracedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            statement = sql.lstrip().upper()
            if statement.startswith(('INSERT', 'UPDATE', 'DELETE')) and 'RM_' in statement:
                writes.append(statement)
            return super().execute(sql, parameters)

    def traced_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=TracedConnection))

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata_store.sqlite3, 'connect', traced_connect)
        with pytest.raises(ReviewMetadataError) as invalid:
            metadata.store.append(first['ref'], metadata.binding, [{'value': 1}],
                expected_generation=first['generation'], request_id='trigger-append', charge=charge())
    assert invalid.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    assert not writes, 'Unexpected schema must be rejected before any metadata mutation'
    with sqlite3.connect(metadata.path) as db:
        assert db.execute('SELECT * FROM security_tasks').fetchall() == before
        assert {table: db.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall()
                for table in metadata_store.TABLES} == metadata_before


def test_real_sqlite_full_rolls_back_then_allows_a_smaller_retry(metadata, monkeypatch):
    budget = replace(metadata.budget, database_bytes=65536)
    store = ReviewMetadataStore(metadata.path, workspace_root=metadata.root, key=KEY, budget=budget)
    first = store.create(metadata.binding, 'plan', limits=limits(), expected_generation=0,
                         request_id='create-plan')
    before = store.ledger(metadata.binding)
    connect, observed = sqlite3.connect, []

    class FullConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            try:
                return super().execute(sql, parameters)
            except sqlite3.Error as error:
                observed.append((getattr(error, 'sqlite_errorcode', 0) or 0) & 255)
                raise

    def tracked_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=FullConnection))

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata_store.sqlite3, 'connect', tracked_connect)
        with pytest.raises(ReviewMetadataError) as full:
            store.append(first['ref'], metadata.binding, [{'value': '1' * 50000}],
                expected_generation=first['generation'], request_id='bounded-append', charge=charge())
    assert full.value.reason_code == 'REVIEW_METADATA_WAITING_CAPACITY'
    assert observed == [sqlite3.SQLITE_FULL], 'Capacity must be exhausted by real SQLite page allocation'
    assert store.manifest(first['ref'], metadata.binding) == first
    assert store.ledger(metadata.binding) == before
    with sqlite3.connect(metadata.path) as db:
        assert db.execute('SELECT count(*) FROM rm_receipts WHERE request_id=?', ('bounded-append',)).fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM rm_pages').fetchone()[0] == 0
    assert metadata.path.stat().st_size <= budget.database_bytes
    smaller = store.append(first['ref'], metadata.binding, [{'value': 1}],
        expected_generation=first['generation'], request_id='bounded-append', charge=charge())
    assert smaller['item_count'] == smaller['page_count'] == 1
    assert smaller['generation'] == first['generation'] + 1
    assert store.ledger(metadata.binding)['spent'] == charge()


def test_external_oversized_page_blob_is_rejected_without_loading_it_into_python(metadata):
    sealed = sealed_two_pages(metadata)
    blob_bytes = 8 * 1024 * 1024
    with sqlite3.connect(metadata.path) as db:
        # SQLite creates the damaged value directly; the test never builds
        # the oversized page as a Python bytes object.
        db.execute('UPDATE rm_pages SET data=zeroblob(?) WHERE ref=? AND page_seq=1',
                   (blob_bytes, sealed['ref']))
    tracemalloc.start()
    try:
        with pytest.raises(ReviewMetadataError) as invalid:
            metadata.store.page(sealed['ref'], metadata.binding)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert invalid.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    assert peak < blob_bytes // 4, 'The corrupt multi-megabyte BLOB was materialized in Python'


CHILD = r'''
import json, os, sqlite3, sys, time
from pathlib import Path
from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataBudget, ReviewMetadataStore,
)
import security_runtime.task_review.metadata_store as metadata_store
path, root, mode, ref = sys.argv[1:]
binding = ReviewMetadataBinding('ts1-'+'b'*32, dict(host='codex', session='a'*64), 1, 'c'*64)
limits = dict(source_bytes=100, navigation_bytes=0, control_bytes=0, total_bytes=100, reads=100)
charge = dict(source_bytes=1, navigation_bytes=0, control_bytes=0, total_bytes=1, reads=1)
connect = sqlite3.connect
changed_page = []
class CrashConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        value = super().execute(sql, parameters)
        statement = sql.lstrip().upper()
        if statement.startswith(('INSERT', 'UPDATE')) and 'RM_PAGES' in statement:
            changed_page.append(True)
            if mode == 'before':
                os._exit(31)
        if mode == 'after' and changed_page and statement == 'COMMIT':
            os._exit(32)
        return value
    def commit(self):
        if mode == 'initial':
            os._exit(33)
        value = super().commit()
        if mode == 'after' and changed_page:
            os._exit(32)
        return value
    def __exit__(self, kind, error, trace):
        if mode == 'initial' and kind is None:
            os._exit(33)
        value = super().__exit__(kind, error, trace)
        if mode == 'after' and changed_page and kind is None:
            os._exit(32)
        return value
def wrapped_connect(*args, **kwargs):
    return connect(*args, **dict(kwargs, factory=CrashConnection))
metadata_store.sqlite3.connect = wrapped_connect
store = ReviewMetadataStore(path, workspace_root=root, key=bytes(range(32)),
                            budget=ReviewMetadataBudget(page_items=2))
if mode == 'parallel':
    Path(path).with_name('ready-'+str(os.getpid())).write_text('ready')
    deadline = time.monotonic()+15
    while not Path(path).with_name('start').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('The isolated concurrent-create gate was not released')
        time.sleep(.005)
if mode in {'parallel', 'initial'}:
    result = store.create(binding, 'plan', limits=limits, request_id='create-plan', expected_generation=0)
else:
    result = store.append(ref, binding, [{'value':1}], charge=charge,
                          request_id='crashing-append', expected_generation=1)
print(json.dumps(result), flush=True)
'''


def child_command(metadata, mode, ref='-'):
    return [sys.executable, '-c', CHILD, str(metadata.path), str(metadata.root), mode, ref]


def child_environment():
    environment = dict(os.environ)
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    source = str(Path(__file__).resolve().parents[2] / 'src')
    environment['PYTHONPATH'] = source + os.pathsep + environment.get('PYTHONPATH', '')
    return environment


@pytest.mark.parametrize('phase,exit_code', [('before', 31), ('after', 32)])
def test_process_exit_preserves_atomic_mutation_and_retry_charge(metadata, phase, exit_code):
    first = create(metadata)
    before = metadata.store.ledger(metadata.binding)
    child = subprocess.run(child_command(metadata, phase, first['ref']), cwd=metadata.root.parent,
        env=child_environment(), capture_output=True, text=True, timeout=20)
    assert child.returncode == exit_code, child.stderr
    current = reopen(metadata)
    if phase == 'before':
        # A deliberate idempotent write can recover SQLite's hot rollback
        # journal; a diagnostic read is not required to repair on disk.
        assert current.create(metadata.binding, 'plan', limits=limits(), request_id='create-plan',
                              expected_generation=0) == first
        assert current.ledger(metadata.binding) == before
        assert current.manifest(first['ref'], metadata.binding) == first
    committed = current.append(first['ref'], metadata.binding, [{'value': 1}],
        expected_generation=first['generation'], request_id='crashing-append', charge=charge())
    assert committed['item_count'] == committed['page_count'] == 1
    assert committed['generation'] == first['generation'] + 1
    assert current.ledger(metadata.binding)['spent'] == charge()
    assert current.append(first['ref'], metadata.binding, [{'value': 1}],
        expected_generation=first['generation'], request_id='crashing-append', charge=charge()) == committed
    assert current.ledger(metadata.binding)['spent'] == charge()


def test_first_initialization_exit_before_commit_does_not_become_a_fresh_store(metadata):
    child = subprocess.run(child_command(metadata, 'initial'), cwd=metadata.root.parent,
        env=child_environment(), capture_output=True, text=True, timeout=20)
    assert child.returncode == 33, child.stderr
    assert metadata.path.exists()
    with pytest.raises(ReviewMetadataError) as interrupted:
        reopen(metadata).create(metadata.binding, 'plan', limits=limits(),
            request_id='create-plan', expected_generation=0)
    assert interrupted.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'


def test_two_processes_first_create_share_one_identity_and_receipt(metadata):
    children = [subprocess.Popen(child_command(metadata, 'parallel'), cwd=metadata.root.parent,
        env=child_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    try:
        deadline = time.monotonic() + 15
        while len(list(metadata.path.parent.glob('ready-*'))) != 2:
            assert all(child.poll() is None for child in children), 'A concurrent child failed before the gate'
            assert time.monotonic() < deadline, 'Concurrent children did not reach the isolated start gate'
            time.sleep(.005)
        metadata.path.with_name('start').write_text('start')
        outputs = []
        for child in children:
            output, error = child.communicate(timeout=20)
            assert child.returncode == 0, error
            outputs.append(json.loads(output))
        assert outputs[0] == outputs[1]
        assert outputs[0]['generation'] == 1
        assert reopen(metadata).ledger(metadata.binding)['spent'] == charge(0, 0)
        assert reopen(metadata).manifest(outputs[0]['ref'], metadata.binding) == outputs[0]
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
