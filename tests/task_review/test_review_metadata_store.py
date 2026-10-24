"""Internal metadata foundation invariants, using real private SQLite files.

No Runtime admission, task preimage, scanner, or host attestation is synthesized.
These tests do not claim that the future paged review protocol is activated.
"""
from dataclasses import replace
import json
import os
import sqlite3

import pytest

from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataBudget, ReviewMetadataError, ReviewMetadataStore,
)

KEY = b'k' * 32
OWNER = dict(host='codex', session='a' * 64)
LIMITS = dict(source_bytes=100, navigation_bytes=100, control_bytes=100, reads=10, total_bytes=300)
CHARGE = dict(source_bytes=2, navigation_bytes=3, control_bytes=4, reads=1, total_bytes=9)


@pytest.fixture
def setup(tmp_path):
    root, private = tmp_path / 'source', tmp_path / 'private'
    root.mkdir()
    private.mkdir(mode=0o700)
    binding = ReviewMetadataBinding('ts1-' + 'a' * 32, OWNER, 1, 'b' * 64)
    store = ReviewMetadataStore(private / 'task-security.db', workspace_root=root, key=KEY,
                                budget=ReviewMetadataBudget(page_items=2, page_bytes=128))
    return store, binding


def create(store, binding, **kwargs):
    return store.create(binding, 'units', limits=LIMITS, request_id='create', **kwargs)


def append(store, binding, head, items=None, **kwargs):
    return store.append(head['ref'], binding, items or [dict(value=n) for n in range(5)],
                        expected_generation=head['generation'], request_id='append', **kwargs)


def seal(store, binding, head):
    return store.seal(head['ref'], binding, expected_generation=head['generation'],
                      expected_items=head['item_count'], request_id='seal')


def test_auto_pages_are_complete_ordered_sealed_and_reader_closes(setup):
    store, binding = setup
    first = create(store, binding)
    with pytest.raises(ReviewMetadataError) as pending:
        store.page(first['ref'], binding)
    assert pending.value.reason_code == 'REVIEW_METADATA_NOT_SEALED'
    written = append(store, binding, first, charge=CHARGE)
    assert written['page_count'] == 3 and written['item_count'] == 5
    sealed = seal(store, binding, written)
    with store.reader(first['ref'], binding) as reader:
        p1 = reader.page()
        p2 = reader.page(after_page=p1['next_cursor'])
        p3 = reader.page(after_page=p2['next_cursor'])
        assert [v['value'] for p in (p1, p2, p3) for v in p['items']] == list(range(5))
        assert p3['next_cursor'] is None
        assert p3['manifest'] == sealed
        # Caller changes cannot mutate this reader's validated ledger.
        p1['manifest']['ledger']['limits']['reads'] = 999
        assert reader.page()['manifest']['ledger']['limits'] == LIMITS
    with pytest.raises(ReviewMetadataError):
        reader.page()
    assert store.ledger(binding)['spent'] == CHARGE


def test_empty_sealed_is_distinct_from_unknown_or_missing(setup):
    store, binding = setup
    assert not store.path.exists()
    with pytest.raises(ReviewMetadataError):
        store.ledger(binding)
    assert not store.path.exists()
    first = create(store, binding)
    final = seal(store, binding, first)
    page = store.page(first['ref'], binding)
    assert page == dict(items=[], page_seq=0, next_cursor=None, manifest=final)
    with pytest.raises(ReviewMetadataError):
        store.page('rm1-' + 'c' * 32, binding)


@pytest.mark.parametrize('mode', ['item', 'request_items', 'request_bytes'])
def test_single_item_and_request_budgets_fail_before_database_mutation(setup, mode):
    store, binding = setup
    if mode == 'item':
        items = [dict(text='a' * 129)]
    elif mode == 'request_items':
        items = [dict(value=0)] * (store.budget.request_items + 1)
    else:
        store = ReviewMetadataStore(store.path, workspace_root=store.root, key=KEY,
                                    budget=replace(store.budget, request_bytes=100))
        items = [dict(text='a' * 60), dict(text='b' * 60)]
    first = create(store, binding)
    before = store.path.read_bytes(), store.ledger(binding)
    with pytest.raises(ReviewMetadataError) as error:
        append(store, binding, first, items)
    assert error.value.reason_code == 'REVIEW_METADATA_PAGE_BUDGET'
    assert (store.path.read_bytes(), store.ledger(binding)) == before


def test_caller_mutation_after_validation_cannot_change_receipted_contents(setup, monkeypatch):
    store, binding = setup
    first = create(store, binding)
    source = [dict(text='original')]
    original = store._request

    def mutate_after_hash(*args, **kwargs):
        result = original(*args, **kwargs)
        source[0]['text'] = 'changed'
        return result

    monkeypatch.setattr(store, '_request', mutate_after_hash)
    head = append(store, binding, first, source)
    seal(store, binding, head)
    assert store.page(first['ref'], binding)['items'] == [dict(text='original')]
    with pytest.raises(ReviewMetadataError) as conflict:
        append(store, binding, first, source)
    assert conflict.value.reason_code == 'REVIEW_METADATA_IDEMPOTENCY_CONFLICT'


def test_seal_count_mismatch_and_stale_cas_preserve_pages_and_ledger(setup):
    store, binding = setup
    first = create(store, binding)
    head = append(store, binding, first)
    before = store.path.read_bytes(), store.ledger(binding)
    with pytest.raises(ReviewMetadataError):
        store.seal(first['ref'], binding, expected_generation=head['generation'],
                   expected_items=4, request_id='bad-count')
    with pytest.raises(ReviewMetadataError) as stale:
        store.seal(first['ref'], binding, expected_generation=first['generation'],
                   expected_items=5, request_id='stale')
    assert stale.value.reason_code == 'REVIEW_METADATA_CAS_CONFLICT'
    assert (store.path.read_bytes(), store.ledger(binding)) == before


@pytest.mark.parametrize('failure', ['capacity', 'sql'])
def test_first_request_failure_leaves_verifiable_empty_allocation_for_retry(setup, monkeypatch, failure):
    original, binding = setup
    store = original
    if failure == 'capacity':
        # Enough for the empty allocation, not a task ledger/receipt/manifest.
        store = ReviewMetadataStore(original.path, workspace_root=original.root, key=KEY,
                                    budget=replace(original.budget, logical_bytes=66000))
    elif failure == 'sql':
        finish = store._finish
        raised = []

        def fail_after_real_request(*args, **kwargs):
            value = finish(*args, **kwargs)
            if not raised:
                raised.append(True)
                raise RuntimeError('ordinary isolated transaction failure')
            return value

        monkeypatch.setattr(store, '_finish', fail_after_real_request)
    expected = ReviewMetadataError if failure == 'capacity' else RuntimeError
    with pytest.raises(expected):
        create(store, binding)
    assert store.marker.exists()
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM rm_registry').fetchone()[0] == 1
        for table in ('rm_collections', 'rm_ledgers', 'rm_pages', 'rm_receipts'):
            assert db.execute(f'SELECT count(*) FROM {table}').fetchone()[0] == 0
    if failure == 'capacity':
        # The unchanged fixed quota rejects honestly again; history is intact.
        with pytest.raises(ReviewMetadataError) as again:
            create(store, binding)
        assert again.value.reason_code == 'REVIEW_METADATA_WAITING_CAPACITY'
    else:
        assert create(store, binding)['generation'] == 1


@pytest.mark.parametrize('damage', ['malformed_marker', 'wrong_marker_type', 'all_tables'])
def test_corrupt_identity_or_erased_schema_is_not_a_fresh_store(setup, damage):
    store, binding = setup
    create(store, binding)
    if damage == 'all_tables':
        with sqlite3.connect(store.path) as db:
            for table in ('rm_registry', 'rm_ledgers', 'rm_collections', 'rm_pages', 'rm_receipts'):
                db.execute(f'DROP TABLE {table}')
    else:
        store.marker.write_bytes(b'[' if damage == 'malformed_marker' else b'null')
    before = store.path.read_bytes()
    with pytest.raises(ReviewMetadataError) as error:
        create(store, binding)
    assert error.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    assert store.path.read_bytes() == before


def test_missing_middle_cannot_be_hidden_by_an_append_or_seal(setup):
    store, binding = setup
    first = create(store, binding)
    head = append(store, binding, first)
    with sqlite3.connect(store.path) as db:
        db.execute('DELETE FROM rm_pages WHERE ref=? AND page_seq=2', (first['ref'],))
    before = store.path.read_bytes()
    for operation in (
        lambda: store.append(first['ref'], binding, [dict(value=6)], expected_generation=head['generation'], request_id='next'),
        lambda: seal(store, binding, head),
        lambda: store.manifest(first['ref'], binding),
    ):
        with pytest.raises(ReviewMetadataError):
            operation()
    assert store.path.read_bytes() == before


@pytest.mark.parametrize('field,value', [('page_bytes', 0), ('request_items', True), ('logical_bytes', float('inf'))])
def test_invalid_budgets_are_rejected_without_allocating(setup, field, value):
    store, binding = setup
    with pytest.raises(ReviewMetadataError) as error:
        ReviewMetadataStore(store.path, workspace_root=store.root, key=KEY,
                            budget=replace(store.budget, **{field: value}))
    assert error.value.reason_code == 'REVIEW_METADATA_INVALID'
    assert not store.path.exists()
