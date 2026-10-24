"""Actual sealed sources and signed catalogs fence internal paged-head GC.

All bindings are isolated store fixtures, not native host or task admissions.
The production coordinator and queue route for this new head remain disabled.
"""
from dataclasses import replace
import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStoreError
from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataError, ReviewMetadataStore,
)
from security_runtime.task_review.paged_task_store import PagedReviewTaskStore, source_binding
from security_runtime.tasks.activity import HARD_TTL, POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import (
    GC_CONTRACT, GC_POLICY, POINTER, REVIEW_CONTRACT, _binding, _store,
)
from paged_review_source_helpers import pack_review_sources


LIMITS = dict(source_bytes=100, navigation_bytes=100, control_bytes=100, reads=100, total_bytes=300)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path.resolve() / 'source'
    root.mkdir()
    hooks = HookStateStore(tmp_path.resolve() / 'private')
    hooks.key(root)
    clock = [1_000_000.0]
    state = TaskSecurityStore(hooks, root, now=lambda: clock[0])
    state.path.parent.chmod(0o700)
    binding = ReviewMetadataBinding('ts1-' + 'a' * 32,
        session_owner('codex', 'isolated-paged-gc'), 1, 'b' * 64)
    return SimpleNamespace(root=root, hooks=hooks, clock=clock, state=state, binding=binding)


def snapshot(label):
    return dict(hashes={'source.py': hashlib.sha256(label.encode()).hexdigest()},
        texts={'source.py': [label]}, inventory=['source.py'], read_priority=['source.py'],
        preimages={}, line_counts={'source.py': 1}, text_truncations={}, text_unavailable={},
        limitations=[], read_limitations=[], inventory_complete=True, redaction_version=3)


def source_pair(sample, *, end='value=2', binding=None):
    binding = binding or sample.binding
    template = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
        task_ref=binding.task_ref, task_owner=binding.owner,
        baseline=snapshot('value=1'), end=snapshot(end))
    return pack_review_sources(sample.state, template)


def create(sample):
    sources = source_pair(sample)
    store = PagedReviewTaskStore(sample.state)
    store.create(sample.binding, task_key='internal-paged-review', baseline=sources['baseline'],
                 end=sources['end'], limits=LIMITS, request_id='create-paged')
    return store, store.get(sample.binding.task_ref, sample.binding.owner)


def revision(sample, store, head):
    binding = replace(sample.binding, revision=2, snapshot_id='c' * 64)
    sources = source_pair(sample, end='value=3')
    store.mutate(binding, {'kind': 'revision', 'end': sources['end']},
        expected_generation=head['generation'], expected_metadata_generation=head['metadata_generation'],
        request_id='next-revision')
    return binding, store.get(binding.task_ref, binding.owner)


def orphan(sample):
    store = _store(sample.state)
    binding = SnapshotBinding('isolated:orphan', sample.binding.owner, 'orphan-source', 3,
                              retention_domain='TASK_PAGES_GC_V1')
    with page_guard(sample.state.path.parent, create=True):
        head = store.create(binding)
        store.append_page(head['ref'], binding, [('orphan.py', b'value=4')],
            expected_cursor=None, cursor='one')
        store.seal(head['ref'], binding, expected_files=1, inventory_complete=True)
    return head['ref'], binding


def page_rows(sample):
    with sqlite3.connect(_store(sample.state).path) as db:
        return {table: db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
                for table in ('captures', 'entries', 'objects', 'usage')}


def control_rows(sample):
    with sqlite3.connect(sample.state.path) as db:
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name='security_tasks' OR name LIKE 'rm_%') ORDER BY name")]
        return {name: db.execute(f'SELECT * FROM {name} ORDER BY 1,2').fetchall() for name in names}


def assert_source(sample, head, field):
    pointer = head[field][POINTER]
    binding = ReviewMetadataBinding(head['task_ref'], head['task_owner'], head['review_revision'],
        head['snapshot_id'], head['representation_version'])
    header = _store(sample.state).resume(pointer['ref'], source_binding(binding, field, pointer['source']))
    assert header['state'] == 'SEALED'
    assert header['binding']['retention_domain'] == 'TASK_PAGED_REVIEW_V1'


def test_catalog_pins_current_and_historical_sources_without_legacy_hydration(sample, monkeypatch):
    store, first = create(sample)
    binding, current = revision(sample, store, first)
    stale_ref, stale_binding = orphan(sample)
    before = control_rows(sample)

    def forbidden_hydration(*args, **kwargs):
        pytest.fail('New paged-head GC must not hydrate legacy source dictionaries')

    monkeypatch.setattr(sample.state, 'decode', forbidden_hydration)
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack', forbidden_hydration)
    result = collect_pages(sample.state, prune=True)
    assert result['collected_captures'] == 1
    assert control_rows(sample) == before
    assert store.get(binding.task_ref, binding.owner) == current
    assert first['end'][POINTER] != current['end'][POINTER]
    for head in (first, current):
        for field in ('baseline', 'end'):
            assert_source(sample, head, field)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        _store(sample.state).resume(stale_ref, stale_binding)


@pytest.mark.parametrize('damage', [
    'current_catalog_mac', 'historical_catalog_mac', 'missing_catalog',
    'missing_historical_source', 'head_catalog_disagreement',
])
def test_any_bad_catalog_or_source_pin_aborts_the_entire_collection(sample, damage):
    store, first = create(sample)
    _, current = revision(sample, store, first)
    orphan(sample)
    if damage == 'missing_historical_source':
        with sqlite3.connect(_store(sample.state).path) as db:
            db.execute('DELETE FROM captures WHERE ref=?', (first['end'][POINTER]['ref'],))
    else:
        with sqlite3.connect(sample.state.path) as db:
            if damage.endswith('catalog_mac'):
                ref = (first if damage.startswith('historical') else current)['source_catalog']['ref']
                assert db.execute('UPDATE rm_pages SET mac=? WHERE ref=? AND page_seq=1',
                                  ('0' * 64, ref)).rowcount == 1
            else:
                raw = db.execute('SELECT data FROM security_tasks WHERE ref=?',
                                 (sample.binding.task_ref,)).fetchone()[0]
                head = json.loads(raw)
                if damage == 'missing_catalog':
                    head['source_catalog']['ref'] = 'rm1-' + 'f' * 32
                else:
                    head['end'][POINTER]['ref'] = first['end'][POINTER]['ref']
                db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=?',
                    (encode(head).decode(), digest(sample.state.key(), head), head['task_ref']))
    before_pages, before_control = page_rows(sample), control_rows(sample)
    with pytest.raises((ReviewMetadataError, SnapshotStoreError)):
        collect_pages(sample.state, prune=True)
    assert page_rows(sample) == before_pages
    assert control_rows(sample) == before_control


def test_new_head_retention_keeps_all_sources_while_old_task_prunes_normally(sample):
    old_binding = replace(sample.binding, task_ref='ts1-' + 'd' * 32)
    old = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY, task_ref=old_binding.task_ref,
        task_owner=old_binding.owner, task_key='old-task', workspace=str(sample.root), review_protocol=3,
        check_policy=POLICY, phase='ACTIVE', generation=0, created_at=sample.clock[0],
        baseline=snapshot('old value=1'), end=snapshot('old value=2'))
    sample.state.save(old, new=True)
    # The internal metadata domain requires an explicitly private database;
    # legacy TaskSecurityStore itself does not change its old creation mode.
    sample.state.path.chmod(0o600)
    with page_guard(sample.state.path.parent):
        with sqlite3.connect(sample.state.path) as db:
            raw = db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (old['task_ref'],)).fetchone()
        old_head = sample.state.head(raw)
    store, first = create(sample)
    _, current = revision(sample, store, first)
    sample.clock[0] += HARD_TTL + 1
    result = collect_pages(sample.state, prune=True)
    assert result['collected_captures'] == 2
    with sqlite3.connect(sample.state.path) as db:
        refs = {row[0] for row in db.execute('SELECT ref FROM security_tasks')}
    assert refs == {current['task_ref']}
    assert store.get(current['task_ref'], current['task_owner']) == current
    for head in (first, current):
        for field in ('baseline', 'end'):
            assert_source(sample, head, field)
    for field in ('baseline', 'end'):
        pointer = old_head[field][POINTER]
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
            _store(sample.state).resume(pointer['ref'], _binding(old_head, field, pointer['source']))


def test_legacy_queue_cannot_claim_support_for_a_paged_review_catalog(sample):
    _, head = create(sample)
    orphan(sample)
    queue = CloseoutQueue(sample.hooks, sample.root, now=lambda: sample.clock[0])
    with queue.transaction() as db:
        queue._put(db, head['task_ref'], dict(contract='task-closeout-queue-v1',
            snapshot_task_contract=REVIEW_CONTRACT, state='QUEUED', expires_at=sample.clock[0] + 86400))
    before_pages, before_control, before_queue = page_rows(sample), control_rows(sample), queue.rows()
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_REFERENCE_INVENTORY_INVALID$'):
        collect_pages(sample.state)
    assert page_rows(sample) == before_pages
    assert control_rows(sample) == before_control
    assert queue.rows() == before_queue


@pytest.mark.parametrize('prune', [False, True])
def test_missing_head_with_intact_fence_and_catalog_prevents_all_collection(sample, prune):
    _, head = create(sample)
    orphan(sample)
    with sqlite3.connect(sample.state.path) as db:
        assert db.execute('DELETE FROM security_tasks WHERE ref=?', (head['task_ref'],)).rowcount == 1
    # Only the signed head is missing. The authenticated metadata domain and
    # its original source catalog still record a task that cannot be retired.
    before_pages, before_control = page_rows(sample), control_rows(sample)
    try:
        result = collect_pages(sample.state, prune=prune)
    except ReviewMetadataError as error:
        assert error.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    else:
        pytest.fail(f"Missing original head was treated as retirement: {result}")
    assert page_rows(sample) == before_pages
    assert control_rows(sample) == before_control


@pytest.mark.parametrize('damage', ['missing_fence', 'foreign_owner', 'missing_task_table'])
def test_broken_head_fence_inventory_refuses_collection_without_changing_rows(sample, damage):
    _, head = create(sample)
    orphan(sample)
    with sqlite3.connect(sample.state.path) as db:
        if damage == 'missing_fence':
            assert db.execute('DELETE FROM rm_head_fences WHERE task_ref=?', (head['task_ref'],)).rowcount == 1
        elif damage == 'missing_task_table':
            db.execute('DROP TABLE security_tasks')
        else:
            head['task_owner'] = session_owner('cursor', 'isolated-foreign-owner')
            db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=?',
                (encode(head).decode(), digest(sample.state.key(), head), head['task_ref']))
    before_pages, before_control = page_rows(sample), control_rows(sample)
    with pytest.raises(ReviewMetadataError) as invalid:
        collect_pages(sample.state, prune=True)
    assert invalid.value.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE'
    assert page_rows(sample) == before_pages
    assert control_rows(sample) == before_control


@pytest.mark.parametrize('standalone_metadata', [False, True])
def test_old_domain_without_head_fences_keeps_its_existing_gc_behavior(sample, standalone_metadata):
    binding = sample.binding
    old = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY, task_ref=binding.task_ref,
        task_owner=binding.owner, task_key='old-task', workspace=str(sample.root), review_protocol=3,
        check_policy=POLICY, phase='ACTIVE', generation=0, created_at=sample.clock[0],
        baseline=snapshot('value=1'), end=snapshot('value=2'))
    sample.state.save(old, new=True)
    sample.state.path.chmod(0o600)
    if standalone_metadata:
        metadata = ReviewMetadataStore(sample.state.path, workspace_root=sample.root, key=sample.state.key())
        metadata.create(replace(binding, task_ref='ts1-' + 'e' * 32), 'unfenced',
                        limits=LIMITS, request_id='standalone-old')
    orphan(sample)
    before = control_rows(sample)
    assert 'rm_head_fences' not in before
    result = collect_pages(sample.state)
    assert result['collected_captures'] == 1
    assert control_rows(sample) == before
    if not standalone_metadata:
        assert not sample.state.path.with_name(sample.state.path.name + '.review-metadata.identity').exists()
