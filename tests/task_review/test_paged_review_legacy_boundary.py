"""Old consumers cannot turn a new bounded head into an empty legacy task."""
import hashlib
import sqlite3

import pytest

from security_runtime.closeout_state import encode
from security_runtime.hook_state import HookStateStore
from security_runtime.task_review.metadata_store import ReviewMetadataBinding, ReviewMetadataError
from security_runtime.task_review.paged_task_store import PagedReviewTaskStore, source_binding
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security_state import CONTRACT, TTL, TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import (
    GC_CONTRACT, GC_POLICY, REVIEW_CONTRACT, POINTER, _store, pack, unpack,
)
from paged_review_source_helpers import pack_review_sources


LIMITS = dict(source_bytes=1000, navigation_bytes=1000, control_bytes=1000,
              reads=100, total_bytes=3000)


def snapshot(label):
    return dict(hashes={'source.py': hashlib.sha256(label.encode()).hexdigest()},
                texts={'source.py': [label]}, inventory=['source.py'],
                read_priority=['source.py'], preimages={}, line_counts={'source.py': 1},
                text_truncations={}, text_unavailable={}, limitations=[],
                read_limitations=[], inventory_complete=True, redaction_version=3)


def legacy(state, owner, clock, number):
    return dict(contract=CONTRACT, task_ref='ts1-' + f'{number:032x}',
                task_key=f'legacy-{number}', workspace=str(state.root),
                task_owner=owner, phase='COMPLETE', generation=0,
                created_at=clock[0], review_protocol=3, baseline=snapshot('legacy'))


@pytest.fixture
def mixed(tmp_path):
    root = tmp_path.resolve() / 'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path.resolve() / 'private')
    hooks.key(root)
    clock = [1000.0]
    state = TaskSecurityStore(hooks, root, now=lambda: clock[0])
    owner = session_owner('codex', 'paged-legacy-retention-fixture')
    old = state.save(legacy(state, owner, clock, 1), new=True)
    # New metadata admission requires an already private task database. The
    # old writer itself does not promise these file/directory modes.
    state.path.parent.chmod(0o700)
    state.path.chmod(0o600)
    ref = 'ts1-' + 'b' * 32
    candidate = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                     task_ref=ref, task_owner=owner,
                     baseline=snapshot('original-before'), end=snapshot('first-end'))
    binding = ReviewMetadataBinding(ref, owner, 1,
                                   hashlib.sha256(b'first-fixed-version').hexdigest())
    current = PagedReviewTaskStore(state)
    # The source producer retains the existing GC guard through publication.
    with page_guard(state.path.parent, create=True):
        sources = pack_review_sources(state, candidate)
        current.create(binding, task_key='new-bounded-head', baseline=sources['baseline'],
                       end=sources['end'], limits=LIMITS, request_id='create-new')
    return state, current, owner, clock, old, current.get(ref, owner), sources


def row(state, ref):
    with sqlite3.connect(state.path) as db:
        return db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (ref,)).fetchone()


def test_old_readers_and_writers_reject_new_head_without_repacking_or_mutation(mixed):
    state, current, owner, _, old, head, fixed = mixed
    assert head['contract'] == REVIEW_CONTRACT
    before = row(state, head['task_ref']), row(state, old['task_ref'])
    assert before[0] is not None
    operations = (
        lambda: state.head(before[0]),
        lambda: state.decode(before[0]),
        lambda: state.get(head['task_ref']),
        lambda: state.save(head),
        lambda: state._save(head),
        lambda: pack(state, head),
        lambda: unpack(state, head),
    )
    for operation in operations:
        with pytest.raises(ValueError, match='Paged review heads require'):
            operation()
    assert (row(state, head['task_ref']), row(state, old['task_ref'])) == before
    assert current.get(head['task_ref'], owner) == head
    for field in ('baseline', 'end'):
        pointer = fixed[field][POINTER]
        binding = ReviewMetadataBinding(head['task_ref'], owner, head['review_revision'],
                                        head['snapshot_id'], head['representation_version'])
        assert _store(state).resume(pointer['ref'], source_binding(binding, field, pointer['source']))['state'] == 'SEALED'


def test_old_ttl_pruning_preserves_new_head_and_sources_while_pruning_old_task(mixed):
    state, current, owner, clock, old, head, fixed = mixed
    original = row(state, head['task_ref'])
    clock[0] += TTL + 1
    # Exercise the old writer's retention and authenticated history counter,
    # not just the standalone collector's new-head branch.
    state.save(legacy(state, owner, clock, 2), new=True)
    assert row(state, old['task_ref']) is None
    assert row(state, head['task_ref']) == original
    collect_pages(state, prune=True)
    assert current.get(head['task_ref'], owner) == head
    assert row(state, head['task_ref']) == original
    for field in ('baseline', 'end'):
        pointer = fixed[field][POINTER]
        binding = ReviewMetadataBinding(head['task_ref'], owner, head['review_revision'],
                                        head['snapshot_id'], head['representation_version'])
        assert _store(state).resume(pointer['ref'], source_binding(binding, field, pointer['source']))['state'] == 'SEALED'
    assert len(encode(head)) <= 32_768


def test_new_task_rejects_sealed_sources_owned_by_the_legacy_collector(mixed):
    state, current, owner, _, old, head, _ = mixed
    ref = 'ts1-' + 'c' * 32
    template = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                    task_ref=ref, task_owner=owner,
                    baseline=snapshot('legacy-domain-before'), end=snapshot('legacy-domain-end'))
    binding = ReviewMetadataBinding(ref, owner, 1, hashlib.sha256(b'rejected-old-domain').hexdigest())
    with page_guard(state.path.parent):
        fixed = pack(state, template)
        sources = {field: {key: fixed[field][key] for key in (POINTER, 'redaction_version')}
                   for field in ('baseline', 'end')}
        with sqlite3.connect(state.path) as db:
            before = tuple(db.iterdump())
        with pytest.raises(ReviewMetadataError, match='^REVIEW_METADATA_HISTORY_UNAVAILABLE$'):
            current.create(binding, task_key='old-domain-must-not-be-adopted',
                baseline=sources['baseline'], end=sources['end'], limits=LIMITS,
                request_id='reject-old-domain')
        with sqlite3.connect(state.path) as db:
            assert tuple(db.iterdump()) == before
    assert row(state, ref) is None
    assert current.get(head['task_ref'], owner) == head
    assert state.get(old['task_ref']) is not None
