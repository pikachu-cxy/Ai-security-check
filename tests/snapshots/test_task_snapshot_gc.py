"""Task publication, retained risks and queue references fence snapshot GC."""
import copy
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3
import subprocess
import threading

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError, TASK_PAGES_GC_DOMAIN
from security_runtime.tasks.activity import ActivityStore, HARD_TTL, IDLE_TTL, POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.projection import _basis, enqueue, reconcile_pending
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import CONTRACT, TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY, POINTER, _binding, _store
from test_task_security import LedgerRuntime


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail('Page maintenance must not invoke scanners')


@pytest.fixture
def sample(tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'project'
    root.mkdir()
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path.resolve() / 'runtime'))
    hooks = HookStateStore(tmp_path.resolve() / 'private-state')
    hooks.key(root)
    clock = [1_000_000.0]
    owner = session_owner('codex', 'gc-integration')
    state = TaskSecurityStore(hooks, root, now=lambda: clock[0])
    service = TaskSecurityService(NoScanner(), hooks, now=lambda: clock[0], owner=owner)
    return root, hooks, clock, owner, state, service


def snapshot(label):
    sha = hashlib.sha256(label.encode()).hexdigest()
    return dict(hashes={'source.py': sha}, texts={'source.py': [label]},
                inventory=['source.py'], read_priority=['source.py'],
                preimages={}, line_counts={'source.py': 1}, text_truncations={},
                text_unavailable={}, limitations=[], read_limitations=[],
                inventory_complete=True, redaction_version=3)


def record(sample, index=1, *, end='end-one', managed=True):
    root, _, clock, owner, _, _ = sample
    value = dict(contract=GC_CONTRACT if managed else CONTRACT,
                 capture_policy=GC_POLICY if managed else 'BATCHED_FILES_V1',
                 task_ref='ts1-' + f'{index:032x}', task_key=f'task-{index}',
                 workspace=str(root), task_owner=owner, check_policy=POLICY,
                 phase='ACTIVE', generation=0, created_at=clock[0], review_protocol=3,
                 baseline=snapshot('original'))
    if end is not None:
        value['end'] = snapshot(end)
    return value


def save(sample, index=1, **kwargs):
    state = sample[4]
    value = record(sample, index, **kwargs)
    state.save(value, new=True)
    return state.get(value['task_ref'])


def pointers(value):
    return {field: value[field][POINTER]['ref'] for field in ('baseline', 'end') if field in value}


def page_state(state):
    store = _store(state)
    with sqlite3.connect(store.path) as db:
        return {table: db.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()
                for table in ('captures', 'entries', 'objects', 'usage')}


def orphan(state, label='orphan', *, domain=TASK_PAGES_GC_DOMAIN):
    store = _store(state)
    owner = SnapshotBinding('orphan:' + label, session_owner('codex', 'gc-orphan'),
                            'source:' + label, 3, retention_domain=domain)
    with page_guard(state.path.parent, create=True):
        ref = store.create(owner)['ref']
        store.append_page(ref, owner, [('orphan.py', label.encode())],
                          expected_cursor=None, cursor='one')
        store.seal(ref, owner, expected_files=1, inventory_complete=True)
    return ref, owner


def test_new_product_task_baseline_and_end_are_gc_managed(sample):
    root, hooks, clock, owner, _, _ = sample
    subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
    (root / 'source.py').write_text('value = 1\n', encoding='utf-8')
    service = TaskSecurityService(LedgerRuntime(), hooks, now=lambda: clock[0], owner=owner)
    ref = service.begin(root, 'actual-product-task', check_policy=POLICY)['task_ref']
    (root / 'source.py').write_text('value = 2\n', encoding='utf-8')
    assert service.finish(root, ref)['status'] == 'READY'
    value = service.load(root, ref)
    assert value['contract'] == GC_CONTRACT and value['capture_policy'] == GC_POLICY
    store = _store(service.store(root))
    for field in ('baseline', 'end'):
        pointer = value[field][POINTER]
        header = store.resume(pointer['ref'], _binding(value, field, pointer['source']))
        assert header['state'] == 'SEALED'
        assert header['binding']['retention_domain'] == TASK_PAGES_GC_DOMAIN
    assert service.before_lines(root, value, 'source.py') == ['value = 1']
    assert service.end_lines(root, value, 'source.py') == ['value = 2']


def test_legacy_pages_remain_unmanaged_and_are_never_collected(sample):
    state = sample[4]
    old = save(sample, managed=False)
    old_refs = pointers(old)
    save(sample, index=2)
    old_orphan, old_binding = orphan(state, 'legacy', domain=None)
    managed_orphan, managed_binding = orphan(state, 'managed')
    result = collect_pages(state)
    assert result['collected_captures'] == 1
    assert pointers(state.get(old['task_ref'])) == old_refs
    assert _store(state).read_content(old_orphan, old_binding, 'orphan.py') == b'legacy'
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        _store(state).resume(managed_orphan, managed_binding)


def test_replaced_end_collects_only_unreferenced_old_version(sample):
    state = sample[4]
    original = save(sample)
    before = pointers(original)
    changed = copy.deepcopy(original)
    changed['end'] = snapshot('end-two')
    state.save(changed)
    current = state.get(original['task_ref'])
    assert pointers(current)['baseline'] == before['baseline']
    assert pointers(current)['end'] != before['end']
    result = collect_pages(state)
    assert result['collected_captures'] == 1
    assert pointers(state.get(original['task_ref'])) == pointers(current)
    old = original['end'][POINTER]
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_HISTORY_UNAVAILABLE$'):
        _store(state).resume(old['ref'], _binding(original, 'end', old['source']))


def test_expiry_preserves_pending_risks_before_releasing_source_pages(sample):
    root, hooks, clock, _, state, service = sample
    candidate = record(sample)
    candidate['phase'] = 'READY'
    candidate['static'] = dict(scan_id='fixture-scan', findings=[
        dict(id='retained-risk', title='Original risk', category='authorization', file_path='source.py')])
    candidate = enqueue(candidate)
    state.save(candidate, new=True)
    original = state.get(candidate['task_ref'])
    basis = _basis(original)
    clock[0] += IDLE_TTL + 1
    result = collect_pages(state, prune=True)
    assert result['collected_captures'] == 2
    assert state.get(candidate['task_ref']) is None
    retained = state.pending_projections()
    assert len(retained) == 1 and _basis(retained[0]) == basis
    assert POINTER not in encode(retained).decode()
    assert retained[0]['end']['hashes'] == original['end']['hashes']
    assert page_state(state)['captures'] == []
    with hooks.lock(root) as acquired:
        assert acquired
        recovered = reconcile_pending(service, root)
    assert recovered['applied'] == 1 and not recovered['pending']
    risk = TaskRiskLedger(hooks, root).read(candidate['task_ref'])
    assert risk[candidate['task_ref'] + ':retained-risk']['original_hashes'] == original['end']['hashes']


@pytest.mark.parametrize('running', [False, True])
def test_queue_pins_old_end_until_expiry_or_running_work_finishes(sample, running):
    _, hooks, clock, owner, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    queue.submit(original, original['end'], configuration={})
    if running:
        assert queue.claim(original['task_ref'], 'worker')['state'] == 'RUNNING'
        clock[0] += 86401  # Its initial queue retention expired while work was running.
    with queue.transaction() as db:
        queue._put(db, '$worker', dict(expires_at=clock[0]+120, lease_owner='dispatcher'))
    changed = copy.deepcopy(original)
    changed['end'] = snapshot('current-end')
    state.save(changed)
    assert collect_pages(state)['collected_captures'] == 0
    pointer = original['end'][POINTER]
    assert _store(state).resume(pointer['ref'], _binding(original, 'end', pointer['source']))['state'] == 'SEALED'
    assert queue.read(original['task_ref'])['owner'] == owner
    with queue.transaction() as db:
        row = queue._get(db, original['task_ref'])
        queue._put(db, row['key'], dict(row, state='EXPIRED', expires_at=clock[0]-1))
    # v2 also owns an indexed end projection, separate from the original end.
    assert collect_pages(state)['collected_captures'] == 2


def test_task_retention_expires_running_queue_before_pruning_and_reclaims_on_next_pass(sample):
    _, hooks, clock, _, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    submitted = queue.submit(original, original['end'], configuration={})
    assert submitted['baseline_pages'] == {POINTER: original['baseline'][POINTER]}
    claimed = queue.claim(original['task_ref'], 'original-worker')
    assert claimed['state'] == 'RUNNING'
    clock[0] += IDLE_TTL + 1

    maintained = collect_pages(state, prune=True)
    assert maintained['collected_captures'] == 0
    assert state.get(original['task_ref']) is None
    expired = queue.read(original['task_ref'])
    assert expired['state'] == 'EXPIRED'
    assert expired['reason'] == 'ORIGINAL_TASK_RETENTION_EXPIRED'
    assert expired['generation'] == claimed['generation'] + 1
    assert expired['lease_owner'] is None and expired['lease_until'] == 0
    assert expired['finished_at'] == clock[0]
    assert not queue.current(claimed) and not queue.renew(claimed)
    assert not queue.finish(claimed, 'READY_FOR_REVIEW')
    store = _store(state)
    for field in ('baseline', 'end'):
        pointer = original[field][POINTER]
        assert store.resume(pointer['ref'], _binding(original, field, pointer['source']))['state'] == 'SEALED'

    # This pass conservatively retains its already-inventoried running pin.
    # The next pass observes the explicit terminal state and releases it.
    assert collect_pages(state, prune=True)['collected_captures'] == 3
    assert page_state(state)['captures'] == []


@pytest.mark.parametrize('queue_state', ['QUEUED', 'RETRY_WAIT'])
@pytest.mark.parametrize('retention', ['idle', 'hard'])
def test_save_prune_expires_pending_queue_before_releasing_original_task(sample, monkeypatch,
                                                                       queue_state, retention):
    _, hooks, clock, _, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    queue.submit(original, original['end'], configuration={})
    if queue_state == 'RETRY_WAIT':
        claimed = queue.claim(original['task_ref'], 'retry-worker')
        assert queue.finish(claimed, 'RETRY_WAIT', 'FIXTURE_RETRY')
    pending = queue.read(original['task_ref'])
    assert pending['state'] == queue_state
    clock[0] += (IDLE_TTL if retention == 'idle' else HARD_TTL) + 1
    if retention == 'hard':
        # Fresh activity cannot extend the task's absolute retention ceiling.
        ActivityStore(hooks, state.root, now=lambda: clock[0]).touch(
            original['task_ref'], clock[0], original['phase'])
    assert state.expired(original)

    # A legacy-compatible save bypasses the managed GC pre-pass, exercising
    # TaskSecurityStore._save's own expiry/prune path directly.
    later = record(sample, index=2, managed=False, end=None)
    with monkeypatch.context() as guarded:
        guarded.setattr('security_runtime.tasks.snapshot_gc.collect_pages',
                        lambda *args, **kwargs: pytest.fail('Use the save transaction prune path'))
        state.save(later, new=True)
    assert state.get(original['task_ref']) is None
    expired = queue.read(original['task_ref'])
    assert expired['state'] == 'EXPIRED' and expired['reason'] == 'ORIGINAL_TASK_RETENTION_EXPIRED'
    assert expired['generation'] == pending['generation'] + 1
    assert expired['lease_owner'] is None and expired['lease_until'] == 0
    assert expired['finished_at'] == clock[0]
    assert len(page_state(state)['captures']) == 4  # Originals, indexed end, and later legacy page.
    assert collect_pages(state)['collected_captures'] == 3
    assert state.get(later['task_ref'])['baseline']['hashes'] == later['baseline']['hashes']


@pytest.mark.parametrize('invalid', ['missing_baseline_pointer', 'already_collected'])
def test_new_managed_queue_rejects_missing_or_collected_original_page_pins(sample, invalid):
    _, hooks, clock, _, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    if invalid == 'missing_baseline_pointer':
        del original['baseline'][POINTER]
        expected = '^Original baseline page reference required$'
    else:
        clock[0] += IDLE_TTL + 1
        assert collect_pages(state, prune=True)['collected_captures'] == 2
        assert state.get(original['task_ref']) is None
        expected = '^Original task unavailable; never reconstruct a baseline$'
    before = page_state(state)
    with pytest.raises(ValueError, match=expected):
        queue.submit(original, original['end'], configuration={})
    assert page_state(state) == before
    assert queue.read(original['task_ref']) is None
    assert not queue.path.exists()


@pytest.mark.parametrize('queue_terminal', ['EXPIRED', 'READY_FOR_REVIEW'])
def test_late_queue_submit_cannot_revive_pruned_task_even_while_original_pages_exist(sample, monkeypatch,
                                                                                   queue_terminal):
    _, hooks, clock, _, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    queue.submit(original, original['end'], configuration={})
    claimed = queue.claim(original['task_ref'], 'original-worker')
    if queue_terminal == 'READY_FOR_REVIEW':
        assert queue.finish(claimed, 'READY_FOR_REVIEW')
    clock[0] += IDLE_TTL + 1
    with monkeypatch.context() as guarded:
        guarded.setattr('security_runtime.tasks.snapshot_gc.collect_pages',
                        lambda *args, **kwargs: pytest.fail('Keep original pages while pruning the expired task head'))
        state.save(record(sample, index=2, managed=False, end=None), new=True)
    assert state.get(original['task_ref']) is None
    terminal = queue.read(original['task_ref'])
    assert terminal['state'] == queue_terminal
    if queue_terminal == 'EXPIRED':
        assert terminal['reason'] == 'ORIGINAL_TASK_RETENTION_EXPIRED'
    # Both cases retain genuine sealed bytes here. Missing source cannot be
    # the reason for rejecting a stale caller's attempted publication.
    for field in ('baseline', 'end'):
        pointer = original[field][POINTER]
        assert _store(state).resume(pointer['ref'], _binding(original, field, pointer['source']))['state'] == 'SEALED'
    before = page_state(state)
    with pytest.raises(ValueError, match='^Original task unavailable; never reconstruct a baseline$'):
        queue.submit(original, original['end'], configuration={})
    assert queue.read(original['task_ref']) == terminal
    assert page_state(state) == before


@pytest.mark.parametrize('phase', ['COMPLETE', 'INCOMPLETE', 'NO_CHANGES'])
def test_current_terminal_task_head_rejects_cached_active_queue_submission(sample, phase):
    _, hooks, clock, _, state, _ = sample
    cached = save(sample)
    terminal = copy.deepcopy(cached)
    terminal['phase'] = phase
    state.save(terminal)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    before = page_state(state)
    with pytest.raises(ValueError, match='^Original task unavailable; never reconstruct a baseline$'):
        queue.submit(cached, cached['end'], configuration={})
    assert not queue.path.exists()
    assert page_state(state) == before
    assert state.get(cached['task_ref'])['phase'] == phase


@pytest.mark.parametrize('mismatch', ['owner', 'baseline', 'head_signature'])
def test_queue_submission_checks_current_head_identity_before_publishing_pin(sample, mismatch):
    _, hooks, clock, _, state, _ = sample
    current = save(sample)
    supplied = copy.deepcopy(current)
    expected = '^Original baseline changed$'
    if mismatch == 'owner':
        supplied['task_owner'] = session_owner('cursor', 'foreign-caller')
    elif mismatch == 'baseline':
        supplied['baseline'][POINTER] = copy.deepcopy(current['end'][POINTER])
    else:
        with sqlite3.connect(state.path) as db:
            db.execute('UPDATE security_tasks SET mac=?', ('0' * 64,))
        expected = '^Task state cannot be verified$'
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    before = page_state(state)
    with pytest.raises(ValueError, match=expected):
        queue.submit(supplied, supplied['end'], configuration={})
    assert not queue.path.exists()
    assert page_state(state) == before


def test_expired_but_unpruned_current_head_rejects_queue_publication(sample):
    _, hooks, clock, _, state, _ = sample
    cached = save(sample)
    clock[0] += IDLE_TTL + 1
    with sqlite3.connect(state.path) as db:
        assert db.execute('SELECT count(*) FROM security_tasks').fetchone()[0] == 1
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    before = page_state(state)
    with pytest.raises(ValueError, match='^Original task unavailable; never reconstruct a baseline$'):
        queue.submit(cached, cached['end'], configuration={})
    assert not queue.path.exists()
    assert page_state(state) == before


@pytest.mark.parametrize('damage', ['task_mac', 'queue_mac', 'task_missing_ref', 'queue_missing_ref'])
def test_bad_reference_inventory_causes_zero_page_deletion(sample, damage):
    _, hooks, clock, _, state, _ = sample
    original = save(sample)
    queue = CloseoutQueue(hooks, state.root, now=lambda: clock[0])
    queue.submit(original, original['end'], configuration={})
    orphan(state, 'would-be-collected')
    if damage.startswith('task'):
        with sqlite3.connect(state.path) as db:
            if damage == 'task_mac':
                db.execute('UPDATE security_tasks SET mac=?', ('0' * 64,))
            else:
                value = json.loads(db.execute('SELECT data FROM security_tasks').fetchone()[0])
                value['baseline'][POINTER]['ref'] = 'ws2-' + 'f' * 32
                db.execute('UPDATE security_tasks SET data=?,mac=?',
                           (encode(value).decode(), digest(state.key(), value)))
    else:
        with sqlite3.connect(queue.path) as db:
            if damage == 'queue_mac':
                db.execute('UPDATE records SET mac=?', ('0' * 64,))
            else:
                value = json.loads(db.execute('SELECT data FROM records').fetchone()[0])
                value['end'][POINTER]['ref'] = 'ws2-' + 'f' * 32
                db.execute('UPDATE records SET data=?,mac=?',
                           (encode(value).decode(), digest(queue._key(), value)))
    before = page_state(state)
    with pytest.raises(ValueError):
        collect_pages(state)
    assert page_state(state) == before


def test_failed_cas_orphan_can_be_collected_without_changing_published_head(sample):
    state = sample[4]
    original = save(sample)
    stale = copy.deepcopy(original)
    current = copy.deepcopy(original)
    current['end'] = snapshot('published-current-end')
    state.save(current)
    published = state.get(original['task_ref'])
    with sqlite3.connect(state.path) as db:
        before_head = db.execute('SELECT data,mac FROM security_tasks').fetchall()
    stale['end'] = snapshot('never-published-end')
    with pytest.raises(ValueError, match='^Task changed concurrently; read current task first$'):
        state.save(stale)
    with sqlite3.connect(state.path) as db:
        assert db.execute('SELECT data,mac FROM security_tasks').fetchall() == before_head
    assert state.get(original['task_ref']) == published
    live = set(pointers(published).values())
    stored = {row[0] for row in page_state(state)['captures']}
    assert len(stored - live) == 1
    assert collect_pages(state)['collected_captures'] == 1
    assert state.get(original['task_ref']) == published


def collector_after_attempt(state, monkeypatch, attempt, entered):
    import security_runtime.tasks.snapshot_gc as gc
    actual = gc.page_guard

    @contextmanager
    def observed_guard(directory, **kwargs):
        if kwargs.get('exclusive'):
            attempt.set()
            kwargs['wait_seconds'] = 10
        with actual(directory, **kwargs):
            entered.set()
            yield

    monkeypatch.setattr(gc, 'page_guard', observed_guard)
    return lambda: collect_pages(state)


def test_gc_waits_for_sealed_pages_to_be_published_in_task_head(sample, monkeypatch):
    state = sample[4]
    save(sample)
    pending = record(sample, index=2, end=None)
    sealed, release, attempted, exclusive = (threading.Event() for _ in range(4))
    actual = SnapshotStore.seal

    def paused_seal(self, ref, binding, **kwargs):
        header = actual(self, ref, binding, **kwargs)
        if binding.task_ref.startswith(pending['task_ref'] + ':'):
            sealed.set()
            assert release.wait(10)
        return header

    monkeypatch.setattr(SnapshotStore, 'seal', paused_seal)
    # Start publication before instrumenting the collector to avoid observing
    # the save's own maintenance pass as the concurrent collector.
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(state.save, pending, new=True)
        try:
            assert sealed.wait(10)
            collect = collector_after_attempt(state, monkeypatch, attempted, exclusive)
            maintenance = pool.submit(collect)
            assert attempted.wait(10)
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                with page_guard(state.path.parent, exclusive=True, wait_seconds=0):
                    pytest.fail('Sealed but unpublished pages require publication protection')
            assert not exclusive.is_set()
        finally:
            release.set()
        writer.result(timeout=10)
        assert maintenance.result(timeout=10)['collected_captures'] == 0
    assert state.get(pending['task_ref'])['baseline']['hashes'] == pending['baseline']['hashes']


def test_gc_waits_for_readers_to_finish_unpacking_original_pages(sample, monkeypatch):
    import security_runtime.tasks.snapshot_pages as pages
    state = sample[4]
    original = save(sample)
    reading, release, attempted, exclusive = (threading.Event() for _ in range(4))
    actual = pages.unpack

    def paused_unpack(state, value):
        if value.get('task_ref') == original['task_ref']:
            reading.set()
            assert release.wait(10)
        return actual(state, value)

    monkeypatch.setattr(pages, 'unpack', paused_unpack)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(state.get, original['task_ref'])
        try:
            assert reading.wait(10)
            collect = collector_after_attempt(state, monkeypatch, attempted, exclusive)
            maintenance = pool.submit(collect)
            assert attempted.wait(10)
            with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_STORE_BUSY$'):
                with page_guard(state.path.parent, exclusive=True, wait_seconds=0):
                    pytest.fail('An active page reader must exclude GC')
            assert not exclusive.is_set()
        finally:
            release.set()
        assert reader.result(timeout=10) == original
        assert maintenance.result(timeout=10)['collected_captures'] == 0
