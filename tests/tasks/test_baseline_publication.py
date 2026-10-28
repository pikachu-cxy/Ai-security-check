"""Real opt-in baseline birth/copy/publication, fault recovery and no recapture."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotStore, SnapshotBinding, SnapshotStoreError
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks import baseline_publication as publisher
from security_runtime.tasks import capture_publication_store as control
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.snapshot_pages import _store
from security_runtime.tasks.snapshot_page_guard import page_guard


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail('Publishing frozen metadata must not start a scanner')


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def create(tmp_path, monkeypatch, *, files=1, scheduled=False):
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    for number in range(files):
        (root / ('source_%05d.py' % number)).write_text('value=%d\n' % number)
    hooks = HookStateStore(tmp_path / 'private')
    owner = session_owner('codex', 'baseline-publisher')
    service = TaskSecurityService(NoScanner(), hooks, owner=owner, now=lambda: 100.0,
                                  frozen_body_contexts=True, capture_sources=True)
    with monkeypatch.context() as schedule:
        if scheduled:
            # Delay only execution; the real task INSERT still creates the
            # signed intent. Never manufacture rows or adopt an older task.
            schedule.setattr(publisher, 'advance', publisher.status)
        response = service.begin(root, 'original-task', check_policy=POLICY)
    state = service.store(root)
    return SimpleNamespace(root=root, hooks=hooks, owner=owner, service=service,
        state=state, ref=response['task_ref'], response=response)


def head(sample):
    return sample.state._frozen_body_record(sample.ref, owner=sample.owner)


def finish(sample, turns=10):
    for _ in range(turns):
        result = sample.service.advance_baseline_publication(sample.root, sample.ref)
        if result['state'] == 'PUBLISHED':
            return result
        assert result['state'] == 'COPYING', result
    pytest.fail('Finite fixed baseline did not finish within its bounded turns')


def test_begin_small_baseline_is_published_without_review_identity_or_ledger(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch)
    result = sample.response['capture_publication']
    assert result['state'] == 'PUBLISHED', result
    record = head(sample)
    assert record['generation'] == 2
    assert 'review_ledger' not in record and 'review_plan' not in record
    assert record['baseline']['capture_source'] == result['receipt']['descriptor']['capture_source']
    assert record['baseline']['paged_entries'] == result['donor']
    assert sample.service.baseline_publication_status(sample.root, sample.ref) == result


@pytest.mark.parametrize('files', [257, 1001])
def test_real_file_baseline_finishes_all_pages_despite_continuing_live_edits(tmp_path, monkeypatch, files):
    sample = create(tmp_path, monkeypatch, files=files, scheduled=True)
    before = head(sample)
    first = sample.service.advance_baseline_publication(sample.root, sample.ref)
    assert first['state'] == 'COPYING' and first['progress']['entry_count'] == 256
    (sample.root / 'source_00000.py').write_text('changed_after_product_baseline=True\n')
    (sample.root / 'later.py').write_text('added_after_product_baseline=True\n')
    result = finish(sample)
    assert result['progress']['entry_count'] == files
    after = head(sample)
    descriptor = after['baseline'].pop('capture_source')
    after.pop('generation')
    before.pop('generation')
    assert after == before  # Activity, lease, original context and TTL unchanged.
    binding = publisher.CaptureSourceBinding(sample.ref, sample.owner, 'baseline', sample.ref, 3)
    with publisher.CaptureCanonicalView(_store(sample.state), {'capture_source': descriptor},
            capture_binding=binding, scratch_directory=publisher._scratch(sample.state)) as view:
        assert view.summary['entry_count'] == files
        assert view.summary['project_coverage'] == 'UNKNOWN'
        assert view.summary['external_bodies_available'] is False
        page = view.entries_page(limit_items=256)
        assert 'later.py' not in [entry['path'] for entry in page['entries']]
    hydrated = sample.service.load(sample.root, sample.ref)
    assert sample.service.before_lines(sample.root, hydrated, 'source_00000.py') == ['value=0']


@pytest.mark.parametrize('stage', ['create', 'append', 'seal', 'before_cas', 'control_rollback', 'reply'])
def test_committed_crash_boundaries_resume_same_task_source_and_cursor(tmp_path, monkeypatch, stage):
    sample = create(tmp_path, monkeypatch, files=257 if stage == 'append' else 1, scheduled=True)
    before = head(sample)
    original_status = sample.service.baseline_publication_status(sample.root, sample.ref)
    with monkeypatch.context() as fault:
        if stage in {'create', 'append', 'seal'}:
            name = {'create': 'create', 'append': 'append_page', 'seal': 'seal'}[stage]
            original = getattr(SnapshotStore, name)
            def crash(*args, **kwargs):
                original(*args, **kwargs)
                raise RuntimeError('simulated post-commit process interruption')
            fault.setattr(SnapshotStore, name, crash)
        elif stage in {'before_cas', 'reply'}:
            original = control.finalize
            def crash(*args, **kwargs):
                if stage == 'reply':
                    original(*args, **kwargs)
                raise RuntimeError('simulated control/reply interruption')
            fault.setattr(control, 'finalize', crash)
        else:
            original = control._put
            def crash(state, db, table, *args, **kwargs):
                if table == 'cp_receipts':
                    raise RuntimeError('simulated transaction rollback')
                return original(state, db, table, *args, **kwargs)
            fault.setattr(control, '_put', crash)
        with pytest.raises(RuntimeError):
            sample.service.advance_baseline_publication(sample.root, sample.ref)
    after_fault = sample.service.baseline_publication_status(sample.root, sample.ref)
    if stage != 'reply':
        assert 'capture_source' not in head(sample)['baseline']
        assert head(sample)['generation'] == before['generation']
    copied = []
    original_copy = SnapshotStore.strict_copy_page
    def observe(store, *args, **kwargs):
        copied.append(kwargs['after_seq'])
        return original_copy(store, *args, **kwargs)
    monkeypatch.setattr(SnapshotStore, 'strict_copy_page', observe)
    result = finish(sample)
    assert result['task_ref'] == sample.ref
    assert result['request_id'] == original_status['request_id']
    assert result['donor'] == original_status['donor']
    if after_fault['target_ref'] is not None:
        assert result['target_ref'] == after_fault['target_ref']
    if stage == 'append':
        assert copied == [256]  # Never reread the accepted first page.
    elif stage in {'seal', 'before_cas', 'control_rollback', 'reply'}:
        assert copied == []
    if stage == 'reply':
        assert result['receipt'] == after_fault['receipt']


def test_logical_pause_preserves_accepted_prefix_and_same_source_then_resumes(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch, files=257, scheduled=True)
    first = sample.service.advance_baseline_publication(sample.root, sample.ref)
    assert first['progress']['entry_count'] == 256
    store = _store(sample.state)
    with store._db() as db:
        used = store._usage(db)
    store.quota = used
    monkeypatch.setattr(publisher, '_store', lambda state: store)
    before = head(sample)
    paused = sample.service.advance_baseline_publication(sample.root, sample.ref)
    assert paused['state'] == 'WAITING_CAPACITY'
    assert paused['progress']['entry_count'] == 256
    assert paused['progress']['cursor'] == 'cp-copy-v1:256'
    assert head(sample) == before
    (sample.root / 'source_00256.py').write_text('changed=True\n')
    store.quota = 128_000_000
    copied = []
    original = store.strict_copy_page
    def observe(*args, **kwargs):
        copied.append(kwargs['after_seq'])
        return original(*args, **kwargs)
    monkeypatch.setattr(store, 'strict_copy_page', observe)
    result = finish(sample)
    assert result['target_ref'] == first['target_ref']
    assert result['request_id'] == first['request_id'] and copied == [256]


def test_ordinary_head_generation_change_does_not_lock_publication_to_birth_generation(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch, scheduled=True)
    original = sample.service.load(sample.root, sample.ref)
    saved = sample.state.save(original)
    assert saved['generation'] == 2
    result = finish(sample)
    assert result['receipt']['publication_generation'] == 3


def test_owner_mismatch_never_advances_the_intent(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch, scheduled=True)
    before = head(sample)
    other = TaskSecurityService(NoScanner(), sample.hooks, owner=session_owner('codex', 'other'),
        now=lambda: 100.0, frozen_body_contexts=True, capture_sources=True)
    from security_runtime.tasks.frozen_body_context import FrozenBodyContextUnavailable
    with pytest.raises(FrozenBodyContextUnavailable):
        other.advance_baseline_publication(sample.root, sample.ref)
    assert head(sample) == before
    assert sample.service.baseline_publication_status(sample.root, sample.ref)['state'] == 'RESERVED'


def test_actual_sqlite_full_rolls_back_page_then_resumes_original_progress(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch, files=257, scheduled=True)
    current = sample.service.baseline_publication_status(sample.root, sample.ref)
    store = _store(sample.state)
    scope = publisher.CaptureSourceBinding(sample.ref, sample.owner, 'baseline', sample.ref, 3)
    binding = publisher.raw_source_binding(scope, current['source'])
    with page_guard(sample.state.path.parent):
        target = store.create(binding)
        current = control.admit_target(sample.state, sample.ref, owner=sample.owner,
            request_id=current['request_id'], expected_intent_generation=current['intent_generation'],
            target_ref=target['ref'])
    with sqlite3.connect(store.path) as db:
        pages = db.execute('PRAGMA page_count').fetchone()[0]
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
        assert db.execute('PRAGMA freelist_count').fetchone()[0] < 2
        original_usage = store._usage(db)
    store.database_quota = pages * page_size
    monkeypatch.setattr(publisher, '_store', lambda state: store)
    paused = sample.service.advance_baseline_publication(sample.root, sample.ref)
    assert paused['state'] == 'WAITING_CAPACITY'
    assert paused['reason_code'] == 'SNAPSHOT_WAITING_CAPACITY'
    header = store.strict_header(target['ref'], binding)
    assert header['state'] == 'CAPTURING'  # Physical rollback cannot commit WAITING.
    assert header['entry_count'] == 0 and header['cursor'] is None
    with sqlite3.connect(store.path) as db:
        assert store._usage(db) == original_usage
    store.database_quota = 128_000_000
    result = finish(sample)
    assert result['target_ref'] == target['ref'] and result['request_id'] == current['request_id']


def test_two_producers_and_collector_preserve_one_source_and_receipt(tmp_path, monkeypatch):
    from security_runtime.tasks.snapshot_gc import collect_pages
    sample = create(tmp_path, monkeypatch, files=257, scheduled=True)
    before = sample.service.baseline_publication_status(sample.root, sample.ref)
    with ThreadPoolExecutor(max_workers=3) as workers:
        futures = [workers.submit(sample.service.advance_baseline_publication, sample.root, sample.ref)
                   for _ in range(2)]
        collector = workers.submit(collect_pages, sample.state)
        results = [future.result() for future in futures]
        assert collector.result()['collected_captures'] == 0
    assert all(result['state'] in {'COPYING', 'PUBLISHED', 'RETRY_REQUIRED', 'WAITING_CAPACITY'}
               for result in results)
    result = finish(sample)
    assert result['request_id'] == before['request_id'] and result['donor'] == before['donor']
    with sqlite3.connect(sample.state.path) as db:
        assert db.execute('SELECT count(*) FROM cp_owners').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM cp_intents').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM cp_receipts').fetchone()[0] == 1


def test_direct_save_validates_unreferenced_raw_content_before_any_expired_head_pruning(tmp_path, monkeypatch):
    sample = create(tmp_path, monkeypatch)
    store = _store(sample.state)
    binding = SnapshotBinding('collectible-orphan', sample.owner, 'independent-source', 3,
        retention_domain='TASK_PAGES_GC_V1')
    with page_guard(sample.state.path.parent):
        orphan = store.create(binding)['ref']
        store.append_page(orphan, binding, [('orphan.py', b'original orphan body')],
                          expected_cursor=None, cursor='1')
        store.seal(orphan, binding, expected_files=1, inventory_complete=True)
    sha = hashlib.sha256(b'original orphan body').hexdigest()
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE objects SET body=? WHERE hash=?', (b'changed! orphan body', sha))
    with sqlite3.connect(sample.state.path) as db:
        before = tuple(db.iterdump())
    raw_before = store.path.read_bytes()
    sample.state.now = lambda: 100.0 + 31 * 24 * 3600
    from security_runtime.tasks.security_state import CONTRACT
    candidate = dict(contract=CONTRACT, task_ref='ts1-' + 'f' * 32, task_key='new-task',
        workspace=str(sample.root), generation=0, phase='REVIEWING', review_protocol=3,
        created_at=sample.state.now())
    with pytest.raises(SnapshotStoreError) as error:
        sample.state._save(candidate, new=True)
    assert error.value.reason_code == 'SNAPSHOT_CONTENT_UNAVAILABLE'
    with sqlite3.connect(sample.state.path) as db:
        assert tuple(db.iterdump()) == before
    assert store.path.read_bytes() == raw_before


@pytest.mark.parametrize('suffix', ['BUSY', 'WAITING_CAPACITY'])
def test_recoverable_lost_reply_returns_actual_published_receipt(tmp_path, monkeypatch, suffix):
    sample = create(tmp_path, monkeypatch, scheduled=True)
    original = control.finalize
    def lost_reply(*args, **kwargs):
        original(*args, **kwargs)
        raise control.CapturePublicationError(suffix)
    with monkeypatch.context() as fault:
        fault.setattr(control, 'finalize', lost_reply)
        result = sample.service.advance_baseline_publication(sample.root, sample.ref)
    assert result['state'] == 'PUBLISHED'
    assert result == sample.service.baseline_publication_status(sample.root, sample.ref)
    assert head(sample)['generation'] == result['receipt']['publication_generation'] == 2
