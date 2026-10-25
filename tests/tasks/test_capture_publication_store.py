"""Control transactions use real original capture/body writers, not review IDs."""
from contextlib import closing
import copy
import hashlib
from pathlib import Path
import sqlite3
import tracemalloc
from types import SimpleNamespace
import uuid

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import HookStateStore
from security_runtime.task_review.capture_source_binding import CaptureSourceBinding, raw_source_binding, source_descriptor
from security_runtime.task_review.snapshot_source import CaptureCanonicalView
from security_runtime.tasks import capture_publication_store as publication
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.capture_source_profile import POLICY as SOURCE_POLICY, PROFILE as SOURCE_PROFILE, PROFILE_FIELD as SOURCE_FIELD
from security_runtime.tasks.frozen_body_context import CONTEXT_FIELD, PROFILE, PROFILE_FIELD, build_context, root_identity
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import TaskPreimageStore
from security_runtime.tasks.security import capture
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, pack, _binding, _store


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def _state(tmp_path):
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    (root / 'first.py').write_text('first=1\n')
    (root / 'last.py').write_text('last=2\n')
    hooks = HookStateStore(tmp_path / 'private')
    hooks.key(root)
    hooks.prepare_database(root, 'task-security.db')
    clock = [100.0]
    state = TaskSecurityStore(hooks, root, now=lambda: clock[0])
    return SimpleNamespace(root=root, hooks=hooks, state=state, clock=clock,
                           owner=session_owner('codex', 'control-transactions'))


def _insert(db, state, head):
    db.execute('INSERT INTO security_tasks VALUES(?,?,?,?,?,?)', (head['task_ref'], head['task_key'],
        head['phase'], head['created_at'], encode(head).decode(), digest(state.key(), head)))


def _new(sample):
    ref = 'ts1-' + uuid.uuid4().hex
    _, identity = root_identity(sample.root)
    bodies = TaskPreimageStore(sample.hooks, sample.root, now=lambda: sample.clock[0], namespace='closeout')
    with bodies.writer(ref, paged=True) as writer:
        baseline = capture(sample.root, preimage_writer=writer, batched_files=True)
    baseline[CONTEXT_FIELD] = build_context(sample.hooks, sample.root, baseline, writer=writer,
        task_ref=ref, owner=sample.owner, expected_root_identity=identity, now=lambda: sample.clock[0])
    value = dict(contract=GC_CONTRACT, task_ref=ref, task_key=ref, workspace=str(sample.root),
        generation=1, phase='ACTIVE', created_at=sample.clock[0], activity_at=sample.clock[0],
        review_protocol=3, check_policy=POLICY, task_owner=sample.owner, baseline=baseline,
        capture_policy=SOURCE_POLICY, **{SOURCE_FIELD: SOURCE_PROFILE, PROFILE_FIELD: PROFILE},
        review_ledger={'contract': 'unchanged-test-ledger', 'spent': 17})
    with page_guard(sample.state.path.parent):
        packed = pack(sample.state, value)
    return packed, value


def _birth(sample):
    publication.prepare_storage(sample.state)
    packed, value = _new(sample)
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        head, value = publication.birth_in_transaction(sample.state, db, packed, value)
        _insert(db, sample.state, head)
    sample.ref, sample.head, sample.value = head['task_ref'], head, value
    return sample


@pytest.fixture
def sample(tmp_path):
    return _birth(_state(tmp_path))


def _dump(state):
    with closing(sqlite3.connect(state.path)) as db:
        return tuple(db.iterdump())


def _head(sample):
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        return sample.state.head(db.execute('SELECT data,mac FROM security_tasks WHERE ref=?', (sample.ref,)).fetchone())


def _copy_target(sample):
    control = publication.status(sample.state, sample.ref, owner=sample.owner)
    store = _store(sample.state)
    binding = CaptureSourceBinding(sample.ref, sample.owner, 'baseline', sample.ref, control['representation_version'])
    target_binding = raw_source_binding(binding, control['source'])
    target = store.create(target_binding)
    control = publication.admit_target(sample.state, sample.ref, owner=sample.owner,
        request_id=control['request_id'], expected_intent_generation=control['intent_generation'], target_ref=target['ref'])
    donor_binding = _binding(sample.head, 'baseline', control['source'])
    seq = target['entry_count']
    while True:
        page = store.strict_copy_page(control['donor']['ref'], donor_binding, after_seq=seq)
        if page['entries']:
            target = store.append_page(target['ref'], target_binding,
                [(entry['path'], entry['content'], entry['metadata']) for entry in page['entries']],
                expected_cursor=target['cursor'], cursor=str(page['next_seq']))
        seq = page['next_seq']
        if page['at_end']:
            break
    store.seal(target['ref'], target_binding, expected_files=seq, inventory_complete=True)
    scratch = sample.root.parent / 'scratch'
    scratch.mkdir(mode=0o700, exist_ok=True)
    return control, CaptureCanonicalView(store, source_descriptor(binding, target['ref'], control['source']),
        capture_binding=binding, scratch_directory=scratch)


def _publish(sample):
    control, view = _copy_target(sample)
    with view:
        receipt = publication.finalize(sample.state, sample.ref, owner=sample.owner,
            request_id=control['request_id'], expected_generation=1,
            expected_intent_generation=control['intent_generation'], verified_view=view)
    return control, receipt


def test_zero_byte_allocation_and_empty_registry_are_reopenable(tmp_path):
    sample = _state(tmp_path)
    assert sample.state.path.stat().st_size == 0
    publication.prepare_storage(sample.state)
    before = _dump(sample.state)
    publication.prepare_storage(sample.state)
    assert _dump(sample.state) == before
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        assert publication.validate_inventory(sample.state, db=db)['total_count'] == 0
        assert db.execute('SELECT count(*) FROM security_tasks').fetchone() == (0,)


def test_first_allocation_sql_rollback_recovers_same_signed_allocation(tmp_path, monkeypatch):
    sample = _state(tmp_path)
    original = publication._write_registry
    def fail_after_registry(*args):
        original(*args)
        raise RuntimeError('real transaction not committed')
    with monkeypatch.context() as patch:
        patch.setattr(publication, '_write_registry', fail_after_registry)
        with pytest.raises(RuntimeError):
            publication.prepare_storage(sample.state)
    marker = publication._read_marker(sample.state)
    assert marker['state'] == 'ALLOCATING'
    assert not any('cp_' in line for line in _dump(sample.state))
    publication.prepare_storage(sample.state)
    assert publication._read_marker(sample.state) == dict(marker, state='READY')


def test_failed_birth_rolls_back_owner_intent_registry_and_head(tmp_path):
    sample = _state(tmp_path)
    publication.prepare_storage(sample.state)
    packed, value = _new(sample)
    before = _dump(sample.state)
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_STATE_UNAVAILABLE'):
        with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("CREATE TEMP TRIGGER fail_intent AFTER INSERT ON cp_intents BEGIN SELECT RAISE(ABORT,'intent fault'); END")
            head, returned = publication.birth_in_transaction(sample.state, db, packed, value)
            _insert(db, sample.state, head)
    assert _dump(sample.state) == before


def test_birth_has_detached_status_and_original_donor_binding(sample):
    state = publication.status(sample.state, sample.ref, owner=sample.owner)
    assert (state['state'], state['intent_generation'], state['head_generation'], state['target_ref']) == ('RESERVED', 1, 1, None)
    assert state['donor'] == sample.head['baseline']['paged_entries']
    assert sample.head[publication.MARKER_FIELD] == sample.value[publication.MARKER_FIELD]
    state['donor']['source'], state['intent']['state'] = '0' * 64, 'PUBLISHED'
    assert publication.status(sample.state, sample.ref, owner=sample.owner)['state'] == 'RESERVED'
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        pins = list(publication.iter_source_pins(sample.state, db=db))
        assert [pin['role'] for pin in pins] == ['donor']
        assert pins[0]['binding'].retention_domain == 'TASK_PAGES_GC_V1'


def test_final_commit_and_response_loss_replay_preserve_original_ledger_ttl(sample):
    before = _head(sample)
    control, receipt = _publish(sample)
    after = _head(sample)
    removed = copy.deepcopy(after)
    removed['baseline'].pop('capture_source')
    removed['generation'] -= 1
    assert removed == before
    later = dict(after, generation=after['generation'] + 1, static_attempts=1)
    with sqlite3.connect(sample.state.path) as db:
        db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=?',
                   (encode(later).decode(), digest(sample.state.key(), later), sample.ref))
    assert publication.replay_receipt(sample.state, sample.ref, owner=sample.owner,
        request_id=control['request_id']) == receipt


def test_real_head_cas_conflict_is_zero_mutation_then_same_intent_can_publish(sample):
    control, view = _copy_target(sample)
    before = _dump(sample.state)
    with view:
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_CAS_CONFLICT'):
            publication.finalize(sample.state, sample.ref, owner=sample.owner,
                request_id=control['request_id'], expected_generation=2,
                expected_intent_generation=control['intent_generation'], verified_view=view)
        assert _dump(sample.state) == before
        receipt = publication.finalize(sample.state, sample.ref, owner=sample.owner,
            request_id=control['request_id'], expected_generation=1,
            expected_intent_generation=control['intent_generation'], verified_view=view)
        assert publication.finalize(sample.state, sample.ref, owner=sample.owner,
            request_id=control['request_id'], expected_generation=1,
            expected_intent_generation=1, verified_view=view) == receipt


def test_checkpoint_reads_real_target_progress_and_duplicate_is_no_mutation(sample):
    control, view = _copy_target(sample)
    updated = publication.checkpoint(sample.state, sample.ref, owner=sample.owner,
        request_id=control['request_id'], expected_intent_generation=control['intent_generation'])
    assert updated['progress']['state'] == 'SEALED' and updated['progress']['entry_count'] == 2
    before = _dump(sample.state)
    assert publication.checkpoint(sample.state, sample.ref, owner=sample.owner,
        request_id=updated['request_id'], expected_intent_generation=updated['intent_generation']) == updated
    assert _dump(sample.state) == before


@pytest.mark.parametrize('table', ['cp_owners', 'cp_intents', 'cp_registry'])
def test_missing_signed_row_is_not_an_empty_collection(sample, table):
    with sqlite3.connect(sample.state.path) as db:
        db.execute('DELETE FROM ' + table)
    before = _dump(sample.state)
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
            publication.validate_inventory(sample.state, db=db)
    assert _dump(sample.state) == before


def test_ready_allocation_missing_table_or_marker_is_never_recreated(sample):
    with sqlite3.connect(sample.state.path) as db:
        db.execute('DROP TABLE cp_receipts')
    before = _dump(sample.state)
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
        publication.prepare_storage(sample.state)
    assert _dump(sample.state) == before
    publication._marker_path(sample.state).unlink()
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
        publication.prepare_storage(sample.state)


def test_ordinary_transition_cannot_adopt_remove_or_change_publication(sample):
    publication.validate_transition(sample.head, copy.deepcopy(sample.head), new=False)
    altered = [dict(sample.head, **{publication.MARKER_FIELD: None}),
        {key: item for key, item in sample.head.items() if key != publication.MARKER_FIELD},
        dict(sample.head, baseline=dict(sample.head['baseline'], capture_source={}))]
    for value in altered:
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_INVALID_TRANSITION'):
            publication.validate_transition(sample.head, value, new=False)
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_INVALID'):
        publication.validate_transition(None, sample.head, new=True)


def test_expired_body_does_not_block_terminal_retirement_or_revive_replay(sample):
    control, receipt = _publish(sample)
    sample.clock[0] += 31 * 86400
    record = _head(sample)
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        publication.retire_for_task(sample.state, record, db=db)
        db.execute('DELETE FROM security_tasks WHERE ref=?', (sample.ref,))
        assert publication.validate_inventory(sample.state, db=db)['active_count'] == 0
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_RETIRED'):
        publication.replay_receipt(sample.state, sample.ref, owner=sample.owner, request_id=control['request_id'])
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        assert [pin['role'] for pin in publication.iter_source_pins(sample.state, db=db)] == ['target']


def _fingerprint(directory):
    return {str(path.relative_to(directory)): (path.lstat().st_mode, path.lstat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
            for path in (directory, *sorted(directory.rglob('*')))}


@pytest.mark.parametrize('journal', ['wal-header', 'wal-live', 'rollback-live'])
def test_status_and_receipt_do_not_recover_or_create_activity_sidecars(sample, journal):
    from security_runtime.tasks.activity import ActivityStore
    activity = ActivityStore(sample.hooks, sample.root, now=lambda: sample.clock[0])
    activity.touch(sample.ref, sample.clock[0], 'ACTIVE')
    connection = sqlite3.connect(activity.path)
    try:
        if journal.startswith('wal'):
            assert connection.execute('PRAGMA journal_mode=WAL').fetchone() == ('wal',)
        if journal.endswith('live'):
            connection.execute('BEGIN IMMEDIATE')
            activity._put(connection, 'task:' + sample.ref,
                          dict(last_activity=sample.clock[0] + 1, seq=1, paths=[], events=[], scope_unknown=False))
            if journal == 'wal-live':
                connection.commit()
                assert Path(str(activity.path) + '-wal').exists()
                assert Path(str(activity.path) + '-shm').exists()
            else:
                assert Path(str(activity.path) + '-journal').exists()
            expected = 'CAPTURE_PUBLICATION_BUSY'
        else:
            connection.close()
            assert not Path(str(activity.path) + '-wal').exists()
            assert not Path(str(activity.path) + '-shm').exists()
            expected = 'CAPTURE_PUBLICATION_STATE_UNAVAILABLE'
        before = _fingerprint(sample.state.path.parent)
        with pytest.raises(publication.CapturePublicationError, match=expected):
            publication.status(sample.state, sample.ref, owner=sample.owner)
        with pytest.raises(publication.CapturePublicationError, match=expected):
            publication.replay_receipt(sample.state, sample.ref, owner=sample.owner,
                                       request_id=sample.head[publication.MARKER_FIELD]['payload']['request_id'])
        assert _fingerprint(sample.state.path.parent) == before
    finally:
        connection.close()


def test_post_allocation_commit_failure_can_promote_same_empty_registry(tmp_path, monkeypatch):
    sample = _state(tmp_path)
    original = publication._publish_marker
    def fail_ready(state, value):
        if value['state'] == 'READY':
            raise OSError('after real empty registry commit')
        return original(state, value)
    with monkeypatch.context() as patch:
        patch.setattr(publication, '_publish_marker', fail_ready)
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_STATE_UNAVAILABLE'):
            publication.prepare_storage(sample.state)
    allocated = publication._read_marker(sample.state)
    assert allocated['state'] == 'ALLOCATING'
    with sqlite3.connect(sample.state.path) as db:
        assert len(list(db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name GLOB 'cp_*'"))) == 4
    publication.prepare_storage(sample.state)
    assert publication._read_marker(sample.state) == dict(allocated, state='READY')


def test_initial_fully_signed_stage_is_recovered_with_its_same_identity(tmp_path, monkeypatch):
    sample = _state(tmp_path)
    original = publication.os.replace
    def fail_replace(source, destination):
        if str(destination).endswith(publication.MARKER_SUFFIX):
            raise OSError('stage fsynced, not yet renamed')
        return original(source, destination)
    with monkeypatch.context() as patch:
        patch.setattr(publication.os, 'replace', fail_replace)
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_STATE_UNAVAILABLE'):
            publication.prepare_storage(sample.state)
    marker = publication._marker_path(sample.state)
    stage = marker.with_name(marker.name + '.next')
    assert not marker.exists() and stage.is_file()
    allocated = publication._read_marker(sample.state, stage)
    publication.prepare_storage(sample.state)
    assert publication._read_marker(sample.state) == dict(allocated, state='READY')
    assert not stage.exists()


def test_unallocated_legacy_inventory_needs_no_new_guard_or_files(tmp_path):
    sample = _state(tmp_path)
    with sqlite3.connect(sample.state.path) as db:
        db.execute(publication.TASK_SCHEMA)
    before = _fingerprint(sample.state.path.parent)
    with closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        assert publication.validate_inventory(sample.state, db=db) == dict(allocated=False, active_count=0, total_count=0)
    assert _fingerprint(sample.state.path.parent) == before


def test_complete_control_and_head_loss_cannot_erase_external_v2_witness(sample):
    control, view = _copy_target(sample)
    with sqlite3.connect(sample.state.path) as db:
        db.execute('DELETE FROM security_tasks')
        for table in publication.TABLES:
            db.execute('DROP TABLE ' + table)
    publication._marker_path(sample.state).unlink()
    before = _fingerprint(sample.state.path.parent)
    with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
        publication.prepare_storage(sample.state)
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
            publication.validate_inventory(sample.state, db=db)
    assert _fingerprint(sample.state.path.parent) == before


@pytest.mark.parametrize('table,column', [
    ('cp_owners', 'task_ref'), ('cp_intents', 'request_id'),
    ('cp_intents', 'generation'), ('security_tasks', 'phase'),
])
def test_giant_index_columns_are_rejected_inside_sql_before_python(sample, table, column):
    with sqlite3.connect(sample.state.path) as db:
        db.execute(f'UPDATE {table} SET {column}=zeroblob(8388608)')
    before = _fingerprint(sample.state.path.parent)
    with page_guard(sample.state.path.parent), closing(sqlite3.connect(sample.state.path)) as db:
        db.execute('BEGIN')
        tracemalloc.start()
        try:
            with pytest.raises(publication.CapturePublicationError, match='CAPTURE_PUBLICATION_HISTORY_UNAVAILABLE'):
                publication.validate_inventory(sample.state, db=db)
            assert tracemalloc.get_traced_memory()[1] < 2 * 1024 * 1024
        finally:
            tracemalloc.stop()
    assert _fingerprint(sample.state.path.parent) == before
