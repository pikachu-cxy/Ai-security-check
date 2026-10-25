"""Real published sources, unfinished prefixes and atomic retirement fences."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStoreError
from security_runtime.task_review.capture_source_binding import (
    CaptureSourceBinding, raw_source_binding, source_descriptor,
)
from security_runtime.tasks.activity import LEGACY, POLICY
from security_runtime.tasks import capture_publication_store as publication
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.projection import enqueue
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages, _protect
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import _binding, _store


pytestmark = pytest.mark.skipif(os.name != 'posix',
    reason='Publication storage currently requires native POSIX private files')


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail('Publication and collection fixtures must never scan')


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))


def sample(tmp_path, *, unfinished=False):
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    count = 300 if unfinished else 3
    for index in range(count):
        (root / f'file-{index:04}.py').write_text(f'value={index}\n')
    clock = {'now': 100.0}
    hooks = HookStateStore(tmp_path / 'private')
    owner = session_owner('codex', 'publication-gc-fixture')
    service = TaskSecurityService(NoScanner(), hooks, owner=owner,
        now=lambda: clock['now'], frozen_body_contexts=True, capture_sources=True)
    response = service.begin(root, 'fresh-publication-task', check_policy=POLICY)
    assert response['status'] == 'ACTIVE'
    ref = response['task_ref']
    state = service.store(root)
    progress = publication.status(state, ref, owner=owner)
    if unfinished:
        # One source turn cannot copy 300 paths through the 256-path budget.
        assert progress['state'] != 'PUBLISHED'
        if progress['target_ref'] is None:
            service.advance_baseline_publication(root, ref)
            progress = publication.status(state, ref, owner=owner)
        assert progress['state'] == 'COPYING' and progress['target_ref'] is not None
    else:
        for _ in range(8):
            if progress['state'] == 'PUBLISHED':
                break
            service.advance_baseline_publication(root, ref)
            progress = publication.status(state, ref, owner=owner)
        assert progress['state'] == 'PUBLISHED'
    record = state.get(ref)
    raw = _store(state)
    donor = record['baseline']['paged_entries']
    donor_binding = _binding(record, 'baseline', donor['source'])
    scope = CaptureSourceBinding(ref, owner, 'baseline', ref,
        record['baseline']['redaction_version'])
    target_binding = raw_source_binding(scope, donor['source'])
    target = progress['target_ref']
    if unfinished:
        header = raw.resume(target, target_binding)
        assert header['state'] == 'CAPTURING' and header['entry_count'] < count
    return SimpleNamespace(root=root, hooks=hooks, service=service, state=state,
        clock=clock, owner=owner, ref=ref, record=record, progress=progress,
        raw=raw, donor=donor, donor_binding=donor_binding,
        scope=scope, target=target, target_binding=target_binding)


def orphan(value, *, domain='TASK_PAGES_GC_V1'):
    ref = 'ts1-' + uuid.uuid4().hex
    source = hashlib.sha256(b'ordinary isolated orphan').hexdigest()
    if domain == 'TASK_CAPTURE_SOURCE_V2':
        binding = raw_source_binding(CaptureSourceBinding(ref, value.owner, 'baseline', ref), source)
    else:
        binding = SnapshotBinding(task_ref=ref, owner=value.owner, source_ref=source,
            representation_version=3, kind='TASK_BEFORE_EDIT', captured_before_edit=True,
            retention_domain=domain)
    with page_guard(value.state.path.parent):
        capture = value.raw.create(binding)['ref']
        value.raw.append_page(capture, binding, [('ordinary.py', b'value=7\n')],
                              expected_cursor=None, cursor='1')
        value.raw.seal(capture, binding, expected_files=1, inventory_complete=True)
    return capture, binding


def database_images(value):
    result = {}
    for name, path in (('control', value.state.path), ('raw', value.raw.path)):
        if not path.exists():
            result[name] = None
            continue
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            rows = tuple(db.iterdump())
        result[name] = path.read_bytes(), rows
    return result


def control_inventory(value):
    with page_guard(value.state.path.parent):
        with sqlite3.connect(value.state.path) as db:
            db.execute('BEGIN')
            return publication.validate_inventory(value.state, db=db)


def resign_head(value, mutate):
    with sqlite3.connect(value.state.path) as db:
        raw = db.execute('SELECT data FROM security_tasks WHERE ref=?', (value.ref,)).fetchone()[0]
        head = json.loads(raw)
        mutate(head)
        db.execute('UPDATE security_tasks SET data=?,mac=? WHERE ref=?',
            (encode(head).decode(), digest(value.state.key(), head), value.ref))


def assert_rejected_without_deletion(value, *, prune):
    before = database_images(value)
    with pytest.raises(ValueError) as error:
        collect_pages(value.state, prune=prune)
    assert getattr(error.value, 'reason_code', '').startswith((
        'CAPTURE_PUBLICATION_', 'CAPTURE_SOURCE_PROFILE_', 'REVIEW_METADATA_', 'SNAPSHOT_'))
    assert database_images(value) == before


@pytest.mark.parametrize('prune', [False, True])
@pytest.mark.parametrize('fault', ['head', 'owner', 'intent', 'receipt', 'registry', 'schema',
                                  'marker', 'head_marker', 'foreign_descriptor'])
def test_incomplete_control_inventory_rejects_entire_nonempty_collection(tmp_path, fault, prune):
    value = sample(tmp_path)
    collectible, binding = orphan(value)
    assert value.raw.resume(collectible, binding)['state'] == 'SEALED'
    if fault in {'head', 'owner', 'intent', 'receipt'}:
        table = {'head': 'security_tasks', 'owner': 'cp_owners',
                 'intent': 'cp_intents', 'receipt': 'cp_receipts'}[fault]
        column = 'ref' if fault == 'head' else 'task_ref'
        with sqlite3.connect(value.state.path) as db:
            db.execute(f'DELETE FROM {table} WHERE {column}=?', (value.ref,))
    elif fault == 'registry':
        with sqlite3.connect(value.state.path) as db:
            db.execute('UPDATE cp_registry SET mac=?', ('0' * 64,))
    elif fault == 'schema':
        with sqlite3.connect(value.state.path) as db:
            db.execute('DROP TABLE cp_registry')
    elif fault == 'marker':
        value.state.path.with_name(value.state.path.name + publication.MARKER_SUFFIX).unlink()
    elif fault == 'head_marker':
        resign_head(value, lambda head: head.pop(publication.MARKER_FIELD))
    else:
        other = session_owner('codex', 'a-different-fixture-owner')
        descriptor = source_descriptor(CaptureSourceBinding(value.ref, other, 'baseline', value.ref),
                                       value.target, value.donor['source'])
        resign_head(value, lambda head: head['baseline'].update(descriptor))
    assert_rejected_without_deletion(value, prune=prune)
    assert value.raw.resume(collectible, binding)['state'] == 'SEALED'


@pytest.mark.parametrize('prune', [False, True])
@pytest.mark.parametrize('fault', ['target_entry_mac', 'target_middle', 'target_header',
                                  'donor_anchor', 'body'])
def test_registered_raw_damage_is_found_before_expired_head_or_projection_changes(tmp_path, fault, prune):
    value = sample(tmp_path)
    record = enqueue(value.state.get(value.ref))
    value.state.save(record)
    collectible, binding = orphan(value)
    value.clock['now'] += 31 * 86400
    with sqlite3.connect(value.raw.path) as db:
        if fault == 'target_entry_mac':
            db.execute('UPDATE entries SET mac=? WHERE ref=? AND seq=2', ('0' * 64, value.target))
        elif fault == 'target_middle':
            db.execute('DELETE FROM entries WHERE ref=? AND seq=2', (value.target,))
        elif fault == 'target_header':
            db.execute('DELETE FROM captures WHERE ref=?', (value.target,))
        elif fault == 'donor_anchor':
            # Structurally valid, signed storage corruption must still fail the
            # original owner's durable source anchor, rather than be re-bound.
            header = json.loads(db.execute('SELECT data FROM captures WHERE ref=?',
                                          (value.donor['ref'],)).fetchone()[0])
            header['root_digest'] = '0' * 64
            value.raw._save(db, header)
        else:
            entry = json.loads(db.execute('SELECT data FROM entries WHERE ref=? AND seq=2',
                                         (value.target,)).fetchone()[0])
            db.execute('UPDATE objects SET body=zeroblob(length(body)) WHERE hash=?', (entry['sha256'],))
    assert_rejected_without_deletion(value, prune=prune)
    assert value.raw.resume(collectible, binding)['state'] == 'SEALED'


@pytest.mark.parametrize('unfinished', [False, True])
def test_healthy_inventory_collects_old_orphan_but_keeps_real_donor_and_target(tmp_path, unfinished):
    value = sample(tmp_path, unfinished=unfinished)
    collectible, binding = orphan(value)
    unknown, unknown_binding = orphan(value, domain='TASK_CAPTURE_SOURCE_V2')
    result = collect_pages(value.state)
    assert result['collected_captures'] == 1 and result['released_logical_bytes'] > 0
    with pytest.raises(SnapshotStoreError) as error:
        value.raw.resume(collectible, binding)
    assert error.value.reason_code == 'SNAPSHOT_HISTORY_UNAVAILABLE'
    assert value.raw.resume(value.donor['ref'], value.donor_binding)['state'] == 'SEALED'
    assert value.raw.resume(value.target, value.target_binding)['state'] in {'CAPTURING', 'SEALED'}
    assert value.raw.resume(unknown, unknown_binding)['state'] == 'SEALED'
    assert control_inventory(value)['active_count'] == 1


def test_expiry_retires_owner_and_intent_with_head_and_keeps_projection_detached(tmp_path):
    value = sample(tmp_path)
    value.state.save(enqueue(value.state.get(value.ref)))
    value.clock['now'] += 31 * 86400
    collect_pages(value.state, prune=True)
    with sqlite3.connect(value.state.path) as db:
        assert db.execute('SELECT 1 FROM security_tasks WHERE ref=?', (value.ref,)).fetchone() is None
        for table in ('cp_owners', 'cp_intents'):
            retired = json.loads(db.execute(f'SELECT data FROM {table} WHERE task_ref=?',
                                           (value.ref,)).fetchone()[0])
            assert retired['state'] == 'RETIRED'
        retained = json.loads(db.execute('SELECT data FROM retained_task_projections WHERE ref=?',
                                        (value.ref,)).fetchone()[0])
        assert retained['retained_for_projection'] is True
        assert publication.MARKER_FIELD not in retained
        assert 'capture_source' not in retained['baseline']
    assert control_inventory(value)['active_count'] == 0
    assert value.raw.resume(value.target, value.target_binding)['state'] == 'SEALED'
    with pytest.raises(publication.CapturePublicationError) as error:
        publication.replay_receipt(value.state, value.ref, owner=value.owner,
                                   request_id=value.progress['request_id'])
    assert error.value.reason_code == 'CAPTURE_PUBLICATION_RETIRED'
    collect_pages(value.state, prune=True)  # Retired history must not demand the missing head.


@pytest.mark.parametrize('prune', [False, True])
def test_lost_raw_database_is_not_an_empty_source_inventory(tmp_path, prune):
    value = sample(tmp_path)
    value.raw.path.unlink()
    assert_rejected_without_deletion(value, prune=prune)


def test_lost_task_database_with_allocation_identity_rejects_without_creating_a_database(tmp_path):
    value = sample(tmp_path)
    value.state.path.unlink()
    assert_rejected_without_deletion(value, prune=True)
    assert not value.state.path.exists()


def test_ready_empty_publication_domain_does_not_invent_a_raw_database(tmp_path):
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    hooks = HookStateStore(tmp_path / 'private')
    hooks.key(root)
    hooks.prepare_database(root, 'task-security.db')
    state = TaskSecurityStore(hooks, root, now=lambda:100.0)
    publication.prepare_storage(state)
    value = SimpleNamespace(state=state, raw=_store(state))
    before = database_images(value)
    assert collect_pages(state)['collected_captures'] == 0
    assert database_images(value) == before and not value.raw.path.exists()


def test_legacy_ordinary_filename_is_not_a_publication_control_marker(tmp_path):
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    (root / 'capture_source').write_text('value=1\n')
    (root / 'source.py').write_text('value=2\n')
    hooks = HookStateStore(tmp_path / 'private')
    service = TaskSecurityService(NoScanner(), hooks, now=lambda:100.0)
    response = service.begin(root, 'ordinary-legacy-task', check_policy=LEGACY)
    state = service.store(root)
    record = state.get(response['task_ref'])
    # Original trusted embeddings may retain extensionless names outside the
    # current discovery filter. Exercise a real signed legacy control row,
    # rather than assuming current discovery selects that filename.
    record['baseline']['inventory'].append('capture_source')
    record['baseline']['hashes']['capture_source'] = hashlib.sha256((root / 'capture_source').read_bytes()).hexdigest()
    state.save(record)
    record = state.get(response['task_ref'])
    assert 'capture_source' in record['baseline']['inventory']
    value = SimpleNamespace(state=state, raw=_store(state))
    before = database_images(value)
    assert collect_pages(state)['collected_captures'] == 0
    assert database_images(value) == before and not value.raw.path.exists()
    assert not state.path.with_name(state.path.name + publication.MARKER_SUFFIX).exists()


def test_lost_guard_rejects_retired_domain_even_after_old_donor_is_collected(tmp_path):
    value = sample(tmp_path)
    value.clock['now'] += 31 * 86400
    collect_pages(value.state, prune=True)
    with pytest.raises(SnapshotStoreError) as gone:
        value.raw.resume(value.donor['ref'], value.donor_binding)
    assert gone.value.reason_code == 'SNAPSHOT_HISTORY_UNAVAILABLE'
    guard = value.state.path.parent / 'snapshot-pages.gc.lock'
    guard.unlink()
    assert_rejected_without_deletion(value, prune=True)
    assert not guard.exists()


def test_retirement_and_head_delete_roll_back_together_after_real_sql_failure(tmp_path, monkeypatch):
    value = sample(tmp_path)
    value.clock['now'] += 31 * 86400
    before = database_images(value)
    original, observed = sqlite3.connect, []

    class FailDelete(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('DELETE FROM security_tasks'):
                for table in ('cp_owners', 'cp_intents'):
                    row = super().execute(f'SELECT data FROM {table} WHERE task_ref=?',
                                          (value.ref,)).fetchone()
                    assert json.loads(row[0])['state'] == 'RETIRED'
                observed.append(True)
                raise sqlite3.OperationalError('isolated failure after retirement before head delete')
            return super().execute(sql, parameters)

    def connect(*args, **kwargs):
        kwargs.setdefault('factory', FailDelete)
        return original(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, 'connect', connect)
        with pytest.raises(sqlite3.OperationalError, match='after retirement before head delete'):
            collect_pages(value.state, prune=True)
    assert observed == [True]
    assert database_images(value) == before
    assert control_inventory(value)['active_count'] == 1
    collect_pages(value.state, prune=True)
    assert control_inventory(value)['active_count'] == 0


def test_process_exit_between_retirement_and_head_delete_recovers_original_transaction(tmp_path):
    value = sample(tmp_path)
    value.clock['now'] += 31 * 86400
    before = database_images(value)
    source = str(Path(__file__).resolve().parents[2] / 'src')
    script = r'''
import json,os,pathlib,sqlite3,sys
sys.path.insert(0,sys.argv[1])
import security_runtime
assert pathlib.Path(security_runtime.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]))
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages
state=TaskSecurityStore(HookStateStore(pathlib.Path(sys.argv[3])),pathlib.Path(sys.argv[2]),now=lambda:float(sys.argv[5]))
actual=sqlite3.connect
class ExitBeforeDelete(sqlite3.Connection):
    def execute(self,sql,parameters=()):
        if sql.startswith('DELETE FROM security_tasks'):
            for table in ('cp_owners','cp_intents'):
                row=super().execute('SELECT data FROM '+table+' WHERE task_ref=?',(sys.argv[4],)).fetchone()
                assert json.loads(row[0])['state']=='RETIRED'
            os._exit(73)
        return super().execute(sql,parameters)
def connect(*args,**kwargs):
    kwargs.setdefault('factory',ExitBeforeDelete)
    return actual(*args,**kwargs)
sqlite3.connect=connect
collect_pages(state,prune=True)
raise AssertionError('The real task DELETE boundary was not reached')
'''
    child = subprocess.run([sys.executable, '-I', '-B', '-c', script, source,
        str(value.root), str(value.hooks.directory), value.ref, str(value.clock['now'])],
        capture_output=True, text=True, timeout=30)
    assert child.returncode == 73, child.stderr
    # Explicit writer recovery of SQLite's real hot journal; this operation is
    # not represented as a readonly inspection or automatic task reconstruction.
    with sqlite3.connect(value.state.path) as db:
        db.execute('BEGIN IMMEDIATE')
        db.rollback()
    assert database_images(value) == before
    assert control_inventory(value)['active_count'] == 1
    collect_pages(value.state, prune=True)
    assert control_inventory(value)['active_count'] == 0


def test_published_descriptor_cannot_be_used_as_an_old_or_foreign_pin(tmp_path):
    value = sample(tmp_path)
    references = set()
    _protect(value.raw, value.record, references)
    assert {value.donor['ref'], value.target} <= references
    bad = copy.deepcopy(value.record)
    bad['baseline']['capture_source']['field'] = 'end'
    with pytest.raises(SnapshotStoreError) as error:
        _protect(value.raw, bad, set())
    assert error.value.reason_code == 'SNAPSHOT_REFERENCE_INVENTORY_INVALID'


def test_pre_publisher_phase_one_task_is_not_adopted_or_changed_by_collection(tmp_path):
    installation = Path('/Users/cxy/.local/share/ai-security-runtime/source-builds/20261024-eccbc44e4a98/venv')
    interpreter = installation / 'bin/python'
    if not interpreter.exists():
        pytest.skip('Requires preserved actual phase-one runtime installation')
    root = (tmp_path / 'source').resolve()
    root.mkdir()
    (root / 'source.py').write_text('value=1\n')
    private = tmp_path / 'private'
    script = r'''
import json,pathlib,sys
import security_runtime
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
assert pathlib.Path(security_runtime.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]))
class NoScanner:
    def scan(self,*args,**kwargs): raise AssertionError('No scanner in this isolated fixture')
root=pathlib.Path(sys.argv[2]); owner=session_owner('codex','old-phase-one-fixture')
service=TaskSecurityService(NoScanner(),HookStateStore(pathlib.Path(sys.argv[3])),owner=owner,
    now=lambda:100.0,frozen_body_contexts=True,capture_sources=True)
response=service.begin(root,'phase-one-task',check_policy=POLICY)
record=service.load(root,response['task_ref'])
assert record['capture_policy']=='BATCHED_FILES_GC_SOURCE_V2'
assert 'capture_publication' not in record and 'capture_source' not in record['baseline']
print(json.dumps({'ref':record['task_ref'],'owner':owner}))
'''
    child = subprocess.run([str(interpreter), '-I', '-B', '-c', script,
        str(installation), str(root), str(private)], capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, child.stderr
    fixture = json.loads(child.stdout)
    state = TaskSecurityStore(HookStateStore(private), root, now=lambda:100.0)
    record = state.get(fixture['ref'])
    value = SimpleNamespace(state=state, raw=_store(state), owner=fixture['owner'])
    orphan(value)
    with sqlite3.connect(state.path) as db:
        before = tuple(db.execute('SELECT ref,data,mac FROM security_tasks'))
    assert collect_pages(state)['collected_captures'] == 1
    with sqlite3.connect(state.path) as db:
        assert tuple(db.execute('SELECT ref,data,mac FROM security_tasks')) == before
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'cp_%'").fetchone()
    assert state.get(fixture['ref']) == record
    assert not state.path.with_name(state.path.name + publication.MARKER_SUFFIX).exists()
