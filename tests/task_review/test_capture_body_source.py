"""V2 capture consumption of genuine original bodies; publication is pending.

The helper writes a separate V2 test capture in the same raw store. It never
publishes its descriptor in a task head and never fabricates a review identity.
"""
import copy
from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStoreError
from security_runtime.task_review.capture_source_binding import (
    CaptureSourceBinding, raw_source_binding, source_descriptor,
)
from security_runtime.task_review.frozen_body_source import FrozenBodySource, FrozenBodySourceError
from security_runtime.task_review.snapshot_source import CaptureCanonicalView, TypedSnapshotSourceError
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.capture_source_profile import POLICY as CAPTURE_POLICY
from security_runtime.tasks.frozen_body_context import CONTEXT_FIELD
from security_runtime.tasks.frozen_end_context import END_CONTEXT_FIELD
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import TaskPreimageStore
from security_runtime.tasks.queued_closeout import enqueue
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.snapshot_pages import _store
from security_runtime.tasks.snapshot_gc import collect_pages
from test_frozen_body_source import fingerprint, forbid_fallbacks
from test_task_security import LedgerRuntime
from test_typed_snapshot_source import logical, path_rows


@pytest.fixture(params=['baseline', 'end'])
def captured(tmp_path, monkeypatch, request):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'runtime-state'))
    root = tmp_path / 'project'
    root.mkdir()
    original = ['original_a=1', "message='中文😀'", 'last_a=1']
    (root / 'ordinary.py').write_text('\n'.join(original) + '\n')
    hooks = HookStateStore(tmp_path / 'private')
    owner, clock = session_owner('codex', 'capture-body-v2'), [100.0]
    service = TaskSecurityService(LedgerRuntime(), hooks, owner=owner,
        now=lambda: clock[0], frozen_body_contexts=True, capture_sources=True)
    response = service.begin(root, 'capture-body', check_policy=POLICY)
    assert response['status'] == 'ACTIVE'
    if request.param == 'end':
        original = ['original_b=2', "message='中文😀'", 'last_b=2']
        (root / 'ordinary.py').write_text('\n'.join(original) + '\n')
        clock[0] += 1
        assert service.finish(root, response['task_ref'])['status'] == 'READY'
    record = service.load(root, response['task_ref'])
    snapshot = record[request.param]
    context = snapshot[CONTEXT_FIELD if request.param == 'baseline' else END_CONTEXT_FIELD]
    state = service.store(root)
    store = _store(state)
    binding = CaptureSourceBinding(record['task_ref'], owner, request.param,
        record['task_ref'] if request.param == 'baseline' else snapshot['version_ref'], 3)
    return SimpleNamespace(root=root, hooks=hooks, owner=owner, clock=clock, record=record,
        state=state, store=store, binding=binding, snapshot=snapshot,
        context=context, original=original, scratch=tmp_path / 'scratch')


def view(sample, *, binding=None):
    binding = binding or sample.binding
    source = hashlib.sha256(encode(logical(sample.snapshot))).hexdigest()
    raw_binding = raw_source_binding(binding, source)
    header = sample.store.create(raw_binding)
    if header['state'] != 'SEALED':
        rows = path_rows(sample.snapshot)
        cursor = header['cursor']
        for offset in range(header['entry_count'], len(rows), sample.store.batch_budget.files):
            page = rows[offset:offset + sample.store.batch_budget.files]
            following = str(offset + len(page))
            header = sample.store.append_page(header['ref'], raw_binding, page,
                expected_cursor=cursor, cursor=following)
            cursor = following
        sample.store.seal(header['ref'], raw_binding, expected_files=len(rows), inventory_complete=True)
    sample.scratch.mkdir(mode=0o700, exist_ok=True)
    return CaptureCanonicalView(sample.store, source_descriptor(binding, header['ref'], source),
        capture_binding=binding, scratch_directory=sample.scratch)


def locator(sample, source, context=None):
    return FrozenBodySource(sample.hooks, sample.root,
        sample.context if context is None else context, typed_source=source,
        now=lambda: sample.clock[0])


def test_capture_view_reads_original_body_without_any_review_identity(captured, monkeypatch):
    source = view(captured)
    (captured.root / 'ordinary.py').write_text('live_c=3\n')
    forbid_fallbacks(monkeypatch)
    before = fingerprint(captured.hooks.directory)
    with source:
        assert not {'review_revision', 'snapshot_id'} & source.scope.keys()
        assert not {'review_revision', 'snapshot_id'} & source.summary.keys()
        assert source.scope['capture_ref'] == captured.context['payload']['preimage_task_ref']
        with locator(captured, source) as bodies:
            assert bodies.read_lines('ordinary.py') == captured.original
        assert source.summary['project_coverage'] == 'UNKNOWN'
        assert source.summary['external_bodies_available'] is False
    assert fingerprint(captured.hooks.directory) == before
    # Reading V2 never replaces the original task/donor pointer or publishes.
    assert captured.state.get(captured.record['task_ref']) == captured.record


def test_capture_body_budget_and_closed_view_keep_original_errors(captured):
    with view(captured) as source:
        with locator(captured, source) as bodies:
            with pytest.raises(FrozenBodySourceError, match='FROZEN_BODY_WAITING_BODY_BUDGET'):
                bodies.read_lines('ordinary.py', max_bytes=1)
            assert bodies.read_lines('ordinary.py') == captured.original
        delayed = locator(captured, source)
    with pytest.raises(TypedSnapshotSourceError, match='TYPED_SOURCE_CLOSED'):
        with delayed:
            pytest.fail('A closed canonical view cannot authorize a body read')


@pytest.mark.parametrize('captured', ['end'], indirect=True)
def test_end_capture_identity_rejects_equal_canonical_source_from_other_end(captured, monkeypatch):
    alternate = replace(captured.binding, capture_ref='ts1-' + 'e' * 32)
    source = view(captured, binding=alternate)
    forbid_fallbacks(monkeypatch)
    with source:
        # Writer authenticated identical original metadata under another raw
        # capture claim. Canonical SHA alone must not authorize the END body.
        assert source.summary['source'] == captured.context['payload']['source']
        assert source.scope['capture_ref'] != captured.context['payload']['version_ref']
        with pytest.raises(FrozenBodySourceError, match='FROZEN_BODY_SCOPE_MISMATCH'):
            with locator(captured, source):
                pytest.fail('Canonical equality cannot replace exact END identity')


@pytest.mark.parametrize('captured', ['end'], indirect=True)
def test_end_version_cannot_be_repointed_inside_an_authenticated_context(captured):
    context = copy.deepcopy(captured.context)
    context['payload']['version_ref'] = 'ts1-' + 'd' * 32
    with view(captured) as source:
        with pytest.raises(ValueError):
            with locator(captured, source, context):
                pytest.fail('Changing a signed END version requires authentication')


@pytest.mark.parametrize('captured', ['baseline'], indirect=True)
@pytest.mark.parametrize('missing_baseline_pin', [False, True])
def test_new_profile_queue_pins_original_baseline_and_missing_pin_stops_all_gc(
        captured, missing_baseline_pin):
    # A genuine queued END and a genuinely collectible orphan distinguish a
    # whole-GC refusal from a vacuous run with nothing eligible for deletion.
    service = TaskSecurityService(LedgerRuntime(), captured.hooks, owner=captured.owner,
        now=lambda: captured.clock[0], frozen_body_contexts=True, capture_sources=True)
    (captured.root / 'ordinary.py').write_text('queued_b=2\n')
    captured.clock[0] += 1
    ref = captured.record['task_ref']
    assert enqueue(service, captured.root, ref, launch=False)['status'] == 'QUEUED'
    queue = CloseoutQueue(captured.hooks, captured.root, now=lambda: captured.clock[0])
    row = queue.read(ref)
    assert row['snapshot_capture_policy'] == CAPTURE_POLICY
    baseline_pin = row['baseline_pages']['paged_entries']
    assert baseline_pin == captured.record['baseline']['paged_entries']
    # This original queue path still holds END metadata inline, before worker
    # task publication. Do not invent a raw END page pin that it never wrote.
    assert 'paged_entries' not in row['end']
    (captured.root / 'ordinary.py').write_text('live_c=3\n')
    orphan_binding = SnapshotBinding('unreferenced-profile-queue-fixture', captured.owner,
        'a' * 64, 3, kind='TASK_END', retention_domain='TASK_PAGES_GC_V1')
    orphan = captured.store.create(orphan_binding)
    captured.store.append_page(orphan['ref'], orphan_binding, [('orphan.py', b'unreferenced')],
        expected_cursor=None, cursor='done')
    captured.store.seal(orphan['ref'], orphan_binding, expected_files=1, inventory_complete=True)
    if missing_baseline_pin:
        with queue.transaction() as db:
            queue._put(db, ref, dict(queue._get(db, ref), baseline_pages={}))
        with pytest.raises(SnapshotStoreError, match='SNAPSHOT_REFERENCE_INVENTORY_INVALID'):
            collect_pages(captured.state)
        assert captured.store.resume(orphan['ref'], orphan_binding)['state'] == 'SEALED'
    else:
        assert collect_pages(captured.state)['collected_captures'] == 1
        with pytest.raises(SnapshotStoreError, match='SNAPSHOT_HISTORY_UNAVAILABLE'):
            captured.store.resume(orphan['ref'], orphan_binding)
    from security_runtime.tasks.snapshot_pages import _binding
    assert captured.store.resume(baseline_pin['ref'], _binding(captured.record, 'baseline',
        baseline_pin['source']))['state'] == 'SEALED'
    original_end = row['end']
    bodies = TaskPreimageStore(captured.hooks, captured.root,
        now=lambda: captured.clock[0], namespace='end')
    assert bodies.read(original_end['version_ref'], 'ordinary.py',
        original_end['hashes']['ordinary.py'], original_end['preimages']['ordinary.py'],
        strict_readonly=True) == ['queued_b=2']
