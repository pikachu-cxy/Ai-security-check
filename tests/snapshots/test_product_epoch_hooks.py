"""Product observations and strict scanner snapshots keep separate authority."""
from concurrent.futures import ThreadPoolExecutor
import json
import os

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore, identity
from security_runtime.host_event_adapters import host_capabilities
from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.host_events import EventKind, NormalizedHostEvent, OperationClass, VerifiedHostContext
from security_runtime.product_epoch_hooks import SCHEMA, ProductEpochHooks
from security_runtime.product_epoch_capture import StableHashReader
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.security import TaskSecurityService
from test_hook_runtime import FakeRuntime, repo, row


pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Product epochs require POSIX descriptor observations')


def core_for(repo, tmp_path, runtime=None, **kwargs):
    return HookCoordinator(runtime or FakeRuntime(), HookStateStore(tmp_path.resolve()/'hooks'),
                           workspace_resolver=lambda _:repo, **kwargs)


def sealed(core, repo):
    service = ProductEpochService(core.store, repo)
    owner = dict(host='cursor', session=identity('s'))
    status = service.ensure(owner)
    for _ in range(100):
        if status['state'] == 'SEALED':
            return service, status
        status = service.step(owner)
    pytest.fail(f'Finite fixture did not seal: {status}')


def start(core, repo, session='s'):
    return core.handle_lifecycle(EventKind.SESSION_START, repo, 'cursor', session)


def activity(core, repo, paths=('A.java',), *, unknown=False, session='s'):
    context = VerifiedHostContext('cursor', repo, identity(os.path.normcase(str(repo))),
        identity(session), None, host_capabilities('cursor'), session)
    event = NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY, context,
        OperationClass.POSSIBLE_WORKSPACE_MUTATION if unknown else OperationClass.DIRECT_FILE_MUTATION,
        candidate_paths=paths, scope_unknown=unknown)
    return handle_normalized_event(event, coordinator=core, lifecycle=True)[0], event


def test_new_session_binds_shared_hash_only_epoch_without_live_capture(repo, tmp_path):
    core = core_for(repo, tmp_path, snapshot_capture=lambda *a:pytest.fail('Product publication cannot recapture the tree'))
    for index in range(1001):
        (repo/f'file-{index}.py').write_text('original\n')
    service, status = sealed(core, repo)
    marker = core.store.pending_activity(repo, 'cursor', 's', mark=True)
    result = start(core, repo)
    state, invalid = core.store.load(core.store.path(repo, 'cursor', 's'))
    assert result['baseline_publish_status'] == 'PUBLISHED' and not invalid
    assert result['snapshot_source'] == 'PRODUCT_OBSERVED_EPOCH'
    assert result['comparison_consistency'] == 'OBSERVED_ONLY' and not result['task_baseline_ready']
    assert result['product_epoch_observed_path_count'] == 1002
    assert state['schema_version'] == SCHEMA and state['epoch_ref'] == status['epoch_ref']
    assert 'file_digests' not in state and 'families' not in state
    assert len(json.dumps(state).encode()) < 2000
    assert core.store.pending_activity(repo, 'cursor', 's') == marker
    (repo/'late.py').write_text('later\n')
    other = start(core, repo, 'another-session')
    assert other['product_epoch_ref'] == status['epoch_ref']
    assert service.lookup(status['epoch_ref'], ['late.py'])['results'][0]['status'] == 'FIRST_OBSERVED_ORDER_UNKNOWN'
    assert not core.runtime.calls


def test_publication_does_not_reject_new_pending_or_edited_tree(repo, tmp_path):
    core = core_for(repo, tmp_path, snapshot_capture=lambda *a:pytest.fail('No quiet-tree capture'))
    service, status = sealed(core, repo)
    original = service.status
    arrived = []

    def change_during_verify(epoch_ref=None):
        if epoch_ref and not arrived:
            (repo/'A.java').write_text('changed while publishing\n')
            arrived.append(core.store.pending_activity(repo, 'cursor', 's', mark=True))
        return original(epoch_ref)

    service.status = change_during_verify
    core.product_epoch_factory = lambda hooks, root:service
    result = start(core, repo)
    assert result['baseline_publish_status'] == 'PUBLISHED'
    assert core.store.pending_activity(repo, 'cursor', 's') == arrived[0]
    assert result['product_epoch_ref'] == status['epoch_ref'] and not core.runtime.calls


def test_shared_sealed_epoch_publishes_concurrent_sessions_without_reacquiring_capture(repo, tmp_path):
    core = core_for(repo, tmp_path, snapshot_capture=lambda *a:pytest.fail('No legacy baseline'))
    service, status = sealed(core, repo)
    service.ensure = lambda owner:pytest.fail('Sealed epoch does not need a capture writer lock')
    core.product_epoch_factory = lambda hooks, root:service
    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(lambda session:start(core, repo, session), ['a', 'b', 'c']))
    assert all(result['baseline_publish_status'] == 'PUBLISHED' for result in outcomes)
    assert {result['product_epoch_ref'] for result in outcomes} == {status['epoch_ref']}


def test_known_normalized_path_compares_epoch_and_scans_in_separate_namespace(repo, tmp_path):
    runtime = FakeRuntime([row(repo)])
    core = core_for(repo, tmp_path, runtime)
    service, status = sealed(core, repo)
    start(core, repo)
    original = core.store.load(core.store.path(repo, 'cursor', 's'))[0]
    (repo/'A.java').write_text('edited after product observation\n')
    result, event = activity(core, repo)
    current, invalid = core.store.load(core.store.path(repo, 'cursor', 's'))
    scan = core.store.load(core.store.scan_path(repo, 'cursor', 's'))[0]
    assert result['product_epoch_comparison_reason'] == 'OBSERVED_HASH_DELTA'
    assert result['product_epoch_changed_path_count'] == 1 and result['product_epoch_comparison_complete']
    assert result['execution']['scanner_run'] and runtime.calls == [('A.java',)]
    assert result['delta']['new'] == 0  # HASH_ONLY is never a task-before scanner proof.
    assert not invalid and current['schema_version'] == SCHEMA
    assert current['epoch_ref'] == original['epoch_ref'] == status['epoch_ref']
    assert current['last_processed_ref'] == identity(event.sequence_identity)
    assert scan['schema_version'] == 'hook-v1' and scan['file_digests']
    assert scan['last_result']['status'] != 'COMPARISON_BASELINE'
    assert service.lookup(status['epoch_ref'], ['A.java'])['results'][0]['observed']


def test_event_lookup_crosses_256_path_pages_and_preserves_the_unobserved_tail(repo, tmp_path):
    core = core_for(repo, tmp_path)
    names = [f'known-{index:04d}.py' for index in range(519)]
    for name in names:
        (repo/name).write_bytes(b'original\n')
    service, _ = sealed(core, repo)
    start(core, repo)
    sizes, lookup = [], service.lookup

    def counted(ref, paths):
        sizes.append(len(paths))
        return lookup(ref, paths)

    service.lookup = counted
    core.product_epoch_factory = lambda hooks, root:service
    (repo/'zz-last.py').write_bytes(b'after the accepted scope\n')
    result, _ = activity(core, repo, tuple(names + ['zz-last.py']))
    assert sizes == [256, 256, 8]
    assert result['product_epoch_compared_path_count'] > 0
    assert (result['product_epoch_compared_path_count'] +
            result['product_epoch_unavailable_path_count']) == 519
    assert result['product_epoch_unobserved_path_count'] == 1
    assert result['product_epoch_comparison_reason'] == 'FIRST_OBSERVED_ORDER_UNKNOWN'
    assert result['product_epoch_comparison_complete'] is False
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


@pytest.mark.parametrize('unknown', [False, True])
def test_unobserved_or_unknown_shell_scope_keeps_pending_without_new_attribution(repo, tmp_path, unknown):
    core = core_for(repo, tmp_path, FakeRuntime([row(repo, file='new.java')]))
    sealed(core, repo)
    start(core, repo)
    (repo/'new.java').write_text('new current bytes\n')
    result, _ = activity(core, repo, () if unknown else ('new.java',), unknown=unknown)
    assert result['product_epoch_comparison_reason'] == ('EVENT_SCOPE_UNKNOWN' if unknown else 'FIRST_OBSERVED_ORDER_UNKNOWN')
    assert result['product_epoch_comparison_complete'] is False
    assert core.store.pending_activity(repo, 'cursor', 's') is not None
    assert result['delta']['new'] == 0 and result['execution']['scanner_run']
    assert core.store.load(core.store.path(repo, 'cursor', 's'))[0]['last_processed_ref'] is None


def test_pending_epoch_activity_continues_original_job_without_legacy_capture(repo, tmp_path):
    core = core_for(repo, tmp_path, snapshot_capture=lambda *a:pytest.fail('Pending epoch cannot become legacy before evidence'))
    service = ProductEpochService(core.store, repo, policy=dict(step_files=1))
    core.product_epoch_factory = lambda hooks, root:service
    first = start(core, repo)
    assert first['status'] == 'BASELINE_PENDING' and first['product_epoch_state'] == 'ENUMERATING'
    ref = first['product_epoch_ref']
    (repo/'A.java').write_text('changed during first connection\n')
    result, _ = activity(core, repo)
    assert result['status'] == 'BASELINE_PENDING' and result['product_epoch_ref'] == ref
    assert result['scanner_skipped_reason'] == 'PRODUCT_EPOCH_PENDING'
    assert core.store.load(core.store.path(repo, 'cursor', 's'))[0] is None
    assert not core.store.scan_path(repo, 'cursor', 's').exists()
    assert core.store.pending_activity(repo, 'cursor', 's') is not None and not core.runtime.calls


@pytest.mark.parametrize('damage', ['mac', 'session_copy', 'policy', 'unknown_field'])
def test_epoch_reference_authentication_rejects_tamper_or_cross_session(repo, tmp_path, damage):
    core = core_for(repo, tmp_path)
    sealed(core, repo)
    start(core, repo)
    path = core.store.path(repo, 'cursor', 's')
    value = json.loads(path.read_bytes())
    if damage == 'session_copy':
        target = core.store.path(repo, 'cursor', 'foreign')
        target.write_bytes(path.read_bytes())
        path = target
    else:
        if damage == 'mac':
            value['signature'] = '0'*64
        elif damage == 'policy':
            value['policy_digest'] = 'f'*64
        else:
            value['file_digests'] = {}
        path.write_text(json.dumps(value))
    assert core.store.load(path) == (None, True)
    before = path.read_bytes()
    result = start(core, repo, 'foreign' if damage == 'session_copy' else 's')
    assert result['status'] == 'INCONCLUSIVE' and path.read_bytes() == before


def test_legacy_hook_snapshot_remains_legacy_on_session_start(repo, tmp_path):
    core = core_for(repo, tmp_path)
    core.handle('SESSION_START', repo, 'cursor', 'legacy')
    path = core.store.path(repo, 'cursor', 'legacy')
    old = path.read_bytes()
    assert start(core, repo, 'legacy')['baseline_publish_status'] == 'RETAINED'
    assert path.read_bytes() == old and core.store.load(path)[0]['schema_version'] == 'hook-v1'
    assert ProductEpochService(core.store, repo).status()['state'] == 'NOT_STARTED'


def test_task_closeout_activity_keeps_true_before_and_does_not_create_scanner_cache(repo, tmp_path):
    core = core_for(repo, tmp_path)
    sealed(core, repo)
    start(core, repo)
    owner = dict(host='cursor', session=identity('s'))
    service = TaskSecurityService(core.runtime, core.store, owner=owner)
    ref = service.begin(repo, 'real-before-task', check_policy=POLICY)['task_ref']
    (repo/'A.java').write_text('after the actual task baseline\n')
    result, _ = activity(core, repo)
    task = service.load(repo, ref)
    assert result['security_task_ref'] == ref and result['task_edit_check_policy'] == POLICY
    assert service.before_lines(repo, task, 'A.java') == ['safe']
    assert not core.store.scan_path(repo, 'cursor', 's').exists() and not core.runtime.calls
    assert core.store.load(core.store.path(repo, 'cursor', 's'))[0]['schema_version'] == SCHEMA


def test_per_edit_task_still_scans_and_keeps_its_real_original_before(repo, tmp_path):
    core = core_for(repo, tmp_path)
    sealed(core, repo)
    start(core, repo)
    owner = dict(host='cursor', session=identity('s'))
    service = TaskSecurityService(core.runtime, core.store, owner=owner)
    ref = service.begin(repo, 'per-edit-original')['task_ref']
    (repo/'A.java').write_text('per-edit change\n')
    result, _ = activity(core, repo)
    assert result['execution']['scanner_run'] and core.runtime.calls == [('A.java',)]
    assert result['security_task_ref'] == ref and result['task_edit_check_policy'] == 'EVERY_OBSERVED_MUTATION'
    assert service.before_lines(repo, service.load(repo, ref), 'A.java') == ['safe']
    assert core.store.load(core.store.path(repo, 'cursor', 's'))[0]['schema_version'] == SCHEMA
    assert core.store.load(core.store.scan_path(repo, 'cursor', 's'))[0]['schema_version'] == 'hook-v1'


def test_pending_product_epoch_does_not_delay_real_per_edit_task_scan(repo, tmp_path):
    core = core_for(repo, tmp_path)
    epoch = ProductEpochService(core.store, repo, policy=dict(step_files=1))
    core.product_epoch_factory = lambda hooks, root:epoch
    assert start(core, repo)['status'] == 'BASELINE_PENDING'
    service = TaskSecurityService(core.runtime, core.store,
                                  owner=dict(host='cursor', session=identity('s')))
    ref = service.begin(repo, 'pending-epoch-real-before')['task_ref']
    (repo/'A.java').write_text('real per-edit change\n')
    result, _ = activity(core, repo)
    assert result['product_epoch_pending_task_scan'] and result['execution']['scanner_run']
    assert result['security_task_ref'] == ref and core.runtime.calls == [('A.java',)]
    assert service.before_lines(repo, service.load(repo, ref), 'A.java') == ['safe']
    assert core.store.load(core.store.path(repo, 'cursor', 's'))[0] is None
    assert core.store.load(core.store.scan_path(repo, 'cursor', 's'))[0]['schema_version'] == 'hook-v1'
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


def test_pending_task_scan_publication_loses_cas_if_epoch_is_published_during_scan(repo, tmp_path, monkeypatch):
    core = core_for(repo, tmp_path)
    epoch = ProductEpochService(core.store, repo, policy=dict(step_files=1))
    core.product_epoch_factory = lambda hooks, root:epoch
    assert start(core, repo)['status'] == 'BASELINE_PENDING'
    service = TaskSecurityService(core.runtime, core.store,
                                  owner=dict(host='cursor', session=identity('s')))
    ref = service.begin(repo, 'pending-publication-real-before')['task_ref']
    (repo/'A.java').write_text('changed before a concurrent epoch publication\n')
    publish = core._publish
    bound = []

    def publish_epoch_first(result, root, host, session, transaction):
        if transaction.get('product_epoch_mode') and transaction.get('product_epoch_state') is None:
            owner = dict(host='cursor', session=identity('s'))
            for _ in range(20):
                if epoch.status()['state'] == 'SEALED':
                    break
                epoch.step(owner)
            assert start(core, repo)['baseline_publish_status'] == 'PUBLISHED'
            bound.append(core.store.path(repo, 'cursor', 's').read_bytes())
        return publish(result, root, host, session, transaction)

    monkeypatch.setattr(core, '_publish', publish_epoch_first)
    result, _ = activity(core, repo)
    assert result['execution']['scanner_run'] and result['reason'] == 'SCAN_ATTEMPT_PUBLICATION_STALE'
    assert result['scan_attempt']['publication'] == 'NOT_PUBLISHED'
    assert core.store.path(repo, 'cursor', 's').read_bytes() == bound[0]
    assert not core.store.scan_path(repo, 'cursor', 's').exists()
    assert core.store.pending_activity(repo, 'cursor', 's') is not None
    assert service.before_lines(repo, service.load(repo, ref), 'A.java') == ['safe']


def test_scanner_publication_recovery_cannot_replace_product_reference(repo, tmp_path, monkeypatch):
    core = core_for(repo, tmp_path)
    sealed(core, repo)
    start(core, repo)
    (repo/'A.java').write_text('changed\n')
    original = core._publish
    monkeypatch.setattr(core, '_publish', lambda *args:None)
    result, _ = activity(core, repo)
    assert result['execution']['scanner_run'] and not core.store.scan_path(repo, 'cursor', 's').exists()
    epoch = core.store.path(repo, 'cursor', 's').read_bytes()
    monkeypatch.setattr(core, '_publish', original)
    recovered = core.recover_publications(repo, 'cursor', 's')
    assert recovered['publication'] == 'PUBLISHED'
    assert core.store.path(repo, 'cursor', 's').read_bytes() == epoch
    assert core.store.load(core.store.scan_path(repo, 'cursor', 's'))[0]['schema_version'] == 'hook-v1'


def compare_fixture(core, repo, paths):
    sealed(core, repo)
    start(core, repo)
    state = core.store.load(core.store.path(repo, 'cursor', 's'))[0]
    core.store.pending_activity(repo, 'cursor', 's', mark=True)
    adapter = ProductEpochHooks(core.store, repo, now=core.clock)
    return lambda:adapter.compare(state, 'cursor', 's', paths, False, event_ref='current-event')


@pytest.mark.parametrize('size', [0, 1_000_000])
def test_current_hash_stream_accepts_empty_and_exact_file_budget_without_body_retention(repo, tmp_path, monkeypatch, size):
    (repo/'boundary.py').write_bytes(b'x'*size)
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['boundary.py'])
    import security_runtime.scan_input as inputs
    monkeypatch.setattr(inputs, '_read_file', lambda *a:pytest.fail('Product comparison only streams HMAC'))
    _, meta = compare()
    assert meta['product_epoch_compared_path_count'] == 1
    assert meta['product_epoch_comparison_complete'] and meta['product_epoch_comparison_reason'] == 'OBSERVED_HASH_MATCH'
    assert meta['comparison_kind'] == 'PRODUCT_COMPARISON'
    assert meta['comparison_consistency'] == 'OBSERVED_ONLY' and meta['comparison_representation'] == 'HASH_ONLY'
    assert meta['product_epoch_strict_task_preimage_eligible'] is False and 'task_baseline_ready' not in meta
    state = core.store.path(repo, 'cursor', 's').read_bytes()
    assert b'file_digests' not in state and b'content' not in state and len(state) < 2000


def test_current_hash_stream_rejects_large_file_without_reading_a_prefix(repo, tmp_path, monkeypatch):
    (repo/'large.py').write_bytes(b'x'*1_000_001)
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['large.py'])
    monkeypatch.setattr(StableHashReader, '_read_chunk', lambda *a:pytest.fail('Oversized file must not read a prefix'))
    _, meta = compare()
    assert meta['product_epoch_unavailable_path_count'] == 1
    assert not meta['product_epoch_comparison_complete'] and meta['product_epoch_compared_path_count'] == 0
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


def test_current_hash_stream_rejects_append_during_read(repo, tmp_path, monkeypatch):
    target = repo/'moving.py'
    target.write_bytes(b'x'*1_000_000)
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['moving.py'])
    read, appended = StableHashReader._read_chunk, []

    def append_after_first_chunk(reader, size):
        raw = read(reader, size)
        if raw and not appended:
            with target.open('ab') as stream:
                stream.write(b'new bytes')
            appended.append(True)
        return raw

    monkeypatch.setattr(StableHashReader, '_read_chunk', append_after_first_chunk)
    _, meta = compare()
    assert appended and not meta['product_epoch_comparison_complete']
    assert meta['product_epoch_unavailable_path_count'] == 1 and meta['product_epoch_compared_path_count'] == 0
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


@pytest.mark.parametrize('replacement', ['link', 'directory'])
def test_current_hash_stream_pins_parent_descriptor_and_rejects_replacement_during_read(repo, tmp_path, monkeypatch, replacement):
    parent = repo/'nested'
    parent.mkdir()
    (parent/'candidate.py').write_bytes(b'original inside project')
    outside = tmp_path/'outside'
    outside.mkdir()
    secret = b'outside source must not be read'
    (outside/'candidate.py').write_bytes(secret)
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['nested/candidate.py'])
    read, chunks, moved = StableHashReader._read_chunk, [], []

    def replace_parent_after_open(reader, size):
        if not moved:
            parent.rename(repo/'old-parent')
            if replacement == 'link':
                parent.symlink_to(outside, target_is_directory=True)
            else:
                parent.mkdir()
                (parent/'candidate.py').write_bytes(secret)
            moved.append(True)
        raw = read(reader, size)
        chunks.append(raw)
        return raw

    monkeypatch.setattr(StableHashReader, '_read_chunk', replace_parent_after_open)
    _, meta = compare()
    assert moved and b''.join(chunks) == b'original inside project'
    assert secret not in b''.join(chunks)
    assert meta['product_epoch_unavailable_path_count'] == 1 and meta['product_epoch_compared_path_count'] == 0
    assert not meta['product_epoch_comparison_complete']
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


def test_current_hash_stream_does_not_follow_parent_link_inserted_before_component_open(repo, tmp_path, monkeypatch):
    parent = repo/'nested'
    parent.mkdir()
    (parent/'candidate.py').write_bytes(b'original')
    outside = tmp_path/'outside'
    outside.mkdir()
    (outside/'candidate.py').write_bytes(b'external private body')
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['nested/candidate.py'])
    opened, substituted = os.open, []

    def substitute_before_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == 'nested' and dir_fd is not None and not substituted:
            parent.rename(repo/'old-parent')
            parent.symlink_to(outside, target_is_directory=True)
            substituted.append(True)
        return opened(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'open', substitute_before_open)
    monkeypatch.setattr(os, 'supports_dir_fd', os.supports_dir_fd | {substitute_before_open})
    monkeypatch.setattr(StableHashReader, '_read_chunk', lambda *a:pytest.fail('No body read through a replaced parent link'))
    _, meta = compare()
    assert substituted and meta['product_epoch_unavailable_path_count'] == 1
    assert not meta['product_epoch_comparison_complete'] and meta['product_epoch_compared_path_count'] == 0


def test_current_hash_stream_deadline_never_marks_skipped_paths_complete(repo, tmp_path, monkeypatch):
    import security_runtime.product_epoch_hooks as consumer
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, ['A.java'])
    # An exhausted cooperative time slice is a real gap, without an empty or
    # prefix digest being treated as a successful observation.
    monkeypatch.setattr(consumer, 'CURRENT_BATCH_SECONDS', 0)
    _, meta = compare()
    assert meta['product_epoch_unavailable_path_count'] == 1
    assert not meta['product_epoch_comparison_complete'] and meta['product_epoch_compared_path_count'] == 0
    assert core.store.pending_activity(repo, 'cursor', 's') is not None


def test_current_hash_stream_total_byte_budget_keeps_tail_unknown_but_accepts_empty_file(repo, tmp_path, monkeypatch):
    import security_runtime.hook_runtime as runtime
    names = ['a.py', 'b.py', 'c-empty.py', 'd-over-budget.py']
    for name, raw in zip(names, [b'a'*32, b'b'*32, b'', b'd'*32]):
        (repo/name).write_bytes(raw)
    core = core_for(repo, tmp_path)
    compare = compare_fixture(core, repo, names)
    read, consumed = StableHashReader._read_chunk, []

    def counted(reader, size):
        raw = read(reader, size)
        consumed.append(len(raw))
        return raw

    monkeypatch.setattr(runtime, 'MAX_BYTES', 64)
    monkeypatch.setattr(StableHashReader, '_read_chunk', counted)
    _, meta = compare()
    assert sum(consumed) == 64
    assert meta['product_epoch_compared_path_count'] == 3 and meta['product_epoch_unavailable_path_count'] == 1
    assert not meta['product_epoch_comparison_complete']
    assert core.store.pending_activity(repo, 'cursor', 's') is not None
