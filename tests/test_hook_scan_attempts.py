"""Hook C: state locks are short; real captured input and CAS fence publication."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from test_hook_runtime import FakeRuntime, coordinator, dirty, repo
from security_runtime.baseline_seed import WorkspaceBaselineSeeds
from security_runtime.bootstrap_diagnostics import BaselinePreparationError
from security_runtime.hook_runtime import capture_snapshot, capture_recheck_expectation, captured_input_matches
from security_runtime.progress import ScanCancelled, NullProgressReporter, progress_context
from security_runtime.scan_attempt import ScanAttemptStore
from security_runtime.scan_input import capture_scan_input, scoped_request


def test_snapshot_and_provider_leave_workspace_state_lock_available(repo, tmp_path):
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime)
    def capture(root, key):
        assert not core.store.lock_held(root)
        with core.store.lock(root) as acquired:
            assert acquired
        return capture_snapshot(root, key)
    core.snapshot_capture = capture
    started = core.handle_lifecycle('SESSION_START', repo, 'cursor', 'owner')
    assert started['baseline_publish_status'] == 'PUBLISHED'
    dirty(repo)
    entered, release = Event(), Event()
    original = runtime.scan
    def blocked(*args, **kwargs):
        assert not core.store.lock_held(repo)
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    runtime.scan = blocked
    with ThreadPoolExecutor(max_workers=1) as pool:
        work = pool.submit(core.handle_lifecycle, 'WORKSPACE_ACTIVITY', repo, 'cursor', 'owner')
        assert entered.wait(5)
        with core.store.lock(repo) as acquired:
            assert acquired
        # Stop is a state read and does not wait for or start Providers.
        stopped = core.handle_lifecycle('SESSION_STOP', repo, 'cursor', 'owner')
        assert stopped['status'] == 'SESSION_FINALIZED'
        assert stopped['scanner_invocation_count'] == 0
        duplicate = core.handle_lifecycle('WORKSPACE_ACTIVITY', repo, 'cursor', 'other')
        assert duplicate['reason'] == 'WORKSPACE_SCAN_ATTEMPT_BUSY'
        assert not duplicate['execution']['scanner_run']
        release.set()
        out = work.result(timeout=10)
    assert out['scan_attempt']['publication'] == 'PUBLISHED'
    assert len(runtime.calls) == 1


def test_new_pending_sequence_prevents_old_worker_publication(repo, tmp_path):
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime)
    core.handle_lifecycle('SESSION_START', repo, 'cursor', 'owner')
    path = core.store.path(repo, 'cursor', 'owner')
    before = path.read_bytes()
    dirty(repo)
    original = runtime.scan
    def newer(*args, **kwargs):
        result = original(*args, **kwargs)
        core.store.pending_activity(repo, 'cursor', 'owner', mark=True)
        return result
    runtime.scan = newer
    out = core.handle_lifecycle('WORKSPACE_ACTIVITY', repo, 'cursor', 'owner')
    assert out['reason'] == 'SCAN_ATTEMPT_PUBLICATION_STALE'
    assert path.read_bytes() == before
    assert core.store.pending_activity(repo, 'cursor', 'owner') is not None
    assert len(runtime.calls) == 1


class ABARuntime(FakeRuntime):
    """Snapshot A, capture B, restore A: final equality cannot authorize B."""
    def scan(self, root, mode, **kwargs):
        source = root / 'A.java'
        original = source.read_bytes()
        source.write_bytes(b'captured-B\n')
        execution = kwargs['execution']
        with capture_scan_input(kwargs['request'], private_parent=execution.private_parent,
                on_created=execution.input_created, on_removed=execution.input_removed) as view:
            source.write_bytes(original)
            execution.input_ready(view)
            pytest.fail('Providers must not execute for a different input revision')


def test_aba_input_is_rejected_before_provider_and_keeps_baseline(repo, tmp_path):
    core = coordinator(tmp_path, ABARuntime())
    core.handle_lifecycle('SESSION_START', repo, 'cursor', 'owner')
    path = core.store.path(repo, 'cursor', 'owner')
    before = path.read_bytes()
    dirty(repo)
    out = core.handle_lifecycle('WORKSPACE_ACTIVITY', repo, 'cursor', 'owner')
    assert out['status'] == 'INCONCLUSIVE'
    assert out['reason'] == 'SCAN_ATTEMPT_CANCELLED'
    assert path.read_bytes() == before
    assert core.store.pending_activity(repo, 'cursor', 'owner') is not None
    journal = ScanAttemptStore(core.store, repo).read()
    assert journal['lane']['state'] == 'CANCELLED' and journal['directories'] == []


def test_setup_seed_rejects_aba_without_replacement_baseline(repo, tmp_path):
    core = coordinator(tmp_path, ABARuntime())
    seeds = WorkspaceBaselineSeeds(coordinator=core)
    with pytest.raises(ScanCancelled):
        seeds.capture_session(repo, 'owner')
    assert not core.store.path(repo, 'codex', 'owner').exists()
    journal = ScanAttemptStore(core.store, repo).read()
    assert journal['lane']['state'] == 'CANCELLED' and journal['directories'] == []


def test_cancelled_fence_cannot_publish_completed_provider_result(repo, tmp_path):
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime)
    core.handle_lifecycle('SESSION_START', repo, 'cursor', 'owner')
    path = core.store.path(repo, 'cursor', 'owner')
    before = path.read_bytes()
    dirty(repo)
    original = runtime.scan
    def cancelled(*args, **kwargs):
        result = original(*args, **kwargs)
        execution = kwargs['execution']
        with core.store.lock(repo) as acquired:
            assert acquired
            assert execution.store.cancel(execution.lease)
        return result
    runtime.scan = cancelled
    out = core.handle_lifecycle('WORKSPACE_ACTIVITY', repo, 'cursor', 'owner')
    assert out['reason'] == 'SCAN_ATTEMPT_PUBLICATION_STALE'
    assert path.read_bytes() == before
    assert out['scan_attempt']['publication'] == 'NOT_PUBLISHED'


def test_runtime_without_input_binding_is_never_published(repo, tmp_path):
    runtime = FakeRuntime()
    # Explicitly simulate an implementation violating the new execution port.
    runtime.scan = runtime.scan.__wrapped__.__get__(runtime, FakeRuntime)
    core = coordinator(tmp_path, runtime)
    dirty(repo)
    out = core.handle('FILE_CHANGED', repo, 'codex', 'owner')
    assert out['reason'] == 'SCAN_ATTEMPT_PUBLICATION_STALE'
    assert not core.store.path(repo, 'codex', 'owner').exists()


def test_cancelled_pre_edit_recovery_stops_before_git_source_read(repo, monkeypatch):
    from security_runtime.first_scan_attribution import recover_bytes
    import security_runtime.hook_runtime as module
    monkeypatch.setattr(module, '_git', lambda *args: pytest.fail('Cancelled recovery must not read Git'))
    progress = NullProgressReporter()
    progress.cancel()
    with progress_context(progress), pytest.raises(ScanCancelled):
        recover_bytes(repo, 'A.java', 'a'*64, b'k'*32)


@pytest.mark.parametrize('initial',['ABSENT','PRESENT'])
def test_known_recheck_expectation_rejects_opposite_input_even_after_source_returns(repo, tmp_path, initial):
    target = repo/'retained.py'
    key = b'k'*32
    captured = capture_snapshot(repo, key)
    assert 'retained.py' not in captured.file_digests
    if initial == 'PRESENT':
        target.write_bytes(b'original-A\n')
    expected = capture_recheck_expectation(repo, captured, key, ['retained.py'])
    assert captured.file_digests.get('retained.py') is None  # Original baseline stays unchanged.
    if initial == 'PRESENT':
        target.unlink()
    else:
        target.write_bytes(b'captured-A\n')
    with capture_scan_input(scoped_request(repo, ['retained.py'])) as view:
        if initial == 'PRESENT':
            target.write_bytes(b'original-A\n')
        else:
            target.unlink()
        assert not captured_input_matches(view, expected, key)


def test_absent_known_recheck_is_bound_but_unknown_mirror_path_is_rejected(repo):
    key = b'k'*32
    captured = capture_snapshot(repo, key)
    expected = capture_recheck_expectation(repo, captured, key, ['removed.py'])
    with capture_scan_input(scoped_request(repo, ['removed.py'])) as view:
        assert captured_input_matches(view, expected, key)
    (repo/'unclaimed.py').write_bytes(b'current\n')
    with capture_scan_input(scoped_request(repo, ['unclaimed.py'])) as view:
        assert not captured_input_matches(view, expected, key)
