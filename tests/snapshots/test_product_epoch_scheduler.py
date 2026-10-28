"""Deterministic epoch scheduling with real finite observation services.

The manual executor controls dispatch order, cancellation and rejection. Source
enumeration, hashing, durable epoch references and file descriptors remain real.
"""
from collections import deque
from concurrent.futures import Future
import asyncio
import threading
from types import SimpleNamespace

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.global_workspace import workspace_state
from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_jobs import ProductEpochJobs
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.ownership import session_owner


class ManualExecutor:
    def __init__(self):
        self.pending = deque()
        self.submitted = 0
        self.reject = False

    def submit(self, function, *arguments):
        if self.reject:
            raise RuntimeError('Fixture executor rejected submission')
        future = Future()
        self.pending.append((future, function, arguments))
        self.submitted += 1
        return future

    def run_one(self):
        future, function, arguments = self.pending.popleft()
        if future.set_running_or_notify_cancel():
            try:
                future.set_result(function(*arguments))
            except BaseException as error:
                future.set_exception(error)
                raise

    def drain(self, maximum=256):
        for _ in range(maximum):
            if not self.pending:
                return
            self.run_one()
        pytest.fail('Scheduler did not leave its finite dispatch queue')

    def shutdown(self, *, wait=True, cancel_futures=False):
        self.reject = True
        if cancel_futures:
            while self.pending:
                self.pending.popleft()[0].cancel()


@pytest.fixture
def sample(tmp_path, monkeypatch):
    root = tmp_path.resolve()/'project'
    root.mkdir()
    (root/'source.py').write_bytes(b'value = 1\n'*40)
    hooks = HookStateStore(tmp_path.resolve()/'private-state')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path.resolve()/'runtime'))
    return root, hooks, session_owner('codex', 'scheduler-fixture')


def track_services(monkeypatch, *, policy=None, ensure=None, step=None):
    created = []
    trace = []

    class TrackedService(ProductEpochService):
        def __init__(self, hooks, root):
            super().__init__(hooks, root, policy=policy)
            self.close_count = 0
            created.append(self)

        def ensure(self, owner):
            trace.append((self.root.name, 'ensure'))
            result = super().ensure(owner)
            return ensure(self, result) if ensure is not None else result

        def step(self, owner):
            trace.append((self.root.name, 'step'))
            if step is not None:
                return step(self, owner)
            return super().step(owner)

        def close(self):
            self.close_count += 1
            super().close()

    monkeypatch.setattr('security_runtime.product_epoch_service.ProductEpochService', TrackedService)
    return created, trace


@pytest.mark.parametrize('pause', ['BUSY', 'WAITING_CAPACITY'])
def test_paused_job_has_no_hot_loop_and_explicit_retry_resumes_original_epoch(sample, monkeypatch, pause):
    root, hooks, owner = sample
    pauses = [pause]

    def temporarily_pause(_service, result):
        return dict(result, state=pauses.pop()) if pauses else result

    created, _ = track_services(monkeypatch, ensure=temporarily_pause)
    executor, jobs = ManualExecutor(), None
    jobs = ProductEpochJobs(executor)
    try:
        first = jobs.start(root, hooks, owner)
        assert jobs.start(root, hooks, session_owner('codex', 'second')) is first
        executor.run_one()
        paused = first.result(timeout=0)
        assert paused['state'] == pause
        assert not executor.pending and executor.submitted == 1
        assert created[0].close_count >= 1
        continued = jobs.start(root, hooks, owner)
        assert continued is not first
        executor.drain()
        sealed = continued.result(timeout=0)
        assert sealed['state'] == 'SEALED'
        assert sealed['epoch_ref'] == paused['epoch_ref']
        assert len(created) == 2
        assert jobs.start(root, hooks, owner) is continued
    finally:
        jobs.close()
        for current in created:
            current.close()


def test_bounded_turns_allow_other_workspace_to_progress_before_large_job_finishes(sample, tmp_path, monkeypatch):
    root, hooks, owner = sample
    second = tmp_path.resolve()/'second'
    second.mkdir()
    (second/'short.py').write_bytes(b'short = True\n')
    created, trace = track_services(monkeypatch, policy=dict(step_files=1, step_bytes=64))
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        large = jobs.start(root, hooks, owner)
        small = jobs.start(second, hooks, owner)
        executor.run_one()
        executor.run_one()
        assert trace[:2] == [('project', 'ensure'), ('second', 'ensure')]
        executor.run_one()
        executor.run_one()
        assert trace[2:4] == [('project', 'step'), ('second', 'step')]
        while not small.done():
            executor.run_one()
        assert small.result(timeout=0)['state'] == 'SEALED'
        assert not large.done()
        executor.drain()
        assert large.result(timeout=0)['state'] == 'SEALED'
    finally:
        jobs.close()
        for current in created:
            current.close()


def test_constructor_failure_does_not_cache_a_never_finishing_future(sample, monkeypatch):
    root, hooks, owner = sample
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)

    def unavailable(*args, **kwargs):
        raise ValueError('Fixture constructor failure')

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr('security_runtime.product_epoch_service.ProductEpochService', unavailable)
            with pytest.raises(ValueError, match='Fixture constructor failure'):
                jobs.start(root, hooks, owner)
        assert root not in jobs.jobs
        future = jobs.start(root, hooks, owner)
        executor.drain()
        assert future.result(timeout=0)['state'] == 'SEALED'
    finally:
        jobs.close()


def test_initial_executor_rejection_releases_constructed_service_and_does_not_poison_retry(sample, monkeypatch):
    root, hooks, owner = sample
    created, _ = track_services(monkeypatch)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    executor.reject = True
    try:
        with pytest.raises(RuntimeError, match='rejected submission'):
            jobs.start(root, hooks, owner)
        assert root not in jobs.jobs and not jobs.resources
        assert created[0].close_count >= 1
        executor.reject = False
        future = jobs.start(root, hooks, owner)
        executor.drain()
        assert future.result(timeout=0)['state'] == 'SEALED'
    finally:
        jobs.close()
        for current in created:
            current.close()


def test_cancellation_while_terminal_step_returns_does_not_leak_or_publish(sample, monkeypatch):
    root, hooks, owner = sample
    public = []

    def cancel_after_seal(current, actor):
        result = ProductEpochService.step(current, actor)
        if result['state'] == 'SEALED':
            assert public[0].cancel()
        return result

    created, _ = track_services(monkeypatch, step=cancel_after_seal)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    try:
        public.append(jobs.start(root, hooks, owner))
        executor.drain()
        assert public[0].cancelled()
        assert not jobs.resources and not jobs.active
        assert created[0].close_count >= 1
        assert created[0]._reader is None and created[0]._directory is None
    finally:
        jobs.close()
        for current in created:
            current.close()


def pending_reader(sample, monkeypatch):
    root, hooks, owner = sample
    created, _ = track_services(monkeypatch, policy=dict(step_files=1, step_bytes=64))
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    future = jobs.start(root, hooks, owner)
    for _ in range(16):
        executor.run_one()
        if created[0]._reader is not None:
            return jobs, executor, future, created[0]
    pytest.fail('Did not reach a real multi-step file reader')


def assert_closed(reader):
    assert reader.fd is None and reader.directory_fd is None


def test_caller_cancellation_releases_reader_and_can_resume_same_epoch(sample, monkeypatch):
    root, hooks, owner = sample
    jobs, executor, future, current = pending_reader(sample, monkeypatch)
    reader = current._reader
    ref = current.status()['epoch_ref']
    try:
        assert future.cancel()
        executor.drain()
        assert_closed(reader)
        resumed = jobs.start(root, hooks, owner)
        assert resumed is not future
        executor.drain()
        assert resumed.result(timeout=0)['epoch_ref'] == ref
        assert resumed.result(timeout=0)['state'] == 'SEALED'
    finally:
        jobs.close()
        current.close()


def test_close_releases_reader_even_when_executor_cancels_its_queued_cleanup_turn(sample, monkeypatch):
    jobs, executor, future, current = pending_reader(sample, monkeypatch)
    reader = current._reader
    try:
        jobs.close()
        executor.shutdown(wait=True, cancel_futures=True)
        assert future.done() and future.cancelled()
        assert_closed(reader)
        with pytest.raises(ValueError, match='closed'):
            jobs.start(*sample)
    finally:
        current.close()


def test_resubmission_failure_closes_reader_and_completes_the_public_future(sample, monkeypatch):
    jobs, executor, future, current = pending_reader(sample, monkeypatch)
    reader = current._reader
    try:
        executor.reject = True
        executor.run_one()
        assert future.done()
        with pytest.raises(RuntimeError, match='rejected submission'):
            future.result(timeout=0)
        assert_closed(reader)
    finally:
        jobs.close()
        current.close()


def test_service_exception_closes_reader_and_finishes_the_public_future(sample, monkeypatch):
    jobs, executor, future, current = pending_reader(sample, monkeypatch)
    reader = current._reader

    def unavailable(*args, **kwargs):
        raise ValueError('Fixture service failed')

    monkeypatch.setattr(current, 'step', unavailable)
    try:
        executor.run_one()
        assert future.done()
        with pytest.raises(ValueError, match='Fixture service failed'):
            future.result(timeout=0)
        assert_closed(reader)
    finally:
        jobs.close()
        current.close()


def test_close_never_closes_a_successor_turn_while_its_real_service_is_active(sample, monkeypatch):
    root, hooks, owner = sample
    entered, release = threading.Event(), threading.Event()
    closed_during_step = []

    def blocked_step(current, actor):
        entered.set()
        assert release.wait(timeout=5)
        return ProductEpochService.step(current, actor)

    created, _ = track_services(monkeypatch, step=blocked_step)
    executor = ManualExecutor()
    jobs = ProductEpochJobs(executor)
    main_thread = threading.get_ident()

    class TurnCompletionGate:
        """Let a submitted successor start before its predecessor finalizes."""
        def __init__(self):
            self.lock = threading.RLock()
            self.armed = False
            self.gated = False

        def __enter__(self):
            if self.armed and not self.gated and threading.get_ident() == main_thread:
                self.gated = True
                assert entered.wait(timeout=5)
            self.lock.acquire()
            return self

        def __exit__(self, *args):
            self.lock.release()

    gate = TurnCompletionGate()
    jobs.lock = gate
    original_submit = executor.submit
    worker = []

    def interleaved_submit(function, *arguments):
        if executor.submitted != 1:
            return original_submit(function, *arguments)
        executor.submitted += 1
        future = Future()

        def run():
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(function(*arguments))
                except BaseException as error:
                    future.set_exception(error)

        thread = threading.Thread(target=run)
        worker.append(thread)
        gate.armed = True
        thread.start()
        return future

    executor.submit = interleaved_submit
    future = jobs.start(root, hooks, owner)
    current = created[0]
    close = current.close

    def guarded_close():
        if entered.is_set() and not release.is_set():
            closed_during_step.append(True)
        close()

    monkeypatch.setattr(current, 'close', guarded_close)
    try:
        executor.run_one()
        assert entered.is_set() and not release.is_set()
        jobs.close()
        assert future.cancelled()
        assert not closed_during_step
    finally:
        release.set()
        for thread in worker:
            thread.join(timeout=5)
            assert not thread.is_alive()
        jobs.close()
        current.close()


def test_global_close_finishes_session_future_waiting_for_queued_publication(tmp_path):
    root, home = tmp_path.resolve()/'project', tmp_path.resolve()/'home'
    root.mkdir(); home.mkdir()
    pool = GlobalWorkspaces(base=tmp_path.resolve()/'routing', integration=SimpleNamespace(home=home))
    pool.executor.shutdown(wait=True, cancel_futures=True)
    executor = ManualExecutor()
    pool.executor = executor
    pool.epoch_jobs = ProductEpochJobs(executor)
    ready = Future()
    ready.set_result(dict(state='SEALED', epoch_ref='pe1-'+'a'*32))
    pool.epoch_jobs.jobs[root] = ready
    key = (root, 'session-key')
    core = SimpleNamespace(store=HookStateStore(tmp_path.resolve()/'private'))
    pool._start_epoch_initialization(key, root, 'session', core)
    session_future = pool.jobs[key]
    assert not session_future.done() and len(executor.pending) == 1
    pool.close()
    assert session_future.done()


def test_readonly_global_route_reports_unverified_state_without_repair_or_new_jobs(tmp_path, monkeypatch):
    root, home = tmp_path.resolve()/'project', tmp_path.resolve()/'home'
    root.mkdir(); home.mkdir()
    (root/'pyproject.toml').write_text('[project]\nname="fixture"\n', encoding='utf-8')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path.resolve()/'runtime'))
    pool = GlobalWorkspaces(base=tmp_path.resolve()/'routing', integration=SimpleNamespace(home=home))
    hooks = HookStateStore(workspace_state(root, pool.base)/'hooks')
    current = ProductEpochService(hooks, root)
    owner = session_owner('codex', 'readonly-fixture')
    current.ensure(owner)
    current.step(owner)
    # The caller sees a fixed diagnostic, not raw database exceptions or a new
    # observation. This corrupt private fixture must not be repaired on read.
    current.store.path.write_bytes(b'PRIVATE_CORRUPTION_DETAIL_MUST_NOT_BE_ECHOED')
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns)
              for path in tmp_path.rglob('*') if path.is_file()}
    for method in ('admit', 'bootstrap', 'bind_session'):
        monkeypatch.setattr(pool, method, lambda *args, **kwargs: pytest.fail('Read-only status must not admit'))
    server = create_global_server(workspaces=pool)
    try:
        result = asyncio.run(server.call_tool('get_product_epoch_status',
            {'workspace_path': str(root)})).structuredContent
        assert result['path_status'] == 'ALLOWED'
        assert result['reason_code'] == 'PRODUCT_EPOCH_STATE_UNVERIFIED'
        assert result['epoch_status'] is None
        assert not result['scanner_run'] and not result['state_modified']
        assert 'PRIVATE_CORRUPTION_DETAIL' not in str(result)
        assert not pool.children and not pool.sessions and not pool.jobs and not pool.epoch_jobs.jobs
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                 for path in tmp_path.rglob('*') if path.is_file()}
        assert before == after
    finally:
        current.close()
        pool.close()
