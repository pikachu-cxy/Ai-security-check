"""Optional closeout waiting observes original saved state, never redispatches."""
import asyncio

import pytest

from security_runtime.development_check import DevelopmentCheckService
from security_runtime.tasks.ownership import TaskOwnershipError
from test_development_check import OWNER, check, execute  # noqa: F401


class WaitClock:
    def __init__(self, service, callback=None):
        self.value, self.sleeps, self.callback = 0, [], callback
        service.monotonic = lambda: self.value
        service.wait_sleep = self.sleep

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds
        if self.callback:
            callback, self.callback = self.callback, None
            callback()


def dirty(check, key='waiting'):
    root, service, _, _ = check
    ref = service.begin(root, key)['check_ref']
    service.record(root, ref, ['app.ts'])
    return ref


def test_default_finish_keeps_dispatch_only_response(check):
    root, service, _, state = check
    ref = dirty(check)
    launches = []
    service.launcher = lambda *args: launches.append(args)
    clock = WaitClock(service)
    result = asyncio.run(service.finish_and_wait(root, ref))
    assert result['status'] == 'QUEUED'
    assert 'closeout_wait' not in result and 'static_result' not in result
    assert len(launches) == 1 and not clock.sleeps and state['calls'] == 0


def test_wait_returns_full_original_scoped_result_once(check, monkeypatch):
    root, service, _, state = check
    ref = dirty(check)
    launches = []
    service.launcher = lambda *args: launches.append(args)
    WaitClock(service, lambda: execute(check, monkeypatch))
    result = asyncio.run(service.finish_and_wait(root, ref, 5))
    # This fixture supplies only the native scanner; keep its actual coverage gap.
    assert result['status'] == 'PARTIAL' and 'SCANNER_COVERAGE_LIMITED' in result['gaps']
    assert result['dirty_seq'] == result['scanned_seq'] == 1
    assert result['scope']['paths'] == ['app.ts'] and not result['scope']['full_project']
    assert result['static_result']['finding_count'] == 0
    assert result['static_result']['findings_access']['arguments']['scan_id'] == result['scan_id']
    assert result['closeout_wait']['stopped_reason'] == 'STATE_AVAILABLE'
    assert not result['closeout_wait']['scanner_dispatched_by_wait']
    assert len(launches) == state['calls'] == 1
    assert not (service.hooks.workspace_directory(root)/'task-security.db').exists()


def test_budget_returns_pending_without_restarting_or_claiming_completion(check):
    root, service, _, state = check
    ref = dirty(check)
    launches = []
    service.launcher = lambda *args: launches.append(args)
    clock = WaitClock(service)
    result = asyncio.run(service.finish_and_wait(root, ref, 1))
    assert clock.sleeps == [1] and result['closeout_wait']['elapsed_ms'] == 1000
    assert result['status'] == 'QUEUED' and result['dirty_seq'] == 1 and result['scanned_seq'] == 0
    assert result['closeout_wait']['stopped_reason'] == 'TIME_BUDGET_EXHAUSTED'
    assert 'OBSERVED_EDITS_PENDING' in result['gaps']
    assert result['next_action']['tool'] == 'get_development_check'
    assert len(launches) == 1 and state['calls'] == 0


def test_new_edit_stops_wait_and_retains_older_result(check, monkeypatch):
    root, service, _, state = check
    ref = dirty(check)
    assert execute(check, monkeypatch) == 0
    old = service.get(root, ref)
    service.record(root, ref, ['app.ts'], event_id='second')
    launches = []

    def wake(*args):
        launches.append(args)
        store = service.store(root)
        with store.transaction() as db:
            store._put(db, '$worker', dict(ticket='b'*64, lease_until=service.now()+90))

    service.launcher = wake

    def append():
        (root/'app.ts').write_text('def run(value):\n    return value + 3\n')
        service.record(root, ref, ['app.ts'], event_id='third')

    clock = WaitClock(service, append)
    result = asyncio.run(service.finish_and_wait(root, ref, 25))
    assert len(clock.sleeps) == 1
    assert result['status'] == 'DIRTY' and (result['dirty_seq'], result['scanned_seq']) == (3, 1)
    assert result['scan_id'] == old['scan_id'] and result['static_result'] == old['static_result']
    assert result['closeout_wait']['requested_dirty_seq'] == 2
    assert result['closeout_wait']['stopped_reason'] == 'VERSION_CHANGED'
    assert len(launches) == state['calls'] == 1


def test_unknown_scope_keeps_partial_gap_and_runs_no_scanner(check, monkeypatch):
    root, service, _, state = check
    ref = service.begin(root, 'unknown')['check_ref']
    service.record(root, ref, [], scope_unknown=True)
    WaitClock(service, lambda: execute(check, monkeypatch))
    result = asyncio.run(service.finish_and_wait(root, ref, 5))
    assert result['status'] == 'PARTIAL' and result['scan_id'] is None
    assert result['scope']['paths'] == [] and result['scope']['scope_unknown']
    assert 'UNOBSERVED_PATHS_POSSIBLE' in result['gaps']
    assert not result['baseline_created'] and state['calls'] == 0


def test_failed_worker_is_returned_without_retry(check):
    root, service, _, state = check
    ref = dirty(check)
    launches = []
    service.launcher = lambda *args: launches.append(args)

    def fail():
        store = service.store(root)
        with store.transaction() as db:
            row = store._get(db, ref)
            store._put(db, ref, dict(row, state='FAILED', reason_code='DEVELOPMENT_SCAN_FAILED'))

    clock = WaitClock(service, fail)
    result = asyncio.run(service.finish_and_wait(root, ref, 25))
    assert result['status'] == 'FAILED' and result['reason_code'] == 'DEVELOPMENT_SCAN_FAILED'
    assert len(clock.sleeps) == len(launches) == 1 and state['calls'] == 0


def test_expired_worker_observation_stops_without_retry(check):
    root, service, _, _ = check
    ref = dirty(check)
    store = service.store(root)
    with store.transaction() as db:
        store._put(db, '$worker', dict(ticket='a'*64, lease_until=service.now()-1))
    clock = WaitClock(service)
    result = asyncio.run(service.finish_and_wait(root, ref, 25))
    assert result['status'] == 'INTERRUPTED' and not clock.sleeps


def test_wait_does_not_cross_owner_or_replaced_root(check):
    root, service, runtime, _ = check
    ref = dirty(check)
    other = DevelopmentCheckService(runtime, service.hooks,
        owner=dict(host='codex', session='2'*64), launcher=lambda *args: pytest.fail('cross-owner wake'))
    with pytest.raises(TaskOwnershipError):
        asyncio.run(other.finish_and_wait(root, ref, 25))

    def replace_root():
        root.rename(root.with_name('original-project'))
        root.mkdir()

    WaitClock(service, replace_root)
    with pytest.raises(ValueError, match='DEVELOPMENT_WORKSPACE_REPLACED'):
        asyncio.run(service.finish_and_wait(root, ref, 25))


def test_wait_yields_and_cancellation_retains_dispatched_request(check):
    root, service, _, state = check
    ref = dirty(check)
    launches = []
    service.launcher = lambda *args: launches.append(args)

    async def run():
        entered = asyncio.Event()
        blocked = asyncio.Event()

        async def pause(seconds):
            entered.set()
            await blocked.wait()

        service.wait_sleep = pause
        pending = asyncio.create_task(service.finish_and_wait(root, ref, 25))
        await asyncio.wait_for(entered.wait(), timeout=5)
        # A separate coroutine reads immediately while the first request waits.
        async def read():
            return service.get(root, ref)
        result = await asyncio.wait_for(read(), timeout=5)
        assert result['status'] == 'QUEUED' and result['finish_requested']
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

    asyncio.run(run())
    assert len(launches) == 1 and state['calls'] == 0
    assert service.get(root, ref)['finish_requested']


@pytest.mark.parametrize('value', [-1, 26, True, 1.25, '1', None])
def test_invalid_wait_is_rejected_before_dispatch(check, value):
    root, service, _, _ = check
    ref = dirty(check)
    service.launcher = lambda *args: pytest.fail('invalid wait must not dispatch')
    with pytest.raises(ValueError, match='DEVELOPMENT_WAIT_INVALID'):
        asyncio.run(service.finish_and_wait(root, ref, value))
    assert not service.get(root, ref)['finish_requested']
