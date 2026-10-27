"""Timeout delivery, generation isolation and bounded recovery contracts."""
import asyncio

import pytest

from security_runtime.development_check import DevelopmentCheckService
from functools import partial
from security_runtime.development_continuation import stop as host_stop, pending_context as context, MAX_CONTINUATIONS

# These legacy budget tests exercise the explicit trusted-host opt-in only.
stop = partial(host_stop, allow_continuation=True)
from security_runtime.development_delivery import publish, acknowledge
from security_runtime.development_scheduler import recover_once
from security_runtime.tasks.ownership import TaskOwnershipError
from test_development_check import OWNER, check, execute  # noqa: F401
from test_development_check_wait import WaitClock


def submitted(check):
    root, service, _, _ = check
    ref = service.begin(root, 'delivery')['check_ref']
    service.record(root, ref, ['app.ts'])
    service.finish(root, ref)
    return ref


def test_timeout_then_saved_result_survives_a_new_connection(check, monkeypatch):
    root, service, runtime, state = check
    ref = submitted(check)
    WaitClock(service)
    before = asyncio.run(service.wait_saved(root, ref, 1))
    assert before['status'] == 'QUEUED' and state['calls'] == 0
    assert execute(check, monkeypatch) == 0
    # No in-memory task/connection mapping is needed with the original verified owner.
    resumed = DevelopmentCheckService(None, service.hooks, owner=OWNER)
    pending = resumed.deliveries(root)
    assert pending['total'] == 1 and not pending['automatic_host_ack']
    result = resumed.saved_result(root, ref, 1)
    assert result['static_result']['scan_id'] == service.get(root, ref)['scan_id']
    assert result['delivery']['delivery'] == 'PENDING'
    assert result['delivery']['user_consumption'] == 'UNKNOWN'
    assert resumed.deliveries(root)['total'] == 1  # Reading never clears the outbox.
    assert state['calls'] == 1 and state['inputs'] == [('app.ts',)]


def test_new_scan_does_not_overwrite_undelivered_version(check, monkeypatch):
    root, service, _, state = check
    ref = submitted(check)
    assert execute(check, monkeypatch) == 0
    original = service.saved_result(root, ref, 1)
    (root/'app.ts').write_text('export const changed = 2;\n')
    service.record(root, ref, ['app.ts'], event_id='next-version')
    assert execute(check, monkeypatch) == 0
    assert service.deliveries(root)['total'] == 2
    assert service.saved_result(root, ref, 1) == original
    assert service.saved_result(root, ref, 2)['delivery']['scan_id'] != original['delivery']['scan_id']
    assert state['calls'] == 2


def test_publication_rolls_back_check_and_outbox_together(check):
    root, service, _, _ = check
    ref = submitted(check)
    store = service.store(root)
    with pytest.raises(RuntimeError):
        with store.transaction() as db:
            row = store._get(db, ref)
            row = store._put(db, ref, dict(row, state='PARTIAL', scanned_seq=1))
            publish(store, db, row)
            raise RuntimeError('interrupt before commit')
    assert store.load(ref)['scanned_seq'] == 0
    assert service.deliveries(root)['total'] == 0


def test_result_and_ack_reject_other_owner_and_wrong_version(check, monkeypatch):
    root, service, _, _ = check
    ref = submitted(check)
    execute(check, monkeypatch)
    other = DevelopmentCheckService(None, service.hooks, owner=dict(host='codex', session='2'*64))
    assert other.deliveries(root)['total'] == 0
    with pytest.raises(TaskOwnershipError):
        other.saved_result(root, ref, 1)
    with pytest.raises(TaskOwnershipError):
        acknowledge(service.store(root), other.owner, ref, 1, '0'*64)
    with pytest.raises(ValueError):
        acknowledge(service.store(root), OWNER, ref, 1, '0'*64)
    result = service.saved_result(root, ref, 1)
    receipt = acknowledge(service.store(root), OWNER, ref, 1, result['delivery']['result_version'])
    assert receipt['delivery'] == 'HOST_REPORTED' and receipt['user_consumption'] == 'UNKNOWN'
    assert service.deliveries(root)['total'] == 0


def test_outbox_generation_is_immutable_on_republish(check, monkeypatch):
    root, service, _, _ = check
    ref = submitted(check)
    execute(check, monkeypatch)
    store = service.store(root)
    row = store.load(ref)
    with store.transaction() as db:
        publish(store, db, row)
    with pytest.raises(ValueError, match='ALREADY_PUBLISHED'):
        with store.transaction() as db:
            publish(store, db, dict(row, scan_id='replacement'))


def test_undelivered_results_protect_old_nonfocus_metadata_from_gc(check, monkeypatch):
    root, service, _, _ = check
    ref = submitted(check)
    execute(check, monkeypatch)
    store = service.store(root)
    with store.transaction() as db:
        store._put(db, ref, dict(store._get(db, ref), updated_at=0))
    service.begin(root, 'another-task')
    service.begin(root, 'gc')
    assert store.load(ref) and service.saved_result(root, ref, 1)


def test_stop_does_not_create_work_and_has_persistent_budget(check):
    root, service, _, state = check
    assert stop(service.hooks, root, OWNER) is None
    assert context(service.hooks, root, OWNER) == ''
    assert not service.store(root).path.exists()
    ref = submitted(check)
    assert stop(service.hooks, root, OWNER, stop_hook_active=True) is None
    for _ in range(MAX_CONTINUATIONS):
        result = stop(service.hooks, root, OWNER)
        assert result['decision'] == 'block' and 'wait_development_check' in result['reason']
        assert ref in result['reason'] and not result['scanner_run']
    assert stop(service.hooks, root, OWNER) is None
    assert state['calls'] == 0
    assert 'get_development_deliveries' in context(service.hooks, root, OWNER)
    assert stop(service.hooks, root, dict(host='codex', session='3'*64)) is None


def test_result_already_prepared_for_model_avoids_extra_stop_but_is_not_acked(check, monkeypatch):
    root, service, _, _ = check
    ref = submitted(check)
    execute(check, monkeypatch)
    assert stop(service.hooks, root, OWNER, offered={(ref, 1)}) is None
    assert service.deliveries(root)['total'] == 1
    result = stop(service.hooks, root, OWNER)
    assert 'get_development_result' in result['reason']


def test_expired_stop_budget_does_not_loop_and_keeps_pending_work(check):
    root, service, _, _ = check
    ref = submitted(check)
    stop(service.hooks, root, OWNER)
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, f'continuation:{ref}:1')
        store._put(db, row['key'], dict(row, expires_at=0))
    assert stop(service.hooks, root, OWNER) is None
    assert service.get(root, ref)['status'] == 'QUEUED'


def test_scheduler_never_runs_unsubmitted_edits_or_reads(check):
    root, service, _, _ = check
    calls = []
    ref = service.begin(root, 'not-submitted')['check_ref']
    service.record(root, ref, ['app.ts'])
    assert not recover_once(service.hooks, root, launcher=lambda *a: calls.append(a))
    assert not calls and not service.deliveries(root)['results']


def test_scheduler_recovery_only_starts_saved_work_and_bounds_launch_failures(check):
    root, service, _, _ = check
    ref = submitted(check)
    store = service.store(root)
    calls = []
    def fail(*args):
        calls.append(args)
        raise OSError('private process details')
    for _ in range(3):
        assert recover_once(service.hooks, root, launcher=fail)
        with store.transaction() as db:
            store._put(db, ref, dict(store._get(db, ref), launch_retry_at=0))
    assert len(calls) == 3
    assert not recover_once(service.hooks, root, launcher=fail)
    assert service.get(root, ref)['status'] == 'FAILED'
    failure = service.saved_result(root, ref, 1)
    assert failure['reason_code'] == 'DEVELOPMENT_WORKER_START_FAILED'
    assert 'private process' not in str(failure)
    service.finish(root, ref)
    assert service.get(root, ref)['status'] == 'FAILED'  # Same finish cannot reset retry quota.


def test_product_budget_validated_before_submit_and_can_exceed_25(check, monkeypatch):
    root, service, _, state = check
    ref = service.begin(root, 'product-wait')['check_ref']
    service.record(root, ref, ['app.ts'])
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', 'invalid')
    with pytest.raises(ValueError):
        asyncio.run(service.complete(root, ref))
    assert not service.store(root).load(ref)['finish_requested']
    monkeypatch.setenv('SECURITY_RUNTIME_DEVELOPMENT_WAIT_SECONDS', '30')
    clock = WaitClock(service)
    result = asyncio.run(service.complete(root, ref))
    assert result['closeout_wait']['requested_seconds'] == 30
    assert clock.value == 30 and state['calls'] == 0
    # Actual worker completion after the request's timeout is still retrievable.
    execute(check, monkeypatch)
    assert service.saved_result(root, ref, 1)['static_result']


def test_transient_scan_failure_retries_in_worker_without_new_host_submission(check, monkeypatch):
    from security_runtime import development_check_worker as worker
    root, service, _, state = check
    ref = submitted(check)
    original = worker._scan
    attempts = []
    def transient(*args, **kwargs):
        attempts.append(True)
        if len(attempts) == 1:
            raise OSError('transient local failure')
        return original(*args, **kwargs)
    monkeypatch.setattr(worker, '_scan', transient)
    assert execute(check, monkeypatch) == 0
    assert len(attempts) == 2 and state['calls'] == 1
    assert service.get(root, ref)['scanned_seq'] == 1
    assert service.deliveries(root)['total'] == 1


def test_resource_busy_retry_budget_is_durable_and_delivers_failure(check, monkeypatch):
    from security_runtime import development_check_worker as worker
    root, service, _, _ = check
    ref = submitted(check)
    store = service.store(root)
    with store.transaction() as db:
        store._put(db, ref, dict(store._get(db, ref), retry_seq=1,
                                busy_attempts=worker.MAX_BUSY_ATTEMPTS-1))
    monkeypatch.setattr(worker, '_scan', lambda *a, **k: None)
    assert execute(check, monkeypatch) == 0
    assert service.get(root, ref)['status'] == 'FAILED'
    assert service.saved_result(root, ref, 1)['reason_code'] == 'WORKSPACE_SCAN_BUSY'


def test_paging_does_not_repeat_full_path_lists(check, monkeypatch):
    root, service, _, _ = check
    ref = submitted(check)
    execute(check, monkeypatch)
    summary = service.deliveries(root)['results'][0]['scope']
    assert summary['path_count'] == 1 and 'paths' not in summary
    assert service.saved_result(root, ref, 1)['delivery']['scope']['paths'] == ['app.ts']


def test_new_edit_during_scan_keeps_outbox_bound_to_captured_scope(check, monkeypatch):
    root, service, _, state = check
    ref = submitted(check)
    def edit(_):
        (root/'later.ts').write_text('export const later = 1;\n')
        service.record(root, ref, ['later.ts'], event_id='during-scan')
    state['callback'] = edit
    execute(check, monkeypatch)
    assert service.get(root, ref)['status'] == 'DIRTY'
    assert service.saved_result(root, ref, 1)['delivery']['scope']['paths'] == ['app.ts']
    assert state['calls'] == 1


def test_many_pending_versions_cannot_exceed_per_turn_continuation_budget(check):
    root, service, _, _ = check
    refs = []
    for index in range(3):
        ref = service.begin(root, f'pending-{index}')['check_ref']
        refs.append(ref)
        service.record(root, ref, [], scope_unknown=True)
        service.finish(root, ref)
        store = service.store(root)
        with store.transaction() as db:
            row = store._put(db, ref, dict(store._get(db, ref), state='PARTIAL', scanned_seq=1))
            publish(store, db, row)
    offered = set()
    for ref in refs[:2]:
        assert stop(service.hooks, root, OWNER, offered=offered, turn_id='one-turn')['decision'] == 'block'
        offered.add((ref, 1))
    assert stop(service.hooks, root, OWNER, offered=offered, turn_id='one-turn') is None
    assert service.deliveries(root)['total'] == 3


def test_old_busy_attempt_cannot_exhaust_new_edit_generation(check, monkeypatch):
    from security_runtime import development_check_worker as worker
    root, service, _, _ = check
    ref = submitted(check)
    store = service.store(root)
    with store.transaction() as db:
        store._put(db, ref, dict(store._get(db, ref), retry_seq=1, attempt_count=2,
                                busy_attempts=worker.MAX_BUSY_ATTEMPTS-1))
    def edit_then_busy(*args, **kwargs):
        service.record(root, ref, ['app.ts'], event_id='new-generation-while-busy')
        return None
    monkeypatch.setattr(worker, '_scan', edit_then_busy)
    assert execute(check, monkeypatch) == 0
    row = store.load(ref)
    assert row['state'] == 'DIRTY' and row['dirty_seq'] == 2
    assert row['attempt_count'] == row['busy_attempts'] == 0
    assert service.deliveries(root)['total'] == 0


def test_old_resident_mcp_append_does_not_carry_retry_quota_to_new_version(check, monkeypatch):
    root, service, _, state = check
    ref = submitted(check)
    execute(check, monkeypatch)
    (root/'app.ts').write_text('export const next = 2;\n')
    store = service.store(root)
    with store.transaction() as db:
        # Simulate the pre-upgrade append contract, which copies unknown fields.
        row = store._get(db, ref)
        store._put(db, ref, dict(row, dirty_seq=2, state='DIRTY', finish_requested=False,
            attempt_count=3, busy_attempts=119, next_attempt_at=store.now()+600, failed_seq=1))
    service.finish(root, ref)
    assert execute(check, monkeypatch) == 0
    row = store.load(ref)
    assert row['scanned_seq'] == row['retry_seq'] == 2
    assert row['attempt_count'] == 1 and row['busy_attempts'] == 0
    assert state['calls'] == 2 and service.deliveries(root)['total'] == 2


@pytest.mark.parametrize('offset,limit', [(-1, 1), (False, 1), (0, 0), (0, 51), (0, True)])
def test_delivery_page_limits_reject_coercion(check, offset, limit):
    root, service, _, _ = check
    with pytest.raises(ValueError):
        service.deliveries(root, offset=offset, limit=limit)
