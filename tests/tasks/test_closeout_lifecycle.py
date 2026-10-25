"""New-policy routing and compatibility use real private stores and snapshots."""
import copy
import pytest

from security_runtime.tasks.activity import ActivityStore, POLICY
from security_runtime.tasks.lifecycle import switch
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import service


def scoped(sample, name='a', now=None):
    old, root, engine = sample
    kwargs = {'now':now} if now else {}
    return TaskSecurityService(engine, old.hooks, owner=session_owner('codex', name), **kwargs)


def test_old_tasks_keep_policy_and_same_baseline(service):
    task = scoped(service)
    root = service[1]
    old = task.begin(root, 'old')['task_ref']
    baseline = copy.deepcopy(task.load(root, old)['baseline'])
    (root/'routes.py').write_text('changed = True\n')
    assert task.begin(root, 'old', check_policy=POLICY)['task_ref'] == old
    assert 'check_policy' not in task.load(root, old)
    assert task.load(root, old)['baseline'] == baseline
    assert ActivityStore(task.hooks, root).focus(task._owner()) is None


def test_switch_resumes_original_baseline_and_rejects_other_session(service):
    a, b = scoped(service), scoped(service, 'b')
    root = service[1]
    first = a.begin(root, 'one', check_policy=POLICY)
    assert first['routing_generation'] == 1
    assert first['check_policy'] == POLICY
    ref = first['task_ref']
    baseline = copy.deepcopy(a.load(root, ref)['baseline'])
    (root/'routes.py').write_text('one = 1\n')
    assert a.begin(root, 'two', check_policy=POLICY)['status'] == 'ACTIVE_TASK_EXISTS'
    second = switch(a, root, ref, new_key='two', generation=1)
    assert second['task_ref'] != ref
    with pytest.raises(ValueError):
        b.finish(root, ref)
    switch(a, root, second['task_ref'], to_ref=ref, generation=2)
    assert a.load(root, ref)['baseline'] == baseline
    with pytest.raises(ValueError, match='routing changed'):
        switch(a, root, ref, to_ref=second['task_ref'], generation=1)


def test_activity_is_small_deduplicated_and_task_scoped(service):
    a, b = scoped(service), scoped(service, 'b')
    root = service[1]
    ar = a.begin(root, 'same', check_policy=POLICY)['task_ref']
    br = b.begin(root, 'same', check_policy=POLICY)['task_ref']
    store = ActivityStore(a.hooks, root)
    baseline_row = a.store(root).path.read_bytes()
    for _ in range(50):
        store.record(a._owner(), event_id='one', paths=('routes.py',), scope_unknown=False)
    assert store.summary(ar)['seq'] == 1
    assert store.summary(ar)['paths'] == ['routes.py']
    assert store.summary(br)['seq'] == 0
    assert a.store(root).path.read_bytes() == baseline_row
    assert service[2].calls == []


def test_new_goal_precheck_does_not_load_active_tasks_source_pages(service, monkeypatch):
    task = scoped(service)
    root = service[1]
    first = task.begin(root, 'one', check_policy=POLICY)
    monkeypatch.setattr('security_runtime.tasks.snapshot_pages.unpack',
                        lambda *args: pytest.fail('Goal precheck loaded task sources'))
    blocked = task.begin(root, 'two', check_policy=POLICY)
    assert blocked['status'] == 'ACTIVE_TASK_EXISTS'
    assert blocked['task_ref'] == first['task_ref']
    assert service[2].calls == []


def test_restart_recovers_focus_without_new_baseline(service):
    a = scoped(service)
    root = service[1]
    ref = a.begin(root, 'one', check_policy=POLICY)['task_ref']
    baseline = a.load(root, ref)['baseline']
    (root/'routes.py').write_text('after_restart = True\n')
    resumed = scoped(service)
    assert resumed.begin(root, 'one', check_policy=POLICY)['task_ref'] == ref
    assert resumed.load(root, ref)['baseline'] == baseline


def test_expired_task_key_cannot_rebuild_baseline(service):
    clock = [100000.0]
    a = scoped(service, now=lambda:clock[0])
    root = service[1]
    a.begin(root, 'one', check_policy=POLICY)
    clock[0] += 8*86400
    with pytest.raises(ValueError, match='never reconstruct'):
        a.begin(root, 'one', check_policy=POLICY)


def test_new_sources_survive_old_retention_period(service):
    clock = [100000.0]
    a = scoped(service, now=lambda:clock[0])
    root = service[1]
    ref = a.begin(root, 'one', check_policy=POLICY)['task_ref']
    before = a.before_lines(root, a.load(root, ref), 'routes.py')
    clock[0] += 2*86400
    assert a.before_lines(root, a.load(root, ref), 'routes.py') == before


def test_fifty_edits_scan_once_at_finish_and_reuse_result(service):
    task = scoped(service)
    root = service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    store = ActivityStore(task.hooks, root)
    for i in range(50):
        (root/'routes.py').write_text(f'value = {i}\n')
        store.record(task._owner(), event_id=str(i), paths=('routes.py',), scope_unknown=False)
    assert not service[2].calls
    result = task.finish(root, ref)
    assert result['status'] == 'READY'
    assert len(service[2].calls) == 1
    frozen = task.load(root, ref)['end']['version_ref']
    task.finish(root, ref)
    assert len(service[2].calls) == 1
    assert task.load(root, ref)['end']['version_ref'] == frozen
    assert task.load(root, ref)['baseline'] == baseline


def test_review_reads_frozen_end_but_cannot_publish_for_changed_workspace(service):
    task = scoped(service)
    root = service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    (root/'routes.py').write_text('value = 1\n')
    task.finish(root, ref)
    packet = task.prepare(root, ref)
    assert packet['review_session']
    (root/'routes.py').write_text('value = 2\n')
    record = task.load(root, ref)
    assert task.end_lines(root, record, 'routes.py') == ['value = 1']
    assert not task._fresh(root, record)
    assert task.prepare(root, ref)['status'] == 'STALE'


def test_new_versions_do_not_exhaust_legacy_two_attempt_budget(service):
    task = scoped(service)
    root = service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    for i in range(3):
        (root/'routes.py').write_text(f'value = {i}\n')
        assert task.finish(root, ref)['static']['status'] == 'SUCCESS'
    assert len(service[2].calls) == 3


def test_lightweight_event_never_enters_scanner_or_inventory(service, monkeypatch):
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.host_event_runtime import handle_normalized_event
    from security_runtime.host_events import EventKind, NormalizedHostEvent, VerifiedHostContext, OperationClass
    from security_runtime.host_lifecycle import connector_profile
    from security_runtime.hook_state import identity
    import os
    task = scoped(service)
    root = service[1]
    task.begin(root, 'one', check_policy=POLICY)
    coordinator = HookCoordinator(service[2], task.hooks)
    def forbidden(*args, **kwargs):
        pytest.fail('Edit event must not read project sources or invoke scanners')
    monkeypatch.setattr(coordinator, 'handle', forbidden)
    monkeypatch.setattr(coordinator, 'snapshot_capture', forbidden)
    context = VerifiedHostContext('codex', root, identity(os.path.normcase(str(root))),
        identity('a'), identity('event'), connector_profile('codex').capabilities, 'a')
    result, _ = handle_normalized_event(NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY,
        context, OperationClass.DIRECT_FILE_MUTATION, candidate_paths=('routes.py',), scope_unknown=False),
        coordinator=coordinator)
    assert result['status'] == 'RECORDED_PENDING'
    assert not result['execution']['scanner_run']


def test_replayed_event_after_switch_keeps_original_task(service):
    task, root = scoped(service), service[1]
    first = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    store = ActivityStore(task.hooks, root)
    store.record(task._owner(), event_id='original', paths=('routes.py',))
    second = switch(task, root, first, new_key='two', generation=1)['task_ref']
    replay = store.record(task._owner(), event_id='original', paths=('routes.py',))
    assert replay['task_ref'] == first and replay['duplicate']
    assert store.summary(second)['seq'] == 0


def test_busy_closeout_restarts_same_task_without_baseline_capture(service):
    from security_runtime.scan_attempt import ScanAttemptStore, source_binding
    task, root = scoped(service), service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'routes.py').write_text('value = 1\n')
    attempts = ScanAttemptStore(task.hooks, root)
    with task.hooks.lock(root) as acquired:
        assert acquired
        lease = attempts.claim('TASK', 'other-task', source_binding({'fixture':True}), owner=task._owner())
    assert lease is not None
    busy = task.finish(root, ref)
    assert busy['status'] == 'BUSY' and busy['resume_task_ref'] == ref
    assert not service[2].calls
    assert ActivityStore(task.hooks, root).read('queue:'+ref)['state'] == 'QUEUED'
    with task.hooks.lock(root) as acquired:
        assert acquired
        attempts.finish(lease, outcome='FAILED')
    resumed = scoped(service)
    assert resumed.finish(root, ref)['status'] == 'READY'
    assert len(service[2].calls) == 1
    assert resumed.load(root, ref)['baseline'] == baseline
    assert not resumed.get(root, ref)['closeout_pending']


def test_auxiliary_configuration_change_invalidates_review(service):
    task, root = scoped(service), service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    (root/'routes.py').write_text('value = 1\n')
    task.finish(root, ref)
    (root/'.semgrepignore').write_text('routes.py\n')
    assert not task._fresh(root, task.load(root, ref))


def test_crash_between_binding_and_task_commit_never_recaptures(service, monkeypatch):
    from security_runtime.tasks.security_state import TaskSecurityStore
    task, root = scoped(service), service[1]
    save = TaskSecurityStore.save
    def fail(self, value, **kwargs):
        if kwargs.get('new'):
            raise OSError('simulated process interruption')
        return save(self, value, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(TaskSecurityStore, 'save', fail)
        with pytest.raises(OSError):
            task.begin(root, 'one', check_policy=POLICY)
    (root/'routes.py').write_text('changed = True\n')
    with pytest.raises(ValueError, match='never reconstruct'):
        scoped(service).begin(root, 'one', check_policy=POLICY)


def test_unknown_shell_and_reverted_edits_reconcile_without_scan(service):
    task, root = scoped(service), service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    original = (root/'routes.py').read_bytes()
    (root/'routes.py').write_text('transient = True\n')
    ActivityStore(task.hooks, root).record(task._owner(), scope_unknown=True)
    (root/'routes.py').write_bytes(original)
    assert task.finish(root, ref)['status'] == 'NO_CHANGES'
    assert not service[2].calls


def test_late_event_after_completion_is_not_assigned_to_closed_task(service):
    task, root = scoped(service), service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    task.finish(root, ref)
    store = ActivityStore(task.hooks, root)
    before = store.summary(ref)
    event = store.record(task._owner(), event_id='late', paths=('routes.py',))
    assert event['task_ref'] is None
    assert store.summary(ref) == before


def test_switch_cannot_bypass_pending_native_repair(service, monkeypatch):
    from security_runtime.native_repair_intent import NativeRepairIntents
    task, root = scoped(service), service[1]
    ref = task.begin(root, 'one', check_policy=POLICY)['task_ref']
    monkeypatch.setattr(NativeRepairIntents, 'guard', lambda self: dict(status='NATIVE_REPAIR_PREPARATION_REQUIRED'))
    assert switch(task, root, ref, generation=1)['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    assert ActivityStore(task.hooks, root).focus(task._owner())['task_ref'] == ref


def test_activity_tampering_cannot_redirect_a_session(service):
    import sqlite3
    task, root = scoped(service), service[1]
    task.begin(root, 'one', check_policy=POLICY)
    store = ActivityStore(task.hooks, root)
    with sqlite3.connect(store.path) as db:
        db.execute('UPDATE activity SET data=? WHERE key=?', ('{}', store.owner_key(task._owner())))
    with pytest.raises(ValueError, match='cannot be verified'):
        store.record(task._owner(), paths=('routes.py',))
