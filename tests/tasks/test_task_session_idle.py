"""Explicit host idle boundaries never finish tasks or relax risk closure."""
import copy
import os

import pytest

from security_runtime.tasks import ownership as own
from security_runtime.tasks.attribution import session_activity, observe_start
from security_runtime.tasks.security import TaskSecurityService, TaskContextError
from task_review_helpers import review_all, read_plan, read_window
from test_task_disconnection import timeline, finish_review, REASON  # noqa: F401
from test_task_security import service  # noqa: F401


def host_task(timeline, host='codex'):
    old, _, root, runtime, clock, _ = timeline
    owner = own.session_owner(host, 'old-chat')
    tasks = TaskSecurityService(runtime, old.hooks, owner=owner, now=lambda: clock[0])
    ref = tasks.begin(root, 'host-task')['task_ref']
    return tasks, root, owner, ref


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_explicit_stop_before_baseline_excludes_idle_task_without_closing_it(timeline, host):
    tasks, root, owner, ref = host_task(timeline, host)
    _, new, _, _, clock, _ = timeline
    before = copy.deepcopy(tasks.load(root, ref))
    clock[0] += 1
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    idle = copy.deepcopy(tasks.load(root, ref))
    assert idle['phase'] == before['phase'] == 'ACTIVE'
    for key in ('baseline', 'static_attempts', 'task_owner', 'limitations'):
        assert idle[key] == before[key]
    assert 'review' not in idle and 'closed_at' not in idle
    clock[0] += 1
    fresh = new.begin(root, 'new')['task_ref']
    assert 'attribution_start' not in new.load(root, fresh)
    finish_review(new, root, fresh)
    assert tasks.load(root, ref) == idle
    with pytest.raises(ValueError, match='another session'):
        new.finish(root, ref)


@pytest.mark.parametrize('resume', ['event', 'save', 'begin', 'stop-again'])
def test_reconnect_or_activity_after_baseline_invalidates_idle_witness(timeline, resume):
    tasks, root, owner, ref = host_task(timeline)
    _, new, _, _, clock, _ = timeline
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    fresh = new.begin(root, 'new')['task_ref']
    clock[0] += 1
    if resume == 'save':
        tasks.store(root).save(tasks.load(root, ref))
    elif resume == 'begin':
        assert tasks.begin(root, 'host-task')['task_ref'] == ref
    else:
        session_activity(tasks.hooks, root, owner, idle=resume == 'stop-again', now=lambda: clock[0])
    finish_review(new, root, fresh)


def test_stop_first_observed_after_new_task_start_cannot_erase_overlap(timeline):
    tasks, root, owner, _ = host_task(timeline)
    _, new, _, _, clock, _ = timeline
    fresh = new.begin(root, 'new')['task_ref']
    clock[0] += 1
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    finish_review(new, root, fresh)


def test_resume_during_baseline_capture_invalidates_idle_witness(timeline, monkeypatch):
    from security_runtime.tasks import security as task_security
    tasks, root, owner, _ = host_task(timeline)
    _, new, _, _, clock, _ = timeline
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    capture = task_security.capture
    def resumed(*args, **kwargs):
        result = capture(*args, **kwargs)
        session_activity(tasks.hooks, root, owner, now=lambda: clock[0])
        return result
    with monkeypatch.context() as patch:
        patch.setattr(task_security, 'capture', resumed)
        fresh = new.begin(root, 'new')['task_ref']
    finish_review(new, root, fresh)


def test_resume_during_review_is_rechecked_at_final_submission(timeline):
    tasks, root, owner, _ = host_task(timeline)
    _, new, _, _, clock, _ = timeline
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    fresh = new.begin(root, 'new')['task_ref']
    (root/'routes.py').write_text('def route(): return 1\n')
    result = new.finish(root, fresh)
    assert not any(item['reason'] == REASON for item in result['limitations'])
    packet = new.prepare(root, fresh, protocol_version=3)
    review_all(new, root, fresh, packet)
    clock[0] += 1
    session_activity(tasks.hooks, root, owner, now=lambda: clock[0])
    assert new.submit(root, fresh, packet['review_session'], [], 'REVIEWED', [])['result_saved']
    result = new.get(root, fresh)
    assert result['host_review']['coverage'] == 'REVIEWED'
    assert not any(item['reason'] == REASON for item in new.load(root, fresh)['limitations'])


@pytest.mark.parametrize('field,value', [('contract', 'unknown'), ('observed_at', float('nan')),
    ('observed_at', -1), ('generation', True), ('generation', 0)])
def test_malformed_idle_checkpoint_never_excludes_task(timeline, field, value):
    tasks, root, owner, ref = host_task(timeline)
    clock = timeline[4]
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    record = copy.deepcopy(tasks.load(root, ref))
    record['session_idle'][field] = value
    assert not observe_start([record], clock[0])['idle_sessions']


def test_active_static_or_review_task_is_not_checkpointed_as_idle(timeline):
    tasks, root, owner, ref = host_task(timeline)
    (root/'routes.py').write_text('value = 1\n')
    tasks.finish(root, ref)
    before = copy.deepcopy(tasks.load(root, ref))
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: timeline[4][0])
    assert tasks.load(root, ref) == before


@pytest.mark.parametrize('status,decision,pending,guard_active,expected', [
    ('ALLOW_STOP', None, False, False, True), ('CONTINUATION_REQUIRED', 'block', False, False, False),
    ('INCONCLUSIVE', None, False, False, False), ('ALLOW_STOP', None, True, False, False),
    ('ALLOW_STOP', None, False, True, False)])
def test_validated_stop_route_and_readonly_reconnect(service, status, decision, pending, guard_active, expected):
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import identity
    from security_runtime.host_event_runtime import handle_normalized_event
    from security_runtime.host_events import (EventKind, HostCapabilities, NormalizedHostEvent,
        OperationClass, VerifiedHostContext)
    original, root, runtime = service
    owner = own.session_owner('codex', 'old-chat')
    tasks = TaskSecurityService(runtime, original.hooks, owner=owner)
    ref = tasks.begin(root, 'stop-route')['task_ref']
    core = HookCoordinator(runtime, original.hooks)
    context = VerifiedHostContext('codex', root, identity(os.path.normcase(str(root))),
        owner['session'], None, HostCapabilities(supports_stop=True), 'old-chat')
    class Guard:
        def handle(self, *args, **kwargs):
            return dict(status=status, decision=decision)
    if pending:
        original.hooks.pending_activity(root, 'codex', 'old-chat', mark=True)
    stop = NormalizedHostEvent(EventKind.SESSION_STOP, context, stop_guard_active=guard_active)
    result, _ = handle_normalized_event(stop, coordinator=core, continuation=Guard())
    assert result['status'] == status and not runtime.calls
    assert bool(tasks.load(root, ref).get('session_idle')) == expected
    activity = NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY, context, OperationClass.READ_ONLY)
    result, _ = handle_normalized_event(activity, coordinator=core)
    assert result['status'] == 'NOT_SCANNED' and not runtime.calls
    assert 'session_idle' not in tasks.load(root, ref)


def test_checkpoint_cannot_be_written_for_another_session(timeline):
    tasks, root, owner, ref = host_task(timeline)
    before = copy.deepcopy(tasks.load(root, ref))
    session_activity(tasks.hooks, root, own.session_owner('codex', 'different-chat'),
                     idle=True, now=lambda: timeline[4][0])
    assert tasks.load(root, ref) == before


def test_unrelated_readonly_activity_does_not_enter_task_write_lock(service, monkeypatch):
    tasks, root, _ = service
    def unexpected(*args, **kwargs):
        raise AssertionError('No task checkpoint requires a write lock')
    monkeypatch.setattr(tasks.hooks, 'lock', unexpected)
    session_activity(tasks.hooks, root, own.session_owner('codex', 'chat'))
    session_activity(tasks.hooks, root, own.session_owner('codex', 'chat'), idle=True)
    assert not tasks.store(root).path.exists()


def test_idle_exemption_cannot_close_risk_when_real_before_source_is_missing(timeline, monkeypatch):
    from security_runtime.tasks import preimages as task_preimages
    from security_runtime.tasks.risk_ledger import TaskRiskLedger
    tasks, root, owner, _ = host_task(timeline)
    _, new, _, _, clock, _ = timeline
    session_activity(tasks.hooks, root, owner, idle=True, now=lambda: clock[0])
    monkeypatch.setattr(task_preimages, 'MAX_FILE_BODY_BYTES', 1)
    fresh = new.begin(root, 'missing-before')['task_ref']
    assert new.load(root, fresh)['baseline']['capture_stats']['saved_body_file_count'] == 0
    monkeypatch.setattr(task_preimages, 'MAX_FILE_BODY_BYTES', 2_000_000)
    (root/'routes.py').write_text('def route(): return 1\n')
    packet = new.prepare(root, fresh, protocol_version=3)
    units, _ = read_plan(new, root, fresh, packet)
    for unit in units:
        for window in unit['required_windows']:
            if window['location_version'] == 'BEFORE_TASK':
                with pytest.raises(TaskContextError, match='cannot be reconstructed'):
                    read_window(new, root, fresh, packet['review_session'], window)
            else:
                read_window(new, root, fresh, packet['review_session'], window)
        new.submit_batch(root, fresh, packet['review_session'], [unit['unit_id']],
                         'PARTIAL', ['Original before source is unavailable.'])
    assert new.submit(root, fresh, packet['review_session'], [], 'REVIEWED', [])['result_saved']
    record = new.load(root, fresh)
    assert record['review']['coverage'] == 'PARTIAL'
    assert not any(item['reason'] == REASON for item in record['limitations'])
    ledger = TaskRiskLedger(tasks.hooks, root)
    monkeypatch.setattr(ledger, 'read_origins', lambda refs: {
        'original:risk': dict(source='HOST_TASK_REVIEW', required_source_paths=['routes.py'])})
    refs = [key for key, value in record['evidence'].items() if value['path'] == 'routes.py']
    updates = ledger.validate_host(record, [dict(original_task_ref='original', finding_id='risk',
        evidence_refs=refs[:1], outcome='CODE_REVIEWED_RESOLVED',
        rationale='Source delivery is incomplete even though the other host is idle.',
        tests='Targeted missing-preimage regression.')], record['review']['coverage'])
    assert updates['original:risk']['status'] == 'INCONCLUSIVE'
