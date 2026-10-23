"""Completed fake-provider facts survive real input capture/publication gaps."""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
import time

import pytest

from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.host_events import OperationClass
from security_runtime.scan_attempt import ScanAttemptStore, source_binding
from security_runtime.scan_publication import ScanPublications
from security_runtime.tasks.security import TaskSecurityService
from test_task_security import service  # noqa: F401
from test_hook_runtime import repo, coordinator, FakeRuntime, dirty  # noqa: F401
from test_host_event_journal import event


def fail_publication_once(monkeypatch, hooks, kind):
    original_stage, original_lock = ScanPublications.stage, hooks.lock
    control = dict(armed=False, used=False)

    def stage(journal, selected_kind, *args, **kwargs):
        value = original_stage(journal, selected_kind, *args, **kwargs)
        if journal.hooks is hooks and selected_kind == kind and not control['used']:
            control.update(armed=True, used=True)
        return value

    @contextmanager
    def lock(root, **kwargs):
        if control['armed'] and kwargs.get('wait_seconds') == 2:
            control['armed'] = False
            yield False
        else:
            with original_lock(root, **kwargs) as acquired:
                yield acquired

    monkeypatch.setattr(ScanPublications, 'stage', stage)
    monkeypatch.setattr(hooks, 'lock', lock)


def pending_task(sample, monkeypatch):
    tasks, root, runtime = sample
    ref = tasks.begin(root, 'pending-publication')['task_ref']
    baseline = tasks.load(root, ref)['baseline']
    (root/'routes.py').write_text('def changed():\n    return 2\n')
    fail_publication_once(monkeypatch, tasks.hooks, 'TASK')
    result = tasks.finish(root, ref)
    assert result['reason'] == 'SCAN_ATTEMPT_PUBLICATION_PENDING'
    return tasks, root, runtime, ref, baseline


def test_task_retry_recovers_original_facts_without_scan_or_budget_reset(service, monkeypatch):
    tasks, root, runtime, ref, baseline = pending_task(service, monkeypatch)
    saved = tasks.load(root, ref)
    lease = saved['static_execution']
    assert saved['phase'] == 'STATIC_RUNNING' and len(runtime.calls) == 1
    restarted = TaskSecurityService(runtime, tasks.hooks)
    # Read-only result inspection does not consume the recovery obligation.
    restarted.get(root, ref)
    assert ScanPublications(tasks.hooks, root).pending('TASK', ref)
    result = restarted.finish(root, ref)
    current = restarted.load(root, ref)
    assert result['status'] == 'READY' and result['publication_recovered']
    assert result['scanner_run'] is False and len(runtime.calls) == 1
    assert current['baseline'] == baseline and current['static_attempts'] == 1
    assert current['static_execution'] == lease
    assert current['static']['execution_attempt']['publication'] == 'COMMITTED'
    assert ScanAttemptStore(tasks.hooks, root).read()['lane']['state'] == 'COMPLETED'
    assert not ScanPublications(tasks.hooks, root).pending('TASK', ref)


@pytest.mark.parametrize('change', ['source', 'auxiliary', 'expiry', 'new-generation'])
def test_task_recovery_never_publishes_old_input_or_new_attempt(service, monkeypatch, change):
    tasks, root, runtime, ref, baseline = pending_task(service, monkeypatch)
    clock = [time.time()]
    tasks.now = lambda: clock[0]
    attempts = ScanAttemptStore(tasks.hooks, root, now=tasks.now)
    newer = None
    if change == 'source':
        (root/'routes.py').write_text('def changed_again():\n    return 3\n')
    elif change == 'auxiliary':
        (root/'.semgrepignore').write_text('routes.py\n')
    else:
        clock[0] += 601
        if change == 'new-generation':
            with tasks.hooks.lock(root):
                newer = attempts.claim('HOOK', 'new-work', source_binding({'new':1}))
    result = tasks.finish(root, ref)
    saved = tasks.load(root, ref)
    assert result['status'] == 'STALE' and len(runtime.calls) == 1
    assert saved['baseline'] == baseline and saved['static_attempts'] == 1
    assert saved['static']['execution_attempt']['publication'] == 'STALE'
    assert not ScanPublications(tasks.hooks, root).pending('TASK', ref)
    assert attempts.is_current(newer) if newer else attempts.read()['lane']['state'] == 'STALE'
    if change == 'expiry':
        retried = tasks.finish(root, ref)
        assert retried['status'] == 'READY' and len(runtime.calls) == 2
        assert tasks.load(root, ref)['static_attempts'] == 2
        assert tasks.load(root, ref)['baseline'] == baseline


def test_stage_failure_retires_only_original_task_attempt(service, monkeypatch):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'journal-write-failure')['task_ref']
    baseline = tasks.load(root, ref)['baseline']
    (root/'routes.py').write_text('def changed():\n    return 2\n')
    monkeypatch.setattr(ScanPublications, 'stage', lambda *a, **k: (_ for _ in ()).throw(OSError('offline journal')))
    with pytest.raises(OSError, match='offline journal'):
        tasks.finish(root, ref)
    assert ScanAttemptStore(tasks.hooks, root).read()['lane']['state'] == 'FAILED'
    saved = tasks.load(root, ref)
    assert saved['phase'] == 'STALE' and saved['static_attempts'] == 1
    assert saved['baseline'] == baseline and len(runtime.calls) == 1


@pytest.mark.parametrize('kind', ['TASK', 'HOOK'])
@pytest.mark.parametrize('failure_point', ['lane-finish', 'ack'])
def test_target_commit_before_lane_finish_recovers_exact_attempt(service, tmp_path, monkeypatch, kind, failure_point):
    original_finish = ScanAttemptStore.finish
    original_ack = ScanPublications.acknowledge
    broken = [False]

    def finish(store, lease, **kwargs):
        if kwargs.get('outcome') == 'COMPLETED' and not broken[0]:
            broken[0] = True
            raise OSError('lane completion interrupted')
        return original_finish(store, lease, **kwargs)

    def acknowledge(journal, value):
        if not broken[0]:
            broken[0] = True
            raise OSError('lane completion interrupted')
        return original_ack(journal, value)

    def inject_failure():
        if failure_point == 'lane-finish':
            monkeypatch.setattr(ScanAttemptStore, 'finish', finish)
        else:
            monkeypatch.setattr(ScanPublications, 'acknowledge', acknowledge)

    if kind == 'TASK':
        tasks, root, runtime = service
        ref = tasks.begin(root, 'target-before-lane')['task_ref']
        (root/'routes.py').write_text('def changed():\n    return 2\n')
        inject_failure()
        with pytest.raises(OSError, match='lane completion'):
            tasks.finish(root, ref)
        assert tasks.load(root, ref)['phase'] == 'READY'
        result = tasks.finish(root, ref)
        assert result['status'] == 'READY' and len(runtime.calls) == 1
        hooks = tasks.hooks
    else:
        root = service[1]
        runtime = FakeRuntime()
        core = coordinator(tmp_path, runtime, cooldown_ms=0)
        core.handle('SESSION_START', root, 'codex', 's')
        dirty(root)
        inject_failure()
        with pytest.raises(OSError, match='lane completion'):
            core.handle('FILE_CHANGED', root, 'codex', 's')
        count = len(runtime.calls)
        recovered = core.recover_publications(root, 'codex', 's')
        assert recovered['publication'] == 'PUBLISHED' and len(runtime.calls) == count
        hooks = core.store
    assert ScanAttemptStore(hooks, root).read()['lane']['state'] == 'COMPLETED'


def pending_hook(repo, tmp_path, monkeypatch):
    runtime = FakeRuntime()
    core = coordinator(tmp_path, runtime, cooldown_ms=0)
    core.handle('SESSION_START', repo, 'codex', 'private-session')
    dirty(repo, 'class Changed {}\n')
    fail_publication_once(monkeypatch, core.store, 'HOOK')
    value = event(repo)
    result, _ = handle_normalized_event(value, coordinator=core)
    assert result['scan_attempt']['publication'] == 'NOT_PUBLISHED'
    assert result['reason'] == 'SCAN_ATTEMPT_PUBLICATION_PENDING' and result['source_result_saved']
    return core, value, result


@pytest.mark.parametrize('replay', ['same-event', 'new-event'])
def test_hook_retry_recovers_before_pending_sequence_and_dedup(repo, tmp_path, monkeypatch, replay):
    core, value, first = pending_hook(repo, tmp_path, monkeypatch)
    count = len(core.runtime.calls)
    if replay == 'new-event':
        value = event(repo, invocation='second-call')
    result, _ = handle_normalized_event(value, coordinator=core)
    assert len(core.runtime.calls) == count and not result['execution']['scanner_run']
    assert ScanAttemptStore(core.store, repo).read()['lane']['state'] == 'COMPLETED'
    assert core.store.pending_activity(repo, 'codex', 'private-session') is None
    state, _ = core.store.load(core.store.path(repo, 'codex', 'private-session'))
    assert state['last_scan_id'] == first['scan_id']
    if replay == 'same-event':
        assert result['publication_recovered'] and result['status'] != 'INCONCLUSIVE'
        assert result['event_processing']['state'] == 'ALREADY_COMPLETED'
    else:
        assert result['status'] == 'NO_CHANGE'


def test_hook_changed_source_retires_original_without_advancing_comparison(repo, tmp_path, monkeypatch):
    core, _, _ = pending_hook(repo, tmp_path, monkeypatch)
    before, _ = core.store.load(core.store.path(repo, 'codex', 'private-session'))
    count = len(core.runtime.calls)
    dirty(repo, 'class Later {}\n')
    recovered = core.recover_publications(repo, 'codex', 'private-session')
    after, _ = core.store.load(core.store.path(repo, 'codex', 'private-session'))
    assert recovered['publication'] == 'NOT_PUBLISHED' and after == before
    assert len(core.runtime.calls) == count
    assert ScanAttemptStore(core.store, repo).read()['lane']['state'] == 'STALE'


@pytest.mark.parametrize('change', ['expired', 'new-generation', 'new-pending'])
def test_hook_recovery_preserves_new_generation_and_pending_fences(repo, tmp_path, monkeypatch, change):
    core, _, _ = pending_hook(repo, tmp_path, monkeypatch)
    path = core.store.path(repo, 'codex', 'private-session')
    before = path.read_bytes()
    attempts = ScanAttemptStore(core.store, repo)
    newer = None
    with core.store.lock(repo):
        if change == 'new-pending':
            core.store.pending_activity(repo, 'codex', 'private-session', mark=True)
        else:
            state = attempts.read()
            state['lane']['expires_at'] = time.time()-1
            attempts._save(state)
            if change == 'new-generation':
                newer = attempts.claim('HOOK', 'another-hook', source_binding({'new':True}))
    count = len(core.runtime.calls)
    recovered = core.recover_publications(repo, 'codex', 'private-session')
    assert recovered['publication'] == 'NOT_PUBLISHED' and path.read_bytes() == before
    assert len(core.runtime.calls) == count
    assert core.store.pending_activity(repo, 'codex', 'private-session') is not None
    assert attempts.is_current(newer) if newer else attempts.read()['lane']['state'] == 'STALE'


def test_hook_stage_failure_retires_execution_and_retains_old_comparison(repo, tmp_path, monkeypatch):
    core = coordinator(tmp_path, FakeRuntime(), cooldown_ms=0)
    core.handle('SESSION_START', repo, 'codex', 's')
    path = core.store.path(repo, 'codex', 's')
    before = path.read_bytes()
    dirty(repo)
    monkeypatch.setattr(ScanPublications, 'stage', lambda *a, **k: (_ for _ in ()).throw(OSError('offline journal')))
    with pytest.raises(OSError, match='offline journal'):
        core.handle('FILE_CHANGED', repo, 'codex', 's')
    assert path.read_bytes() == before
    assert ScanAttemptStore(core.store, repo).read()['lane']['state'] == 'FAILED'


@pytest.mark.parametrize('replacement', [False, True])
def test_interrupt_after_hook_stage_cannot_later_publish_cancelled_facts(repo, tmp_path, monkeypatch, replacement):
    core = coordinator(tmp_path, FakeRuntime(), cooldown_ms=0)
    core.handle('SESSION_START', repo, 'codex', 's')
    path = core.store.path(repo, 'codex', 's')
    before = path.read_bytes()
    dirty(repo)
    publish = core._publish
    attempts = ScanAttemptStore(core.store, repo)
    newest = []
    def interrupted(*args, **kwargs):
        if replacement:
            with core.store.lock(repo):
                state = attempts.read()
                state['lane']['expires_at'] = time.time()-1
                attempts._save(state)
                newest.append(attempts.claim('HOOK', 'later-work', source_binding({'new':True})))
        raise KeyboardInterrupt()
    monkeypatch.setattr(core, '_publish', interrupted)
    with pytest.raises(KeyboardInterrupt):
        core.handle('FILE_CHANGED', repo, 'codex', 's')
    assert attempts.is_current(newest[0]) if newest else attempts.read()['lane']['state'] == 'CANCELLED'
    monkeypatch.setattr(core, '_publish', publish)
    count = len(core.runtime.calls)
    assert core.recover_publications(repo, 'codex', 's')['publication'] == 'NOT_PUBLISHED'
    assert path.read_bytes() == before and len(core.runtime.calls) == count
    assert attempts.is_current(newest[0]) if newest else attempts.read()['lane']['state'] == 'CANCELLED'


def test_read_only_event_does_not_recover_pending_hook(repo, tmp_path, monkeypatch):
    core, value, _ = pending_hook(repo, tmp_path, monkeypatch)
    before = ScanAttemptStore(core.store, repo).read()
    result, _ = handle_normalized_event(replace(value, operation=OperationClass.READ_ONLY), coordinator=core)
    assert result['status'] == 'NOT_SCANNED'
    assert ScanAttemptStore(core.store, repo).read() == before
    assert ScanPublications(core.store, repo).pending('HOOK', before['lane']['scope_key'])


def test_signed_publication_cannot_be_rebound_by_unsigned_index(service, monkeypatch):
    tasks, root, _, ref, _ = pending_task(service, monkeypatch)
    journal = ScanPublications(tasks.hooks, root)
    with sqlite3.connect(journal.path) as db:
        db.execute("UPDATE scan_publications SET scope_key='other-task'")
    with pytest.raises(ValueError, match='index binding'):
        journal.pending('TASK', 'other-task')


def test_old_scopes_are_collected_boundedly_without_dropping_live_generation(service):
    tasks, root, _ = service
    clock = [time.time()]
    attempts = ScanAttemptStore(tasks.hooks, root, now=lambda:clock[0])
    journal = ScanPublications(tasks.hooks, root)
    for index in range(32):
        with tasks.hooks.lock(root):
            lease = attempts.claim('TASK', 'scope-'+str(index), source_binding({'i':index}))
        journal.stage('TASK', 'scope-'+str(index), lease, {'safe_result':'fixture'})
        clock[0] += 601
    # Pure reads retain the pending facts; a new mutation uses the existing
    # signed generation to recover capacity even for tasks past their TTL.
    assert journal.pending('TASK', 'scope-0')
    clock[0] += 24*3600
    with tasks.hooks.lock(root):
        assert journal.collect(attempts) == 8
        live = attempts.claim('TASK', 'current', source_binding({'i':'current'}))
    journal.stage('TASK', 'current', live, {'safe_result':'current fixture'})
    with tasks.hooks.lock(root):
        assert journal.collect(attempts, limit=32) == 24
    assert journal.pending('TASK', 'current') and attempts.is_current(live)
    assert not journal.pending('TASK', 'scope-0')
