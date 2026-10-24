"""Source drift resumes the original background task through real v3 review.

Filesystem snapshots, private queue, fencing and review ledger are real. The
detector fixture records its requested files; no installed scanners are run.
"""
import copy

import pytest

from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue, MAX_SOURCE_RECOVERIES
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.queued_closeout import enqueue, execute_one, cancel, status
from security_runtime.tasks.security import TaskSecurityService
from task_review_helpers import review_all
from test_task_security import service  # noqa: F401


@pytest.fixture
def background(service, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'dispatcher'))
    monkeypatch.setattr('security_runtime.task_closeout_worker.launch_worker', lambda *a:None)
    old, root, engine = service
    for source in root.glob('*.py'):
        source.unlink()
    task = TaskSecurityService(engine, old.hooks, owner=session_owner('codex', 'recovery'))
    ref = task.begin(root, 'labels-task', check_policy=POLICY,
                     background_closeout=True)['task_ref']
    baseline = copy.deepcopy(task.load(root, ref)['baseline'])
    (root/'labels.py').write_text('def normalize_label(text):\n    return text.strip().lower()\n')
    return task, root, engine, ref, baseline


def complete(task, root, ref, packet):
    _, units = review_all(task, root, ref, packet)
    assert {unit['path'] for unit in units} == {'labels.py', 'demo.py'}
    receipt = task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE' and receipt['result_saved']
    result = task.get(root, ref, completion_revision=receipt['next_action']['completion_revision'])
    assert result['status'] == 'COMPLETE' and result['current_version']
    assert result['host_review']['coverage'] == 'REVIEWED'


@pytest.mark.parametrize('timing', ['queued', 'scanning', 'before_review', 'during_review'])
def test_added_file_recovers_same_task_and_completes(background, timing):
    task, root, engine, ref, baseline = background
    first = enqueue(task, root, ref, launch=False)
    initial_packet = None
    spent = None

    def add_demo(_=None):
        (root/'demo.py').write_text('def demo():\n    return "example"\n')
        engine.mutate = None

    if timing == 'queued':
        add_demo()
    elif timing == 'scanning':
        engine.mutate = add_demo
    execute_one(task, root, ref)
    if timing == 'during_review':
        initial_packet = task.prepare(root, ref)
        review_all(task, root, ref, initial_packet)
        spent = copy.deepcopy(task.load(root, ref)['review_ledger'])
        add_demo()
    elif timing == 'before_review':
        add_demo()
    else:
        stale = status(task, root, ref)
        assert stale['status'] == 'STALE'
        assert stale['next_action'] == 'prepare_task_security_review'
        assert stale['reason'] == 'SOURCE_CHANGED_SINCE_CLOSEOUT'
    saved = copy.deepcopy(task.load(root, ref))
    queue = CloseoutQueue(task.hooks, root)
    saved_queue = queue.read(ref)
    for _ in range(3):
        status(task, root, ref)
        task.get(root, ref)
    assert task.load(root, ref) == saved and queue.read(ref) == saved_queue
    assert engine.calls == [('labels.py',)]

    resumed = task.prepare(root, ref)
    assert resumed['status'] == 'QUEUED' and resumed['task_ref'] == ref
    assert resumed['job_ref'] != first['job_ref']
    assert resumed['source_recovery_count'] == 1
    assert resumed['baseline_recreated'] is False
    assert task.prepare(root, ref)['job_ref'] == resumed['job_ref']
    execute_one(task, root, ref)
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    assert engine.calls == [('labels.py',), ('demo.py', 'labels.py')]
    packet = task.prepare(root, ref)
    record = task.load(root, ref)
    assert record['baseline'] == baseline and not baseline['hashes']
    if initial_packet:
        assert packet['review_session'] != initial_packet['review_session']
        assert record['review_history'][0]['plan']['snapshot_id']
        for key in ('source_bytes', 'navigation_bytes', 'control_bytes', 'total_bytes', 'reads'):
            assert record['review_ledger'][key] >= spent[key]
        with pytest.raises(ValueError):
            task.submit(root, ref, initial_packet['review_session'], [], 'REVIEWED', [])
    complete(task, root, ref, packet)
    assert task.load(root, ref)['baseline'] == baseline


def test_legacy_stale_reason_is_recoverable_without_recreating_baseline(background):
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    (root/'demo.py').write_text('value = 1\n')
    execute_one(task, root, ref)
    queue = CloseoutQueue(task.hooks, root)
    with queue.transaction() as db:
        row = queue._get(db, ref)
        queue._put(db, ref, dict(row, reason='STALE'))
    assert task.prepare(root, ref)['status'] == 'QUEUED'
    execute_one(task, root, ref)
    complete(task, root, ref, task.prepare(root, ref))
    assert task.load(root, ref)['baseline'] == baseline


def test_persistent_changes_stop_recovery_without_polling_or_reset(background):
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    for index in range(MAX_SOURCE_RECOVERIES + 1):
        (root/'demo.py').write_text(f'value = {index}\n')
        execute_one(task, root, ref)
        result = task.prepare(root, ref)
        if index < MAX_SOURCE_RECOVERIES:
            assert result['status'] == 'QUEUED'
            assert result['source_recovery_count'] == index + 1
        else:
            assert result['status'] == 'STALE' and result['recovery_blocked']
            assert result['reason'] == 'SOURCE_RECOVERY_LIMIT'
            assert result['next_action'] is None
    saved = CloseoutQueue(task.hooks, root).read(ref)
    assert status(task, root, ref)['next_action'] is None
    task.prepare(root, ref)
    assert CloseoutQueue(task.hooks, root).read(ref) == saved
    assert len(engine.calls) == MAX_SOURCE_RECOVERIES + 1
    assert task.load(root, ref)['baseline'] == baseline


@pytest.mark.parametrize('terminal', ['CANCELLED', 'FAILED', 'EXPIRED'])
def test_terminal_queue_never_restarts_during_prepare(background, terminal):
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    execute_one(task, root, ref)
    queue = CloseoutQueue(task.hooks, root)
    with queue.transaction() as db:
        row = queue._get(db, ref)
        queue._put(db, ref, dict(row, state=terminal))
    (root/'demo.py').write_text('value = 1\n')
    assert task.prepare(root, ref)['status'] == terminal
    assert len(engine.calls) == 1
    assert task.load(root, ref)['baseline'] == baseline


def test_execution_identity_change_does_not_auto_recover(background, monkeypatch):
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    (root/'demo.py').write_text('value = 1\n')
    execute_one(task, root, ref)
    monkeypatch.setattr('security_runtime.tasks.queued_closeout.execution_identity',
                        lambda:dict(build_id='different'))
    result = task.prepare(root, ref)
    assert result['reason'] == 'RUNTIME_OR_CONFIGURATION_CHANGED'
    assert result['recovery_blocked'] and result['next_action'] is None
    assert len(engine.calls) == 1
    assert task.load(root, ref)['baseline'] == baseline


def test_cancellation_during_recovery_capture_wins(background, monkeypatch):
    from security_runtime.tasks import queued_closeout
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    (root/'demo.py').write_text('value = 1\n')
    execute_one(task, root, ref)
    original = queued_closeout.capture_end

    def cancel_after_capture(*args):
        result = original(*args)
        cancel(task, root, ref)
        return result

    monkeypatch.setattr(queued_closeout, 'capture_end', cancel_after_capture)
    assert task.prepare(root, ref)['status'] == 'CANCELLED'
    assert task.load(root, ref)['baseline'] == baseline
    assert len(engine.calls) == 1


def test_completed_review_is_history_after_later_edits(background):
    task, root, engine, ref, baseline = background
    (root/'demo.py').write_text('value = 1\n')
    enqueue(task, root, ref, launch=False)
    execute_one(task, root, ref)
    complete(task, root, ref, task.prepare(root, ref))
    (root/'later.py').write_text('later = True\n')
    assert task.prepare(root, ref)['status'] == 'COMPLETE'
    assert len(engine.calls) == 1
    assert task.load(root, ref)['baseline'] == baseline


def test_public_mcp_prepare_resumes_stale_task_with_original_signed_session(background):
    from mcp.server.fastmcp.exceptions import ToolError
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.mcp_server import create_server
    from security_runtime.tasks.ownership import issue_session_ref
    from test_task_review_protocol_mcp import local_call
    task, root, engine, _, _ = background
    token = issue_session_ref(task.hooks, root, 'codex', 'public-recovery')
    other = issue_session_ref(task.hooks, root, 'codex', 'other-session')
    server = create_server(engine, hook_coordinator=HookCoordinator(engine, task.hooks),
                           global_mode=False)
    arguments = dict(workspace_path=str(root), session_ref=token)
    started = local_call(server, 'begin_security_task', task_key='public', **arguments)
    ref = started['task_ref']
    original = TaskSecurityService(engine, task.hooks,
                                  owner=session_owner('codex', 'public-recovery'))
    baseline = copy.deepcopy(original.load(root, ref)['baseline'])
    (root/'labels.py').write_text('def normalize_label(text):\n    return text.strip().lower() + "!"\n')
    assert local_call(server, 'finish_security_task', task_ref=ref, **arguments)['status'] == 'QUEUED'
    (root/'demo.py').write_text('value = 1\n')
    execute_one(original, root, ref)
    stale = local_call(server, 'get_task_closeout_status', task_ref=ref, **arguments)
    assert stale['status'] == 'STALE' and stale['next_action'] == 'prepare_task_security_review'
    with pytest.raises(ToolError, match='belongs to another session'):
        local_call(server, 'prepare_task_security_review', task_ref=ref,
                   workspace_path=str(root), session_ref=other)
    assert len(engine.calls) == 1
    resumed = local_call(server, stale['next_action'], task_ref=ref, **arguments)
    assert resumed['status'] == 'QUEUED' and resumed['task_ref'] == ref
    execute_one(original, root, ref)
    packet = local_call(server, 'prepare_task_security_review', task_ref=ref, **arguments)
    review_all(original, root, ref, packet)
    receipt = local_call(server, 'submit_task_security_review', task_ref=ref,
        review_session=packet['review_session'], findings=[], coverage='REVIEWED',
        limitations=[], **arguments)
    assert receipt['result_saved'] and receipt['status'] == 'COMPLETE'
    action = dict(receipt['next_action'])
    tool = action.pop('tool')
    delivered = local_call(server, tool, **action, **arguments)
    assert delivered['status'] == 'COMPLETE' and delivered['current_version']
    assert original.load(root, ref)['baseline'] == baseline


def test_normal_closeout_accepts_queue_loaded_before_recovery_upgrade(background, monkeypatch):
    from security_runtime.tasks import queued_closeout
    task, root, engine, ref, baseline = background

    class LoadedQueue(CloseoutQueue):
        supports_source_recovery = False

        # Signature of a queue imported by SessionStart before source editing.
        def submit(self, record, end, configuration, input_ref=None, preparation_ms=0):
            return super().submit(record, end, configuration, input_ref, preparation_ms)

    monkeypatch.setattr(queued_closeout, 'CloseoutQueue', LoadedQueue)
    assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
    execute_one(task, root, ref)
    packet = task.prepare(root, ref)
    review_all(task, root, ref, packet)
    receipt = task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])
    assert receipt['status'] == 'COMPLETE'
    assert task.load(root, ref)['baseline'] == baseline


def test_recovery_with_loaded_legacy_queue_keeps_fencing_and_reports_restart(background, monkeypatch):
    from security_runtime.tasks import queued_closeout
    from security_runtime.tasks.diagnostics import TaskRuntimeRestartRequired, runtime_compatibility_failure
    task, root, engine, ref, baseline = background
    first = enqueue(task, root, ref, launch=False)
    (root/'demo.py').write_text('value = 1\n')
    execute_one(task, root, ref)
    saved = CloseoutQueue(task.hooks, root).read(ref)

    class LoadedQueue(CloseoutQueue):
        supports_source_recovery = False

        def submit(self, *args, **kwargs):
            pytest.fail('Recovery must not bypass the atomic generation fence')

    monkeypatch.setattr(queued_closeout, 'CloseoutQueue', LoadedQueue)
    with pytest.raises(TaskRuntimeRestartRequired) as rejected:
        task.prepare(root, ref)
    failure = runtime_compatibility_failure(rejected.value)
    assert failure['reason_code'] == 'RUNTIME_RESTART_REQUIRED'
    assert failure['original_task_preserved'] and failure['baseline_recreated'] is False
    assert failure['recovery']['same_task_required']
    assert CloseoutQueue(task.hooks, root).read(ref) == saved
    assert task.load(root, ref)['baseline'] == baseline and len(engine.calls) == 1

    monkeypatch.setattr(queued_closeout, 'CloseoutQueue', CloseoutQueue)
    # Reconnecting loads the new queue but continues the original signed task.
    resumed = task.prepare(root, ref)
    assert resumed['task_ref'] == ref and resumed['job_ref'] != first['job_ref']
    execute_one(task, root, ref)
    complete(task, root, ref, task.prepare(root, ref))
    assert task.load(root, ref)['baseline'] == baseline
