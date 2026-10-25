"""Real files and private stores verify capture cost without weakening inputs."""
from collections import Counter
import copy
import hashlib

import pytest

from security_runtime.local_evidence import WorkspaceReader
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.queued_closeout import enqueue, execute_one
from security_runtime.tasks.queued_inputs import QueuedInputs, _CaptureWriter
from test_closeout_queue import setup, private_dispatcher  # noqa: F401
from test_closeout_source_recovery import background  # noqa: F401
from test_task_security import service  # noqa: F401


@pytest.mark.parametrize('files', [3, 1001])
def test_end_capture_reads_each_source_once_and_copies_outside_workspace_lock(service, monkeypatch, files):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    for number in range(files-3):
        (root/f'module_{number:05}.py').write_text('value = 1\n')
    expected = {path.name: path.read_bytes() for path in root.glob('*.py')}
    reads, writes, validations = Counter(), [], []
    read = WorkspaceReader.read
    from security_runtime.tasks import queued_inputs
    raw_read, write, verify = queued_inputs._read_file, queued_inputs._write, QueuedInputs._open_tree

    def source_read(reader, name, **kwargs):
        if name in expected:
            reads[name] += 1
        return read(reader, name, **kwargs)

    def no_second_source_read(path, *args):
        if path.parent == root and path.name in expected:
            pytest.fail('Queue reread the live source after end capture')
        return raw_read(path, *args)

    def copied(target, name, raw):
        assert not task.hooks.lock_held(root), 'Raw copy held the workspace lock'
        writes.append(name)
        return write(target, name, raw)

    def verified(store, *args):
        assert not task.hooks.lock_held(root), 'Whole-input validation held the workspace lock'
        validations.append(True)
        return verify(store, *args)

    monkeypatch.setattr(WorkspaceReader, 'read', source_read)
    monkeypatch.setattr(queued_inputs, '_read_file', no_second_source_read)
    monkeypatch.setattr(queued_inputs, '_write', copied)
    monkeypatch.setattr(QueuedInputs, '_open_tree', verified)
    assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
    assert reads == Counter({name: 1 for name in expected})
    assert Counter(writes) == Counter({name: 1 for name in expected})
    assert validations == []  # Producer does not reread its just-written copy.
    row = CloseoutQueue(task.hooks, root).read(ref)
    inputs = QueuedInputs(task.hooks, root)
    saved = inputs.read(row['input_ref'])
    assert 'hashes' not in saved and 'snapshot_scope' in saved
    frozen = inputs.open(row['input_ref'])
    assert {name: (frozen/name).read_bytes() for name in expected} == expected


def test_capture_preserves_original_bom_crlf_empty_and_secret_bytes(service):
    task, root, ref = setup(service)
    bodies = {
        'routes.py': b'\xef\xbb\xbfvalue = 1\r\n# original spacing  \r\n',
        'empty.py': b'',
        'secret_sample.py': b'token = "ghp_012345678901234567890123456789012345"\n',
    }
    for name, raw in bodies.items():
        (root/name).write_bytes(raw)
    before = copy.deepcopy(task.load(root, ref)['baseline'])
    enqueue(task, root, ref, launch=False)
    row = CloseoutQueue(task.hooks, root).read(ref)
    frozen = QueuedInputs(task.hooks, root).open(row['input_ref'])
    for name, raw in bodies.items():
        assert (frozen/name).read_bytes() == raw
    from security_runtime.tasks.closeout_pages import restore
    end = restore(task.store(root), task.load(root, ref), row['end'])
    assert {name: end['hashes'][name] for name in bodies} == {
        name: hashlib.sha256(raw).hexdigest() for name, raw in bodies.items()}
    assert task.load(root, ref)['baseline'] == before


def test_private_copy_corruption_is_rejected_before_scanner_execution(service, monkeypatch):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('changed = True\n')
    before = copy.deepcopy(task.load(root, ref))
    prepare = _CaptureWriter.prepare

    def corrupted(sink, *args):
        target = sink.store.parent/sink.ref/'routes.py'
        target.chmod(0o600)
        target.write_text('wrong version\n')
        target.chmod(0o400)
        return prepare(sink, *args)

    monkeypatch.setattr(_CaptureWriter, 'prepare', corrupted)
    assert enqueue(task, root, ref, launch=False)['status'] == 'QUEUED'
    row = CloseoutQueue(task.hooks, root).read(ref)
    with pytest.raises(ValueError, match='Queued input modified'):
        QueuedInputs(task.hooks, root).open(row['input_ref'])
    assert execute_one(task, root, ref)
    assert CloseoutQueue(task.hooks, root).read(ref)['state'] == 'FAILED'
    assert QueuedInputs(task.hooks, root).rows() == []
    after = task.load(root, ref)
    # Publishing a queued request performs the original idle-lease refresh;
    # failure before input validation must change no task/source/review facts.
    assert after['generation'] == before['generation'] + 1
    assert after['phase'] == before['phase'] == 'ACTIVE'
    assert {key:value for key,value in after.items()
            if key not in {'generation', 'activity_at', 'lease_until'}} == {
        key:value for key,value in before.items()
        if key not in {'generation', 'activity_at', 'lease_until'}}
    assert not service[2].calls


def test_edit_after_capture_does_not_replace_frozen_scanner_bytes(service, monkeypatch):
    task, root, ref = setup(service)
    (root/'routes.py').write_text('version = 1\n')
    prepare = _CaptureWriter.prepare

    def later_edit(sink, *args):
        (root/'routes.py').write_text('version = 2\n')
        return prepare(sink, *args)

    monkeypatch.setattr(_CaptureWriter, 'prepare', later_edit)
    enqueue(task, root, ref, launch=False)
    row = CloseoutQueue(task.hooks, root).read(ref)
    frozen = QueuedInputs(task.hooks, root).open(row['input_ref'])
    assert (frozen/'routes.py').read_bytes() == b'version = 1\n'
    assert execute_one(task, root, ref)
    assert CloseoutQueue(task.hooks, root).read(ref)['state'] == 'STALE'
    assert task.end_lines(root, task.load(root, ref), 'routes.py') == ['version = 1']


def test_ready_prepare_performs_one_full_freshness_check_and_no_rescan(background, monkeypatch):
    task, root, engine, ref, baseline = background
    enqueue(task, root, ref, launch=False)
    assert execute_one(task, root, ref)
    calls, fresh = [], task._fresh

    def measured(*args):
        calls.append(True)
        assert task.hooks.lock_held(root)
        return fresh(*args)

    monkeypatch.setattr(task, '_fresh', measured)
    assert task.prepare(root, ref)['status'] == 'REVIEW_REQUIRED'
    assert calls == [True]
    assert engine.calls == [('labels.py',)]
    assert task.load(root, ref)['baseline'] == baseline


def test_raw_write_failure_does_not_publish_or_leave_a_partial_input(service, monkeypatch):
    from security_runtime.tasks.preimages import TaskPreimageUnavailable
    task, root, ref = setup(service)
    before = copy.deepcopy(task.load(root, ref))
    from security_runtime.tasks import queued_inputs
    original, writes = queued_inputs._write, []

    def failed(target, name, raw):
        writes.append(name)
        if len(writes) == 2:
            raise OSError('fixture disk-write failure')
        return original(target, name, raw)

    monkeypatch.setattr(queued_inputs, '_write', failed)
    with pytest.raises(TaskPreimageUnavailable) as failure:
        enqueue(task, root, ref, launch=False)
    # The existing preimage transaction translates nested filesystem errors;
    # keep its rollback contract and the actual raw-write failure as context.
    assert isinstance(failure.value.__context__, OSError)
    assert str(failure.value.__context__) == 'fixture disk-write failure'
    assert len(writes) == 2
    assert QueuedInputs(task.hooks, root).rows() == []
    assert CloseoutQueue(task.hooks, root).read(ref) is None
    assert task.load(root, ref) == before


def test_real_sql_failure_at_seal_rolls_back_and_preserves_task(service, monkeypatch):
    import json
    import sqlite3
    from security_runtime.tasks.durable import TaskOperationError
    task, root, ref = setup(service)
    before = copy.deepcopy(task.load(root, ref))
    inputs = QueuedInputs(task.hooks, root)
    connect, failures = sqlite3.connect, []

    class RejectReady(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith('INSERT OR REPLACE INTO records') and parameters:
                if json.loads(parameters[1]).get('state') == 'READY':
                    failures.append(True)
                    # A real SQL error inside the actual transaction, without
                    # changing persistent schema or fabricating an exception.
                    super().execute('INSERT INTO records(missing_column) VALUES(1)')
            return super().execute(sql, parameters)

    def failing(database, *args, **kwargs):
        if str(database) == str(inputs.path):
            kwargs['factory'] = RejectReady
        return connect(database, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(sqlite3, 'connect', failing)
        with pytest.raises(TaskOperationError):
            enqueue(task, root, ref, launch=False)
    assert failures == [True]
    assert inputs.rows() == []
    assert CloseoutQueue(task.hooks, root).read(ref) is None
    assert task.load(root, ref) == before


def test_nonwriting_activity_during_scan_keeps_one_scan_and_completes_review(background):
    import os
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import identity
    from security_runtime.host_events import (EventKind, NormalizedHostEvent,
        OperationClass, VerifiedHostContext)
    from security_runtime.host_event_runtime import handle_normalized_event
    from security_runtime.host_lifecycle import connector_profile
    from task_review_helpers import review_all
    task, root, engine, ref, baseline = background
    coordinator = HookCoordinator(engine, task.hooks)
    context = VerifiedHostContext('codex', root, identity(os.path.normcase(str(root))),
        identity('recovery'), identity('nonwriting-test-event'),
        connector_profile('codex').capabilities, 'recovery')
    event = NormalizedHostEvent(EventKind.WORKSPACE_ACTIVITY, context,
        OperationClass.POSSIBLE_WORKSPACE_MUTATION)
    observed = []

    def verification_activity(_):
        result, _ = handle_normalized_event(event, coordinator=coordinator)
        observed.append(result['status'])
        assert result['execution']['scanner_run'] is False

    enqueue(task, root, ref, launch=False)
    engine.mutate = verification_activity
    assert execute_one(task, root, ref)
    assert observed == ['RECORDED_PENDING']
    packet = task.prepare(root, ref)
    review_all(task, root, ref, packet)
    assert task.submit(root, ref, packet['review_session'], [], 'REVIEWED', [])['status'] == 'COMPLETE'
    assert engine.calls == [('labels.py',)]
    assert task.load(root, ref)['baseline'] == baseline
