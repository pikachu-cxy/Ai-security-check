"""Queue facade. Worker execution never begins or adopts a development task."""
import os
import threading
import time
import uuid

from .activity import deferred
from .closeout_queue import CloseoutQueue, PENDING, fingerprint
from .end_versions import capture_end
from .ownership import record_owner
from .baseline_identity import baseline_snapshot, baseline_fingerprint


def execution_identity():
    from ..build_identity import build_identity
    from ..rulepacks import RulePackManager
    try:
        rules = RulePackManager().resolve().checksum
    except (OSError, ValueError):
        rules = None
    return dict(build_id=build_identity()['build_id'],
        rule_pack_checksum=rules,
        environment={name: os.environ.get(name) for name in
                     ('GITLEAKS_CONFIG', 'TRIVY_CONFIG', 'SECURITY_RUNTIME_OFFLINE')})


def enqueue(service, workspace, ref, *, launch=True, recovery_from=None):
    root = service.root(workspace)
    record = service.load(root, ref)
    if not deferred(record) or record.get('native_repair'):
        return service.finish(workspace, ref)
    if record_owner(record) != service._owner():
        raise ValueError('Closeout requires the original task owner')
    queue = CloseoutQueue(service.hooks, root, now=service.now)
    if recovery_from is not None and not getattr(queue, 'supports_source_recovery', False):
        from .diagnostics import TaskRuntimeRestartRequired
        raise TaskRuntimeRestartRequired()
    pending = queue.read(ref)
    if pending and pending['state'] in PENDING:
        if pending['owner'] != service._owner():
            raise ValueError('Closeout owner mismatch')
        if launch:
            from ..task_closeout_worker import launch_worker
            launch_worker(service.hooks, root)
        return queue.view(ref, service._owner())
    started = time.perf_counter()
    end, staged = capture_end(service, root, record)
    from .queued_inputs import QueuedInputs
    inputs = QueuedInputs(service.hooks, root, now=service.now)
    input_ref = None
    try:
        configuration = dict(auxiliary=service._closeout_configuration(root, end),
            hook_revision=service._hook_inputs(root, record)[0], execution=execution_identity())
        from pathlib import Path
        for name in ('GITLEAKS_CONFIG', 'TRIVY_CONFIG'):
            if os.environ.get(name):
                path = Path(os.environ[name]).expanduser()
                path = (root/path).resolve() if not path.is_absolute() else path.resolve()
                if not path.is_relative_to(root):
                    raise ValueError('Queued scan requires project-local scanner configuration')
        engine = service.runtime() if callable(service.runtime) else service.runtime
        scan_path = getattr(getattr(engine, 'store', None), 'path', None)
        configuration['scan_store'] = str(scan_path.resolve()) if scan_path is not None else None
        # Serialize submission against foreground completion/cancellation.
        with service.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return dict(status='BUSY', task_ref=ref, scanner_run=False, reason='QUEUE_SUBMISSION_LOCK')
            current = service.load(root, ref)
            if baseline_snapshot(current) != baseline_snapshot(record):
                raise ValueError('Original baseline changed')
            if recovery_from is not None and current['phase'] in {'COMPLETE', 'INCOMPLETE'}:
                return service._view(current)
            # Ordinary closeout retains the original call contract. A long-lived
            # DEV process may have imported the queue before recovery was added.
            recovery_args = {} if recovery_from is None else dict(recovery_from=recovery_from)
            from .snapshot_page_guard import page_guard
            from .snapshot_pages import managed
            # Keep unpublished pages fenced until their queue reference commits.
            with page_guard(service.store(root).path.parent, create=managed(current)):
                if managed(current):
                    from .closeout_pages import freeze
                    end, small = freeze(service.store(root), current, end)
                    input_ref = inputs.capture(end, configuration['auxiliary'], snapshot=small, record=current)
                else:
                    input_ref = inputs.capture(end, configuration['auxiliary'])
                row = queue.submit(current, end, configuration, input_ref,
                                   preparation_ms=round(1000*(time.perf_counter()-started)),
                                   **recovery_args)
            service.store(root).save(current)  # Explicit closeout refreshes idle retention, never the baseline.
        if launch:
            from ..task_closeout_worker import launch_worker
            launch_worker(service.hooks, root)
        return queue.view(ref, service._owner())
    finally:
        if staged:
            from .end_versions import discard_unreferenced
            discard_unreferenced(service, root, ref, staged)
        # Cleanup must never replace the original failure with a second error.
        try:
            saved = queue.read(ref)
            if input_ref and (not saved or saved.get('input_ref') != input_ref):
                inputs.discard(input_ref)
        except Exception:
            pass  # Unknown references retain their original TTL and quota.


def recover_source_change(service, workspace, ref, *, resume_capacity=False):
    """Explicit prepare may refresh an unfinished end, never a baseline or read.

    The original signed queue fences identity/configuration and concurrent
    cancellation. Existing refinish archives review evidence and retains spending.
    Return None when ordinary preparation should continue unchanged.
    """
    from .closeout_queue import source_recoverable, MAX_SOURCE_RECOVERIES
    root = service.root(workspace)
    record = service.load(root, ref)
    if (record.get('closeout_dispatch') != 'BACKGROUND_V1' or record.get('native_repair')
            or record['phase'] in {'ACTIVE', 'STATIC_RUNNING', 'COMPLETE'}
            or record['phase'] == 'INCOMPLETE' and not resume_capacity):
        return None
    queue = CloseoutQueue(service.hooks, root, now=service.now)
    row = queue.read(ref)
    if not row or row['owner'] != service._owner():
        return None
    if not (source_recoverable(row) or row['state'] == 'READY_FOR_REVIEW'):
        return None
    if row.get('end', {}).get('version_ref') != record.get('end', {}).get('version_ref'):
        return None
    execution = execution_identity()
    if execution != row['configuration']['execution']:
        # Explicit preparation of an old pre-delivery capacity diagnosis may
        # continue reviewing the SAVED scan facts after a Runtime update. This
        # never changes the scan's recorded build or executes/reuses a new scan.
        # Configuration/rules and the complete source must still be unchanged.
        if (resume_capacity and row['state'] == 'READY_FOR_REVIEW'
                and dict(row['configuration']['execution'], build_id=execution['build_id']) == execution
                and service._fresh(root, record)):
            return None
        return dict(status='STALE', task_ref=ref, reason='RUNTIME_OR_CONFIGURATION_CHANGED',
                    next_action=None, baseline_recreated=False, recovery_blocked=True,
                    message='执行身份或配置已变化，不能自动沿用旧检查；保留原任务与基线并说明检查缺口。')
    if not source_recoverable(row) and service._fresh(root, record):
        return None
    if row.get('source_recovery_count', 0) >= MAX_SOURCE_RECOVERIES:
        result = queue.view(ref, service._owner())
        result.update(status='STALE', next_action=None, recovery_blocked=True,
                      reason='SOURCE_RECOVERY_LIMIT',
                      message='源码持续变化，已达到本轮自动恢复上限；保留原基线与检查记录，报告未完成范围。')
        return result
    return enqueue(service, root, ref, recovery_from=row)


def status(service, workspace, ref):
    root = service.root(workspace)
    record = service.load_header(root, ref, read_only=True)
    queue = CloseoutQueue(service.hooks, root, now=service.now)
    result = queue.view(ref, service._owner())
    row = queue.read(ref)
    if (row and row['state'] in {'READY_FOR_REVIEW', 'NO_CHANGES'}
            and record['phase'] in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}
            and record.get('end', {}).get('version_ref') == row['end'].get('version_ref')):
        result.update(status=record['phase'], next_action='get_task_security_review')
    return result


def cancel(service, workspace, ref):
    from ..scan_attempt import ScanAttemptStore, AttemptLease
    root = service.root(workspace)
    service.load(root, ref)
    queue = CloseoutQueue(service.hooks, root, now=service.now)
    with service.hooks.lock(root, wait_seconds=2) as acquired:
        if not acquired:
            return dict(status='BUSY', task_ref=ref)
        queue.cancel(ref, service._owner())
        attempts = ScanAttemptStore(service.hooks, root, now=service.now)
        lane = attempts.read()['lane']
        if lane and lane['state'] == 'ACTIVE' and lane['kind'] == 'TASK' and lane['scope_key'] == ref:
            attempts.cancel(AttemptLease(**{k:lane[k] for k in
                ('attempt_id', 'generation', 'lease_owner', 'cancel_generation')}))
    row = queue.read(ref)
    if row.get('input_ref'):
        from .queued_inputs import QueuedInputs
        QueuedInputs(service.hooks, root, now=service.now).discard(row['input_ref'])
    return queue.view(ref, service._owner())


def execute_one(service, workspace, ref, *, worker=None):
    """A bounded turn; Busy retries perform no source inventory or hashing."""
    from ..scan_attempt import ScanAttemptStore
    root = service.root(workspace)
    queue = CloseoutQueue(service.hooks, root, now=service.now)
    claim = queue.claim(ref, worker or uuid.uuid4().hex)
    if claim is None:
        return False
    stop = threading.Event()

    def heartbeat():
        while not stop.wait(20):
            try:
                if not queue.renew(claim):
                    return
            except (OSError, ValueError):
                return

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        record = service.load(root, ref)
        if record_owner(record) != claim['owner'] or baseline_fingerprint(record) != claim['baseline_digest']:
            raise ValueError('Original task identity changed')
        if record['phase'] == 'INCOMPLETE':
            queue.finish(claim, 'CANCELLED', 'TASK_ALREADY_CLOSED')
            return True
        from .closeout_pages import restore
        # The queue stays compact. Only the worker's compatibility view expands.
        claim = dict(claim, end=restore(service.store(root), record, claim['end']))
        lane = ScanAttemptStore(service.hooks, root, now=service.now).read()['lane']
        if lane and lane['state'] == 'ACTIVE' and lane['expires_at'] > service.now():
            queue.finish(claim, 'RETRY_WAIT', 'SCAN_RESOURCE_BUSY')
            return True
        expected = claim['configuration']
        if execution_identity() != expected['execution']:
            queue.finish(claim, 'STALE', 'RUNTIME_OR_CONFIGURATION_CHANGED')
            return True
        candidate = dict(record, end=claim['end'], end_auxiliary_hashes=expected['auxiliary'],
                         finished_hook_revision=expected['hook_revision'])
        from .queued_inputs import QueuedInputs
        inputs = QueuedInputs(service.hooks, root, now=service.now)
        frozen = inputs.open(claim['input_ref']) if claim.get('input_ref') else None
        # Legacy queue records without pinned bytes cannot prove old sources.
        if frozen is None and not service._fresh(root, candidate):
            queue.finish(claim, 'STALE', 'SOURCE_CHANGED_SINCE_CLOSEOUT')
            return True
        if not queue.started(claim):
            return True
        result = service._finish(root, ref, end=claim['end'], queue_guard=lambda:queue.current(claim),
                                 frozen_source=frozen, frozen_auxiliary=expected['auxiliary'])
        state = result['status']
        source_changed = ((state in {'READY', 'REVIEWING', 'COMPLETE', 'NO_CHANGES'}
                           or state == 'STALE' and not result.get('reason'))
                          and not service._fresh(root, candidate))
        if source_changed:
            state = 'STALE'
        outcome = ('RETRY_WAIT' if state == 'BUSY' else 'NO_CHANGES' if state == 'NO_CHANGES'
                   else 'READY_FOR_REVIEW' if state in {'READY', 'REVIEWING', 'COMPLETE'}
                   else 'STALE' if state == 'STALE' else 'FAILED')
        queue.finish(claim, outcome, 'SOURCE_CHANGED_SINCE_CLOSEOUT' if source_changed else
                     None if outcome in {'READY_FOR_REVIEW', 'NO_CHANGES'} else state)
        return True
    except Exception as exc:
        # Fixed reason; never persist exception text containing source or secrets.
        from .diagnostics import owned_storage_failure
        admission = owned_storage_failure(exc)
        from .durable import operation_failure
        operation = operation_failure(exc)
        if operation is not None:
            queue.finish(claim, 'RETRY_WAIT' if operation['status'] in {'BUSY', 'CAPACITY_REQUIRED'}
                         else 'FAILED', operation['reason_code'])
        elif admission is not None and admission['retryable']:
            # Keep the original frozen inputs and task/version binding. A
            # permission-admission lock is not a terminal execution failure.
            queue.finish(claim, 'RETRY_WAIT', admission['reason_code'])
        else:
            queue.finish(claim, 'FAILED', 'TASK_EXECUTION_UNAVAILABLE')
        return True
    finally:
        stop.set()
        thread.join(timeout=1)
        row = queue.read(ref)
        if claim.get('input_ref') and (not row or row['job_ref'] != claim['job_ref'] or row['state'] not in PENDING):
            from .queued_inputs import QueuedInputs
            QueuedInputs(service.hooks, root, now=service.now).discard(claim['input_ref'])
