"""Queue facade. Worker execution never begins or adopts a development task."""
import os
import threading
import time
import uuid

from .activity import deferred
from .closeout_queue import CloseoutQueue, PENDING, fingerprint
from .end_versions import capture_end
from .ownership import record_owner


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


def enqueue(service, workspace, ref, *, launch=True):
    root = service.root(workspace)
    record = service.load(root, ref)
    if not deferred(record) or record.get('native_repair'):
        return service.finish(workspace, ref)
    if record_owner(record) != service._owner():
        raise ValueError('Closeout requires the original task owner')
    queue = CloseoutQueue(service.hooks, root, now=service.now)
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
        input_ref = inputs.capture(end, configuration['auxiliary'])
        # Serialize submission against foreground completion/cancellation.
        with service.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return dict(status='BUSY', task_ref=ref, scanner_run=False, reason='QUEUE_SUBMISSION_LOCK')
            current = service.load(root, ref)
            if current['baseline'] != record['baseline']:
                raise ValueError('Original baseline changed')
            row = queue.submit(current, end, configuration, input_ref,
                               preparation_ms=round(1000*(time.perf_counter()-started)))
            service.store(root).save(current)  # Explicit closeout refreshes idle retention, never the baseline.
        if launch:
            from ..task_closeout_worker import launch_worker
            launch_worker(service.hooks, root)
        return queue.view(ref, service._owner())
    finally:
        saved = queue.read(ref)
        if staged and (not saved or saved['end'].get('version_ref') != staged):
            service.end_versions(root).discard(staged)
        if input_ref and (not saved or saved.get('input_ref') != input_ref):
            inputs.discard(input_ref)


def status(service, workspace, ref):
    root = service.root(workspace)
    record = service.load(root, ref, read_only=True)
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
        if record_owner(record) != claim['owner'] or fingerprint(record['baseline']) != claim['baseline_digest']:
            raise ValueError('Original task identity changed')
        if record['phase'] == 'INCOMPLETE':
            queue.finish(claim, 'CANCELLED', 'TASK_ALREADY_CLOSED')
            return True
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
        if state in {'READY', 'REVIEWING', 'COMPLETE', 'NO_CHANGES'} and not service._fresh(root, candidate):
            state = 'STALE'
        outcome = ('RETRY_WAIT' if state == 'BUSY' else 'NO_CHANGES' if state == 'NO_CHANGES'
                   else 'READY_FOR_REVIEW' if state in {'READY', 'REVIEWING', 'COMPLETE'}
                   else 'STALE' if state == 'STALE' else 'FAILED')
        queue.finish(claim, outcome, None if outcome in {'READY_FOR_REVIEW', 'NO_CHANGES'} else state)
        return True
    except Exception:
        # Fixed reason; never persist exception text containing source or secrets.
        queue.finish(claim, 'FAILED', 'TASK_EXECUTION_UNAVAILABLE')
        return True
    finally:
        stop.set()
        thread.join(timeout=1)
        row = queue.read(ref)
        if claim.get('input_ref') and (not row or row['job_ref'] != claim['job_ref'] or row['state'] not in PENDING):
            from .queued_inputs import QueuedInputs
            QueuedInputs(service.hooks, root, now=service.now).discard(claim['input_ref'])
