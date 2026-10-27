"""Detached, coalescing observed-file checks. Never scans a project inventory."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict, replace
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

from .development_check import DevelopmentCheckStore, root_identity
from .hook_state import HookStateStore, no_links
from .tasks.durable import SignedRecords

LEASE_SECONDS = 90
MAX_WORKERS = 2
DEBOUNCE_SECONDS = 0.35
MAX_DEBOUNCE_SECONDS = 2
MAX_WORKER_SECONDS = 120
MAX_SCAN_ATTEMPTS = 3
MAX_BUSY_ATTEMPTS = 120


def _capacity(hooks):
    # The existing input parent already normalizes the supported global layout.
    from .scan_attempt import _input_parent
    anchor = _input_parent(hooks).parent
    capacity_hooks = HookStateStore(anchor/'development-capacity')
    capacity_hooks.key(anchor)
    store = SignedRecords(capacity_hooks, anchor, 'workers.db')
    store.max_record_bytes = 8_000
    return store


def _pending_key(hooks, root):
    return 'pending:'+hashlib.sha256((str(hooks.directory)+'\0'+str(root)).encode()).hexdigest()


def _reserve(hooks, root, ticket):
    capacity = _capacity(hooks)
    key = _pending_key(hooks, root)
    with capacity.transaction() as db:
        for index in range(MAX_WORKERS):
            ref = 'slot:'+str(index)
            row = capacity._get(db, ref)
            if not row or row.get('lease_until', 0) <= capacity.now():
                capacity._put(db, ref, dict(ticket=ticket, lease_until=capacity.now()+LEASE_SECONDS,
                    hooks=str(Path(hooks.directory).absolute()), root=str(root)))
                if capacity._get(db, key):
                    db.execute('DELETE FROM records WHERE key=?', (key,))
                return True
        capacity._put(db, key, dict(root=str(root), hooks=str(Path(hooks.directory).absolute()),
            queued_at=capacity.now()))
    return False


def _renew_capacity(hooks, ticket):
    capacity = _capacity(hooks)
    with capacity.transaction() as db:
        for index in range(MAX_WORKERS):
            key = 'slot:'+str(index)
            row = capacity._get(db, key)
            if row and secrets.compare_digest(row['ticket'], ticket):
                if row['lease_until'] <= capacity.now():
                    return False
                capacity._put(db, key, dict(row, lease_until=capacity.now()+LEASE_SECONDS))
                return True
    return False


def _release_capacity(hooks, ticket, *, dispatch=True):
    capacity = _capacity(hooks)
    pending = []
    with capacity.transaction() as db:
        for index in range(MAX_WORKERS):
            key = 'slot:'+str(index)
            row = capacity._get(db, key)
            if row and secrets.compare_digest(row['ticket'], ticket):
                capacity._put(db, key, dict(row, lease_until=0))
        if dispatch:
            pending = sorted((row for row in capacity._all(db) if row['key'].startswith('pending:')),
                key=lambda row: row['queued_at'])[:MAX_WORKERS]
    for row in pending:
        try:
            launch_worker(HookStateStore(Path(row['hooks'])), Path(row['root']))
        except (OSError, ValueError):
            pass  # Saved requests remain queued; reads never restart workers.


def launch_worker(hooks, root):
    """At most one process per workspace and two per shared runtime state."""
    queue = DevelopmentCheckStore(hooks, root)
    ticket = secrets.token_hex(32)
    with queue.transaction() as db:
        worker = queue._get(db, '$worker')
        if worker and worker.get('lease_until', 0) > queue.now():
            return False
        if not any(row.get('kind') == 'check' and row['state'] in {'QUEUED', 'RUNNING'}
                   for row in queue._all(db)):
            return False
        if not _reserve(hooks, queue.root, ticket):
            return False
        # A dead worker must not strand RUNNING rows forever. Reuse the same
        # observed scope and reference; no baseline or prior result is replaced.
        for row in queue._all(db):
            if row.get('kind') == 'check' and row['state'] == 'RUNNING':
                queue._put(db, row['check_ref'], dict(row, state='QUEUED',
                    reason_code='DEVELOPMENT_WORKER_RECOVERED'))
        queue._put(db, '$worker', dict(kind='worker', ticket=ticket,
            lease_until=queue.now()+LEASE_SECONDS, root_identity=root_identity(queue.root)))
    from .background_preparation import runtime_command
    argv = runtime_command()
    if '-m' in argv and '-I' not in argv:
        argv.insert(1, '-I')
    argv += ['development-check-worker']
    argv += ['--workspace', str(queue.root), '--hooks', str(Path(hooks.directory).absolute()), '--ticket', ticket]
    # DETACHED_PROCESS cancels CREATE_NO_WINDOW on Windows. The venv launcher
    # can then create a console for its child interpreter despite DEVNULL.
    options = ({'creationflags': subprocess.CREATE_NO_WINDOW}
               if os.name == 'nt' else {'start_new_session': True})
    try:
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, cwd=str(queue.path.parent), **options)
    except OSError:
        with queue.transaction() as db:
            row = queue._get(db, '$worker')
            if row and row['ticket'] == ticket:
                queue._put(db, '$worker', dict(row, lease_until=0))
        _release_capacity(hooks, ticket, dispatch=False)
        raise
    return True


def _valid_worker(queue, ticket):
    row = queue.read('$worker')
    return bool(row and secrets.compare_digest(row.get('ticket', ''), ticket)
        and row['lease_until'] > queue.now() and row['root_identity'] == root_identity(queue.root))


def _heartbeat(queue, ticket, stop):
    while not stop.wait(15):
        try:
            with queue.transaction() as db:
                row = queue._get(db, '$worker')
                if not row or row['ticket'] != ticket or row['lease_until'] <= queue.now():
                    return
                queue._put(db, '$worker', dict(row, lease_until=queue.now()+LEASE_SECONDS))
            if not _renew_capacity(queue.hooks, ticket):
                return
        except (OSError, ValueError):
            return


def _scan(queue, row, ticket, runtime_factory=None):
    from .dependency_inputs import is_dependency_input
    from .scan_attempt import ScanAttemptStore, ScanAttemptExecution, ScanAttemptLost, source_binding
    from .scan_input import scoped_request
    from .progress import ScanCancelled
    attempts = ScanAttemptStore(queue.hooks, queue.root)
    attempts.recover_cleanup(limit=2)
    with queue.hooks.lock(queue.root, wait_seconds=0) as acquired:
        if not acquired:
            return None
        lease = attempts.claim('HOOK', row['check_ref'], source_binding(dict(
            contract=row['contract'], check_ref=row['check_ref'], dirty_seq=row['dirty_seq'],
            observed_paths=row['observed_paths'])), owner=row['owner'])
        if lease is None:
            return None
    receipt = {}

    def validate(view):
        # A result covers actual captured bytes, never just the path journal.
        return (_valid_worker(queue, ticket)
            and set(view.request.requested_files).issubset(set(row['observed_paths'])))

    def publish(view, result):
        if not _valid_worker(queue, ticket):
            raise ScanAttemptLost('DEVELOPMENT_WORKER_SUPERSEDED')
        applicability = view.check_current()
        outcome = 'COMPLETED' if applicability.state == 'CURRENT' else 'STALE'
        with queue.hooks.lock(queue.root, wait_seconds=2) as acquired:
            if not acquired or not attempts.finish(lease, input_id=view.input_id,
                    scan_id=result.scan_id, outcome=outcome):
                raise ScanAttemptLost('DEVELOPMENT_PUBLICATION_LOST')
        receipt.update(execution.receipt, publication='COMMITTED' if outcome == 'COMPLETED' else 'STALE',
            source_applicability=applicability.state)
        result.scanner_diagnostics['execution_publication'] = dict(receipt)

    execution = ScanAttemptExecution(attempts, lease, validator=validate, after_scan=publish)
    try:
        no_links(Path(row['scan_path']))
        if runtime_factory is None:
            from .runtime import SecurityRuntime
            from .storage import SQLiteStore
            runtime = SecurityRuntime(store=SQLiteStore(Path(row['scan_path'])))
        else:
            runtime = runtime_factory(row)
        request = scoped_request(queue.root, row['observed_paths'],
            dependency_changes=[name for name in row['observed_paths'] if is_dependency_input(name)])
        # Feature enables applicable IaC checks on the explicit observed files.
        # It never changes the selection to a repository inventory or Git diff.
        request = replace(request, mode='feature')
        from .verification_policy import local_recheck
        with local_recheck():
            result = runtime.scan(queue.root, mode='feature', request=request, execution=execution)
        if execution.input_id is None or not receipt:
            raise ScanAttemptLost('DEVELOPMENT_INPUT_NOT_BOUND')
        gaps = []
        absent = list(request.absent_files)
        if absent:
            gaps.append('DELETED_PATH_SEMANTICS_NOT_REVIEWED')
        actual = set(result.scan_context.get('input_files', []))
        excluded = sorted(set(request.files)-actual)
        if excluded:
            gaps.append('OBSERVED_FILES_NOT_SCANNED')
        if receipt.get('source_applicability') != 'CURRENT':
            gaps.append('SOURCE_CHANGED_DURING_SCAN')
        if (result.status != 'COMPLETED' or any(value not in {'EXECUTED', 'NOT_APPLICABLE'}
                for value in result.capability_results.values())):
            gaps.append('SCANNER_COVERAGE_LIMITED')
        runs = [asdict(run) for run in result.scanner_runs]
        return dict(scan_id=result.scan_id, status=result.status, coverage=result.coverage,
            gaps=gaps, absent_paths=absent, excluded_paths=excluded,
            execution=dict(receipt, scanner_run=any(run['status'] in {'SUCCESS', 'FAILED', 'TIMEOUT'}
                for run in runs), host_review_completed=False, repair_authorized=False))
    except BaseException as error:
        with queue.hooks.lock(queue.root, wait_seconds=2) as acquired:
            if acquired:
                attempts.finish(lease, input_id=execution.input_id,
                    outcome='CANCELLED' if isinstance(error, ScanCancelled) else 'FAILED')
        raise


def run_worker(workspace, hooks_path, ticket, *, runtime_factory=None,
               debounce_seconds=DEBOUNCE_SECONDS, max_seconds=MAX_WORKER_SECONDS):
    hooks = HookStateStore(Path(hooks_path).absolute())
    queue = DevelopmentCheckStore(hooks, workspace)
    if not isinstance(ticket, str) or len(ticket) != 64 or not _valid_worker(queue, ticket):
        return 2
    workers = HookStateStore(Path(hooks.directory)/'development-workers')
    with ExitStack() as stack:
        # The previous process can have retired its journal lease while it is
        # still releasing its OS lock. Let that short handover finish.
        acquired = stack.enter_context(workers.lock(queue.root, wait_seconds=2))
        if not acquired or not _valid_worker(queue, ticket):
            with queue.transaction() as db:
                worker = queue._get(db, '$worker')
                if worker and worker['ticket'] == ticket:
                    queue._put(db, '$worker', dict(worker, lease_until=0))
            _release_capacity(hooks, ticket)
            return 2
        stop = threading.Event()
        thread = threading.Thread(target=_heartbeat, args=(queue, ticket, stop), daemon=True)
        thread.start()
        deadline, debounce_started = time.monotonic()+max_seconds, {}
        try:
            while time.monotonic() < deadline and _valid_worker(queue, ticket):
                pending = sorted((r for r in queue.rows() if r.get('kind') == 'check'
                    and r['state'] == 'QUEUED'), key=lambda r: r['updated_at'])
                if not pending:
                    # Retirement and the final queue check share the write
                    # transaction used by arrivals. New edits either keep this
                    # worker alive or observe an expired lease and launch one.
                    with queue.transaction() as db:
                        if any(r.get('kind') == 'check' and r['state'] == 'QUEUED' for r in queue._all(db)):
                            continue
                        worker = queue._get(db, '$worker')
                        if worker and worker['ticket'] == ticket:
                            queue._put(db, '$worker', dict(worker, lease_until=0))
                    return 0
                row = pending[0]
                retry_seq = row.get('retry_seq', row.get('attempted_seq', 0))
                if retry_seq == row['dirty_seq'] and row.get('next_attempt_at', 0) > queue.now():
                    stop.wait(min(1, row['next_attempt_at']-queue.now(), max(0, deadline-time.monotonic())))
                    continue
                start = debounce_started.setdefault(row['check_ref'], time.monotonic())
                quiet = queue.now()-row['last_event_at'] >= debounce_seconds
                if not row['finish_requested'] and not quiet and time.monotonic()-start < MAX_DEBOUNCE_SECONDS:
                    time.sleep(min(0.05, max(0, deadline-time.monotonic())))
                    continue
                with queue.transaction() as db:
                    row = queue._get(db, row['check_ref'])
                    if row['state'] != 'QUEUED':
                        continue
                    if row['root_identity'] != root_identity(queue.root):
                        raise ValueError('DEVELOPMENT_WORKSPACE_REPLACED')
                    if row.get('retry_seq', row.get('attempted_seq', 0)) != row['dirty_seq']:
                        # Older resident MCP processes do not clear the new
                        # fields on append. Bind quotas in the worker as well.
                        row = dict(row, attempt_count=0, busy_attempts=0, next_attempt_at=0)
                    if row.get('attempt_count', 0) >= MAX_SCAN_ATTEMPTS:
                        from .development_delivery import publish
                        failed = queue._put(db, row['check_ref'], dict(row, state='FAILED',
                            failed_seq=row['dirty_seq'], reason_code='DEVELOPMENT_RETRIES_EXHAUSTED'))
                        publish(queue, db, dict(failed, scanned_seq=row['dirty_seq'], scan_id=None, result=None))
                        continue
                    row = queue._put(db, row['check_ref'], dict(row, state='RUNNING',
                        attempted_seq=row['dirty_seq'], attempt_count=row.get('attempt_count', 0)+1,
                        retry_seq=row['dirty_seq'], failed_seq=None, worker_ticket=ticket, reason_code=None))
                if not row['observed_paths']:
                    with queue.transaction() as db:
                        current = queue._get(db, row['check_ref'])
                        state = ('QUEUED' if current['finish_requested'] else 'DIRTY') if current['dirty_seq'] > row['dirty_seq'] else 'PARTIAL'
                        queue._put(db, row['check_ref'], dict(current, state=state,
                            scanned_seq=row['dirty_seq'], reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
                        from .development_delivery import publish
                        publish(queue, db, dict(row, state='PARTIAL', scanned_seq=row['dirty_seq'],
                            scan_id=None, result=None, reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
                    continue
                try:
                    result = _scan(queue, row, ticket, runtime_factory)
                except Exception:
                    with queue.transaction() as db:
                        current = queue._get(db, row['check_ref'])
                        newer = current['dirty_seq'] > row['dirty_seq']
                        state = (('QUEUED' if current['finish_requested'] else 'DIRTY') if newer else
                                 'QUEUED' if row['attempt_count'] < MAX_SCAN_ATTEMPTS else 'FAILED')
                        failed = queue._put(db, row['check_ref'], dict(current, state=state,
                            failed_seq=row['dirty_seq'] if state == 'FAILED' else None,
                            next_attempt_at=current.get('next_attempt_at', 0) if newer else
                                queue.now()+min(2**row['attempt_count'], 8),
                            reason_code=current.get('reason_code') if newer else 'DEVELOPMENT_SCAN_FAILED',
                            updated_at=queue.now()))
                        if state == 'FAILED':
                            from .development_delivery import publish
                            publish(queue, db, dict(failed, scanned_seq=row['dirty_seq'], scan_id=None, result=None))
                    continue
                with queue.transaction() as db:
                    current = queue._get(db, row['check_ref'])
                    if not _valid_worker(queue, ticket):
                        return 2
                    if result is None:
                        if current['dirty_seq'] != row['dirty_seq']:
                            # The busy attempt belongs to an older generation.
                            # Never charge its retry quota to a new edit batch.
                            queue._put(db, row['check_ref'], dict(current,
                                state='QUEUED' if current['finish_requested'] else 'DIRTY'))
                            continue
                        count = row.get('busy_attempts', 0) + 1
                        busy_state = ('DIRTY' if not current['finish_requested'] else
                                      'FAILED' if count >= MAX_BUSY_ATTEMPTS else 'QUEUED')
                        busy = queue._put(db, row['check_ref'], dict(current,
                            state=busy_state, busy_attempts=count,
                            failed_seq=row['dirty_seq'] if busy_state == 'FAILED' else None,
                            attempt_count=max(0, row['attempt_count']-1),
                            next_attempt_at=queue.now()+min(0.25*count, 2),
                            reason_code='WORKSPACE_SCAN_BUSY', updated_at=queue.now()))
                        if busy_state == 'FAILED':
                            from .development_delivery import publish
                            publish(queue, db, dict(busy, scanned_seq=row['dirty_seq'], scan_id=None, result=None))
                    else:
                        state = (('QUEUED' if current['finish_requested'] else 'DIRTY') if current['dirty_seq'] > row['dirty_seq'] else
                            'PARTIAL' if current['scope_unknown'] or result['gaps'] else 'RESULTS_READY')
                        queue._put(db, row['check_ref'], dict(current, state=state,
                            scan_id=result['scan_id'], scanned_seq=row['dirty_seq'], result=result,
                            reason_code=None, updated_at=queue.now()))
                        from .development_delivery import publish
                        publish(queue, db, dict(row, state='PARTIAL' if row['scope_unknown'] or result['gaps'] else 'RESULTS_READY',
                            scan_id=result['scan_id'], scanned_seq=row['dirty_seq'], result=result, reason_code=None))
                if result is None:
                    time.sleep(min(0.25, max(0, deadline-time.monotonic())))
                else:
                    debounce_started.pop(row['check_ref'], None)
            return 2
        finally:
            stop.set()
            thread.join(timeout=2)
            with queue.transaction() as db:
                worker = queue._get(db, '$worker')
                if worker and worker['ticket'] == ticket:
                    queue._put(db, '$worker', dict(worker, lease_until=0))
            _release_capacity(hooks, ticket)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--hooks', required=True)
    parser.add_argument('--ticket', required=True)
    args = parser.parse_args(argv)
    return run_worker(args.workspace, args.hooks, args.ticket)


if __name__ == '__main__':
    raise SystemExit(main())
