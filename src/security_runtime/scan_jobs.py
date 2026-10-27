"""Durable explicit scan requests, independent of an MCP connection lifetime.

Only submission can launch a worker. Reads never retry or scan; an interrupted
worker remains interrupted rather than silently scanning a different version.
"""
from __future__ import annotations

from pathlib import Path
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import uuid

from .hook_state import HookStateStore, no_links
from .progress import ProgressReporter
from .tasks.durable import SignedRecords

ACTIVE = frozenset({'QUEUED', 'RUNNING'})
LEASE_SECONDS = 90
REF = re.compile(r'sj1-[a-f0-9]{32}')
REQUEST_KEY = re.compile(r'[A-Za-z0-9_.:-]{8,128}')


def root_identity(root):
    no_links(root)
    info = Path(root).stat()
    if not Path(root).is_dir():
        raise ValueError('Workspace directory required')
    return [info.st_dev, info.st_ino]


def normalize_request(mode, files, force_rescan):
    if mode not in {'project', 'files', 'quick', 'feature'} or type(force_rescan) is not bool:
        raise ValueError('Invalid scan job request')
    if mode == 'files':
        # selected_request below performs the existing canonical validation.
        if not isinstance(files, list) or not files or len(files) > 100:
            raise ValueError('Selected files required')
        if any(not isinstance(p, str) for p in files):
            raise ValueError('Invalid selected files')
        from .scan_request import relative_path
        for path in files:
            relative_path(path)
        files = sorted(set(files))
    elif files is not None:
        raise ValueError('Files require files mode')
    if force_rescan and mode != 'project':
        raise ValueError('force_rescan requires project mode')
    return dict(mode=mode, files=files, force_rescan=force_rescan)


class ScanJobs(SignedRecords):
    max_record_bytes = 32_000

    def __init__(self, hooks, root, *, scan_path=None, now=time.time):
        super().__init__(hooks, root, 'explicit-scan-jobs.db', now=now)
        self.scan_path = Path(scan_path).absolute() if scan_path is not None else None

    def load(self, ref):
        if not isinstance(ref, str) or not REF.fullmatch(ref):
            raise ValueError('Invalid scan job reference')
        row = self.read(ref)
        if row is None:
            raise ValueError('Scan job does not belong to this workspace')
        if row['root_identity'] != root_identity(self.root):
            raise ValueError('Original scan workspace unavailable')
        return row

    def submit(self, request_key, *, mode='project', files=None, force_rescan=False, launcher=None):
        if not isinstance(request_key, str) or not REQUEST_KEY.fullmatch(request_key):
            raise ValueError('request_key must be 8-128 identifier characters')
        request = normalize_request(mode, files, force_rescan)
        identity = root_identity(self.root)
        if self.scan_path is None:
            raise ValueError('Scan store required for submission')
        no_links(self.scan_path)
        self.hooks.key(self.root)
        created = False
        with self.transaction() as db:
            rows = self._all(db)
            previous = next((r for r in rows if request_key in r['request_keys']), None)
            if previous:
                if previous['request'] != request or previous['root_identity'] != identity:
                    raise ValueError('Request key already belongs to a different scan request')
                row = previous
            else:
                # A lost response followed by a retry with a different key must
                # not start a second concurrent scan of the same request.
                row = next((r for r in rows if r['state'] in ACTIVE and r['lease_until'] > self.now() and r['request'] == request
                            and r['root_identity'] == identity), None)
                if row is not None:
                    if len(row['request_keys']) >= 32:
                        raise ValueError('Active scan request alias capacity exceeded')
                    row = self._put(db, row['job_ref'], dict(row, request_keys=[*row['request_keys'], request_key]))
                if row is None:
                    if mode == 'files':
                        from .selected_scan import selected_request
                        selected_request(self.root, request['files'])
                    created = True
                    ref = 'sj1-' + uuid.uuid4().hex
                    row = self._put(db, ref, dict(contract='explicit-scan-job-v1',
                        job_ref=ref, request_keys=[request_key], request=request,
                        root_identity=identity, scan_path=str(self.scan_path),
                        state='QUEUED', ticket=secrets.token_hex(32),
                        created_at=self.now(), updated_at=self.now(),
                        lease_until=self.now()+LEASE_SECONDS, scan_id=None,
                        phase='QUEUED', providers={}, reason_code=None,
                        worker_pid=None, execution=None))
        if created:
            try:
                (launcher or launch)(self, row)
            except OSError:
                self.update(row['job_ref'], row['ticket'], state='FAILED',
                            reason_code='WORKER_START_FAILED')
        return self.status(row['job_ref'])

    def update(self, ref, ticket, **changes):
        with self.transaction() as db:
            row = self._get(db, ref)
            if not row or not secrets.compare_digest(row['ticket'], ticket) or row['state'] not in ACTIVE:
                return False
            self._put(db, ref, dict(row, **changes, updated_at=self.now(),
                                    lease_until=self.now()+LEASE_SECONDS))
        return True

    def status(self, ref):
        row = self.load(ref)
        state = row['state']
        if state in ACTIVE and row['lease_until'] <= self.now():
            state = 'INTERRUPTED'
        return dict(contract=row['contract'], job_ref=ref, workspace=str(self.root),
            status=state, phase=row['phase'], providers=row['providers'],
            created_at=row['created_at'], updated_at=row['updated_at'],
            scan_id=row['scan_id'], scan_status=row.get('scan_status'),
            reason_code='WORKER_LEASE_EXPIRED' if state == 'INTERRUPTED' else row['reason_code'],
            result_available=state == 'COMPLETED', scanner_run=False,
            source_modified=False, repair_authorized=False,
            poll_after_seconds=2 if state in ACTIVE else None,
            next_action=dict(tool='get_scan_result' if state == 'COMPLETED' else 'get_scan_status',
                arguments=dict(workspace_path=str(self.root), job_ref=ref)),
            scope_notice='扫描版本在工作进程开始时捕获；查询只读取原任务，不检查当前源码，也不重新扫描。')

    def listing(self, limit=20):
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError('limit must be 1-50')
        rows = sorted(self.rows(), key=lambda r: r['created_at'], reverse=True)
        return dict(jobs=[self.status(r['job_ref']) for r in rows[:limit]],
                    total=len(rows), truncated=len(rows)>limit, scanner_run=False)

    def result(self, ref, *, summary=True):
        from .storage import ReadOnlySQLiteStore
        from .mcp_tools.presentation import _agent_result
        status = self.status(ref)
        if not status['result_available']:
            return status
        row = self.load(ref)
        no_links(Path(row['scan_path']))
        scan = ReadOnlySQLiteStore(Path(row['scan_path'])).get_scan(row['scan_id'])
        if scan is None or Path(scan['target_profile']['path']).resolve() != self.root:
            raise ValueError('Original scan result unavailable')
        data = _agent_result(scan, summary=summary)
        data.update(job_ref=ref, retrieval_scanner_run=False,
                    execution=row['execution'], result_is_saved_version=True,
                    scope_notice=status['scope_notice'])
        if summary:
            data['findings_access']['arguments']['workspace_path'] = str(self.root)
        return data


def launch(queue, row):
    from .background_preparation import runtime_command
    argv = runtime_command()+['scan-job-worker', '--workspace', str(queue.root),
        '--hooks', str(Path(queue.hooks.directory).absolute()),
        '--job-ref', row['job_ref'], '--ticket', row['ticket']]
    # Do not combine DETACHED_PROCESS: it makes CREATE_NO_WINDOW ineffective,
    # allowing a venv child interpreter to create a visible console.
    flags = ({'creationflags': subprocess.CREATE_NO_WINDOW}
             if os.name == 'nt' else {'start_new_session': True})
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, cwd=str(queue.path.parent), **flags)


def run_worker(workspace, hooks_path, job_ref, ticket, *, application_factory=None):
    hooks = HookStateStore(Path(hooks_path).absolute())
    queue = ScanJobs(hooks, Path(workspace).absolute())
    # Missing original records/keys are never created during worker recovery.
    row = queue.load(job_ref)
    if not secrets.compare_digest(row['ticket'], ticket) or (row['state'] != 'QUEUED' or row['lease_until'] <= queue.now()):
        return 2
    workers = HookStateStore(Path(hooks.directory)/'explicit-workers')
    with workers.lock(queue.root, wait_seconds=0) as acquired:
        if not acquired:
            queue.update(job_ref, ticket, state='FAILED', reason_code='WORKSPACE_SCAN_BUSY')
            return 2
        # Reload under the OS lock: competing launches cannot both execute.
        row = queue.load(job_ref)
        if row['state'] != 'QUEUED' or not secrets.compare_digest(row['ticket'], ticket):
            return 2
        queue.update(job_ref, ticket, state='RUNNING', phase='PREPARING', worker_pid=os.getpid())
        stop = threading.Event()

        def heartbeat():
            while not stop.wait(15):
                try:
                    if not queue.update(job_ref, ticket):
                        return
                except (OSError, ValueError, sqlite3.DatabaseError):
                    return

        def progress(event):
            providers = dict(queue.load(job_ref)['providers'])
            if event.scanner and len(providers) < 32:
                providers[event.scanner] = dict(event=event.event_type, duration_ms=event.duration_ms)
            queue.update(job_ref, ticket, phase=event.event_type, providers=providers)

        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        try:
            no_links(Path(row['scan_path']))
            if application_factory is None:
                from .workspace_application import WorkspaceApplication
                from .runtime import SecurityRuntime
                from .storage import SQLiteStore
                runtime = SecurityRuntime(store=SQLiteStore(Path(row['scan_path'])))
                application = WorkspaceApplication(runtime, hooks, scan_path_provider=lambda: runtime.store.path)
            else:
                application = application_factory(row)
            request, reporter = row['request'], ProgressReporter(progress)
            if request['mode'] == 'project':
                result = application.scan_project(str(queue.root),
                    force_rescan=request['force_rescan'], progress=reporter)
            elif request['mode'] == 'files':
                result = application.scan_files(str(queue.root), request['files'], progress=reporter)
            else:
                result = application.scan(str(queue.root), request['mode'], progress=reporter)
            data = result if isinstance(result, dict) else vars(result)
            reused = isinstance(result, dict) and data.get('result_reuse', {}).get('reused') is True
            queue.update(job_ref, ticket, state='COMPLETED', phase='COMPLETED',
                scan_id=data['scan_id'], scan_status=data['status'],
                execution=dict(scanner_run=not reused and any(
                    (r.get('status') if isinstance(r, dict) else r.status) in {'SUCCESS', 'FAILED', 'TIMEOUT'}
                    for r in data['scanner_runs']), result_reused=reused, host_review_completed=False,
                    repair_authorized=False))
            return 0
        except Exception as exc:
            from .explicit_scan import ExplicitScanBusy
            from .progress import ScanCancelled
            reason = ('SCAN_ATTEMPT_BUSY' if isinstance(exc, ExplicitScanBusy) else
                      'SCAN_CANCELLED' if isinstance(exc, ScanCancelled) else 'SCAN_WORKER_FAILED')
            # No raw exception, provider stderr, source or credentials in status.
            queue.update(job_ref, ticket, state='FAILED', phase='FAILED', reason_code=reason)
            return 2
        finally:
            stop.set()
            thread.join(timeout=2)
