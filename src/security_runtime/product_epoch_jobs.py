"""Fair, workspace-shared driving of finite product observation epochs.

The service owns durable progress and cross-process fencing. This scheduler
only lends one executor turn at a time; it never authorizes task preimages.
"""
from concurrent.futures import Future, InvalidStateError
import sqlite3
import threading

from .product_epoch_store import ProductEpochError


TERMINAL = frozenset({'SEALED', 'WAITING_CAPACITY', 'CAPTURE_CONFLICT',
                      'CANCELLED', 'HISTORY_UNAVAILABLE', 'BUSY', 'PLATFORM_UNSUPPORTED',
                      'WAITING_PROGRESS'})
RETRYABLE = frozenset({'WAITING_CAPACITY', 'BUSY', 'WAITING_PROGRESS'})
MAX_NO_PROGRESS_TURNS = 4


def _progress_watermark(status):
    """Only committed source work counts; retry/control noise cannot keep a job alive."""
    counts, progress = status.get('counts', {}), status.get('progress', {})
    return (status.get('epoch_ref'), status.get('policy_digest'), status.get('scope_closed'),
            *(counts.get(name, 0) for name in ('members', 'observed', 'gaps', 'directories')),
            *(progress.get(name, 0) for name in ('enumerated_entries', 'directories_done', 'file_cursor',
                                               'pending_file_seq', 'pending_file_bytes')),
            status.get('current_path_attempts', 0))


def _advance(service, owner, first):
    try:
        return service.ensure(owner) if first else service.step(owner)
    except ProductEpochError as error:
        if error.reason_code != 'PRODUCT_EPOCH_WAITING_CAPACITY':
            raise
        # Initial ensure can hit an existing store's quota before loading its
        # header. Only a verified original epoch permits a recoverable pause.
        status = service.status()
        if (status.get('epoch_ref') is None or status.get('policy_digest') != service.policy_digest
                or status.get('root_identity') != service.store.root_identity
                or status.get('workspace_id') != service.store.workspace_id):
            raise
        if status.get('state') == 'SEALED':
            return status
        return dict(status, state='WAITING_CAPACITY', reason=error.reason_code)


class ProductEpochJobs:
    def __init__(self, executor, *, detached=False):
        if type(detached) is not bool:
            raise ValueError('Invalid product observation scheduler option')
        self.executor = executor
        self.detached = detached
        self.lock = threading.RLock()
        self.jobs = {}
        self.resources = {}
        self.active = {}
        self.progress = {}
        self.closed = False

    def start(self, root, hooks, owner):
        from .product_epoch_service import ProductEpochService
        with self.lock:
            if self.closed:
                raise ValueError('Product observation scheduler is closed')
            existing = self.jobs.get(root)
            if existing is not None:
                if not existing.done():
                    return existing
                if not existing.cancelled():
                    try:
                        if existing.result()['state'] not in RETRYABLE:
                            return existing
                    except Exception:
                        return existing
            service = ProductEpochService(hooks, root)
            result = Future()
            self.jobs[root] = result
            self.resources[result] = service
            try:
                self.executor.submit(self._turn, service, owner, result, True)
            except BaseException:
                self.jobs.pop(root, None)
                self.resources.pop(result, None)
                service.close()
                raise
            return result

    def _turn(self, service, owner, result, first=False):
        with self.lock:
            if self.closed or result.done():
                if not self.active.get(result):
                    self.resources.pop(result, None)
                    self.progress.pop(result, None)
                    service.close()
                return
            self.active[result] = self.active.get(result, 0)+1
        try:
            if self.detached:
                status = self._detached_turn(service, owner, first)
                if status is None:
                    timer = threading.Timer(1, self._poll, (service, owner, result))
                    timer.daemon = True
                    timer.start()
                    return
            else:
                status = _advance(service, owner, first)
            if status['state'] in TERMINAL:
                result.set_result(status)
                return
            watermark = _progress_watermark(status)
            with self.lock:
                previous, stalled = self.progress.get(result, (None, 0))
                stalled = stalled+1 if watermark == previous else 0
                self.progress[result] = watermark, stalled
            if stalled >= MAX_NO_PROGRESS_TURNS:
                result.set_result(dict(status, state='WAITING_PROGRESS', reason='PRODUCT_EPOCH_NO_PROGRESS'))
                return
            with self.lock:
                if self.closed or result.cancelled():
                    result.cancel()
                    return
                # Resubmission returns the worker after every bounded step.
                # Another workspace can make progress before our next turn.
                self.executor.submit(self._turn, service, owner, result)
        except InvalidStateError:
            # Shutdown may cancel a Future while its bounded step completes.
            pass
        except Exception as exc:
            try:
                result.set_exception(exc)
            except InvalidStateError:
                pass
        finally:
            with self.lock:
                remaining = self.active[result]-1
                if remaining:
                    self.active[result] = remaining
                else:
                    self.active.pop(result)
                if not remaining and (self.closed or result.done()):
                    self.resources.pop(result, None)
                    self.progress.pop(result, None)
                    service.close()

    def _detached_turn(self, service, owner, first):
        from .product_epoch_worker import EpochQueue, EpochWorkerUnavailable, launch
        queue = EpochQueue(service.hooks, service.root)
        if first:
            status = _advance(service, owner, True)
            if status['state'] in TERMINAL:
                return status
            queue.submit(service, owner, status)
        job = queue.read('$job')
        if job is None:
            raise ValueError('Original product observation request unavailable')
        current = queue.verify(service, job)
        if current['state'] == 'SEALED':
            return current
        if job['state'] in {'QUEUED', 'RUNNING'}:
            # Reclaims an expired process lease; live leases do not respawn.
            try:
                launch(service.hooks, service.root)
            except EpochWorkerUnavailable:
                return dict(current, state='BUSY', reason='PRODUCT_EPOCH_WORKER_UNAVAILABLE')
            except sqlite3.OperationalError as error:
                if getattr(error, 'sqlite_errorcode', None) not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                    raise
                return dict(current, state='BUSY', reason='PRODUCT_EPOCH_WORKER_BUSY')
            return None
        return dict(current, state=job['state'], reason=job.get('reason'))

    def _poll(self, service, owner, result):
        with self.lock:
            if self.closed or result.done():
                return
            try:
                self.executor.submit(self._turn, service, owner, result)
            except RuntimeError as error:
                if not result.done():
                    result.set_exception(error)
                self.resources.pop(result, None)
                service.close()

    def close(self):
        with self.lock:
            self.closed = True
            for future in self.jobs.values():
                if not future.done():
                    future.cancel()
            for future, service in list(self.resources.items()):
                if future not in self.active:
                    service.close()
                    self.resources.pop(future, None)
                    self.progress.pop(future, None)
