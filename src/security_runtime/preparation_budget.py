"""A command-local preparation budget; scan execution remains independent."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import time
import threading

from .download_estimate import DownloadEstimate


@dataclass
class PreparationBudget:
    seconds: int
    retries: int
    idle_seconds: int
    progress: object
    started: float
    attempts: int = 0
    error_code: str = ''
    source: str = ''
    source_attempts: int = 0
    sources_attempted: list[str] = field(default_factory=list)
    adaptive: bool = False
    max_wait_seconds: int = 0
    _deadline: float = field(init=False, repr=False)
    _validation_deadline: float | None = field(default=None, init=False, repr=False)
    _stream: tuple | None = field(default=None, init=False, repr=False)
    _received: int = field(default=0, init=False, repr=False)
    _estimate: DownloadEstimate = field(default_factory=DownloadEstimate, init=False, repr=False)
    _lock: object = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        self.max_wait_seconds = self.max_wait_seconds or self.seconds
        self._deadline = self.started + self.seconds

    def hard_remaining(self):
        """One absolute ceiling shared by every component, source and retry."""
        return max(0., self.started + self.max_wait_seconds - time.monotonic())

    def remaining(self):
        with self._lock:
            deadline = min(self._deadline, self.started + self.max_wait_seconds)
            if self._validation_deadline is not None:
                deadline = min(deadline, self._validation_deadline)
            return max(0., deadline - time.monotonic())

    def _reset_transfer(self):
        self._stream, self._received, self._validation_deadline = None, 0, None
        self._estimate.reset()

    def observe_transfer(self, component, received, total=None, source=''):
        """Only increasing byte counters can extend a live preparation wait.

        A short observation window lets the estimator collect samples. Once a
        stable rate exists, allow its ETA plus bounded transfer/validation
        margins. At 100%, replace the network wait with at most 120 seconds of
        local validation; no repeated frame can renew it.
        """
        if (not self.adaptive or type(received) is not int or not 0 <= received <= 8_000_000_000
                or total is not None and (type(total) is not int or not received <= total <= 8_000_000_000)):
            return
        with self._lock:
            now = time.monotonic()
            if self.remaining() <= 0:
                return
            stream = (component, source, total)
            if stream != self._stream or received < self._received:
                self._reset_transfer()
                self._stream = stream
            grew = received > self._received
            self._received = received
            if total:
                self._estimate.update(received, total, now)
            if not grew:
                return
            hard_deadline = self.started + self.max_wait_seconds
            if total and received == total:
                if self._validation_deadline is None:
                    self._validation_deadline = min(hard_deadline, now + 120)
                proposed = self._validation_deadline
            else:
                estimate = self._estimate.estimate(now) if total else None
                if estimate is None:
                    proposed = now + min(self.idle_seconds, 15)
                else:
                    eta = estimate['remaining_seconds']
                    proposed = now + eta + max(10, eta * .2) + 120
            self._deadline = min(hard_deadline, max(self._deadline, proposed))

    def report(self, event):
        from .install_progress import validate_preparation_event, report_progress
        safe = validate_preparation_event(event)
        if safe is None:
            return
        with self._lock:
            if safe['event'] in {'DOWNLOAD_STARTED', 'DOWNLOAD_FALLBACK', 'DOWNLOAD_RETRY',
                    'DOWNLOAD_FAILED', 'DOWNLOAD_COMPLETE', 'COMPONENT_STARTED', 'COMPONENT_COMPLETE', 'COMPONENT_FAILED'}:
                self._reset_transfer()
        if safe['event'] == 'DOWNLOAD_PROGRESS':
            self.observe_transfer(safe['component'], safe['received_bytes'], safe['total_bytes'], safe.get('source', ''))
        self.attempts = max(self.attempts, safe.get('attempt', 0))
        if safe['event'] == 'DOWNLOAD_STARTED' and safe['component'] == 'vulnerability_db' and safe.get('source'):
            self.source_attempts += 1
            if safe['source'] not in self.sources_attempted:
                self.sources_attempted.append(safe['source'])
        if safe['event'] in {'DOWNLOAD_FAILED', 'COMPONENT_FAILED'}:
            self.error_code, self.source = safe.get('error_code', ''), safe.get('source', '')
        elif safe['event'] == 'DOWNLOAD_COMPLETE':
            self.error_code, self.source = '', safe.get('source', '')
        try:
            report_progress(self.progress, safe)
        except Exception:
            pass


_current = ContextVar('scanner_preparation_budget', default=None)


def current_budget():
    return _current.get()


def bounded_timeout(seconds, *, hard=False):
    budget = current_budget()
    if budget is None:
        return seconds
    remaining = budget.hard_remaining() if hard else budget.remaining()
    if remaining <= 0:
        raise TimeoutError('preparation budget exhausted')
    return min(seconds, remaining)


@contextmanager
def preparation_budget(seconds=300, retries=0, idle_seconds=30, progress=None, *, adaptive=False, max_wait_seconds=None):
    maximum = (1800 if adaptive else seconds) if max_wait_seconds is None else max_wait_seconds
    if (type(seconds) is not int or not 1 <= seconds <= 1800
            or type(retries) is not int or not 0 <= retries <= 1
            or type(idle_seconds) is not int or not 1 <= idle_seconds <= 300
            or type(adaptive) is not bool or type(maximum) is not int or not seconds <= maximum <= 1800):
        raise ValueError('Invalid preparation budget')
    budget = PreparationBudget(seconds, retries, idle_seconds, progress, time.monotonic(),
        adaptive=adaptive, max_wait_seconds=maximum if adaptive else seconds)
    token = _current.set(budget)
    try:
        yield budget
    finally:
        _current.reset(token)
