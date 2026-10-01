"""Local structured progress and cooperative cancellation, with no UI output."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time

from .diagnostics import sanitize


class ScanCancelled(Exception):
    pass


@dataclass(frozen=True)
class ProgressEvent:
    event_type: str
    timestamp: str
    component: str
    message: str
    elapsed_ms: int
    scanner: str = ''
    scanner_version: str = ''
    capability: tuple[str, ...] = ()
    duration_ms: int | None = None
    finding_count: int | None = None
    error_code: str = ''
    source: str = ''


class ProgressReporter:
    def __init__(self, sink=None):
        self.sink = sink
        self.started = time.monotonic()
        self.cancelled = threading.Event()
        self.lock = threading.RLock()

    def emit(self, event_type, *, component='runtime', message='', **fields):
        safe = {key: sanitize(value, 300) if isinstance(value, str) else value for key, value in fields.items()}
        if 'capability' in safe:
            safe['capability'] = tuple(sanitize(value, 80) for value in safe['capability'])
        event = ProgressEvent(sanitize(event_type, 80), datetime.now(timezone.utc).isoformat(),
            sanitize(component, 80), sanitize(message, 500), round((time.monotonic()-self.started)*1000), **safe)
        with self.lock:
            if self.sink is not None:
                # Presentation failures must not affect findings or execution.
                try:
                    self.sink(event)
                except Exception:
                    pass
        return event

    def checkpoint(self):
        if self.cancelled.is_set():
            raise ScanCancelled()

    def cancel(self):
        self.cancelled.set()


class NullProgressReporter(ProgressReporter):
    pass


_current = ContextVar('security_runtime_progress', default=None)


def current_reporter():
    return _current.get()


def emit(event_type, **fields):
    reporter = current_reporter()
    if reporter is not None:
        return reporter.emit(event_type, **fields)


def checkpoint():
    reporter = current_reporter()
    if reporter is not None:
        reporter.checkpoint()


@contextmanager
def progress_context(reporter):
    token = _current.set(reporter)
    try:
        yield reporter
    finally:
        _current.reset(token)
