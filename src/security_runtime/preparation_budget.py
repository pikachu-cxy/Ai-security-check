"""A command-local preparation budget; scan execution remains independent."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import time


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

    def remaining(self):
        return max(0., self.seconds - (time.monotonic() - self.started))

    def report(self, event):
        from .install_progress import validate_preparation_event, report_progress
        safe = validate_preparation_event(event)
        if safe is None:
            return
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


def bounded_timeout(seconds):
    budget = current_budget()
    if budget is None:
        return seconds
    remaining = budget.remaining()
    if remaining <= 0:
        raise TimeoutError('preparation budget exhausted')
    return min(seconds, remaining)


@contextmanager
def preparation_budget(seconds=300, retries=0, idle_seconds=30, progress=None):
    if (type(seconds) is not int or not 1 <= seconds <= 1800
            or type(retries) is not int or not 0 <= retries <= 1
            or type(idle_seconds) is not int or not 1 <= idle_seconds <= 300):
        raise ValueError('Invalid preparation budget')
    budget = PreparationBudget(seconds, retries, idle_seconds, progress, time.monotonic())
    token = _current.set(budget)
    try:
        yield budget
    finally:
        _current.reset(token)
