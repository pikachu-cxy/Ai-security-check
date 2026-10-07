"""Bounded process-local preparation only; no scan results or authority."""
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import secrets
import threading

from .scanner_observation import workspace as observed_workspace

_workspace = ContextVar('scanner_preparation_workspace', default=None)


class PreparationBucket:
    def __init__(self):
        self.values = {}
        self.lock = threading.RLock()


class ProcessPreparations:
    def __init__(self, generation=1):
        self.pid = os.getpid()  # Internal only; diagnostics use a random identity.
        self.instance_id = secrets.token_hex(16)
        self.generation = generation
        self.buckets = {}
        self.lock = threading.RLock()

    def bucket(self, kind, scope):
        with self.lock:
            key = (kind, scope)
            if key not in self.buckets:
                if len(self.buckets) >= 64:
                    self.buckets.pop(next(iter(self.buckets)))
                self.buckets[key] = PreparationBucket()
            return self.buckets[key]


_process = ProcessPreparations()


def process_preparations():
    global _process
    # A fork must not inherit a parent's positive probes, locks or clock identity.
    if _process.pid != os.getpid():
        _process = ProcessPreparations(_process.generation + 1)
    return _process


def lifetime():
    state = process_preparations()
    return {'runtime_instance_id': state.instance_id, 'cache_generation': state.generation,
            'cache_scope': 'PROCESS_LOCAL_CONTENT_VALIDATED'}


def preparation_bucket(kind, scope=''):
    return process_preparations().bucket(kind, scope)


def workspace_key():
    return os.path.normcase(str(Path(observed_workspace() or _workspace.get() or Path.cwd()).resolve()))


@contextmanager
def workspace_scope(root):
    token = _workspace.set(os.path.normcase(str(Path(root).resolve())))
    try:
        yield
    finally:
        _workspace.reset(token)
