"""Connection-local policy for bounded, offline scanner rechecks."""
from contextlib import contextmanager
from contextvars import ContextVar
import os

_local_recheck = ContextVar('local_security_recheck', default=False)
_execution = ContextVar('local_security_execution', default=None)


def scanner_process_observed():
    ledger = _execution.get()
    if ledger is not None:
        ledger['engine_process_observed'] = True


def offline_scanning():
    return _local_recheck.get() or os.getenv('SECURITY_RUNTIME_OFFLINE') == '1'


def local_recheck_requested():
    return _local_recheck.get()


@contextmanager
def local_recheck():
    token = _local_recheck.set(True)
    ledger = {'engine_process_observed': False}
    execution_token = _execution.set(ledger)
    try:
        yield ledger
    finally:
        _execution.reset(execution_token)
        _local_recheck.reset(token)
