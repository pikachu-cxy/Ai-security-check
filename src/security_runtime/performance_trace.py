"""Opt-in, bounded local timing. Never records arguments, source or results."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

_PARENT = ContextVar('performance_parent', default=None)
_LOCK = threading.Lock()
_INSTANCE = uuid.uuid4().hex
_MAX_BYTES = 8_000_000


def enabled():
    return bool(os.environ.get('SECURITY_RUNTIME_PERF_DIR'))


def _write(row):
    # Fail open for diagnostics only; business errors/results are never changed.
    try:
        root = Path(os.environ['SECURITY_RUNTIME_PERF_DIR'])
        if not root.is_absolute():
            return
        # Resolve system /tmp aliases, but reject a symlink at the selected leaf.
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or os.name != 'nt' and info.st_mode & 0o077:
            return
        if hasattr(os, 'getuid') and info.st_uid != os.getuid():
            return
        trace = os.environ.get('SECURITY_RUNTIME_PERF_RUN', '')
        if not re.fullmatch(r'[a-f0-9]{32}', trace):
            return
        row.update(contract='performance-trace-v1', run=trace, process=_INSTANCE,
                   pid=os.getpid(), thread=threading.get_ident())
        raw = (json.dumps(row, separators=(',', ':'))+'\n').encode()
        # One file per process; lock serializes threads. Never follow log links.
        with _LOCK:
            fd = os.open(root / ('events-'+str(os.getpid())+'-'+_INSTANCE+'.jsonl'),
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
            try:
                info = os.fstat(fd)
                if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and (os.name == 'nt' or not info.st_mode & 0o077)
                        and info.st_size + len(raw) <= _MAX_BYTES):
                    os.write(fd, raw)
            finally:
                os.close(fd)
    except (OSError, ValueError, KeyError):
        pass


@contextmanager
def span(phase):
    if not enabled():
        yield
        return
    # Call sites supply literal phase labels, never user input.
    if not re.fullmatch(r'[a-z][a-z0-9_.]{0,95}', phase):
        yield
        return
    identity = uuid.uuid4().hex
    parent = _PARENT.get()
    started = time.perf_counter_ns()
    _write(dict(event='start', span=identity, parent=parent, phase=phase,
                monotonic_ns=started, wall_ns=time.time_ns()))
    token = _PARENT.set(identity)
    status = 'returned'
    try:
        yield
    except BaseException:
        status = 'raised'
        raise
    finally:
        _PARENT.reset(token)
        ended = time.perf_counter_ns()
        _write(dict(event='end', span=identity, parent=parent, phase=phase,
                    monotonic_ns=ended, duration_ms=(ended-started)/1_000_000,
                    status=status))


def timed(phase):
    def decorate(fn):
        if inspect.iscoroutinefunction(fn):
            @wraps(fn)
            async def asynchronous(*args, **kwargs):
                with span(phase):
                    return await fn(*args, **kwargs)
            return asynchronous
        @wraps(fn)
        def synchronous(*args, **kwargs):
            with span(phase):
                return fn(*args, **kwargs)
        return synchronous
    return decorate


def observe_mcp(registry):
    """Outermost server handler; excludes transport/model time and JSON encoding."""
    from mcp.types import CallToolRequest
    handlers = registry.low_level.request_handlers
    original = handlers[CallToolRequest]
    names = registry.names()

    async def handler(request):
        from .mcp_tool_groups import original_call
        name, _ = original_call(request.params.name, request.params.arguments)
        phase = 'mcp.' + (name if name in names else 'unknown')
        with span(phase):
            return await original(request)
    handlers[CallToolRequest] = handler


def _batch(row):
    import hashlib
    run = os.environ.get('SECURITY_RUNTIME_PERF_RUN', '')
    return hashlib.sha256((run + ':' + row['check_ref'] + ':' + str(row['dirty_seq'])).encode()).hexdigest()


def queue_event(event, row):
    """Correlation digest is diagnostic only, never an owner/reference credential."""
    if not enabled() or event not in {'submitted', 'attempt'}:
        return
    _write(dict(event='queue', phase='check.queue', action=event, batch=_batch(row),
                monotonic_ns=time.perf_counter_ns()))


def review_event(action, check, progress=None):
    """Observed review window, not model thinking time or a report receipt."""
    if not enabled() or action not in {'evidence_read', 'saved'}:
        return
    statuses = {key: progress[key] for key in ('scanner_review', 'business_review')} if progress else {}
    _write(dict(event='review', phase='review.lifecycle', action=action,
                batch=_batch(check), monotonic_ns=time.perf_counter_ns(), **statuses))
