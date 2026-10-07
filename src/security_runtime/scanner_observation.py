"""Per-invocation metadata only; never scanner-result caching or authorization."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time

_current = ContextVar('scanner_observation', default=None)


@contextmanager
def observation(workspace):
    data = {'timing_ms': {}, 'counts': {}, 'cache': {}, 'invocations': [], 'invocation_count': 0,
            'invocations_truncated': False, 'workspace': workspace}
    token = _current.set(data)
    started = time.perf_counter()
    try:
        yield data
    finally:
        measured = data['timing_ms']
        measured['scanner_total'] = milliseconds(started)
        measured['actual_scanner_execution'] = None  # No reliable CPU/startup split.
        _current.reset(token)


def milliseconds(start):
    return round(max(0, time.perf_counter()-start)*1000, 3)


@contextmanager
def span(name):
    data = _current.get()
    if data is None:
        yield
        return
    started = time.perf_counter()
    try:
        yield
    finally:
        add_time(name, milliseconds(started))


def add_time(name, value):
    data = _current.get()
    if data is not None and isinstance(value, (int,float)) and math.isfinite(value) and value >= 0:
        data['timing_ms'][name] = round(data['timing_ms'].get(name, 0)+value, 3)


def count(name, amount=1):
    data = _current.get()
    if data is not None:
        data['counts'][name] = data['counts'].get(name, 0)+amount


def cache(name, hit):
    data = _current.get()
    if data is not None:
        data['cache'][name] = 'HIT' if hit else 'MISS'


def workspace():
    data = _current.get()
    return data['workspace'] if data is not None else None


def metadata(data):
    # Internal workspace is never projected. No filename, source, command or log.
    result = {name: data[name] for name in ('timing_ms','counts','cache','invocations')}
    result['invocation_count'] = data['invocation_count']
    result['invocations_truncated'] = data['invocations_truncated']
    if 'scope' in data:
        result['scope'] = data['scope']
    return result


def invocation(kind, target_count):
    data = _current.get()
    if data is not None:
        if kind != 'VERSION_PROBE':
            data['invocation_count'] += 1
        if len(data['invocations']) < 64:
            data['invocations'].append({'type': kind, 'target_count': target_count})
        else:
            data['invocations_truncated'] = True


def scope(files, kind):
    data = _current.get()
    if data is not None:
        from .diagnostics import sanitize
        data['scope'] = {'target_files': len(files), 'kind': kind, 'repository_discovery': False,
                         'relative_targets': [sanitize(name, 300) for name in files[:20]],
                         'targets_truncated': len(files) > 20}
