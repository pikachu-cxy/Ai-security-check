"""One immutable preference snapshot per operation; never mutate process environment."""
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from functools import wraps
from copy import deepcopy
from .user_config import read_config, _merge, DEFAULTS, validate_preferences

_current = ContextVar('scan_preferences', default=None)


def snapshot():
    if _current.get() is None:
        with preferences():
            return deepcopy(_current.get())
    return deepcopy(_current.get())


def section(*keys):
    value = (_current.get() or read_config())['values']
    for key in keys:
        value = value[key]
    return deepcopy(value)


def explicit(*keys):
    value = (_current.get() or read_config()).get('explicit', {})
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


@contextmanager
def preferences(value=None):
    if value is None and _current.get() is not None:
        yield
        return
    value = deepcopy(value if value is not None else read_config())
    value['values'] = _merge(DEFAULTS, value['values'])
    validate_preferences(value['values'])
    token = _current.set(value)
    try:
        from .target import TargetDetector
        detector = TargetDetector()
        names = {'max_files': detector.max_files, 'max_directories': detector.max_directories,
                 'max_depth': detector.max_depth, 'max_file_bytes': detector.max_file_size}
        value['values']['scan']['discovery'] = names
        # Worker snapshots must not consult a later environment or legacy file.
        value.setdefault('explicit', {}).setdefault('scan', {})['discovery'] = dict(names)
        import hashlib, json
        value['revision'] = hashlib.sha256(json.dumps(value['values'], sort_keys=True).encode()).hexdigest()
    except BaseException:
        _current.reset(token)
        raise
    from .configured_rules import resource_scope, end_scope
    with ExitStack() as stack:
        resource_token = resource_scope(stack)
        try:
            yield
        finally:
            end_scope(resource_token)
            _current.reset(token)


def configured(function):
    @wraps(function)
    def call(*args, **kwargs):
        with preferences():
            return function(*args, **kwargs)
    return call
