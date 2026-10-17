"""Bounded probe provenance, without exception text, locals, paths or output."""
import hashlib
import json
import re
import sys

CONTRACT = 'component-probe-v1'
OPERATIONS = frozenset({'MANAGER_INIT', 'RESOLVE', 'ENSURE', 'VERSION_RESOLUTION'})
RECOVERY = frozenset({'NOT_ATTEMPTED', 'READY', 'VERSION_MISMATCH', 'FAILED', 'IDENTITY_CHANGED'})
INTERNAL_ERRORS = (AttributeError, TypeError, KeyError, ImportError, RuntimeError, NameError, AssertionError)
_EXCEPTIONS = frozenset(error.__name__ for error in INTERNAL_ERRORS) | {'OtherException'}
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')
_MODULE = re.compile(r'security_runtime(?:\.[a-z_][a-z0-9_]*){1,4}')


def capture_probe_failure(exception, operation):
    """Only code-owned identifiers are evidence; raw exception data stays private.

    AttributeError.name is included only when it occurs literally in a product
    frame's compiled names. A dynamic/user-provided attribute name is omitted.
    """
    frames, names = [], set()
    tb, inspected = exception.__traceback__, 0
    while tb is not None and inspected < 64:
        inspected += 1
        code, module = tb.tb_frame.f_code, tb.tb_frame.f_globals.get('__name__', '')
        if isinstance(module, str) and _MODULE.fullmatch(module) and _IDENTIFIER.fullmatch(code.co_name):
            frames.append({'module': module, 'function': code.co_name, 'line': tb.tb_lineno})
            names.update(code.co_names)
        tb = tb.tb_next
    attribute = exception.name if type(exception) is AttributeError else None
    attribute = attribute if isinstance(attribute, str) and _IDENTIFIER.fullmatch(attribute) and attribute in names else ''
    kind = type(exception).__name__ if type(exception).__module__ == 'builtins' else 'OtherException'
    kind = kind if kind in _EXCEPTIONS else 'OtherException'
    build, instance, generation = '', '', 0
    try:
        if getattr(sys, 'frozen', False):
            from .build_identity import build_identity
            build = build_identity().get('build_id', '')
        from .scanner_cache import lifetime
        lifetime_value = lifetime()
        instance, generation = lifetime_value['runtime_instance_id'], lifetime_value['cache_generation']
    except Exception:
        # A broken diagnostic dependency must not replace the original fault.
        pass
    value = {'contract': CONTRACT, 'operation': operation, 'exception_type': kind,
             'attribute': attribute, 'frames': frames[-4:], 'build_id': build,
             'runtime_instance_id': instance, 'cache_generation': generation, 'recovery': 'NOT_ATTEMPTED'}
    fingerprint = {key: value[key] for key in ('operation', 'exception_type', 'attribute', 'frames', 'build_id')}
    value['fault_id'] = 'pr1-' + hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()[:20]
    return value


def probe_fault_id(value):
    return value['fault_id'] if valid_probe(value) else ''


def valid_probe(value):
    try:
        return _valid_probe(value)
    except (TypeError, ValueError, AttributeError, RecursionError):
        return False


def _valid_probe(value):
    if not isinstance(value, dict) or set(value) != {'contract', 'operation', 'exception_type', 'attribute',
            'frames', 'build_id', 'runtime_instance_id', 'cache_generation', 'recovery', 'fault_id'}:
        return False
    if (value['contract'] != CONTRACT or value['operation'] not in OPERATIONS
            or value['exception_type'] not in _EXCEPTIONS or value['recovery'] not in RECOVERY
            or not isinstance(value['attribute'], str)
            or value['attribute'] and not _IDENTIFIER.fullmatch(value['attribute'])
            or not isinstance(value['fault_id'], str) or not re.fullmatch(r'pr1-[a-f0-9]{20}', value['fault_id'])
            or not isinstance(value['build_id'], str) or not re.fullmatch(r'(?:[a-f0-9]{64})?', value['build_id'])
            or not isinstance(value['runtime_instance_id'], str) or not re.fullmatch(r'(?:[a-f0-9]{32})?', value['runtime_instance_id'])
            or type(value['cache_generation']) is not int or not 0 <= value['cache_generation'] <= 1_000_000
            or not isinstance(value['frames'], list) or len(value['frames']) > 4):
        return False
    return all(isinstance(frame, dict) and set(frame) == {'module', 'function', 'line'}
        and isinstance(frame['module'], str) and _MODULE.fullmatch(frame['module'])
        and isinstance(frame['function'], str) and _IDENTIFIER.fullmatch(frame['function'])
        and type(frame['line']) is int and 1 <= frame['line'] <= 1_000_000 for frame in value['frames'])
