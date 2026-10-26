"""Closed, source-free execution diagnostics; never exception text or locals."""
import errno
import re
import sqlite3

CONTRACT = 'task-execution-diagnostic-v1'
STAGES = frozenset({'LOAD_TASK', 'RESTORE_END', 'CHECK_SCAN_LANE', 'CHECK_EXECUTION_IDENTITY',
    'OPEN_FROZEN_INPUTS', 'MARK_SCAN_STARTED', 'TASK_CLOSEOUT', 'VALIDATE_CURRENT_SOURCE',
    'PUBLISH_QUEUE_RESULT', 'STATIC_SCAN'})
TYPES = frozenset({'ValueError', 'TypeError', 'KeyError', 'RuntimeError', 'AssertionError',
    'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutError', 'Error', 'DatabaseError',
    'OperationalError', 'IntegrityError', 'InterfaceError', 'ProgrammingError',
    'SnapshotStoreError', 'TaskOperationError', 'OwnedWorkspaceStorageError', 'ScanAttemptLost',
    'CapturePublicationError', 'FrozenBodyContextUnavailable', 'TypedSnapshotSourceError',
    'ReviewControlError', 'OTHER'})
SQLITE_CODES = {getattr(sqlite3, name): name for name in ('SQLITE_ERROR', 'SQLITE_BUSY',
    'SQLITE_LOCKED', 'SQLITE_READONLY', 'SQLITE_IOERR', 'SQLITE_CORRUPT', 'SQLITE_FULL',
    'SQLITE_CANTOPEN', 'SQLITE_CONSTRAINT', 'SQLITE_MISUSE', 'SQLITE_NOTADB')}
STORAGE_CODES = frozenset(SQLITE_CODES.values()) | frozenset(errno.errorcode.values())


def failure_diagnostic(error, stage):
    if stage not in STAGES:
        raise ValueError('Unknown task execution stage')
    kind = type(error)
    trusted = kind.__module__ in {'builtins', 'sqlite3'} or kind.__module__.startswith('security_runtime.')
    name = kind.__name__ if trusted and kind.__name__ in TYPES else 'OTHER'
    storage = None
    cause = error
    for _ in range(8):
        if isinstance(cause, sqlite3.Error):
            code = getattr(cause, 'sqlite_errorcode', None)
            if type(code) is int:
                storage = SQLITE_CODES.get(code & 255)
        elif isinstance(cause, OSError) and type(cause.errno) is int:
            storage = errno.errorcode.get(cause.errno)
        if storage:
            break
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    location = None
    trace = error.__traceback__
    while trace is not None:
        module = trace.tb_frame.f_globals.get('__name__', '')
        if (isinstance(module, str) and len(module) <= 160
                and re.fullmatch(r'security_runtime(?:\.[A-Za-z_][A-Za-z_0-9]*)+', module)):
            function = trace.tb_frame.f_code.co_name
            location = dict(module=module, function=function if function.isidentifier() and len(function) <= 80 else None,
                            line=trace.tb_lineno)
        trace = trace.tb_next
    return validate(dict(contract=CONTRACT, stage=stage, exception_type=name,
                         storage_error=storage, location=location, security_proof=False))


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'contract', 'stage', 'exception_type',
            'storage_error', 'location', 'security_proof'} or value['contract'] != CONTRACT
            or not isinstance(value['stage'], str) or value['stage'] not in STAGES
            or not isinstance(value['exception_type'], str) or value['exception_type'] not in TYPES
            or value['storage_error'] is not None and (not isinstance(value['storage_error'], str)
                or value['storage_error'] not in STORAGE_CODES)
            or value['security_proof'] is not False):
        raise ValueError('Invalid task execution diagnostic')
    location = value['location']
    if location is not None and (not isinstance(location, dict)
            or set(location) != {'module', 'function', 'line'}
            or not isinstance(location['module'], str) or len(location['module']) > 160
            or not re.fullmatch(r'security_runtime(?:\.[A-Za-z_][A-Za-z_0-9]*)+', location['module'])
            or location['function'] is not None and (not isinstance(location['function'], str)
                or len(location['function']) > 80 or not location['function'].isidentifier())
            or type(location['line']) is not int or not 1 <= location['line'] <= 1_000_000):
        raise ValueError('Invalid task execution location')
    return dict(value, location=dict(location) if location else None)
