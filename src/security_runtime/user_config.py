"""User-owned product preferences, independent of project source and install versions."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tomllib

from .hook_state import no_links

DEFAULTS = {
    'schema_version': 1,
    'storage': {'development_record_limit_enabled': True, 'development_max_records': 1024,
        'explicit_scan_jobs': {'max_records': 128, 'max_total_bytes': 96000000, 'max_database_bytes': 128000000},
        'scan_publication': {'max_records': 32, 'max_record_bytes': 8_000_000, 'max_total_bytes': 32_000_000}},
    'scan': {
        'discovery': {'max_files': 10000, 'max_directories': 2000, 'max_depth': 32, 'max_file_bytes': 1000000},
        'input': {'max_files': 10000, 'max_total_bytes': 128000000, 'max_file_bytes': 4000000, 'max_index_bytes': 8000000},
        'git': {'timeout_seconds': 10, 'max_output_bytes': 4000000},
        'execution': {'sast_timeout_seconds': 45, 'gitleaks_timeout_seconds': 30, 'trivy_timeout_seconds': 90, 'max_output_bytes': 4000000},
        'dataflow': {'max_files': 256, 'max_total_bytes': 8000000, 'max_steps': 1000000, 'max_depth': 6, 'max_file_bytes': 500000, 'feature_timeout_seconds': 3, 'release_timeout_seconds': 30}},
    'rules': {'sast': {'mode': 'builtin', 'paths': [], 'exclude_ids': []}, 'gitleaks': {'config_path': ''}},
    'vulnerability_data': {'trivy': {'repositories': [], 'cache_dir': '', 'update_mode': 'auto',
        'update_interval_seconds': 0, 'stale_policy': 'allow_with_gap'}},
    'agent': {'review_scanner_findings': True, 'audit_business_logic': False},
    'development': {'business_audit_delivery': 'fast',
                    'stop_fallback': {'enabled': True, 'wait_timeout_seconds': 120, 'max_continuations': 2}},
}


def config_path():
    override = os.getenv('SECURITY_RUNTIME_CONFIG')
    if override:
        path = Path(override)
        if not path.is_absolute():
            raise ValueError('USER_CONFIG_PATH_MUST_BE_ABSOLUTE')
        return path
    # A single user setting must not follow per-workspace SECURITY_RUNTIME_STATE_DIR.
    base = (Path(os.environ['APPDATA']) if os.name == 'nt' and os.getenv('APPDATA')
            else Path(os.getenv('XDG_CONFIG_HOME', Path.home()/'.config')))
    return base / 'ai-security-runtime' / 'config.toml'


def _merge(default, supplied, prefix=''):
    if not isinstance(supplied, dict) or set(supplied) - set(default):
        raise ValueError('USER_CONFIG_INVALID_FIELDS:' + prefix)
    result = copy.deepcopy(default)
    for key, value in supplied.items():
        field = prefix + key
        if isinstance(default[key], dict):
            result[key] = _merge(default[key], value, field + '.')
        elif type(value) is not type(default[key]):
            raise ValueError('USER_CONFIG_INVALID_TYPE:' + field)
        else:
            result[key] = value
    return result


def read_config():
    path = config_path()
    no_links(path)
    supplied = {}
    if path.exists():
        if not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('USER_CONFIG_INVALID_FILE')
        with path.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('USER_CONFIG_TOO_LARGE')
        try:
            supplied = tomllib.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError):
            raise ValueError('USER_CONFIG_INVALID_TOML') from None
    result = _merge(DEFAULTS, supplied)
    stop = result['development']['stop_fallback']
    if (result['schema_version'] != 1 or result['storage']['development_max_records'] < 1
            or not 1 <= stop['wait_timeout_seconds'] <= 3600
            or not 1 <= stop['max_continuations'] <= 10):
        raise ValueError('USER_CONFIG_VALUE_OUT_OF_RANGE')
    validate_preferences(result)
    return dict(explicit=supplied, precedence='OPERATION_ARGUMENT > EXPLICIT_USER_CONFIG > LEGACY_ENVIRONMENT > LEGACY_FILE > DEFAULT',
                migration_note='Legacy discovery settings remain supported; explicit scan.discovery fields take priority.',
                path=str(path), source='FILE' if path.exists() else 'DEFAULT', values=result,
                revision=hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest())


def batch_config(row):
    # Old records keep the previous behavior and are never auto-submitted by Stop.
    return _merge(DEFAULTS, (row.get('effective_config') or {'values': DEFAULTS})['values'])


def analysis_requirements(row):
    agent = batch_config(row)['agent']
    return {name: ('REQUIRED' if enabled else 'SKIPPED_BY_CONFIG') for name, enabled in agent.items()}


def describe_config():
    try:
        return dict(status='VALID', **read_config(), host_support={
            'codex_cli': 'IMPLEMENTED_REQUIRES_NATIVE_HOOKS',
            'cursor_cli': 'IMPLEMENTED_REQUIRES_NATIVE_HOOKS',
            'claude_code': 'PLANNED', 'qoder_cli': 'PLANNED'})
    except (ValueError, OSError) as error:
        return dict(status='INVALID', reason=str(error) if isinstance(error, ValueError) else 'USER_CONFIG_UNREADABLE',
                    automatic_fallback_allowed=False)


def validate_preferences(values):
    if values['development']['business_audit_delivery'] not in {'fast', 'wait'}:
        raise ValueError('USER_CONFIG_INVALID_AUDIT_DELIVERY')
    for section in (*values['scan'].values(), values['storage']['explicit_scan_jobs'], values['storage']['scan_publication']):
        if any(type(v) is not int or v < 0 for v in section.values()):
            raise ValueError('USER_CONFIG_LIMIT_MUST_BE_NONNEGATIVE_INTEGER')
    sast = values['rules']['sast']
    data = values['vulnerability_data']['trivy']
    if (sast['mode'] not in {'builtin', 'extend', 'replace'}
            or data['update_mode'] not in {'auto', 'manual', 'offline'}
            or data['stale_policy'] not in {'allow_with_gap', 'require_fresh'}
            or data['update_interval_seconds'] < 0):
        raise ValueError('USER_CONFIG_INVALID_POLICY')
    for items in (sast['paths'], sast['exclude_ids'], data['repositories']):
        if any(not isinstance(v, str) or not v or len(v) > 4096 for v in items) or len(set(items)) != len(items):
            raise ValueError('USER_CONFIG_INVALID_LIST')
    if sast['mode'] != 'builtin' and not sast['paths'] or sast['mode'] == 'builtin' and sast['paths']:
        raise ValueError('USER_CONFIG_RULE_PATHS_REQUIRED_FOR_CUSTOM_MODE')
    for name in (*sast['paths'], values['rules']['gitleaks']['config_path'], data['cache_dir']):
        if name and not Path(name).is_absolute():
            raise ValueError('USER_CONFIG_PATH_MUST_BE_ABSOLUTE')
    for repository in data['repositories']:
        if any(c.isspace() for c in repository) or '://' in repository or '@' in repository or '?' in repository or repository.startswith('-'):
            raise ValueError('USER_CONFIG_INVALID_PUBLIC_OCI_REPOSITORY')


def save_config(values, expected_revision):
    """Compare and atomically replace user preferences; active batches retain snapshots."""
    from contextlib import closing
    import sqlite3
    import tempfile
    merged = _merge(DEFAULTS, values)
    validate_preferences(merged)
    stop = merged['development']['stop_fallback']
    if (merged['schema_version'] != 1 or merged['storage']['development_max_records'] < 1
            or not 1 <= stop['wait_timeout_seconds'] <= 3600 or not 1 <= stop['max_continuations'] <= 10):
        raise ValueError('USER_CONFIG_VALUE_OUT_OF_RANGE')
    path = config_path()
    no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_suffix('.lock.db')
    no_links(lock)
    with closing(sqlite3.connect(lock, timeout=2)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        if read_config()['revision'] != expected_revision:
            raise ValueError('USER_CONFIG_VERSION_CONFLICT')
        lines = []
        def section(items, prefix=''):
            if prefix:
                lines.append('['+prefix+']')
            for key, value in items.items():
                if not isinstance(value, dict):
                    lines.append(key+' = '+json.dumps(value, ensure_ascii=True))
            lines.append('')
            for key, value in items.items():
                if isinstance(value, dict):
                    section(value, prefix+'.'+key if prefix else key)
        section(merged)
        raw = '\n'.join(lines).encode()
        if len(raw) > 65536:
            raise ValueError('USER_CONFIG_TOO_LARGE')
        fd, name = tempfile.mkstemp(prefix='.preferences-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            no_links(path)
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)
    return dict(saved=True, effective='NEXT_BATCH', active_batches_unchanged=True, **read_config())
