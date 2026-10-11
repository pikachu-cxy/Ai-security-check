"""Prepare the product's supported scanners and public data during installation.

This module has no project path and never resolves, installs or runs project
dependencies. A present vulnerability database is not proof that it is current.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import struct
import threading

from .install_progress import report_progress
from .progress import ScanCancelled, checkpoint
from .toolchain import ToolManager, ToolStatus, VERSIONS


CONTRACT = 'installation-readiness-v1'
CORE_TOOLS = ('semgrep', 'gitleaks', 'trivy')
# Reviewed against the trivy-db commit pinned by built-in Trivy 0.74.0.
# A product engine upgrade must review this compatibility value together.
TRIVY_DATABASE_SCHEMA_VERSION = 2
_BOLT_MAGIC = 0xED0CDAED
_BOLT_FORMAT_VERSION = 2
_BOLT_PAGE_SIZES = (1024, 2048, 4096, 8192, 16384, 32768, 65536)
_TOOL_STATUSES = frozenset(status.value for status in ToolStatus)
_FRESHNESS = frozenset({'FRESH', 'STALE', 'UNKNOWN', 'MISSING'})
_STAGES = frozenset({'INSTALL_TOOLS', 'INSTALL_DATA', 'VERIFY_SCAN_READINESS'})
_EXCEPTION_TYPES = frozenset({'OSError', 'PermissionError', 'FileNotFoundError',
    'TimeoutError', 'ValueError', 'TypeError', 'RuntimeError', 'KeyError',
    'AttributeError', 'ImportError', 'OtherException'})
_VERSION = re.compile(r'[0-9]{1,6}(?:\.[0-9]{1,6}){1,3}')
_LABELS = {'semgrep': '代码检查', 'gitleaks': '密钥检查', 'trivy': '依赖检查'}


@contextmanager
def _quiet_preparation_logs():
    """Keep this install's internal events out of normal user output only.

    A logger-level filter runs in the emitting thread. Other threads, existing
    handlers and logger levels remain untouched, including active MCP logging.
    Each nested/concurrent preparation removes only its own filter on exit.
    """
    owner = threading.get_ident()
    class PreparationFilter(logging.Filter):
        def filter(self, record):
            return threading.get_ident() != owner
    logger = logging.getLogger('security_runtime.toolchain')
    prepared_filter = PreparationFilter()
    logger.addFilter(prepared_filter)
    try:
        yield
    finally:
        logger.removeFilter(prepared_filter)


def _version(value):
    """Only numeric version tokens belong in the installation receipt."""
    if not isinstance(value, str):
        return ''
    match = _VERSION.search(value[:300])
    return match.group() if match else ''


def _status(value):
    return str(value) if isinstance(value, str) and value in _TOOL_STATUSES else ToolStatus.BROKEN.value


def _failure(failures, stage, component, exception):
    name = type(exception).__name__
    if type(exception).__module__ != 'builtins' or name not in _EXCEPTION_TYPES:
        name = 'OtherException'
    item = {'stage': stage, 'component': component, 'exception_type': name}
    if item not in failures:
        failures.append(item)


def _report(progress, stage):
    try:
        report_progress(progress, stage)
    except ScanCancelled:
        raise
    except Exception:
        # A broken presentation callback must not invalidate preparation.
        pass


def _component(result, expected):
    status = _status(getattr(result, 'status', ToolStatus.BROKEN))
    actual = _version(getattr(result, 'version', ''))
    if status == ToolStatus.READY and actual != expected:
        status = ToolStatus.VERSION_MISMATCH.value
    if status == ToolStatus.READY and not getattr(result, 'path', ''):
        status = ToolStatus.BROKEN.value
    return {'status': status, 'version': actual, 'expected_version': expected,
        'ready': status == ToolStatus.READY and actual == expected}


def _file_identity(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _fnv64a(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def _database_readable(manager):
    return validate_database_directory(Path(manager.trivy_cache_dir()) / 'db')


def validate_database_directory(directory):
    """Reject invalid or unreadable download candidates before cache activation."""
    try:
        return _validate_database_directory(Path(directory))
    except Exception:
        # No cache mutation and no exception text: failed validation never
        # licenses replacing the previous public vulnerability database.
        return False


def _validate_database_directory(directory):
    """Bounded, read-only schema and bbolt header/root sanity verification.

    Trivy uses bbolt, not SQLite. This checks the same meta magic/version and
    FNV-1a checksum used by bbolt's Meta.Validate, plus root-page bounds. It does
    not traverse the full vulnerability content or prove every record intact.
    """
    metadata_path, database_path = directory / 'metadata.json', directory / 'trivy.db'
    metadata_before = metadata_path.stat()
    if metadata_before.st_size > 64_000:
        return False
    with metadata_path.open('rb') as stream:
        metadata = json.loads(stream.read(64_001))
    if (not isinstance(metadata, dict) or type(metadata.get('Version')) is not int
            or metadata['Version'] != TRIVY_DATABASE_SCHEMA_VERSION
            or _file_identity(metadata_before) != _file_identity(metadata_path.stat())):
        return False
    before = database_path.stat()
    if before.st_size < 4 * min(_BOLT_PAGE_SIZES):
        return False
    candidates = []
    with database_path.open('rb') as stream:
        if _file_identity(before) != _file_identity(os.fstat(stream.fileno())):
            return False
        # Page zero can be damaged independently. Find page one's valid meta
        # using the bounded supported page sizes rather than trusting page zero.
        for page_id, offset in ((0, 0), *((1, size) for size in _BOLT_PAGE_SIZES)):
            stream.seek(offset)
            data = stream.read(80)
            if len(data) != 80:
                continue
            identity, flags, count, overflow = struct.unpack_from('<QHHI', data)
            fields = struct.unpack_from('<IIIIQQQQQQ', data, 16)
            magic, version, size, _, root, _, freelist, highwater, transaction, checksum = fields
            if (identity != page_id or flags != 4 or count != 0 or overflow != 0
                    or magic != _BOLT_MAGIC or version != _BOLT_FORMAT_VERSION
                    or size not in _BOLT_PAGE_SIZES or page_id == 1 and offset != size
                    or checksum != _fnv64a(data[16:72]) or highwater < 4
                    or highwater * size > before.st_size or not 2 <= root < highwater
                    or freelist != 0xFFFFFFFFFFFFFFFF and not 2 <= freelist < highwater):
                continue
            candidates.append((transaction, size, root, highwater))
        if not candidates:
            return False
        _, size, root, highwater = max(candidates)
        stream.seek(root * size)
        data = stream.read(16)
        if len(data) != 16:
            return False
        identity, flags, count, overflow = struct.unpack('<QHHI', data)
        if (identity != root or flags not in {1, 2} or count == 0
                or root + overflow >= highwater or 16 + count * 16 > size * (overflow + 1)):
            return False
        # Validate the first directory entry's key bounds, without walking its
        # buckets or loading the large vulnerability database into memory.
        entry = stream.read(16)
        if len(entry) != 16:
            return False
        if flags == 2:
            _, position, key_size, value_size = struct.unpack('<IIII', entry)
            bounded = 16 + position + key_size + value_size <= size * (overflow + 1)
        else:
            position, key_size, child_page = struct.unpack('<IIQ', entry)
            bounded = (16 + position + key_size <= size * (overflow + 1)
                and 2 <= child_page < highwater)
        if key_size == 0 or position < count * 16 or not bounded:
            return False
        if _file_identity(before) != _file_identity(os.fstat(stream.fileno())):
            return False
    return _file_identity(before) == _file_identity(database_path.stat())


def _database(manager, failures, stage):
    status, freshness = ToolStatus.BROKEN.value, 'UNKNOWN'
    try:
        checkpoint()
        status = _status(manager.database_status())
    except ScanCancelled:
        raise
    except Exception as exc:
        _failure(failures, stage, 'vulnerability_db', exc)
    try:
        checkpoint()
        value = manager.database_freshness()
        reported = value.get('status') if isinstance(value, dict) else None
        freshness = reported if reported in _FRESHNESS else 'UNKNOWN'
    except ScanCancelled:
        raise
    except Exception as exc:
        _failure(failures, stage, 'vulnerability_db', exc)
    if status == ToolStatus.READY:
        try:
            checkpoint()
            if not _database_readable(manager):
                status = ToolStatus.BROKEN.value
        except ScanCancelled:
            raise
        except Exception as exc:
            status = ToolStatus.BROKEN.value
            _failure(failures, stage, 'vulnerability_db', exc)
    return {'status': status, 'freshness': freshness,
        'ready': status == ToolStatus.READY and freshness == 'FRESH',
        'cached_usable': status == ToolStatus.READY}


def _message(tools, database, *, offline, ready):
    if ready:
        return '代码、密钥和依赖检查已准备完成，漏洞数据在有效期内。'
    notes = []
    for name, component in tools.items():
        if not component['ready']:
            notes.append(_LABELS[name] + ('组件版本不兼容。'
                if component['status'] == ToolStatus.VERSION_MISMATCH else '尚未准备完成。'))
    if not database['ready']:
        if database['status'] == ToolStatus.BROKEN:
            notes.append('漏洞数据无法正常读取或格式不兼容，需重新准备。')
        elif database['freshness'] == 'STALE':
            notes.append('漏洞数据已过期，本次更新未完成。')
        elif database['freshness'] == 'UNKNOWN':
            notes.append('暂时无法确认漏洞数据是否在有效期内。')
        else:
            notes.append('漏洞数据尚未准备完成。')
        if database['cached_usable']:
            notes.append('已有漏洞数据已保留，依赖检查的覆盖可能不完整。')
    if offline:
        notes.append('当前离线，无法补齐所需组件或更新漏洞数据。')
    return '安全检查尚未全部准备完成。' + ''.join(notes)


def _receipt(tools, database, failures, *, offline):
    ready = all(component['ready'] for component in tools.values()) and database['ready']
    usable = any(component['ready'] for component in tools.values()) or database['cached_usable']
    return {'contract': CONTRACT, 'status': 'READY' if ready else 'PARTIAL' if usable else 'UNAVAILABLE',
        'ready': ready, 'message': _message(tools, database, offline=offline, ready=ready),
        'network_allowed': not offline, 'tools': tools, 'vulnerability_db': database,
        'failures': failures}


def prepare_installation_readiness(*, progress=None, manager=None, offline=False):
    """Reuse compatible tools; repair missing tools and refresh public data online.

    Explicit offline mode is resolve-only, including Python-based engines: even
    an external no-index package registration cannot start an installation.
    Cancellation remains cancellation; other failures are independently recorded
    with fixed stages and exception types, never exception text or source paths.
    """
    with _quiet_preparation_logs():
        return _prepare_installation_readiness(progress=progress, manager=manager, offline=offline)


def _prepare_installation_readiness(*, progress=None, manager=None, offline=False):
    offline = bool(offline)
    failures = []
    _report(progress, 'INSTALL_TOOLS')
    if manager is None:
        try:
            checkpoint()
            manager = ToolManager()
        except ScanCancelled:
            raise
        except Exception as exc:
            for name in CORE_TOOLS:
                _failure(failures, 'INSTALL_TOOLS', name, exc)
            tools = {name: _component(None, VERSIONS[name]) for name in CORE_TOOLS}
            database = {'status': 'BROKEN', 'freshness': 'UNKNOWN', 'ready': False,
                'cached_usable': False}
            _report(progress, 'INSTALL_DATA')
            _report(progress, 'VERIFY_SCAN_READINESS')
            return _receipt(tools, database, failures, offline=offline)

    tools, resolved = {}, {}
    for name in CORE_TOOLS:
        try:
            expected = _version(manager.versions.get(name, VERSIONS[name])) or VERSIONS[name]
        except ScanCancelled:
            raise
        except Exception as exc:
            expected = VERSIONS[name]
            _failure(failures, 'INSTALL_TOOLS', name, exc)
        current = None
        try:
            checkpoint()
            current = manager.resolve(name)
        except ScanCancelled:
            raise
        except Exception as exc:
            _failure(failures, 'INSTALL_TOOLS', name, exc)
        if not _component(current, expected)['ready'] and not offline:
            try:
                checkpoint()
                current = manager.ensure(name, offline=False)
            except ScanCancelled:
                raise
            except Exception as exc:
                _failure(failures, 'INSTALL_TOOLS', name, exc)
        tools[name] = _component(current, expected)
        resolved[name] = current

    _report(progress, 'INSTALL_DATA')
    database = _database(manager, failures, 'INSTALL_DATA')
    if not database['ready'] and tools['trivy']['ready'] and not offline:
        try:
            checkpoint()
            manager.prepare_trivy_database(resolved['trivy'].path, offline=False,
                force=database['status'] == ToolStatus.BROKEN,
                validate_database=validate_database_directory)
        except ScanCancelled:
            raise
        except Exception as exc:
            _failure(failures, 'INSTALL_DATA', 'vulnerability_db', exc)

    # Verify what is available now. A downloader may return READY after retaining
    # an expired previous database, so its return code is deliberately not proof.
    _report(progress, 'VERIFY_SCAN_READINESS')
    for name in CORE_TOOLS:
        try:
            checkpoint()
            current = manager.resolve(name)
        except ScanCancelled:
            raise
        except Exception as exc:
            current = None
            _failure(failures, 'VERIFY_SCAN_READINESS', name, exc)
        tools[name] = _component(current, tools[name]['expected_version'])
    database = _database(manager, failures, 'VERIFY_SCAN_READINESS')
    return _receipt(tools, database, failures, offline=offline)


def validate_readiness_receipt(value):
    """Check a child version's receipt without assuming the parent's tool pins."""
    try:
        return _validate_readiness_receipt(value)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        return False


def _validate_readiness_receipt(value):
    if not isinstance(value, dict) or set(value) != {'contract', 'status', 'ready',
            'message', 'network_allowed', 'tools', 'vulnerability_db', 'failures'}:
        return False
    if (value['contract'] != CONTRACT or value['status'] not in {'READY', 'PARTIAL', 'UNAVAILABLE'}
            or type(value['ready']) is not bool or type(value['network_allowed']) is not bool
            or not isinstance(value['message'], str) or len(value['message']) > 1_000):
        return False
    tools = value['tools']
    if not isinstance(tools, dict) or set(tools) != set(CORE_TOOLS):
        return False
    for component in tools.values():
        if not isinstance(component, dict) or set(component) != {'status', 'version', 'expected_version', 'ready'}:
            return False
        if (component['status'] not in _TOOL_STATUSES or type(component['ready']) is not bool
                or not isinstance(component['expected_version'], str)
                or _VERSION.fullmatch(component['expected_version']) is None
                or not isinstance(component['version'], str)
                or component['version'] and _VERSION.fullmatch(component['version']) is None):
            return False
        expected_ready = component['status'] == 'READY' and component['version'] == component['expected_version']
        if component['ready'] != expected_ready or component['status'] == 'READY' and not expected_ready:
            return False
    database = value['vulnerability_db']
    if not isinstance(database, dict) or set(database) != {'status', 'freshness', 'ready', 'cached_usable'}:
        return False
    if (database['status'] not in _TOOL_STATUSES or database['freshness'] not in _FRESHNESS
            or type(database['ready']) is not bool or type(database['cached_usable']) is not bool
            or database['cached_usable'] != (database['status'] == 'READY')
            or database['ready'] != (database['status'] == 'READY' and database['freshness'] == 'FRESH')):
        return False
    failures = value['failures']
    if not isinstance(failures, list) or len(failures) > 20:
        return False
    for failure in failures:
        if (not isinstance(failure, dict) or set(failure) != {'stage', 'component', 'exception_type'}
                or failure['stage'] not in _STAGES or failure['component'] not in {*CORE_TOOLS, 'vulnerability_db'}
                or failure['exception_type'] not in _EXCEPTION_TYPES):
            return False
    ready = all(component['ready'] for component in tools.values()) and database['ready']
    usable = any(component['ready'] for component in tools.values()) or database['cached_usable']
    status = 'READY' if ready else 'PARTIAL' if usable else 'UNAVAILABLE'
    return value['ready'] == ready and value['status'] == status
