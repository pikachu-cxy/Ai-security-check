"""Installation readiness proves tools and current data, without project work."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import inspect
import json
import logging
import struct
import threading
from types import SimpleNamespace

import pytest

from security_runtime.install_readiness import (
    CORE_TOOLS, TRIVY_DATABASE_SCHEMA_VERSION, prepare_installation_readiness,
    validate_readiness_receipt, validate_database_directory, _fnv64a,
)
from security_runtime.progress import ProgressReporter, ScanCancelled, progress_context
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolSource, ToolStatus, VERSIONS


def resolved(name, *, status=ToolStatus.READY, version=None, path=None):
    return ResolvedTool(name, VERSIONS[name] if version is None else version,
        f'/isolated/cache/{name}' if path is None else path, ToolSource.MANAGED, status)


def bolt_database():
    """Synthetic format-only fixture; no real advisory content is claimed."""
    size = 4096
    data = bytearray(4 * size)
    for page_id in (0, 1):
        offset = page_id * size
        struct.pack_into('<QHHI', data, offset, page_id, 4, 0, 0)
        meta = struct.pack('<IIIIQQQQQ', 0xED0CDAED, 2, size, 0, 3, 0, 2, 4, page_id)
        data[offset + 16:offset + 72] = meta
        struct.pack_into('<Q', data, offset + 72, _fnv64a(meta))
    struct.pack_into('<QHHI', data, 2 * size, 2, 16, 0, 0)
    struct.pack_into('<QHHI', data, 3 * size, 3, 2, 1, 0)
    key = b'vulnerability'
    struct.pack_into('<IIII', data, 3 * size + 16, 1, 16, len(key), 16)
    data[3 * size + 32:3 * size + 32 + len(key)] = key
    return bytes(data)


class Manager:
    def __init__(self, *, freshness='FRESH', missing=(), refresh_to='FRESH'):
        self.versions = dict(VERSIONS)
        self.tools = {name: resolved(name, status=ToolStatus.MISSING, version='', path='')
            if name in missing else resolved(name) for name in CORE_TOOLS}
        self.freshness = freshness
        self.refresh_to = refresh_to
        self.calls = []
        self.ensure_errors = {}
        self.resolve_errors = {}
        self.database_error = None
        self.database_validators = []
        directory = self.database_root / 'db'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'metadata.json').write_text(json.dumps({'Version': TRIVY_DATABASE_SCHEMA_VERSION}), encoding='utf-8')
        (directory / 'trivy.db').write_bytes(bolt_database())

    def trivy_cache_dir(self):
        return self.database_root

    def resolve(self, name):
        self.calls.append(('resolve', name))
        error = self.resolve_errors.get(name)
        if error:
            raise error
        return self.tools[name]

    def ensure(self, name, *, offline=None):
        self.calls.append(('ensure', name, offline))
        error = self.ensure_errors.get(name)
        if error:
            raise error
        self.tools[name] = resolved(name)
        return self.tools[name]

    def database_status(self):
        self.calls.append(('database_status',))
        return ToolStatus.MISSING if self.freshness == 'MISSING' else ToolStatus.READY

    def database_freshness(self):
        self.calls.append(('database_freshness',))
        return {'status': self.freshness}

    def prepare_trivy_database(self, binary, *, offline=None, force=False, validate_database=None):
        self.calls.append(('prepare_trivy_database', binary, offline, force))
        self.database_validators.append(validate_database)
        if self.database_error:
            raise self.database_error
        self.freshness = self.refresh_to
        return ToolStatus.READY


@pytest.fixture(autouse=True)
def manager_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(Manager, 'database_root', tmp_path / 'fake-cache', raising=False)


def assert_valid(receipt):
    assert validate_readiness_receipt(receipt) is True
    assert all(name not in receipt['message'] for name in (*CORE_TOOLS, 'READY', 'PARTIAL', 'STALE', 'FRESH'))
    assert 'network_query' not in receipt


def test_valid_tools_and_fresh_data_reused_without_download():
    manager = Manager()
    stages = []
    receipt = prepare_installation_readiness(manager=manager, progress=stages.append)
    assert receipt['status'] == 'READY'
    assert receipt['ready'] is True
    assert receipt['network_allowed'] is True  # Permission, not invented network evidence.
    assert stages == ['INSTALL_TOOLS', 'INSTALL_DATA', 'VERIFY_SCAN_READINESS']
    assert not any(call[0] in {'ensure', 'prepare_trivy_database'} for call in manager.calls)
    assert {call[1] for call in manager.calls if call[0] == 'resolve'} == set(CORE_TOOLS)
    assert_valid(receipt)


def test_version_mismatch_replaced_by_supported_version():
    manager = Manager()
    manager.tools['gitleaks'] = resolved('gitleaks', status=ToolStatus.VERSION_MISMATCH, version='9.0.0')
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is True
    assert ('ensure', 'gitleaks', False) in manager.calls
    assert not any(call[0] == 'ensure' and call[1] != 'gitleaks' for call in manager.calls)
    assert receipt['tools']['gitleaks']['version'] == VERSIONS['gitleaks']
    assert_valid(receipt)


@pytest.mark.parametrize('source,offline,install', [
    (ToolSource.SYSTEM, False, True),
    (ToolSource.SYSTEM, True, False),
    (ToolSource.EXPLICIT, False, False),
    (ToolSource.MANAGED, False, False),
])
def test_readiness_only_prepares_unverified_system_semgrep_online(source, offline, install):
    from security_runtime.component_health import diagnosis
    manager = Manager()
    problem = diagnosis('COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE')
    manager.tools['semgrep'] = ResolvedTool('semgrep', VERSIONS['semgrep'], '/external/semgrep',
        source, ToolStatus.BROKEN, problem.error_summary, problem)
    receipt = prepare_installation_readiness(manager=manager, offline=offline)
    assert receipt['ready'] is install
    assert (('ensure', 'semgrep', False) in manager.calls) is install
    assert validate_readiness_receipt(receipt)
    if not install:
        assert receipt['tools']['semgrep']['diagnostic']['code'] == problem.error_code


@pytest.mark.parametrize('freshness', ['STALE', 'UNKNOWN', 'MISSING'])
def test_non_current_data_refreshed_online(freshness):
    manager = Manager(freshness=freshness)
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is True
    assert receipt['vulnerability_db']['freshness'] == 'FRESH'
    assert ('prepare_trivy_database', '/isolated/cache/trivy', False, False) in manager.calls
    assert_valid(receipt)


@pytest.mark.parametrize('freshness', ['STALE', 'UNKNOWN'])
def test_database_ready_return_does_not_prove_current_data(freshness):
    manager = Manager(freshness=freshness, refresh_to=freshness)
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is False
    assert receipt['status'] == 'PARTIAL'
    assert receipt['vulnerability_db']['cached_usable'] is True
    assert receipt['vulnerability_db']['freshness'] == freshness
    assert '已有漏洞数据已保留' in receipt['message']
    assert_valid(receipt)


def test_failed_refresh_retains_cached_data_and_omits_exception_text():
    manager = Manager(freshness='STALE')
    manager.database_error = TimeoutError('secret-token and arbitrary scanner output')
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['status'] == 'PARTIAL'
    assert receipt['vulnerability_db']['cached_usable'] is True
    assert receipt['failures'] == [{'stage': 'INSTALL_DATA', 'component': 'vulnerability_db',
        'exception_type': 'TimeoutError'}]
    assert 'secret-token' not in json.dumps(receipt)
    assert_valid(receipt)


@pytest.mark.parametrize('freshness', ['STALE', 'UNKNOWN', 'MISSING'])
def test_offline_path_never_calls_installers_or_downloaders(freshness):
    manager = Manager(freshness=freshness, missing=('gitleaks',))
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is False
    assert receipt['network_allowed'] is False
    assert not any(call[0] in {'ensure', 'prepare_trivy_database'} for call in manager.calls)
    assert '仅核对本地组件和缓存' in receipt['message']
    assert_valid(receipt)


def test_fully_current_offline_cache_is_ready():
    manager = Manager()
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is True
    assert receipt['network_allowed'] is False
    assert not any(call[0] in {'ensure', 'prepare_trivy_database'} for call in manager.calls)
    assert_valid(receipt)


def test_all_tools_missing_and_no_database_are_unavailable_offline():
    manager = Manager(freshness='MISSING', missing=CORE_TOOLS)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['status'] == 'UNAVAILABLE'
    assert receipt['ready'] is False
    assert not any(call[0] in {'ensure', 'prepare_trivy_database'} for call in manager.calls)
    assert_valid(receipt)


def test_one_tool_failure_does_not_skip_remaining_preparation():
    manager = Manager(freshness='MISSING', missing=CORE_TOOLS)
    manager.ensure_errors['semgrep'] = PermissionError('private-path')
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['status'] == 'PARTIAL'
    assert receipt['tools']['semgrep']['ready'] is False
    assert receipt['tools']['gitleaks']['ready'] is True
    assert receipt['tools']['trivy']['ready'] is True
    assert receipt['vulnerability_db']['ready'] is True
    assert ('ensure', 'gitleaks', False) in manager.calls
    assert ('ensure', 'trivy', False) in manager.calls
    assert 'private-path' not in json.dumps(receipt)
    assert_valid(receipt)


def test_final_verification_detects_tool_removed_after_data_update():
    manager = Manager(freshness='MISSING')
    original = manager.prepare_trivy_database
    def prepare(*args, **kwargs):
        result = original(*args, **kwargs)
        manager.tools['trivy'] = resolved('trivy', status=ToolStatus.MISSING, version='', path='')
        return result
    manager.prepare_trivy_database = prepare
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is False
    assert receipt['status'] == 'PARTIAL'
    assert receipt['vulnerability_db']['ready'] is True
    assert receipt['tools']['trivy']['ready'] is False
    assert_valid(receipt)


def test_resolve_exception_is_safe_and_other_components_are_prepared():
    class PrivateCredentialError(Exception):
        pass
    manager = Manager(freshness='MISSING', missing=('gitleaks',))
    manager.resolve_errors['semgrep'] = PrivateCredentialError('source-code')
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is False
    assert receipt['tools']['gitleaks']['ready'] is True
    assert all(failure['exception_type'] == 'OtherException' for failure in receipt['failures'])
    assert 'PrivateCredentialError' not in json.dumps(receipt)
    assert 'source-code' not in json.dumps(receipt)
    assert_valid(receipt)


def test_real_stale_cache_preserved_when_database_download_fails(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    manager = ToolManager(root=tmp_path / 'product-cache', now=lambda: now)
    db_dir = manager.root / 'cache' / 'trivy' / 'db'
    db_dir.mkdir(parents=True)
    (db_dir / 'trivy.db').write_bytes(bolt_database())
    metadata = {'Version': TRIVY_DATABASE_SCHEMA_VERSION, 'UpdatedAt': (now - timedelta(days=2)).isoformat(),
        'NextUpdate': (now - timedelta(days=1)).isoformat()}
    (db_dir / 'metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    before = {path.name: path.read_bytes() for path in db_dir.iterdir()}
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(name))
    monkeypatch.setattr(manager, 'ensure', lambda *args, **kwargs: pytest.fail('valid cache must be reused'))
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stderr='download connection failed'))
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    with progress_context(ProgressReporter()):
        receipt = prepare_installation_readiness(manager=manager)
    assert receipt['status'] == 'PARTIAL'
    assert receipt['vulnerability_db']['freshness'] == 'STALE'
    assert {path.name: path.read_bytes() for path in db_dir.iterdir()} == before
    assert_valid(receipt)


def test_real_fresh_database_reused_without_network_or_rewrite(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    manager = ToolManager(root=tmp_path / 'product-cache', now=lambda: now)
    db_dir = manager.root / 'cache' / 'trivy' / 'db'
    db_dir.mkdir(parents=True)
    (db_dir / 'trivy.db').write_bytes(bolt_database())
    (db_dir / 'metadata.json').write_text(json.dumps({
        'Version': TRIVY_DATABASE_SCHEMA_VERSION,
        'UpdatedAt': (now - timedelta(hours=2)).isoformat(),
        'NextUpdate': (now + timedelta(hours=2)).isoformat()}), encoding='utf-8')
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in db_dir.iterdir()}
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(name))
    monkeypatch.setattr(manager, 'ensure', lambda *args, **kwargs: pytest.fail('valid tools must be reused'))
    monkeypatch.setattr(manager, 'prepare_trivy_database', lambda *args, **kwargs: pytest.fail('fresh data must be reused'))
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['status'] == 'READY'
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in db_dir.iterdir()} == before
    assert_valid(receipt)


@pytest.mark.parametrize('schema', [None, True, 1, 3, '2'])
def test_fresh_metadata_with_incompatible_schema_is_not_ready_offline(schema):
    manager = Manager()
    (manager.trivy_cache_dir() / 'db' / 'metadata.json').write_text(json.dumps({'Version': schema}), encoding='utf-8')
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['status'] == 'PARTIAL' and receipt['ready'] is False
    assert receipt['vulnerability_db'] == {'status': 'BROKEN', 'freshness': 'FRESH',
        'ready': False, 'cached_usable': False}
    assert '漏洞数据无法正常读取或格式不兼容' in receipt['message']
    assert '漏洞数据已过期' not in receipt['message']
    assert not any(call[0] == 'prepare_trivy_database' for call in manager.calls)
    assert_valid(receipt)


@pytest.mark.parametrize('contents', [b'', b'not-a-database', bolt_database()[:8192]],
    ids=['empty', 'invalid', 'truncated'])
def test_empty_invalid_or_truncated_fresh_database_not_ready(contents):
    manager = Manager()
    (manager.trivy_cache_dir() / 'db' / 'trivy.db').write_bytes(contents)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is False
    assert receipt['vulnerability_db']['status'] == 'BROKEN'
    assert receipt['vulnerability_db']['cached_usable'] is False
    assert_valid(receipt)


def test_bad_bolt_meta_checksum_is_not_ready():
    manager = Manager()
    contents = bytearray(bolt_database())
    contents[72] ^= 1
    contents[4096 + 72] ^= 1
    (manager.trivy_cache_dir() / 'db' / 'trivy.db').write_bytes(contents)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is False
    assert receipt['vulnerability_db']['status'] == 'BROKEN'
    assert_valid(receipt)


def test_one_bad_meta_page_uses_the_other_valid_meta():
    manager = Manager()
    contents = bytearray(bolt_database())
    contents[16] ^= 1
    (manager.trivy_cache_dir() / 'db' / 'trivy.db').write_bytes(contents)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is True
    assert_valid(receipt)


def test_valid_meta_with_corrupt_root_header_is_not_ready():
    manager = Manager()
    contents = bytearray(bolt_database())
    contents[3 * 4096 + 8] = 4
    (manager.trivy_cache_dir() / 'db' / 'trivy.db').write_bytes(contents)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['ready'] is False
    assert receipt['vulnerability_db']['status'] == 'BROKEN'
    assert_valid(receipt)


def test_invalid_fresh_cache_forces_download_and_revalidates():
    manager = Manager()
    path = manager.trivy_cache_dir() / 'db' / 'trivy.db'
    path.write_bytes(b'corrupted')
    original = manager.prepare_trivy_database
    def repair(*args, **kwargs):
        result = original(*args, **kwargs)
        path.write_bytes(bolt_database())
        return result
    manager.prepare_trivy_database = repair
    receipt = prepare_installation_readiness(manager=manager)
    assert ('prepare_trivy_database', '/isolated/cache/trivy', False, True) in manager.calls
    assert manager.database_validators == [validate_database_directory]
    assert receipt['ready'] is True
    assert_valid(receipt)


def test_invalid_fresh_cache_still_not_ready_after_downloader_ready_return():
    manager = Manager()
    path = manager.trivy_cache_dir() / 'db' / 'trivy.db'
    path.write_bytes(b'corrupted')
    receipt = prepare_installation_readiness(manager=manager)
    assert ('prepare_trivy_database', '/isolated/cache/trivy', False, True) in manager.calls
    assert receipt['ready'] is False
    assert path.read_bytes() == b'corrupted'
    assert_valid(receipt)


@pytest.mark.parametrize('corruption', ['schema', 'header'])
def test_invalid_fresh_download_does_not_replace_existing_cached_database(tmp_path, monkeypatch, corruption):
    monkeypatch.delenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    manager = ToolManager(root=tmp_path / 'product-cache', now=lambda: now)
    current = manager.trivy_cache_dir() / 'db'
    current.mkdir(parents=True)
    (current / 'trivy.db').write_bytes(bolt_database())
    (current / 'metadata.json').write_text(json.dumps({
        'Version': TRIVY_DATABASE_SCHEMA_VERSION,
        'UpdatedAt': (now - timedelta(days=2)).isoformat(),
        'NextUpdate': (now - timedelta(days=1)).isoformat()}), encoding='utf-8')
    original = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in current.iterdir()}
    downloads = []
    def download(argv, **kwargs):
        from pathlib import Path
        staging = Path(argv[argv.index('--cache-dir') + 1]) / 'db'
        staging.mkdir(parents=True)
        (staging / 'trivy.db').write_bytes(bolt_database() if corruption == 'schema' else b'invalid-bolt-database')
        (staging / 'metadata.json').write_text(json.dumps({
            'Version': 3 if corruption == 'schema' else TRIVY_DATABASE_SCHEMA_VERSION,
            'UpdatedAt': (now - timedelta(hours=1)).isoformat(),
            'NextUpdate': (now + timedelta(hours=1)).isoformat()}), encoding='utf-8')
        downloads.append(staging)
        assert manager.database_freshness(staging)['status'] == 'FRESH'
        return SimpleNamespace(returncode=0, stderr='')
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(name))
    monkeypatch.setattr(manager, 'ensure', lambda *args, **kwargs: pytest.fail('compatible tools must be reused'))
    monkeypatch.setattr('security_runtime.toolchain.run_process', download)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    receipt = prepare_installation_readiness(manager=manager)
    assert downloads
    assert receipt['ready'] is False and receipt['status'] == 'PARTIAL'
    assert receipt['vulnerability_db']['freshness'] == 'STALE'
    assert receipt['vulnerability_db']['cached_usable'] is True
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in current.iterdir()} == original
    assert not any(path.exists() for path in downloads)
    assert_valid(receipt)


def test_directory_validator_failure_is_closed_and_does_not_mutate(tmp_path):
    missing = tmp_path / 'not-created'
    assert validate_database_directory(missing) is False
    assert not missing.exists()
    assert validate_database_directory(None) is False


def test_manager_initialization_failure_is_safe_and_not_ready(monkeypatch):
    def broken():
        raise ImportError('private module path')
    monkeypatch.setattr('security_runtime.install_readiness.ToolManager', broken)
    stages = []
    receipt = prepare_installation_readiness(progress=stages.append)
    assert receipt['status'] == 'UNAVAILABLE'
    assert receipt['ready'] is False
    assert len(receipt['failures']) == len(CORE_TOOLS)
    assert all(item['exception_type'] == 'ImportError' for item in receipt['failures'])
    assert 'private module path' not in json.dumps(receipt)
    assert stages == ['INSTALL_TOOLS', 'INSTALL_DATA', 'VERIFY_SCAN_READINESS']
    assert_valid(receipt)


def test_real_manager_offline_path_has_no_preparation_side_effect(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    manager = ToolManager(root=tmp_path / 'product-cache')
    monkeypatch.setattr(manager, 'resolve', lambda name: resolved(name, status=ToolStatus.MISSING, version='', path=''))
    monkeypatch.setattr(manager, 'ensure', lambda *args, **kwargs: pytest.fail('offline must not install'))
    monkeypatch.setattr(manager, 'prepare_trivy_database', lambda *args, **kwargs: pytest.fail('offline must not refresh'))
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'requirements.txt').write_text('PyYAML==5.3.1', encoding='utf-8')
    before = (project / 'requirements.txt').read_bytes()
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert receipt['status'] == 'UNAVAILABLE'
    assert not manager.root.exists()
    assert (project / 'requirements.txt').read_bytes() == before
    assert list(inspect.signature(prepare_installation_readiness).parameters) == ['progress', 'manager', 'offline', 'timeout_seconds', 'retries', 'idle_seconds', 'adaptive', 'max_wait_seconds']
    assert_valid(receipt)


def test_cancellation_is_not_turned_into_installation_failure():
    manager = Manager()
    manager.resolve_errors['semgrep'] = ScanCancelled()
    with pytest.raises(ScanCancelled):
        prepare_installation_readiness(manager=manager)


def test_presentation_failure_does_not_change_readiness():
    def broken(_):
        raise RuntimeError('output is unavailable')
    receipt = prepare_installation_readiness(manager=Manager(), progress=broken)
    assert receipt['ready'] is True
    assert_valid(receipt)


def test_preparation_internal_logs_hidden_and_logging_restored(capsys):
    manager = Manager(freshness='MISSING', missing=('semgrep',))
    logger = logging.getLogger('security_runtime.toolchain')
    handler = logging.StreamHandler()
    original_level, original_filters = logger.level, tuple(logger.filters)
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    original = manager.ensure
    def ensure(*args, **kwargs):
        logger.warning('tool_install_failed tool=semgrep reason=PrivateOutput')
        raise PermissionError('private-path')
    manager.ensure = ensure
    try:
        receipt = prepare_installation_readiness(manager=manager)
        print(receipt['message'])
        output = capsys.readouterr()
        assert '代码检查不可用' in output.out and '组件尚未安装' in output.out
        assert receipt['vulnerability_db']['ready'] is True
        assert receipt['ready'] is False and receipt['tools']['semgrep']['ready'] is False
        assert any(item['component'] == 'semgrep' for item in receipt['failures'])
        assert_valid(receipt)
        assert all(value not in output.out + output.err for value in (
            'tool_install_failed', 'semgrep', 'PrivateOutput', 'private-path'))
        assert tuple(logger.filters) == original_filters
        logger.warning('logging-after-preparation')
        assert 'logging-after-preparation' in capsys.readouterr().err
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)
        manager.ensure = original


def test_preparation_log_filter_does_not_suppress_other_threads(capsys):
    manager = Manager(missing=('semgrep',))
    logger = logging.getLogger('security_runtime.toolchain')
    handler = logging.StreamHandler()
    original_level, original_filters = logger.level, tuple(logger.filters)
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    original = manager.ensure
    def ensure(*args, **kwargs):
        logger.warning('private-current-thread-installation')
        thread = threading.Thread(target=lambda: logger.warning('other-thread-MCP-message'))
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
        return original(*args, **kwargs)
    manager.ensure = ensure
    try:
        assert prepare_installation_readiness(manager=manager)['ready']
        output = capsys.readouterr()
        assert 'private-current-thread-installation' not in output.err
        assert 'other-thread-MCP-message' in output.err
        assert tuple(logger.filters) == original_filters
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)


def test_cancellation_removes_only_its_own_log_filter():
    manager = Manager()
    manager.resolve_errors['semgrep'] = ScanCancelled()
    logger = logging.getLogger('security_runtime.toolchain')
    sentinel = logging.Filter()
    logger.addFilter(sentinel)
    before = tuple(logger.filters)
    try:
        with pytest.raises(ScanCancelled):
            prepare_installation_readiness(manager=manager)
        assert tuple(logger.filters) == before
    finally:
        logger.removeFilter(sentinel)


def test_validator_uses_child_expected_versions_instead_of_parent_pins():
    receipt = prepare_installation_readiness(manager=Manager())
    receipt['tools']['trivy']['version'] = '9.99.0'
    receipt['tools']['trivy']['expected_version'] = '9.99.0'
    assert validate_readiness_receipt(receipt) is True


@pytest.mark.parametrize('mutate', [
    lambda receipt: receipt['vulnerability_db'].update(freshness='STALE'),
    lambda receipt: receipt['tools']['trivy'].update(status='MISSING'),
    lambda receipt: receipt['tools']['trivy'].update(version='0.0.0'),
    lambda receipt: receipt.update(status='PARTIAL'),
    lambda receipt: receipt.update(ready=1),
    lambda receipt: receipt.update(network_allowed=1),
    lambda receipt: receipt.update(contract='unknown'),
    lambda receipt: receipt['tools'].pop('gitleaks'),
    lambda receipt: receipt['tools']['trivy'].update(status=[]),
    lambda receipt: receipt['vulnerability_db'].update(freshness={}),
    lambda receipt: receipt.update(failures=[{'stage': 'unexpected', 'component': 'trivy', 'exception_type': 'RuntimeError'}]),
    lambda receipt: receipt.update(failures=[{'stage': 'INSTALL_DATA', 'component': 'trivy', 'exception_type': 'SecretValue'}]),
    lambda receipt: receipt.update(unexpected='not part of the contract'),
])
def test_validator_rejects_inconsistent_or_malformed_receipts(mutate):
    receipt = deepcopy(prepare_installation_readiness(manager=Manager()))
    mutate(receipt)
    assert validate_readiness_receipt(receipt) is False


@pytest.mark.parametrize('available,freshness,code', [
    (False, 'MISSING', 'VULNERABILITY_DB_UNAVAILABLE'),
    (True, 'STALE', 'VULNERABILITY_DB_STALE'),
    (True, 'UNKNOWN', 'VULNERABILITY_DB_FRESHNESS_UNKNOWN'),
])
def test_offline_database_diagnosis_separates_missing_expired_and_unconfirmed(
        tmp_path, monkeypatch, available, freshness, code):
    manager = ToolManager(tmp_path / 'tools')
    monkeypatch.setattr(manager, 'database_status',
        lambda: ToolStatus.READY if available else ToolStatus.MISSING)
    monkeypatch.setattr(manager, 'database_freshness', lambda: {'status': freshness})
    monkeypatch.setattr(manager, '_download_trivy_database',
        lambda *a: pytest.fail('offline preparation must not download'))
    result = manager.prepare_trivy_database('unused-trivy', offline=True)
    assert result == (ToolStatus.READY if available else ToolStatus.OFFLINE)
    diagnostic = manager.data_diagnostics['vulnerability_db']
    assert diagnostic.error_code == code
    assert 'security-check tools install trivy' in diagnostic.remediation
    if freshness == 'UNKNOWN':
        assert 'cannot be verified' in diagnostic.error_summary
        assert 'past' not in diagnostic.error_summary
