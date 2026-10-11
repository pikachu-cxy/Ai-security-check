from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from security_runtime.toolchain import ToolManager, ToolStatus
from security_runtime.processes import ProcessResult

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def database(directory, *, fresh=True):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'trivy.db').write_bytes(b'fresh-data' if fresh else b'old-data')
    metadata = {'UpdatedAt': (NOW - timedelta(days=2)).isoformat(),
                'NextUpdate': (NOW + timedelta(hours=6) if fresh else NOW - timedelta(days=1)).isoformat()}
    (directory / 'metadata.json').write_text(json.dumps(metadata))


def manager(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', raising=False)
    monkeypatch.delenv('TRIVY_CACHE_DIR', raising=False)
    return ToolManager(tmp_path, now=lambda: NOW)


def test_fresh_database_has_no_network_and_expired_database_refreshes(tmp_path, monkeypatch):
    tools = manager(tmp_path, monkeypatch)
    final = tools.trivy_cache_dir() / 'db'
    database(final)
    calls = []
    def download(argv, **kwargs):
        calls.append(argv)
        staging = Path(argv[argv.index('--cache-dir') + 1])
        assert staging != tools.trivy_cache_dir()
        database(staging / 'db')
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', download)
    assert tools.prepare_trivy_database('trivy.exe') == ToolStatus.READY
    assert not calls
    database(final, fresh=False)
    assert tools.prepare_trivy_database('trivy.exe', offline=False) == ToolStatus.READY
    assert len(calls) == 1 and tools.database_freshness()['status'] == 'FRESH'
    assert (final / 'trivy.db').read_bytes() == b'fresh-data'
    assert not list(tools.trivy_cache_dir().glob('db-update-*'))


def test_failed_refresh_preserves_old_database_and_reports_stale(tmp_path, monkeypatch):
    tools = manager(tmp_path, monkeypatch)
    final = tools.trivy_cache_dir() / 'db'
    database(final, fresh=False)
    before = {p.name: p.read_bytes() for p in final.iterdir()}
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *a, **k: ProcessResult(1, '', 'HTTP 429', 1))
    assert tools.prepare_trivy_database('trivy.exe', offline=False) == ToolStatus.READY
    assert before == {p.name: p.read_bytes() for p in final.iterdir()}
    assert tools.data_diagnostics['vulnerability_db'].error_code == 'VULNERABILITY_DB_STALE'


@pytest.mark.parametrize('present', [True, False])
def test_offline_missing_or_stale_is_explicit_and_never_downloads(tmp_path, monkeypatch, present):
    tools = manager(tmp_path, monkeypatch)
    if present:
        database(tools.trivy_cache_dir() / 'db', fresh=False)
    def forbidden(*args, **kwargs):
        pytest.fail('offline update attempted network')
    monkeypatch.setattr('security_runtime.toolchain.run_process', forbidden)
    assert tools.prepare_trivy_database('trivy.exe', offline=True) == (ToolStatus.READY if present else ToolStatus.OFFLINE)
    assert tools.database_freshness()['status'] == ('STALE' if present else 'MISSING')


def test_missing_timestamp_is_not_considered_fresh(tmp_path, monkeypatch):
    tools = manager(tmp_path, monkeypatch)
    directory = tools.trivy_cache_dir() / 'db'
    database(directory)
    (directory / 'metadata.json').write_bytes(b'{}')
    assert tools.database_freshness()['status'] == 'UNKNOWN'
