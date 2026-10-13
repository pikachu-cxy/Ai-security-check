"""Official source fallback and staged activation regressions; no network."""
from pathlib import Path

import pytest

from security_runtime.preparation_budget import preparation_budget
from security_runtime.processes import ProcessIdleTimeout, ProcessResult
from security_runtime.toolchain import ToolStatus
from test_preparation_download import database


GHCR = 'ghcr.io/aquasecurity/trivy-db:2'
MIRROR = 'mirror.gcr.io/aquasec/trivy-db:2'


def _repository(arguments):
    assert '--db-repository' in arguments, 'Each attempt must select one official source'
    index = arguments.index('--db-repository')
    value = arguments[index + 1]
    assert value in {GHCR, MIRROR}, 'Only the fixed official DB sources are allowed'
    assert arguments.count('--db-repository') == 1
    return value


def _staging(arguments):
    return Path(arguments[arguments.index('--cache-dir') + 1]) / 'db'


def _bytes(directory):
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def test_idle_primary_falls_back_and_activates_valid_fresh_database(database, monkeypatch):
    manager, cache, before, write = database
    sources, events = [], []

    def execute(arguments, **options):
        options.pop('env', None)  # Never include inherited environment in assertion output.
        source = _repository(arguments)
        sources.append(source)
        assert 0 < options['timeout'] <= 30
        if source == GHCR:
            raise ProcessIdleTimeout('simulated primary idle')
        assert _bytes(cache / 'db') == before, 'Old cache stays active until validation'
        write(_staging(arguments), fresh=True)
        return ProcessResult(0, '', '', 1)

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    with preparation_budget(30, progress=events.append):
        status = manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True)

    assert status == ToolStatus.READY
    assert sources == [GHCR, MIRROR], 'Default preparation tries each source once'
    assert manager.database_freshness()['status'] == 'FRESH'
    assert (cache / 'db' / 'metadata.json').read_bytes() != before['metadata.json']
    assert any(event['event'] == 'DOWNLOAD_STARTED' and event.get('source') == 'ghcr.io' for event in events)
    assert any(event['event'] == 'DOWNLOAD_FALLBACK' and event.get('source') == 'mirror.gcr.io' for event in events)
    assert any(event['event'] == 'DOWNLOAD_COMPLETE' and event.get('source') == 'mirror.gcr.io' for event in events)


@pytest.mark.parametrize('retries', [0, 1])
def test_failed_sources_preserve_cached_bytes_and_limit_attempts(database, monkeypatch, retries):
    manager, cache, before, _ = database
    sources = []

    def execute(arguments, **options):
        options.pop('env', None)
        sources.append(_repository(arguments))
        raise ProcessIdleTimeout('simulated download idle')

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    with preparation_budget(30, retries=retries):
        status = manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True)

    assert status == ToolStatus.READY, 'READY here means retained valid cached data only'
    assert sources == [GHCR, MIRROR] * (1 + retries)
    assert _bytes(cache / 'db') == before
    assert manager.database_freshness()['status'] == 'STALE'
    assert manager.data_diagnostics['vulnerability_db'].error_code == 'VULNERABILITY_DB_STALE'


def test_unreadable_old_cache_is_not_usable_after_download_failure(database, monkeypatch):
    manager, cache, _, _ = database
    (cache / 'db' / 'trivy.db').write_bytes(b'invalid old database')
    before = _bytes(cache / 'db')
    monkeypatch.setattr('security_runtime.toolchain.run_process',
        lambda *args, **options: ProcessResult(1, '', 'unexpected EOF', 1))
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)

    with preparation_budget(30):
        status = manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: False)

    assert status == ToolStatus.BROKEN
    assert _bytes(cache / 'db') == before, 'An unreadable old cache still must not be destroyed'


def test_complete_transfer_disables_network_idle_without_resetting_total_budget(database, monkeypatch):
    manager, _, _, write = database
    clock = [100.0]
    seen_timeouts = []
    monkeypatch.setattr('security_runtime.toolchain.time.monotonic', lambda: clock[0])

    def execute(arguments, **options):
        options.pop('env', None)
        seen_timeouts.append(options['timeout'])
        assert 0 < options['timeout'] <= 5, 'Total preparation budget bounds extraction too'
        options['on_stderr_line']('10.00 MiB / 10.00 MiB [================] 100%')
        clock[0] += 2
        activity = options.get('activity_clock')
        last_activity = activity() if activity is not None else None
        idle_limit = options.get('idle_timeout')
        assert (idle_limit is None or last_activity is None or clock[0] - last_activity < idle_limit), (
            'After verified 100% transfer, extraction must not be killed by network idle')
        write(_staging(arguments), fresh=True)
        return ProcessResult(0, '', '', 1)

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(5, idle_seconds=1):
        assert manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True) == ToolStatus.READY
    assert seen_timeouts


def test_complete_progress_with_error_exit_cannot_activate_database(database, monkeypatch):
    manager, cache, before, write = database

    def execute(arguments, **options):
        options.pop('env', None)
        options['on_stderr_line']('10.00 MiB / 10.00 MiB [================] 100%')
        write(_staging(arguments), fresh=True)
        return ProcessResult(1, '', 'unexpected EOF', 1)

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    with preparation_budget(30):
        manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True)
    assert _bytes(cache / 'db') == before
    assert manager.database_freshness()['status'] == 'STALE'


def test_failed_candidate_promotion_restores_previous_database(database, monkeypatch):
    manager, cache, before, write = database
    import security_runtime.toolchain as toolchain
    original_replace = toolchain.os.replace
    promotion_failures, restorations = [], []

    def execute(arguments, **options):
        options.pop('env', None)
        write(_staging(arguments), fresh=True)
        return ProcessResult(0, '', '', 1)

    def replace(source, destination):
        source, destination = Path(source), Path(destination)
        if destination == cache / 'db' and source.name == 'db' and source.parent.name.startswith('db-update-'):
            promotion_failures.append(source)
            raise OSError('simulated second replace failure')
        if destination == cache / 'db' and source.name == 'previous-db':
            restorations.append(source)
        return original_replace(source, destination)

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    monkeypatch.setattr(toolchain.os, 'replace', replace)
    with preparation_budget(30):
        manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True)

    assert promotion_failures and len(restorations) == len(promotion_failures)
    assert _bytes(cache / 'db') == before
    assert manager.database_freshness()['status'] == 'STALE'
    assert not list(cache.glob('db-update-*'))


def test_fallback_uses_remaining_total_budget(database, monkeypatch):
    manager, _, _, write = database
    clock, sources, limits = [100.0], [], []
    monkeypatch.setattr('security_runtime.toolchain.time.monotonic', lambda: clock[0])
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)

    def execute(arguments, **options):
        options.pop('env', None)
        source = _repository(arguments)
        sources.append(source)
        limits.append(options['timeout'])
        if source == GHCR:
            clock[0] += 7
            raise ProcessIdleTimeout('simulated primary idle')
        assert 0 < options['timeout'] <= 3, 'Fallback cannot renew the overall budget'
        write(_staging(arguments), fresh=True)
        return ProcessResult(0, '', '', 1)

    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(10):
        assert manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True) == ToolStatus.READY
    assert sources == [GHCR, MIRROR]
    assert limits[1] < limits[0]
