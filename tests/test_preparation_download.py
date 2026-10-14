"""Bounded download, retry and cache activation regressions; no network."""
from datetime import datetime, timedelta, timezone
import io
import json
import sys
import time

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.install_progress import InstallationProgress, parse_download_progress
from security_runtime.preparation_budget import preparation_budget, bounded_timeout
from security_runtime.processes import run_process, ProcessIdleTimeout, ProcessResult
from security_runtime.toolchain import ToolManager, ToolStatus
from test_install_readiness import bolt_database


@pytest.fixture
def database(tmp_path, monkeypatch):
    # These tests explicitly simulate an online download through a mocked process.
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    cache = tmp_path / 'cache'
    monkeypatch.setenv('SECURITY_RUNTIME_TRIVY_CACHE_DIR', str(cache))
    now = datetime(2026, 10, 13, 4, tzinfo=timezone.utc)
    manager = ToolManager(root=tmp_path / 'tools', now=lambda: now)
    def write(directory, fresh=False):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'trivy.db').write_bytes(bolt_database())
        metadata = dict(Version=2, UpdatedAt=(now - timedelta(days=2)).isoformat(),
            NextUpdate=(now + timedelta(hours=1) if fresh else now - timedelta(days=1)).isoformat())
        (directory / 'metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    write(cache / 'db')
    before = {p.name: p.read_bytes() for p in (cache / 'db').iterdir()}
    return manager, cache, before, write


@pytest.mark.parametrize('line,expected', [
    ('10.86 MiB / 126.98 MiB [--->] 8.55%', (int(10.86 * 1048576), int(126.98 * 1048576))),
    ('\x1b[2K1.00 KiB / 10.00 KiB [>] 10%', (1024, 10240)),
    ('private-token=SECRET', None), ('20.00 MiB / 10.00 MiB [>]', None),
    ('0.00 B / 0.00 B [>]', None), ('NaN MiB / 100.00 MiB [>]', None),
])
def test_parser_only_accepts_real_bounded_transfer_counts(line, expected):
    assert parse_download_progress(line) == expected


def test_carriage_return_progress_arrives_live_and_is_not_raw_receipt_text():
    lines = []
    script = "import sys,time;sys.stderr.write('1.00 MiB / 10.00 MiB [>]\\r');sys.stderr.flush();time.sleep(.2)"
    result = run_process([sys.executable, '-c', script], on_stderr_line=lines.append)
    assert result.returncode == 0 and lines == ['1.00 MiB / 10.00 MiB [>]']


def test_no_progress_terminates_child_promptly():
    started = time.monotonic()
    with pytest.raises(ProcessIdleTimeout):
        run_process([sys.executable, '-c', 'import time;time.sleep(30)'],
            idle_timeout=.2, activity_clock=lambda: started)
    assert time.monotonic() - started < 6


def test_total_budget_limits_nested_process_and_resets_after_exit():
    with preparation_budget(1):
        with pytest.raises(TimeoutError):
            run_process([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=30)
        with pytest.raises(TimeoutError):
            bounded_timeout(30)
    assert bounded_timeout(30) == 30


def test_default_no_blind_retry_and_failure_preserves_old_cache(database, monkeypatch):
    manager, cache, before, _ = database
    calls, events = [], []
    def execute(args, **kwargs):
        calls.append((args, {key: value for key, value in kwargs.items() if key != 'env'}))
        kwargs['on_stderr_line']('10.00 MiB / 100.00 MiB [>] 10%')
        return ProcessResult(1, '', 'failed to download artifact from mirror.gcr.io/aquasec/trivy-db:2: context deadline exceeded', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(30, progress=events.append) as budget:
        assert manager.prepare_trivy_database('trivy.exe') == ToolStatus.READY  # Cached usability only.
        assert budget.attempts == 1 and budget.source_attempts == 2 and budget.error_code == 'NETWORK_TIMEOUT'
    assert len(calls) == 2 and '--quiet' not in calls[0][0] and '--timeout' in calls[0][0]
    sources = [args[args.index('--db-repository') + 1] for args, _ in calls]
    assert len(set(sources)) == 2  # No blind retry of the same source in one round.
    assert 0 < calls[0][1]['timeout'] <= 30
    assert {p.name: p.read_bytes() for p in (cache / 'db').iterdir()} == before
    assert manager.database_freshness()['status'] == 'STALE'
    assert [e['event'] for e in events] == ['DOWNLOAD_STARTED', 'DOWNLOAD_PROGRESS', 'DOWNLOAD_FAILED',
        'DOWNLOAD_FALLBACK', 'DOWNLOAD_STARTED', 'DOWNLOAD_PROGRESS', 'DOWNLOAD_FAILED']


def test_extended_budget_is_used_by_one_attempt_without_a_hidden_five_minute_cap(database, monkeypatch):
    manager, _, _, _ = database
    calls = []
    def execute(args, **kwargs):
        calls.append((args, {key: value for key, value in kwargs.items() if key != 'env'}))
        return ProcessResult(1, '', 'unexpected EOF', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(600):
        manager.prepare_trivy_database('trivy.exe')
    assert len(calls) == 2
    args, options = calls[0]
    assert 590 < options['timeout'] <= 600
    assert 590 < float(args[args.index('--timeout') + 1].removesuffix('s')) <= 600


def test_explicit_retry_reports_attempt_then_success_and_activates_only_valid_data(database, monkeypatch):
    manager, cache, before, write = database
    calls, events = [], []
    def execute(args, **kwargs):
        calls.append(args)
        if len(calls) <= 2:
            return ProcessResult(1, '', 'unexpected EOF', 1)
        write(__import__('pathlib').Path(args[args.index('--cache-dir') + 1]) / 'db', fresh=True)
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    monkeypatch.setattr('security_runtime.toolchain.time.sleep', lambda _: None)
    with preparation_budget(30, retries=1, progress=events.append) as budget:
        assert manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: True) == ToolStatus.READY
        assert budget.attempts == 2 and budget.source_attempts == 3 and not budget.error_code
    assert manager.database_freshness()['status'] == 'FRESH'
    assert any(e['event'] == 'DOWNLOAD_RETRY' and e['attempt'] == 2 for e in events)
    assert events[-1]['event'] == 'DOWNLOAD_COMPLETE'
    assert (cache / 'db' / 'metadata.json').read_bytes() != before['metadata.json']


def test_invalid_success_receipt_never_replaces_cached_database(database, monkeypatch):
    manager, cache, before, write = database
    def execute(args, **kwargs):
        write(__import__('pathlib').Path(args[args.index('--cache-dir') + 1]) / 'db', fresh=True)
        return ProcessResult(0, '', '', 1)
    monkeypatch.setattr('security_runtime.toolchain.run_process', execute)
    with preparation_budget(30):
        manager.prepare_trivy_database('trivy.exe', validate_database=lambda _: False)
    assert {p.name: p.read_bytes() for p in (cache / 'db').iterdir()} == before


def test_concurrent_database_preparation_reports_busy_and_retains_cache(database, monkeypatch):
    manager, cache, before, _ = database
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *a, **k: pytest.fail('duplicate download'))
    locks = HookStateStore(cache / '.update-state')
    events = []
    with locks.lock(cache) as acquired, preparation_budget(30, progress=events.append):
        assert acquired
        assert manager.prepare_trivy_database('trivy.exe') == ToolStatus.READY
    assert events[-1]['error_code'] == 'DOWNLOAD_BUSY'
    assert {p.name: p.read_bytes() for p in (cache / 'db').iterdir()} == before


def test_idle_failure_reports_reason_and_never_replaces_old_cache(database, monkeypatch):
    manager, cache, before, _ = database
    def idle(*a, **k):
        raise ProcessIdleTimeout('private detail')
    monkeypatch.setattr('security_runtime.toolchain.run_process', idle)
    events = []
    with preparation_budget(30, progress=events.append):
        manager.prepare_trivy_database('trivy.exe')
    assert events[-1]['error_code'] == 'DOWNLOAD_STALLED'
    assert 'private' not in json.dumps(events)
    assert {p.name: p.read_bytes() for p in (cache / 'db').iterdir()} == before
