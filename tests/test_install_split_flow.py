"""Installation must finish independently of public data download failures."""
import io
import json

import pytest

from security_runtime.cli import main
from security_runtime.diagnostics import classify_network_error
from security_runtime.install_progress import InstallationProgress
import security_runtime.personal_install as personal
from test_personal_install import installed, projects, skill
from test_personal_install_readiness import readiness, mock_prepare


def test_default_install_only_checks_cache_and_keeps_program_installed(installed, monkeypatch):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kw: installed)
    calls = mock_prepare(monkeypatch, readiness(ready=False, freshness='STALE'))
    data = personal.install_personal_codex()
    assert calls[0]['offline'] is True
    assert data['installation']['status'] == 'INSTALLED'
    assert data['installation']['local_files_ready'] is True
    assert data['installation']['scan_ready'] is False
    assert data['overall'] == 'DEGRADED'
    assert data['execution']['network_query'] is False
    assert '后台准备' in data['installation']['message']
    assert data['background_preparation']['status'] == 'QUEUED'


def test_install_exit_success_is_distinct_from_scan_readiness(monkeypatch, capsys):
    data = {'installation': {'local_files_ready': True, 'scan_ready': False,
        'status': 'INSTALLED', 'message': '程序已安装；依赖检查尚未准备完成。'}}
    monkeypatch.setattr(personal, 'install_personal_codex', lambda **kw: data)
    assert main(['install', 'codex', '--json']) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)['installation']['scan_ready'] is False
    assert '扫描能力准备状态' in output.err


def test_download_context_deadline_is_classified_as_timeout():
    error = classify_network_error(stderr='failed to download artifact from mirror.gcr.io/aquasec/trivy-db:2: context deadline exceeded')
    assert error.error_code == 'NETWORK_TIMEOUT'
    assert error.source == 'mirror.gcr.io'


def test_download_progress_is_numeric_and_private_text_is_never_forwarded():
    stream = io.StringIO()
    progress = InstallationProgress(stream=stream)
    progress({'event': 'DOWNLOAD_PROGRESS', 'component': 'vulnerability_db',
        'received_bytes': 10_485_760, 'total_bytes': 104_857_600, 'attempt': 1, 'max_attempts': 1})
    progress.close()  # A redirected stream keeps one final real progress snapshot.
    text = stream.getvalue()
    assert '10.00' in text and '100.00' in text and '10.0%' in text
    progress({'event': 'DOWNLOAD_PROGRESS', 'component': 'vulnerability_db',
        'received_bytes': 99, 'total_bytes': 100, 'private': 'SECRET-IN-OUTPUT'})
    assert 'SECRET-IN-OUTPUT' not in stream.getvalue()


def test_public_preparation_status_never_downloads(monkeypatch, capsys):
    calls = mock_prepare(monkeypatch, readiness(ready=False, freshness='STALE'))
    assert main(['prepare-scanners', '--status', '--json']) == 2
    assert calls[0]['offline'] is True
    assert json.loads(capsys.readouterr().out)['ready'] is False


@pytest.mark.parametrize('command', ['prepare-scanners', 'prepare-installation'])
def test_internal_preparation_receipt_keeps_old_parent_compatibility(monkeypatch, capsys, command):
    data = readiness(ready=True)
    data['preparation'] = dict(budget_seconds=300, elapsed_ms=1, max_attempts=1,
        attempts=1, error_code='', source='ghcr.io', source_attempts=1, sources_attempted=['ghcr.io'],
        adaptive=True, max_wait_seconds=1800)
    mock_prepare(monkeypatch, data)
    assert main([command, '--json']) == 0
    result = json.loads(capsys.readouterr().out)['preparation']
    assert ('sources_attempted' in result) == (command == 'prepare-scanners')
    assert ('source_attempts' in result) == (command == 'prepare-scanners')
    assert ('adaptive' in result) == (command == 'prepare-scanners')
    assert ('max_wait_seconds' in result) == (command == 'prepare-scanners')
    if command == 'prepare-installation':
        assert set(result) == {'budget_seconds', 'elapsed_ms', 'max_attempts', 'attempts', 'error_code', 'source'}


@pytest.mark.parametrize('options,adaptive,maximum', [([], True, 1800),
    (['--max-wait', '600'], True, 600), (['--fixed-timeout'], False, 300),
    (['--status'], False, 300), (['--offline'], False, 300)])
def test_public_preparation_adaptive_policy(monkeypatch, capsys, options, adaptive, maximum):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    calls = mock_prepare(monkeypatch, readiness(ready=True))
    assert main(['prepare-scanners', '--json', *options]) == 0
    assert calls[0]['adaptive'] is adaptive and calls[0]['max_wait_seconds'] == maximum
    assert json.loads(capsys.readouterr().out)['ready'] is True


@pytest.mark.parametrize('options', [['--timeout', '300', '--max-wait', '299'],
    ['--max-wait', '1801'], ['--max-wait', '0']])
def test_public_preparation_rejects_invalid_global_ceiling(monkeypatch, capsys, options):
    calls = mock_prepare(monkeypatch, readiness())
    with pytest.raises(SystemExit) as stopped:
        main(['prepare-scanners', *options])
    assert stopped.value.code == 2 and not calls
    capsys.readouterr()


@pytest.mark.parametrize('payload', [None, [], {'event': []}, {'event': 'DOWNLOAD_FAILED',
    'component': 'vulnerability_db', 'error_code': []}, {'event': 'DOWNLOAD_PROGRESS',
    'component': 'vulnerability_db', 'received_bytes': True, 'total_bytes': 1}])
def test_malformed_progress_cannot_break_install_or_echo_child_text(payload):
    from security_runtime.install_progress import validate_preparation_event
    assert validate_preparation_event(payload) is None
