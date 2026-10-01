"""Failure semantics, privacy and bounded execution, without remote services."""
import io
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from security_runtime.cli import doctor, main, render
from security_runtime.diagnostics import DiagnosticError, classify_network_error, retry_after, sanitize
from security_runtime.findings import FindingNormalizer
from security_runtime.mcp_server import _agent_result, create_server
from security_runtime.models import RunStatus, ScanContext, ScanMode, ScannerRun
from security_runtime.processes import OutputLimitError, ProcessResult, run_process
from security_runtime.runtime import SecurityRuntime, aggregate_provider_statuses
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter, TrivyAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.target import DiscoveryLimitError, TargetDetector
from security_runtime.toolchain import OfficialReleaseProvider, ResolvedTool, ToolManager, ToolStatus
from security_runtime.workspace import WorkspaceError, WorkspaceResolver


MAVEN_FAILURE = ('INFO documentation https://trivy.dev/latest/docs/scanner\n'
                 'failed to resolve dependencies: GET https://repo.maven.apache.org/maven2/org/example/test.pom: '
                 '429 Too Many Requests\nRetry-After: 1299\nAuthorization: Bearer PRIVATE_AUTH_VALUE\n'
                 'password=PRIVATE_PASSWORD_VALUE\nhttps://user:PRIVATE_URL_PASSWORD@example.org/path?token=PRIVATE_QUERY_VALUE')


@pytest.mark.parametrize('error,code', [
    (URLError(TimeoutError()), 'NETWORK_TIMEOUT'),
    (URLError(ConnectionRefusedError()), 'CONNECTION_REFUSED'),
    (URLError(socket.gaierror()), 'DNS_RESOLUTION_FAILED'),
    (URLError(ssl.SSLError()), 'TLS_ERROR'),
    ('ProxyError: connection failed', 'PROXY_CONNECTION_FAILED'),
    (IncompleteRead(b'private'), 'DOWNLOAD_INTERRUPTED'),
    ('connection reset by peer', 'DOWNLOAD_INTERRUPTED'),
    ('checksum verification failed', 'CHECKSUM_MISMATCH'),
    ('unavailable offline', 'OFFLINE_MODE'),
    ('unknown network failure', 'UNKNOWN_NETWORK_ERROR'),
    (URLError('unknown transport failure'), 'UNKNOWN_NETWORK_ERROR'),
    ('generic local failure', 'SCANNER_FAILED'),
    ('HTTP 401', 'HTTP_401'), ('HTTP 403', 'HTTP_403'), ('HTTP 404', 'HTTP_404'),
    ('HTTP 429', 'HTTP_429'), ('HTTP 500', 'HTTP_5XX'), ('HTTP 503', 'HTTP_5XX'),
    ('HTTP/1.1 429 Too Many Requests', 'HTTP_429'),
    ('401 Client Error: Unauthorized for url', 'HTTP_401'),
])
def test_network_classification(error, code):
    diagnostic = classify_network_error(error)
    assert diagnostic.error_code == code
    assert diagnostic.remediation


def test_retry_after_http_exception():
    error = HTTPError('https://github.com/private?token=PRIVATE_VALUE', 429, 'limit', {'Retry-After': '1299'}, None)
    diagnostic = classify_network_error(error)
    assert diagnostic.retry_after_seconds == 1299
    assert diagnostic.source == 'github.com'
    assert 'PRIVATE_VALUE' not in json.dumps(diagnostic.to_dict())


def test_retry_after_http_date():
    value = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120), usegmt=True)
    assert 118 <= retry_after(value) <= 120
    assert retry_after('not a date') is None


def test_maven_rate_limit_not_database_failure():
    diagnostic = classify_network_error(stderr=MAVEN_FAILURE, return_code=1)
    assert diagnostic.error_code == 'MAVEN_RATE_LIMITED'
    assert diagnostic.source == 'repo.maven.apache.org'
    assert diagnostic.retry_after_seconds == 1299
    assert 'Maven' in diagnostic.error_summary
    assert 'database' not in diagnostic.error_summary.lower()
    assert all(word in diagnostic.remediation for word in ('cache', 'mirror', 'retry'))
    assert 'PRIVATE_' not in json.dumps(diagnostic.to_dict())


@pytest.mark.parametrize('text', [
    'password=PRIVATE_VALUE', 'token: PRIVATE_VALUE', 'api_key="PRIVATE_VALUE"',
    'Authorization: Bearer PRIVATE_VALUE', 'Proxy-Authorization: Basic PRIVATE_VALUE',
    '<password>PRIVATE_VALUE</password>', 'https://user:PRIVATE_VALUE@host.test/a?secret=PRIVATE_VALUE',
    '{"password": "PRIVATE_VALUE", "token": "PRIVATE_VALUE"}',
])
def test_sanitize_secrets(text):
    assert 'PRIVATE_VALUE' not in sanitize(text)


def test_capture_both_streams_without_stdout_pollution(capsys):
    result = run_process([sys.executable, '-c', "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"])
    assert result.return_code == 7 and result.stdout.strip() == 'out' and result.stderr.strip() == 'err'
    assert result.duration_ms >= 0
    assert capsys.readouterr() == ('', '')


def test_process_deadline_kills_child(tmp_path):
    sentinel = tmp_path / 'should-not-exist'
    script = tmp_path / 'child.py'
    script.write_text(f'import time\nfrom pathlib import Path\ntime.sleep(1)\nPath({str(sentinel)!r}).touch()\n')
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        run_process([sys.executable, str(script)], timeout=.1)
    assert time.monotonic() - start < 3
    time.sleep(1.1)
    assert not sentinel.exists()


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_output_bound_kills_process(stream):
    with pytest.raises(OutputLimitError):
        run_process([sys.executable, '-c', f"import sys; sys.{stream}.write('x' * 1000000)"], max_output=1000)


@pytest.mark.parametrize('statuses,expected', [
    (['SUCCESS'], 'EXECUTED'), (['SUCCESS', 'SUCCESS'], 'EXECUTED'),
    (['SUCCESS', 'FAILED'], 'PARTIAL'), (['SUCCESS', 'UNAVAILABLE'], 'PARTIAL'),
    (['SUCCESS', 'TIMEOUT'], 'PARTIAL'), (['FAILED'], 'FAILED'),
    (['FAILED', 'UNAVAILABLE'], 'FAILED'), (['TIMEOUT'], 'FAILED'),
    (['UNAVAILABLE', 'UNAVAILABLE'], 'UNAVAILABLE'), ([], 'UNAVAILABLE'),
])
def test_provider_aggregation(statuses, expected):
    assert aggregate_provider_statuses([ScannerRun('provider', '', status, 0) for status in statuses]) == expected


def mock_registry(root):
    manager = ToolManager(root=root / 'managed')
    manager.ensure = lambda tool: ResolvedTool(tool, 'mock', tool, None, ToolStatus.READY)
    manager.prepare_trivy_database = lambda binary: ToolStatus.READY
    registry = ScannerRegistry(tool_manager=manager)
    def execute(args, cwd, timeout):
        if Path(args[0]).name == 'semgrep':
            return ProcessResult(0, '{"results": []}', '', 1)
        if args[0] == 'gitleaks':
            report = Path(args[args.index('--report-path') + 1])
            report.write_text(json.dumps([{'Description': 'Synthetic secret', 'File': 'application.yml',
                                         'StartLine': 1, 'RuleID': 'synthetic-test'}]))
            return ProcessResult(0, '', '', 1)
        assert args[0] == 'trivy'
        return ProcessResult(1, '', MAVEN_FAILURE, 1)
    return registry, execute


def java_fixture(root):
    (root / 'pom.xml').write_text('<project><modelVersion>4.0.0</modelVersion></project>')
    (root / 'application.yml').write_text('password: synthetic-only\n')
    (root / 'App.java').write_text('class App {}\n')


def test_maven_mock_end_to_end_storage_human_json_mcp(tmp_path, capsys):
    java_fixture(tmp_path)
    registry, execute = mock_registry(tmp_path)
    runtime = SecurityRuntime(registry, SQLiteStore(tmp_path / '.security-runtime' / 'test.db'))
    with patch('security_runtime.scanners._execute', side_effect=execute):
        result = runtime.scan(tmp_path, 'release')
    assert result.status == 'PARTIAL' and result.release_status != 'SAFE'
    assert len(result.findings) == 1
    assert result.capability_results['CODE_SAST'] == 'EXECUTED'
    assert result.capability_results['SECRET_SCAN'] == 'PARTIAL'
    assert result.capability_results['DEPENDENCY_VULN'] == 'FAILED'
    failure = next(run for run in result.scanner_runs if run.scanner == 'trivy')
    assert failure.error_code == 'MAVEN_RATE_LIMITED' and failure.retry_after_seconds == 1299
    human = render(result)
    assert all(value in human for value in ('Secret Security', 'PARTIAL', 'Dependency Security', 'FAILED', '1299', 'remain valid', 'undetected'))
    stored = runtime.store.get_scan(result.scan_id)
    mcp = _agent_result(result)
    assert mcp['scanner_runs'][-1]['error_code'] == 'MAVEN_RATE_LIMITED'
    assert 'PRIVATE_' not in json.dumps([result.to_dict(), stored, mcp, human])
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('configured', [False, True])
def test_first_download_timeout_proxy_flags_only(tmp_path, monkeypatch, configured):
    for name in ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy'):
        monkeypatch.delenv(name, raising=False)
    if configured:
        monkeypatch.setenv('HTTPS_PROXY', 'http://user:PRIVATE_VALUE@proxy.test:8080/?token=PRIVATE_VALUE')
        monkeypatch.setenv('HTTP_PROXY', 'http://user:PRIVATE_VALUE@proxy.test:8080')
    manager = ToolManager(root=tmp_path / 'managed')
    manifest = manager.manifest('gitleaks')
    assert manifest
    with patch('urllib.request.urlopen', side_effect=URLError(TimeoutError('PRIVATE_VALUE'))):
        with pytest.raises(DiagnosticError) as caught:
            manager.provider.download(manifest, tmp_path / 'asset')
    diagnostic = caught.value.diagnostic
    assert diagnostic.error_code == 'NETWORK_TIMEOUT' and diagnostic.source == 'github.com'
    assert diagnostic.https_proxy == ('configured' if configured else 'not configured')
    assert diagnostic.http_proxy == diagnostic.https_proxy
    assert 'PRIVATE_VALUE' not in json.dumps(diagnostic.to_dict())
    assert not (tmp_path / 'asset').exists()


def test_tools_install_actionable_timeout(tmp_path, capsys):
    manager = ToolManager(root=tmp_path)
    diagnostic = classify_network_error(TimeoutError(), url='https://github.com/private')
    manager.ensure = lambda name: ResolvedTool(name, '', '', None, ToolStatus.BROKEN, diagnostic.error_summary, diagnostic)
    with patch('security_runtime.cli.ToolManager', return_value=manager), patch('security_runtime.cli.configure_logging'):
        assert main(['tools', 'install', 'gitleaks']) == 2
    output = capsys.readouterr().out
    assert all(value in output for value in ('NETWORK_TIMEOUT', 'github.com', 'HTTPS proxy:', 'security-check tools install gitleaks'))


@pytest.mark.parametrize('mode,staged', [('quick', False), ('feature', False), ('release', True)])
def test_non_git_diff_modes_recommend_release(tmp_path, mode, staged):
    java_fixture(tmp_path)
    with pytest.raises(WorkspaceError, match='require Git.*release'):
        SecurityRuntime(store=SQLiteStore(tmp_path / 'test.db')).scan(tmp_path, mode, staged=staged)


def test_non_git_default_source_directory(tmp_path, monkeypatch):
    java_fixture(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert WorkspaceResolver().resolve(allow_non_git_source=True).path == tmp_path.resolve()
    registry, execute = mock_registry(tmp_path)
    with patch('security_runtime.scanners._execute', side_effect=execute):
        assert SecurityRuntime(registry, SQLiteStore(tmp_path / '.security-runtime' / 'test.db')).scan(mode='release').status == 'PARTIAL'


def test_platform_parent_alias_does_not_reject_safe_project(tmp_path, monkeypatch):
    # macOS commonly exposes temporary projects through /var -> /private/var.
    # Validate the project boundary after canonicalization, not a system alias.
    java_fixture(tmp_path)
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda path: path == tmp_path.parent or original(path))
    assert WorkspaceResolver().resolve(tmp_path, allow_non_git_explicit=True).path == tmp_path.resolve()


@pytest.mark.parametrize('target', ['home', 'drive'])
def test_non_git_unsafe_root_before_scanner(target):
    root = Path.home() if target == 'home' else Path(Path.cwd().anchor)
    with patch('security_runtime.target.TargetDetector.detect', side_effect=AssertionError('discovery called')):
        with pytest.raises(WorkspaceError):
            SecurityRuntime().scan(root, 'release')


def test_non_git_limits_and_ignored_dirs(tmp_path, monkeypatch):
    (tmp_path / 'app.py').write_text('pass')
    ignored = tmp_path / 'node_modules'
    ignored.mkdir()
    (ignored / 'large.py').write_text('x' * 3000)
    assert TargetDetector().detect(tmp_path).files == ['app.py']
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_FILE_SIZE', '10')
    (tmp_path / 'app.py').write_text('x' * 11)
    with pytest.raises(DiscoveryLimitError):
        SecurityRuntime().scan(tmp_path, 'release')


def test_doctor_prerequisites_and_separate_data(tmp_path, capsys):
    java_fixture(tmp_path)
    manager = ToolManager(root=tmp_path / 'managed')
    manager.statuses = lambda: {name: ResolvedTool(name, 'mock', name, None, ToolStatus.READY) for name in ('semgrep', 'gitleaks', 'trivy')}
    cache = manager.trivy_cache_dir() / 'db'
    cache.mkdir(parents=True)
    (cache / 'trivy.db').touch()
    (cache / 'metadata.json').write_text('{}')
    with patch('security_runtime.cli.ToolManager', return_value=manager):
        assert doctor(tmp_path, json_output=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['trivy_data'] == {'vulnerability_db': 'READY', 'java_db': 'MISSING', 'checks': 'UNKNOWN'}
    assert 'does not guarantee' in report['message']
    with patch('security_runtime.cli.ToolManager', return_value=manager):
        doctor(tmp_path, verbose=True)
    output = capsys.readouterr().out
    assert '✓' not in output and 'java_db: MISSING' in output and 'READY' in output


@pytest.mark.parametrize('error,code,status', [(TimeoutError(), 'PROCESS_TIMEOUT', 'TIMEOUT'),
    (OutputLimitError(), 'OUTPUT_LIMIT_EXCEEDED', 'FAILED')])
def test_scanner_structured_process_failures(tmp_path, error, code, status):
    java_fixture(tmp_path)
    registry, _ = mock_registry(tmp_path)
    adapter = registry.adapters[-1]
    with patch('security_runtime.scanners._execute', side_effect=error):
        findings, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.RELEASE, ('pom.xml',)), FindingNormalizer(tmp_path))
    assert not findings and run.error_code == code and run.status == status


def test_db_preparation_structured_429_no_retry(tmp_path):
    manager = ToolManager(root=tmp_path)
    with patch('security_runtime.toolchain.run_process', return_value=ProcessResult(1, '', 'GET https://ghcr.io/v2/db: 429\nRetry-After: 50', 1)) as execute, patch('security_runtime.toolchain.time.sleep') as sleep:
        assert manager.prepare_trivy_database('trivy', offline=False) == ToolStatus.BROKEN
    assert execute.call_count == 1 and not sleep.called
    assert manager.data_diagnostics['vulnerability_db'].error_code == 'HTTP_429'
    assert manager.data_diagnostics['vulnerability_db'].retry_after_seconds == 50


def test_bound_generic_mcp_accepts_safe_non_git_project(tmp_path, monkeypatch):
    java_fixture(tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', str(tmp_path))
    monkeypatch.setenv('SECURITY_RUNTIME_INTEGRATION', 'generic-mcp')
    server = create_server(SecurityRuntime(ScannerRegistry(adapters=[]), SQLiteStore(tmp_path / '.security-runtime' / 'test.db')))
    tool = server._tool_manager.get_tool('scan_project')
    assert tool.fn()['workspace'] == str(tmp_path.resolve())
    outside = tmp_path.parent / 'outside-project'
    outside.mkdir()
    with pytest.raises(ValueError, match='outside'):
        tool.fn(str(outside))
