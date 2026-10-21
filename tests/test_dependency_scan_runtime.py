import ast
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessResult
from security_runtime.progress import NullProgressReporter, ProgressEvent, ProgressReporter, progress_context
from security_runtime.scanners import TrivyAdapter
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolStatus
from security_runtime.verification_policy import local_recheck, scanner_process_observed


@pytest.mark.parametrize('with_sink', [False, True])
def test_stale_database_preparation_does_not_crash_progress(tmp_path, monkeypatch, with_sink):
    now = datetime(2026, 10, 11, tzinfo=timezone.utc)
    manager = ToolManager(tmp_path / 'managed', now=lambda: now)
    directory = manager.trivy_cache_dir() / 'db'
    directory.mkdir(parents=True)
    (directory / 'trivy.db').write_bytes(b'cached-data')
    (directory / 'metadata.json').write_text(json.dumps({
        'UpdatedAt': (now - timedelta(days=10)).isoformat(),
        'NextUpdate': (now - timedelta(days=9)).isoformat(),
    }))
    calls = []
    monkeypatch.setattr(manager, '_prepare_trivy_database', lambda *a, **k: calls.append(k) or ToolStatus.READY)
    events = []
    reporter = ProgressReporter(events.append) if with_sink else NullProgressReporter()
    with progress_context(reporter):
        assert manager.prepare_trivy_database('trivy', offline=True) == ToolStatus.READY
    assert calls == [{'offline': True, 'force': False}]
    if with_sink:
        assert events[0].event_type == 'DATA_PREPARING'
        assert events[0].component == 'vulnerability_db'
        assert 'STALE' in events[0].message


def test_progress_emit_keywords_match_event_schema():
    allowed = {field.name for field in fields(ProgressEvent)} - {'event_type', 'timestamp', 'elapsed_ms'}
    source = Path(__file__).resolve().parents[1] / 'src/security_runtime'
    failures = []
    for path in source.glob('*.py'):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        imports_emit = any(isinstance(node, ast.ImportFrom) and node.module == 'progress'
            and any(alias.name == 'emit' and alias.asname is None for alias in node.names)
            for node in tree.body)
        if not imports_emit:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'emit':
                failures.extend((path.name, node.lineno, keyword.arg) for keyword in node.keywords
                    if keyword.arg is not None and keyword.arg not in allowed)
    assert failures == []


def configured_adapter(tmp_path, monkeypatch, output, stderr=''):
    manager = ToolManager(tmp_path / 'managed')
    events = []
    monkeypatch.setattr(manager, 'ensure', lambda *a, **k: events.append(('ensure', k)) or
        ResolvedTool('trivy', '0.74.0', 'trivy', None, ToolStatus.READY))
    monkeypatch.setattr(manager, 'prepare_trivy_database', lambda *a, **k: events.append(('prepare', k)) or ToolStatus.READY)
    monkeypatch.setattr(manager, 'database_freshness', lambda: {'status': 'FRESH'})
    def execute(args, cwd, timeout):
        events.append(('execute', args))
        return ProcessResult(0, json.dumps(output), stderr, 5)
    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    return TrivyAdapter(manager), events


def package_output(name='requirements.txt', packages=None):
    return {'Results': [{'Target': name, 'Type': 'pip',
        'Packages': packages if packages is not None else [{'Name': 'PyYAML', 'Version': '5.3.1'}],
        'Vulnerabilities': [{'PkgName': 'PyYAML', 'InstalledVersion': '5.3.1',
            'VulnerabilityID': 'CVE-2020-14343', 'Severity': 'HIGH'}]}]}


def test_quick_dependency_scan_uses_local_engines_and_reports_actual_inventory(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, calls = configured_adapter(tmp_path, monkeypatch, package_output())
    with progress_context(NullProgressReporter()):
        found, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.QUICK, ('requirements.txt',)), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert calls[0] == ('ensure', {'offline': True})
    assert calls[1] == ('prepare', {'offline': True})
    assert '--offline-scan' in calls[2][1] and '--list-all-pkgs' in calls[2][1]
    assert found[0].technical_details['package_version'] == '5.3.1'
    assert found[0].technical_details['vulnerability_id'] == 'CVE-2020-14343'
    assert run.dependency_inventory['package_occurrences'] == 1
    assert run.dependency_inventory['confirmed_manifests'] == 1
    assert run.dependency_inventory['complete_dependency_graph_attested'] is False
    assert run.dependency_inventory['vulnerability_db_freshness'] == 'FRESH'
    assert run.scanner_diagnostics['invocations'] == [{'type': 'DEPENDENCY_SCAN', 'target_count': 1}]


@pytest.mark.parametrize('freshness,code', [
    ('UNKNOWN', 'VULNERABILITY_DB_FRESHNESS_UNKNOWN'),
    ('STALE', 'VULNERABILITY_DB_STALE'),
])
def test_cached_scan_distinguishes_unknown_freshness_from_expired_data(tmp_path, monkeypatch, freshness, code):
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, _ = configured_adapter(tmp_path, monkeypatch, package_output())
    monkeypatch.setattr(adapter.tool_manager, 'database_freshness', lambda: {'status': freshness})
    _, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.QUICK, ('requirements.txt',)), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert run.dependency_inventory['vulnerability_db_freshness'] == freshness
    assert any(note.startswith(code + ':') for note in run.coverage_notes)
    if freshness == 'UNKNOWN':
        assert not any('VULNERABILITY_DB_STALE' in note for note in run.coverage_notes)


@pytest.mark.parametrize('output', [
    {'Results': []},
    package_output(packages=[]),
    package_output(packages=[{'Name': 'PyYAML', 'Version': ''}]),
    package_output(packages=[{'Name': [], 'Version': '5.3.1'}]),
])
def test_empty_or_unconfirmed_inventory_is_never_full(tmp_path, monkeypatch, output):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, _ = configured_adapter(tmp_path, monkeypatch, output)
    _, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.RELEASE, ('requirements.txt',)), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert run.coverage_notes
    assert run.dependency_inventory['confirmed_package_occurrences'] == 0


def test_release_retains_online_preparation(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, calls = configured_adapter(tmp_path, monkeypatch, package_output())
    adapter.scan(ScanContext(str(tmp_path), ScanMode.RELEASE, ('requirements.txt',)), FindingNormalizer(tmp_path))
    assert calls[0] == ('ensure', {}) and calls[1] == ('prepare', {})
    assert '--offline-scan' not in calls[2][1]


def test_quick_keeps_existing_hook_execution_ledger(tmp_path, monkeypatch):
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, _ = configured_adapter(tmp_path, monkeypatch, package_output())
    def execute(*args, **kwargs):
        scanner_process_observed()
        return ProcessResult(0, json.dumps(package_output()), '', 5)
    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    with local_recheck() as ledger:
        _, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.QUICK, ('requirements.txt',)), FindingNormalizer(tmp_path))
        assert ledger['engine_process_observed'] is True
    assert run.status == 'SUCCESS'


def test_dependency_engine_receives_only_planned_dependency_inputs(tmp_path, monkeypatch):
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    (tmp_path / 'App.java').write_text('class App {}')
    (tmp_path / 'trivy.yaml').write_text('any project scanner configuration')
    adapter, _ = configured_adapter(tmp_path, monkeypatch, package_output())
    snapshots = []
    def execute(args, cwd, timeout):
        snapshots.append(sorted(p.name for p in Path(cwd).iterdir()))
        return ProcessResult(0, json.dumps(package_output()), '', 5)
    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    _, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.RELEASE,
        ('requirements.txt', 'App.java', 'trivy.yaml')), FindingNormalizer(tmp_path))
    assert snapshots == [['requirements.txt']]
    assert run.scanner_diagnostics['scope']['relative_targets'] == ['requirements.txt']
    assert run.scanner_diagnostics['invocations'] == [{'type': 'DEPENDENCY_SCAN', 'target_count': 1}]


@pytest.mark.parametrize('stage', ['ENGINE_PREPARATION', 'DATA_PREPARATION', 'SCANNER_EXECUTION'])
def test_unexpected_errors_keep_safe_stage_without_exception_text(tmp_path, monkeypatch, stage):
    (tmp_path / 'requirements.txt').write_text('PyYAML==5.3.1\n')
    adapter, _ = configured_adapter(tmp_path, monkeypatch, package_output())
    def fail(*args, **kwargs):
        raise TypeError('private source / credentials token=secret-value')
    if stage == 'ENGINE_PREPARATION':
        monkeypatch.setattr(adapter.tool_manager, 'ensure', fail)
    elif stage == 'DATA_PREPARATION':
        monkeypatch.setattr(adapter.tool_manager, 'prepare_trivy_database', fail)
    else:
        monkeypatch.setattr('security_runtime.scanners._execute', fail)
    _, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.RELEASE, ('requirements.txt',)), FindingNormalizer(tmp_path))
    assert run.error_code == 'SCANNER_FAILED'
    assert run.scanner_diagnostics['failure'] == {'stage': stage, 'exception_type': 'TypeError'}
    assert stage in run.diagnostic_detail
    assert 'private' not in json.dumps(run.__dict__) and 'secret-value' not in json.dumps(run.__dict__)


def test_provider_supports_changed_lockfile_and_manifest_context(tmp_path):
    adapter = TrivyAdapter(ToolManager(tmp_path / 'managed'))
    assert adapter.supports(None, ScanContext(str(tmp_path), ScanMode.QUICK, ('nested/poetry.lock',)))
    assert adapter.supports(None, ScanContext(str(tmp_path), ScanMode.FEATURE, ('App.java',), context_files=('requirements.txt',)))
    assert not adapter.supports(None, ScanContext(str(tmp_path), ScanMode.QUICK, ('App.java',)))
