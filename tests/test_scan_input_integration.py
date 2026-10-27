"""Actual Runtime/storage boundaries with deterministic providers, not desktop acceptance."""
from dataclasses import asdict
from dataclasses import replace
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import threading

import pytest

from security_runtime.capabilities import Capability
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_freshness import summary, source_revision
from security_runtime.scan_input import scoped_request
from security_runtime.scan_input import CapturedScanInput
from security_runtime.scanners import BaseScanner, ScannerRegistry, execution_environment
from security_runtime.storage import ReadOnlySQLiteStore, SQLiteStore
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolStatus
from test_scanner_hot_path import engine  # noqa: F401
from test_secret_recheck_coverage import secret_engine  # noqa: F401


OLD = b'def query(db, value):\n    return db.execute(value)\n'
NEW = b'def query(db, value):\n    return db.safe_query(value)\n'


@pytest.fixture
def project(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'app.py').write_bytes(OLD)
    return root, SQLiteStore(tmp_path / 'state' / 'scans.db')


class Reader:
    filter_changed_lines = False
    capabilities = frozenset({Capability.CODE_SAST})

    def __init__(self, name, callback=None, finding=False):
        self.name = self.scanner_id = name
        self.callback, self.finding, self.calls = callback, finding, []

    def supports(self, profile, context):
        return bool(context.files)

    def scan(self, context, normalizer):
        if self.callback:
            self.callback(context)
        raw = (Path(context.root) / 'app.py').read_bytes()
        self.calls.append((Path(context.root), raw))
        findings = []
        if self.finding:
            row = normalizer.make(scanner=self.name, category='sql-injection', title='Fixture call',
                description='Deterministic provider contract fixture', severity='HIGH', confidence='MEDIUM',
                file_path='app.py', line=2, rule_id='fixture.query')
            row.technical_details['evidence_locator'] = snapshot_fingerprint(context.root, 'app.py')
            findings.append(row)
        return findings, ScannerRun(self.name, 'fixture', 'SUCCESS', 0)


def test_two_providers_and_scope_storage_use_same_captured_bytes_after_live_edit(project):
    root, store = project
    changed = threading.Event()

    def mutate(_context):
        (root / 'app.py').write_bytes(NEW)
        changed.set()

    def await_edit(_context):
        assert changed.wait(timeout=2)

    first, second = Reader('first', mutate, True), Reader('second', await_edit)
    result = SecurityRuntime(ScannerRegistry([first, second]), store).scan(root, 'release')
    assert first.calls[0][1] == second.calls[0][1] == OLD
    assert first.calls[0][0] == second.calls[0][0] != root
    assert not first.calls[0][0].exists()
    assert result.target_profile.path == str(root)
    assert result.findings[0].file_path == 'app.py'
    assert result.status == 'PARTIAL' and result.coverage == 'UNKNOWN'
    assert result.scan_context['fixed_input']['applicability'] == 'STALE'
    assert result.scan_context['source_consistent'] is False
    scope = store.finding_scope_snapshot(result.scan_id, result.findings[0].id)
    assert scope['file_sha256'] == hashlib.sha256(OLD).hexdigest()
    assert scope['file_sha256'] != hashlib.sha256((root / 'app.py').read_bytes()).hexdigest()
    assert 'source_scopes' not in result.to_dict()
    assert store.get_scan(result.scan_id)['scan_context']['fixed_input']['applicability'] == 'STALE'


def test_freshness_uses_captured_bytes_and_logical_workspace_identity(project):
    root, store = project
    result = SecurityRuntime(ScannerRegistry([Reader('fixture')]), store).scan(root, 'release')
    assert result.scan_context['source_revision'] == source_revision(root, store.evidence_key())[0]
    assert result.scan_context['source_consistent'] is True
    before = store.path.read_bytes()
    facts = summary(result.to_dict(), ReadOnlySQLiteStore(store.path), root)
    assert facts['source_freshness'] == 'CURRENT' and facts['full_project_reusable'] is False
    assert store.path.read_bytes() == before
    (root / 'app.py').write_bytes(NEW)
    assert summary(result.to_dict(), ReadOnlySQLiteStore(store.path), root)['source_freshness'] == 'STALE'


def test_index_scope_proof_does_not_bind_different_worktree_bytes(project):
    root, store = project
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', 'app.py'], check=True)
    (root / 'app.py').write_bytes(NEW)
    provider = Reader('index-fixture', finding=True)
    result = SecurityRuntime(ScannerRegistry([provider]), store).scan(root, staged=True)
    assert provider.calls[0][1] == OLD
    assert result.scan_context['fixed_input']['source_kind'] == 'INDEX'
    assert result.scan_context['fixed_input']['applicability'] == 'CURRENT'
    assert store.finding_scope_snapshot(result.scan_id, result.findings[0].id)['file_sha256'] == hashlib.sha256(OLD).hexdigest()
    assert (root / 'app.py').read_bytes() == NEW


def test_empty_fixed_scope_handoff_never_falls_back_to_live_scope_capture(project):
    root, store = project
    provider = Reader('fixture', finding=True)
    result = SecurityRuntime(ScannerRegistry([provider]), store).scan(root, 'release')
    result.source_scopes = None
    result.scan_id = 'fixed-input-missing-scope-handoff'
    store.save(result)
    assert store.finding_scope_snapshot(result.scan_id, result.findings[0].id) is None


def test_runtime_rule_cache_reuses_selection_without_reusing_deleted_view(engine):
    root, path, _, adapter, calls, _ = engine
    path.write_text('class A { void f() { connection.setHostnameVerifier((h,s)->true); } }')
    runtime = SecurityRuntime(ScannerRegistry([adapter], fallback_adapters=[]), SQLiteStore(root.parent / 'scans.db'))
    first, second = runtime.scan(root, 'release'), runtime.scan(root, 'release')
    assert first.findings and second.findings
    assert len(calls) == 2
    assert second.scanner_runs[0].scanner_diagnostics['rule_plan_cache'] == 'HIT'
    assert second.scanner_runs[0].scanner_diagnostics['execution_binding']['verified'] is True


def test_all_providers_receive_the_same_final_overlay_identity(engine, monkeypatch):
    root, _, _, adapter, _, _ = engine
    seen = []
    original = adapter.scan

    def record(context, normalizer):
        assert context.input_view.rules_path.is_dir()
        seen.append((context.input_view.input_id, context.input_view.rules_path))
        return original(context, normalizer)

    monkeypatch.setattr(adapter, 'scan', record)

    class Observer:
        name = scanner_id = 'overlay-observer'
        capabilities = frozenset({Capability.CODE_SAST})
        filter_changed_lines = False

        def supports(self, profile, context):
            return True

        def scan(self, context, _normalizer):
            seen.append((context.input_view.input_id, context.input_view.rules_path))
            assert context.input_view.rules_path.is_dir()
            return [], ScannerRun(self.name, 'fixture', 'SUCCESS', 0)

    runtime = SecurityRuntime(ScannerRegistry([adapter, Observer()]), SQLiteStore(root.parent / 'overlay.db'))
    result = runtime.scan(root, 'release')
    assert len(seen) == 2 and seen[0] == seen[1]
    assert seen[0][0] == result.scan_context['fixed_input']['input_id']
    assert not seen[0][1].exists()


def test_native_selection_uses_fixed_source_and_never_copies_deferred_rules(project, monkeypatch):
    import security_runtime.runtime as runtime_module
    from security_runtime.dynamic_function import NativeFunctionScanner
    from security_runtime.scanners import SemgrepAdapter
    root, store = project
    path = root / 'calc.js'
    path.write_text('export function calc(value){ return new Function(value)(); }\n')
    original_capture = runtime_module.capture_scan_input

    @contextmanager
    def edit_after_capture(*args, **kwargs):
        with original_capture(*args, **kwargs) as view:
            path.write_text('export function calc(value){ return 1; }\n')
            yield view

    monkeypatch.setattr(runtime_module, 'capture_scan_input', edit_after_capture)
    monkeypatch.setattr(CapturedScanInput, 'with_rules', lambda *_args:
        pytest.fail('deferred Semgrep rules must not be copied'))
    monkeypatch.setattr(SemgrepAdapter, 'scan', lambda *_args:
        pytest.fail('deferred Semgrep must not execute'))
    request = replace(scoped_request(root, ['calc.js']), code_preference='CANONICAL_DYNAMIC_WHEN_ELIGIBLE')
    result = SecurityRuntime(ScannerRegistry([SemgrepAdapter(), NativeFunctionScanner()]), store).scan(root, request=request)
    assert result.findings and result.findings[0].file_path == 'calc.js'
    assert result.rule_coverage['coverage_scope'] == 'CANONICAL_DYNAMIC_CODE_ONLY'
    assert result.scan_context['fixed_input']['applicability'] == 'STALE'
    assert result.scanner_diagnostics['code_selection']['input_id'] == result.scan_context['fixed_input']['input_id']
    assert all(run.scanner != 'semgrep' for run in result.scanner_runs)


def tool_fixture(root, store, *, engine='gitleaks', dependency=False, callback=None):
    manager = ToolManager(root=root.parent / 'managed')
    binary = root.parent / (engine + '-synthetic.bin')
    binary.write_bytes(b'deterministic non-executed provider fixture')
    manager.ensure = lambda *_args, **_kwargs: ResolvedTool(engine, manager.versions[engine],
        str(binary), None, ToolStatus.READY)

    class Provider(BaseScanner):
        name = scanner_id = engine_id = engine
        capabilities = frozenset({Capability.DEPENDENCY_VULN if dependency else Capability.SECRET_SCAN})
        checks = 'vuln' if dependency else ''

        def _scan(self, _binary, context, _normalizer):
            if callback:
                callback(binary, manager, context)
            return []

    provider = Provider(manager)
    runtime = SecurityRuntime(ScannerRegistry([provider], fallback_adapters=[]), store)
    return runtime, provider, binary, manager


def test_actual_tool_content_change_cannot_prove_a_clean_execution(project):
    root, store = project
    runtime, _, _, _ = tool_fixture(root, store,
        callback=lambda binary, _manager, _context: binary.write_bytes(b'different tool content'))
    result = runtime.scan(root, 'release')
    run = result.scanner_runs[0]
    assert run.status == 'FAILED' and run.coverage_contract == 'NONE'
    assert run.error_code == 'SCAN_EXECUTION_IDENTITY_CHANGED'
    assert result.scan_context['execution_bindings']['gitleaks']['verified'] is False
    assert result.status == 'PARTIAL'


def test_database_content_fingerprint_is_disabled_during_execution(project, monkeypatch):
    root, store = project
    (root / 'requirements.txt').write_bytes(b'fixture==1\n')

    def change(_binary, manager, _context):
        (manager.trivy_cache_dir() / 'db' / 'trivy.db').write_bytes(b'new database')

    runtime, _, _, manager = tool_fixture(root, store, engine='trivy', dependency=True, callback=change)
    monkeypatch.setattr(manager, 'execution_data_identity', lambda *_a, **_k:
        pytest.fail('vulnerability database content must not be fingerprinted'))
    db = manager.trivy_cache_dir() / 'db'
    db.mkdir(parents=True)
    (db / 'trivy.db').write_bytes(b'old database')
    (db / 'metadata.json').write_bytes(b'{}')
    result = runtime.scan(root, 'release')
    run = result.scanner_runs[0]
    assert run.status == 'SUCCESS' and not run.error_code
    binding = result.scan_context['execution_bindings']['trivy']
    assert binding['verified'] is True and binding['data_status'] == 'DISABLED'
    assert binding['data'] is None and binding['data_required'] is False
    assert not any('DATA_IDENTITY_UNVERIFIABLE' in note for note in run.coverage_notes)


def test_osv_database_fingerprint_disabled_does_not_create_a_coverage_gap(project, monkeypatch):
    root, store = project
    monkeypatch.delenv('SECURITY_RUNTIME_OFFLINE', raising=False)
    (root / 'requirements.txt').write_bytes(b'fixture==1\n')
    runtime, _, _, manager = tool_fixture(root, store, engine='osv-scanner', dependency=True)
    monkeypatch.setattr(manager, 'execution_data_identity', lambda *_a, **_k:
        pytest.fail('vulnerability database content must not be fingerprinted'))
    result = runtime.scan(root, 'release')
    run = result.scanner_runs[0]
    assert run.status == 'SUCCESS' and run.coverage_contract == 'FULL'
    assert run.scanner_diagnostics['execution_binding']['data_status'] == 'DISABLED'
    assert result.capability_results[Capability.DEPENDENCY_VULN] == 'EXECUTED'


def test_unbound_external_scanner_configuration_never_reads_live(project, monkeypatch):
    root, store = project
    external = root.parent / 'private-external.toml'
    external.write_bytes(b'canary-unbound-configuration-content')
    monkeypatch.setenv('GITLEAKS_CONFIG', str(external))
    calls = []
    runtime, _, _, _ = tool_fixture(root, store, callback=lambda *_args: calls.append(True))
    result = runtime.scan(root, 'release')
    assert not calls
    assert result.scanner_runs[0].error_code == 'SCAN_INPUT_CONFIGURATION_UNBOUND'
    assert 'canary-unbound-configuration-content' not in json.dumps(result.to_dict())


def test_bound_configuration_uses_frozen_path_and_environment(project, monkeypatch):
    root, store = project
    configuration = root / 'custom-gitleaks.toml'
    configuration.write_bytes(b'old scanner configuration')
    monkeypatch.setenv('GITLEAKS_CONFIG', str(configuration))
    observed = []

    def inspect(binary, _manager, context):
        environment = execution_environment(binary)
        path = Path(environment['GITLEAKS_CONFIG'])
        assert path.is_relative_to(Path(context.root)) and path != configuration
        configuration.write_bytes(b'new scanner configuration')
        monkeypatch.setenv('GITLEAKS_CONFIG', str(root.parent / 'later-config.toml'))
        observed.append(path.read_bytes())

    runtime, _, _, _ = tool_fixture(root, store, callback=inspect)
    result = runtime.scan(root, 'release')
    assert observed == [b'old scanner configuration']
    assert result.scanner_runs[0].scanner_diagnostics['execution_binding']['verified'] is True
    assert result.scan_context['fixed_input']['applicability'] == 'STALE'


def test_removed_manifest_is_retained_in_public_request(project):
    root, _ = project
    value = scoped_request(root, ['package-lock.json', 'app.py'], dependency_changes=['package-lock.json'])
    assert value.requested_files == ('app.py', 'package-lock.json')
    assert value.files == ('app.py',) and value.absent_files == ('package-lock.json',)
    assert value.dependency_changes == ('package-lock.json',)


@pytest.mark.parametrize('provider',['semgrep','gitleaks'])
def test_selected_rules_and_secret_report_stay_under_the_protected_input_base(request,provider,monkeypatch):
    import security_runtime.scanners as scanners
    fixture=request.getfixturevalue('engine' if provider=='semgrep' else 'secret_engine')
    root=fixture[0]
    adapter=fixture[3] if provider=='semgrep' else fixture[2]
    original=scanners._execute
    seen=[]
    def inspect(argv,cwd,timeout):
        flag='--config' if provider=='semgrep' else '--report-path'
        artifact=Path(argv[argv.index(flag)+1])
        base=Path(cwd).parent
        assert artifact.is_relative_to(base) and not artifact.is_relative_to(Path(cwd))
        assert not artifact.is_relative_to(root)
        seen.append(artifact)
        return original(argv,cwd,timeout)
    monkeypatch.setattr(scanners,'_execute',inspect)
    runtime=SecurityRuntime(ScannerRegistry([adapter],fallback_adapters=[]),SQLiteStore(root.parent/'artifacts.db'))
    result=runtime.scan(root,'release')
    assert seen and result.scanner_runs[0].status=='SUCCESS'
    assert all(not path.exists() for path in seen)
