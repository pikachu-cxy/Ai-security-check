"""Real-project failure shape, without private source, filenames or credentials."""
import asyncio
import json
import subprocess
from pathlib import Path

import pytest

from security_runtime import cli
from security_runtime.capabilities import Capability
from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import _agent_result, create_server
from security_runtime.models import RunStatus, ScannerRun
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import RulePackManager
from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_freshness import summary
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore
from security_runtime.target import DiscoveryLimitError, TargetDetector, selection_summary
from test_global_integration import installed, projects, structured


class RecordingScanner:
    name = scanner_id = 'fixture-code-and-secret'
    capabilities = frozenset({Capability.CODE_SAST, Capability.SECRET_SCAN})
    filter_changed_lines = False

    def __init__(self):
        self.calls = []

    def supports(self, profile, context):
        return True

    def scan(self, context, normalizer):
        self.calls.append(context.files)
        return [], ScannerRun(self.name, '1.0.0', RunStatus.SUCCESS, 0)


def runtime_at(root, state):
    from security_runtime.scanners import ScannerRegistry
    scanner = RecordingScanner()
    return SecurityRuntime(ScannerRegistry([scanner]), SQLiteStore(state / 'scans.db')), scanner


@pytest.mark.parametrize('git', [False, True], ids=['source-directory', 'git'])
def test_large_document_does_not_block_scanners_or_lose_secret_text(tmp_path, git):
    root = tmp_path / 'project'; root.mkdir()
    if git:
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'App.java').write_text('class App {}\n')
    (root / '.env').write_text('SETTING=fixture\n')
    (root / 'notes.data').write_text('arbitrary text for Secret scope\n')
    (root / 'renamed.docx').write_text('plain text still in Secret scope\n')
    (root / 'document.docx').write_bytes(b'PK\x03\x04' + b'x' * 1_100_000)
    runtime, scanner = runtime_at(root, tmp_path / 'state')
    result = runtime.scan(root, 'release')
    assert scanner.calls == [('.env', 'App.java', 'notes.data', 'renamed.docx')]
    assert result.coverage == 'FULL'
    ledger = result.target_profile.skipped_files
    assert ledger == [{'path': 'document.docx', 'reason': 'UNSUPPORTED_BINARY_DOCUMENT',
                       'source': 'RUNTIME_TARGET_SELECTION', 'size_bytes': 1_100_004}]
    persisted = runtime.store.get_scan(result.scan_id)
    assert persisted['target_profile']['skipped_files'] == ledger
    assert _agent_result(result)['target_selection']['excluded_count'] == 1
    assert summary(persisted, ReadOnlySQLiteStore(runtime.store.path), root)['source_freshness'] == 'CURRENT'
    assert 'plain text still' not in json.dumps(persisted)


@pytest.mark.parametrize('name', ['large.py', '.env', 'settings.data', 'package-lock.json', 'archive.jar'])
def test_relevant_oversized_inputs_still_fail_closed(tmp_path, name):
    root = tmp_path / 'project'; root.mkdir()
    (root / name).write_bytes(b'x' * 1_000_001)
    runtime, scanner = runtime_at(root, tmp_path / 'state')
    with pytest.raises(DiscoveryLimitError) as raised:
        runtime.scan(root, 'release')
    assert raised.value.to_dict()['reason_code'] == 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
    assert raised.value.to_dict()['relative_path'] == name
    assert not scanner.calls
    assert runtime.store.latest_scan(root) is None


def test_content_and_extension_both_required(tmp_path):
    (tmp_path / 'text.pdf').write_text('text must remain eligible for Secret scanning')
    (tmp_path / 'App.java').write_bytes(b'PK\x03\x04')
    (tmp_path / 'archive.jar').write_bytes(b'PK\x03\x04')
    (tmp_path / 'image.png').write_bytes(b'\x89PNG\r\n\x1a\n')
    profile = TargetDetector().detect(tmp_path, select_scan_targets=True)
    assert profile.files == ['App.java', 'archive.jar', 'text.pdf']
    assert [row['path'] for row in profile.skipped_files] == ['image.png']


def test_direct_target_validation_still_enforces_limits(tmp_path):
    (tmp_path / 'document.docx').write_bytes(b'PK\x03\x04' + b'x' * 1_000_000)
    with pytest.raises(DiscoveryLimitError):
        TargetDetector().detect(tmp_path, ['document.docx'])


def test_document_exclusion_cannot_bypass_path_boundary(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    (tmp_path / 'outside.docx').write_bytes(b'PK\x03\x04')
    with pytest.raises(ValueError, match='outside'):
        TargetDetector().detect(root, ['../outside.docx'], select_scan_targets=True)
    try:
        (root / 'linked.docx').symlink_to(tmp_path / 'outside.docx')
    except OSError:
        pytest.skip('Windows symlink privilege unavailable')
    with pytest.raises(ValueError):
        TargetDetector().detect(root, ['linked.docx'], select_scan_targets=True)


def test_only_excluded_documents_never_claim_full(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'document.docx').write_bytes(b'PK\x03\x04' + b'x' * 1_100_000)
    runtime, scanner = runtime_at(root, tmp_path / 'state')
    result = runtime.scan(root, 'release')
    assert result.coverage == 'NONE' and result.release_status == 'NOT_ASSESSED'
    assert not scanner.calls
    assert result.target_profile.skipped_files


def test_mcp_limit_returns_typed_diagnostic_before_provider_execution(tmp_path):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'App.java').write_bytes(b'x' * 1_000_001)
    runtime, scanner = runtime_at(root, tmp_path / 'state')
    binding = WorkspaceBinding('fixture', str(root), '', 'generic-mcp', 'PROJECT', '')
    server = create_server(runtime, workspace_binding=binding, global_mode=False)
    value = structured(asyncio.run(server.call_tool('scan_project', {'summary': True})))
    assert value['reason_code'] == 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
    assert value['coverage'] == 'UNKNOWN' and not value['scanner_run']
    assert 'WORKSPACE_OR_REFERENCE_REJECTED' not in json.dumps(value)
    assert not scanner.calls


def test_global_forwarding_retains_discovery_diagnostic(installed, projects, tmp_path):
    installed.execute('setup')
    root = projects[0]
    (root / 'large.java').write_bytes(b'x' * 1_000_001)
    runtime, scanner = runtime_at(root, tmp_path / 'isolated-state')
    def child_factory(root, directory, binding):
        return create_server(runtime, workspace_binding=binding, global_mode=False), None
    pool = GlobalWorkspaces(base=tmp_path / 'workspaces', integration=installed, child_factory=child_factory)
    try:
        server = create_global_server(workspaces=pool)
        value = structured(asyncio.run(server.call_tool('scan_project', {'workspace_path': str(root), 'summary': True})))
        assert value['reason_code'] == 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
        assert not value['scanner_run'] and value['relative_path'] == 'large.java'
        assert not scanner.calls
    finally:
        pool.close()


def test_cli_json_diagnostic_is_not_a_success(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    root = tmp_path / 'project'; root.mkdir()
    (root / 'large.py').write_bytes(b'x' * 1_000_001)
    assert cli.main(['scan', '--path', str(root), '--mode', 'release', '--json', '--no-progress']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['reason_code'] == 'TARGET_FILE_SIZE_LIMIT_EXCEEDED'
    assert value['coverage'] == 'UNKNOWN' and not value['scanner_run']


def test_global_scope_cli_does_not_use_legacy_git_binding(installed, tmp_path, monkeypatch, capsys):
    root = tmp_path / 'project'; root.mkdir()
    (root / 'app.js').write_text('const fixture = 1;')
    installed.execute('setup')
    monkeypatch.setattr('security_runtime.global_integration.GlobalCodexIntegration', lambda **kwargs: installed)
    assert cli.main(['integration', 'status', 'codex', '--scope', 'global', '--path', str(root), '--json']) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['scope'] == 'GLOBAL' and value['overall'] == 'CONFIGURED'


def test_global_os_error_is_not_an_ownership_conflict(monkeypatch, capsys):
    def failed(**kwargs):
        raise PermissionError('synthetic-private-location')
    monkeypatch.setattr('security_runtime.global_integration.GlobalCodexIntegration', failed)
    assert cli.main(['status', '--json']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['diagnostics'] == ['GLOBAL_STATE_ACCESS_FAILED']
    assert 'synthetic-private-location' not in json.dumps(value)


def test_selection_display_is_bounded_and_legacy_snapshots_supported(tmp_path):
    for i in range(23):
        (tmp_path / f'{i:02}.png').write_bytes(b'\x89PNG\r\n\x1a\n')
    view = selection_summary(TargetDetector().detect(tmp_path, select_scan_targets=True))
    assert view['excluded_count'] == 23 and len(view['excluded_files']) == 20
    assert view['exclusions_truncated']
    assert selection_summary({'files': ['app.py']})['excluded_count'] == 0


@pytest.mark.parametrize('reason', ['too_big', 'binary', 'insufficient_permissions', 'private-token-value'])
def test_engine_skip_prevents_false_full_even_when_path_listed_scanned(reason):
    plan = plan_rules(RulePackManager().resolve(), ['App.java', 'Skipped.java'])
    data = {'time': {'rules': [r.rule_id for r in plan.rules]},
            'paths': {'scanned': list(plan.files), 'skipped': [{'path': 'Skipped.java', 'reason': reason,
                                                             'details': 'private scanner detail'}]}}
    plan.observe(data, plan.files)
    value = plan.coverage('SUCCESS')
    assert value['status'] == 'PARTIAL'
    assert value['per_language']['java']['scanned_files'] == 1
    assert value['engine_skipped_count'] == 1
    assert 'private' not in json.dumps(value)
    from security_runtime.hook_runtime import covered
    family = {'scanner_sources': ['semgrep'], 'file_path': 'Skipped.java',
              'rule_id': plan.rules[0].rule_id,
              'proof': {'rule_pack_checksum': plan.pack.checksum,
                        'rule_version': plan.rules[0].rule_version, 'engine': 'semgrep',
                        'rule_versions': {plan.rules[0].rule_id: plan.rules[0].rule_version}}}
    # Supply the same provider receipt as a real Semgrep run: otherwise the
    # positive control fails at provider validation before testing file skips.
    run = ScannerRun('semgrep', 'fixture', RunStatus.SUCCESS, 0, provider='semgrep')
    assert not covered(family, [run], {'semgrep': plan})
    assert covered({**family, 'file_path': 'App.java'}, [run], {'semgrep': plan})
