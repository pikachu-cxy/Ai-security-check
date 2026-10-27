"""Installation/API/pack compatibility checks; no old/new efficacy comparison."""
import hashlib
import json
import os
from pathlib import Path

import pytest

from security_runtime.engines import ON_DEMAND_ENGINES
from security_runtime.rulepacks import RulePackManager, DEFAULT_RULE_PACK, execution_rule
from security_runtime.scanners import OpenGrepAdapter, ScannerRegistry, ScanContext
from security_runtime.sast import OpenGrepEngineProvider, SASTRequest
from security_runtime.toolchain import ToolManager, VERSIONS


@pytest.fixture(scope='module')
def pack():
    return RulePackManager().resolve()


def test_default_engine_and_rules_are_replaced(pack):
    names = [a.name for a in ScannerRegistry().adapters]
    assert 'opengrep' in names and 'semgrep' not in names
    assert 'semgrep' in ON_DEMAND_ENGINES
    assert VERSIONS['opengrep'] == '1.32.0'
    assert pack.descriptor.rule_pack_id == 'opengrep-rules'
    assert len(pack.catalog) == 2007
    assert len({r.rule_id for r in pack.catalog}) == 2007
    assert pack.program is None
    assert not list(pack.path.glob('core/*'))


def test_vendored_rules_match_import_receipt(pack):
    receipt = json.loads((pack.path.parent/'opengrep_rules.json').read_text(encoding='utf-8'))
    for name, expected in receipt['sha256'].items():
        assert hashlib.sha256((pack.path/name).read_bytes()).hexdigest() == expected
    assert receipt['commit'] == pack.descriptor.version
    assert not pack.descriptor.commercial_use_allowed


def test_upstream_collisions_are_namespaced_not_dropped(pack):
    matches = [r for r in pack.catalog if r.provenance['original_rule_id'] == 'eval-detected']
    assert len(matches) > 1
    assert len({r.rule_id for r in matches}) == len(matches)


def test_user_rules_directory_keeps_original_ids(tmp_path):
    (tmp_path/'custom.yml').write_text('rules:\n- id: customer-rule\n  languages: [python]\n  message: Custom\n  severity: WARNING\n  pattern: eval(...)\n')
    custom = RulePackManager().resolve(user_path=tmp_path)
    assert custom.catalog[0].rule_id == 'customer-rule'
    assert not custom.descriptor.bundled
    assert execution_rule({'id':'customer-rule'}, 'custom.yml', custom.descriptor)['id'] == 'customer-rule'


def test_invalid_user_rules_are_not_silently_ignored(tmp_path):
    (tmp_path/'bad.yml').write_text('rules: [{id: broken}]')
    with pytest.raises(ValueError):
        RulePackManager().resolve(user_path=tmp_path)


def test_native_command_does_not_pass_removed_python_metrics_option(pack, tmp_path):
    command = OpenGrepEngineProvider().command(str(tmp_path/'opengrep.exe'), SASTRequest(tmp_path,pack,('a.py',)))
    assert '--metrics' not in command
    assert '--no-rewrite-rule-ids' in command
    assert '--disable-version-check' in command


@pytest.mark.parametrize('system,arch', [('windows','x64'),('linux','x64'),('linux','arm64'),('macos','x64'),('macos','arm64')])
def test_official_binary_manifests_are_pinned(tmp_path, monkeypatch, system, arch):
    monkeypatch.setattr('security_runtime.toolchain.platform_key', lambda:(system,arch))
    manifest = ToolManager(tmp_path).manifest('opengrep')
    assert '/opengrep/opengrep/releases/download/v1.32.0/' in manifest.download_url
    assert manifest.archive_type == 'binary' and len(manifest.sha256) == 64


def test_verified_download_survives_failed_probe_and_is_reused(tmp_path, monkeypatch):
    from dataclasses import replace
    from security_runtime.component_health import diagnosis
    from security_runtime.diagnostics import DiagnosticError
    data = b'verified test binary'
    calls = []
    class Provider:
        def download(self, manifest, destination):
            calls.append(1)
            destination.write_bytes(data)
    manager = ToolManager(tmp_path, provider=Provider())
    manifest = replace(manager.manifest('opengrep'), sha256=hashlib.sha256(data).hexdigest())
    def failed(tool, path, *, initial_install=False):
        assert initial_install
        manager._probe_diagnostics[(tool, str(path))] = diagnosis('COMPONENT_START_TIMEOUT')
        return ''
    monkeypatch.setattr(manager, '_probe_version', failed)
    with pytest.raises(DiagnosticError) as error:
        manager._install_binary(manifest)
    assert error.value.diagnostic.error_code == 'COMPONENT_START_TIMEOUT'
    monkeypatch.setattr(manager, '_probe_version', lambda *args, **kwargs: manifest.version)
    manager._install_binary(manifest)
    assert len(calls) == 1
    assert (tmp_path / 'tools' / 'opengrep' / manifest.version / 'opengrep').read_bytes() == data


def test_macos_opengrep_initial_probe_allows_cold_start(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import security_runtime.toolchain as toolchain
    timeouts = []
    monkeypatch.setattr(toolchain.sys, 'platform', 'darwin')
    monkeypatch.setattr(toolchain, 'run_process', lambda *a, **kw: (timeouts.append(kw['timeout']) or
        SimpleNamespace(returncode=0, stdout='1.32.0', stderr='')))
    manager = ToolManager(tmp_path)
    assert manager._probe_version('opengrep', tmp_path / 'opengrep', initial_install=True) == '1.32.0'
    assert manager._probe_version('opengrep', tmp_path / 'opengrep') == '1.32.0'
    assert timeouts == [120, 8]


def test_additional_languages_are_selected(pack):
    from security_runtime.rule_coverage import plan_rules
    plan = plan_rules(pack, ('a.cs','a.rb','a.rs','Dockerfile','a.py'))
    for language in ('csharp','ruby','rust','dockerfile','python'):
        assert any(language in r.engine_languages for r in plan.rules)
    assert set(plan.files) == {'a.cs','a.rb','a.rs','Dockerfile','a.py'}


def test_real_opengrep_custom_and_default_rules(tmp_path, monkeypatch):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native engine smoke check')
    from security_runtime.findings import FindingNormalizer
    monkeypatch.setenv('SECURITY_RUNTIME_OPENGREP_PATH', binary)
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')
    root = tmp_path/'project'
    root.mkdir()
    (root/'sample.py').write_text('def run(user_input):\n    return eval(user_input)\n')
    custom = tmp_path/'custom'
    custom.mkdir()
    (custom/'rule.yml').write_text('rules:\n- id: custom-eval\n  languages: [python]\n  message: Do not eval input\n  severity: ERROR\n  pattern: eval(...)\n')
    adapter = OpenGrepAdapter(ToolManager(tmp_path/'tools'))
    for rules_path in (str(custom), None):
        findings, result = adapter.scan(ScanContext(str(root),'quick',('sample.py',),rules_path=rules_path), FindingNormalizer(root))
        assert result.status == 'SUCCESS', (result.error_code,result.error,result.scanner_diagnostics)
        assert result.rule_coverage['total_executed'] > 0, result.rule_coverage
        assert findings
        assert all(f.scanner_sources == ['opengrep'] for f in findings)
        if rules_path:
            assert findings[0].technical_details['rule_id'] == 'custom-eval'


def test_real_managed_install_and_frozen_input_scan(tmp_path, monkeypatch):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native engine smoke check')
    import shutil
    import subprocess
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.storage import SQLiteStore
    from security_runtime.scan_input import scoped_request
    class LocalRelease:
        def download(self, manifest, destination):
            shutil.copyfile(binary, destination)
    manager=ToolManager(tmp_path/'tools', provider=LocalRelease())
    manager._install_binary(manager.manifest('opengrep'))
    assert manager.ensure('opengrep', offline=True).status == 'READY'
    root=tmp_path/'project'
    root.mkdir()
    subprocess.run(['git','init',str(root)], check=True, capture_output=True)
    (root/'sample.py').write_text('def run(user_input):\n    return eval(user_input)\n')
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    runtime=SecurityRuntime(registry=ScannerRegistry([OpenGrepAdapter(manager)], tool_manager=manager),
                            store=SQLiteStore(tmp_path/'scans.db'))
    result=runtime.scan(root, request=scoped_request(root,['sample.py']))
    assert result.execution_state == 'EXECUTED', result.scanner_diagnostics
    assert result.scanner_runs[0].status == 'SUCCESS', result.scanner_runs
    assert result.findings
    from dataclasses import asdict
    from security_runtime.verification import VerificationService
    original = next(f for f in result.findings if 'eval' in f.technical_details['rule_id'])
    (root/'sample.py').write_text('def run(user_input):\n    return int(user_input)\n')
    checked = VerificationService(runtime.registry).verify_many(root, [asdict(original)], asdict(result))
    assert checked[0]['status'] == 'RESOLVED', checked
    assert checked[0]['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


def test_dockerfile_only_project_enables_sast(tmp_path):
    from security_runtime.target import TargetDetector
    (tmp_path/'Dockerfile').write_text('FROM alpine:3.20\n')
    profile = TargetDetector().detect(tmp_path)
    assert 'Dockerfile' in profile.languages
    assert OpenGrepAdapter().supports(profile, ScanContext(str(tmp_path), 'quick', ('Dockerfile',)))


def test_generic_rules_enable_plain_config_project(tmp_path):
    from security_runtime.target import TargetDetector
    (tmp_path/'nginx.conf').write_text('server {}\n')
    profile = TargetDetector().detect(tmp_path)
    assert OpenGrepAdapter().supports(profile, ScanContext(str(tmp_path), 'quick', ('nginx.conf',)))


def test_generic_catalog_does_not_invent_regex_coverage(tmp_path):
    from security_runtime.rule_coverage import plan_rules
    (tmp_path/'rule.yml').write_text('rules:\n- id: plain\n  languages: [generic]\n  message: Test\n  severity: WARNING\n  pattern: danger\n')
    pack = RulePackManager().resolve(user_path=tmp_path)
    plan = plan_rules(pack, ('nginx.conf',))
    plan.observe({'time': {'rules': ['plain']}, 'paths': {'scanned': ['nginx.conf']}}, plan.files)
    assert plan.detected_languages == ('generic',)
    assert plan.coverage('SUCCESS')['status'] == 'EXECUTED'
