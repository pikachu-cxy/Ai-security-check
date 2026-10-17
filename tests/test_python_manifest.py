"""Declaration extraction and real adapter boundaries, without network or installs."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime.python_manifest import declarations, stage_python_manifests, manifest_target
from security_runtime.dependency_fallback import should_fallback
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode, ScannerRun
from security_runtime.osv import OSVDependencyAdapter
from security_runtime.processes import ProcessResult
from security_runtime.scanners import TrivyAdapter
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus


def test_declared_exact_versions_include_optional_and_build_without_evaluating_markers(tmp_path):
    manifest = tmp_path / 'pyproject.toml'
    manifest.write_text('''[build-system]
requires = ["setuptools>=77"]
[project]
dependencies = ["PyYAML==5.3.1", "six==1.17.0; python_version < '2'", "requests>=2", "remote @ https://example.invalid/pkg.whl"]
[project.optional-dependencies]
test = ["pytest==8.4.0"]
''', encoding='utf-8')
    pins, report = declarations(manifest)
    assert pins == ['PyYAML==5.3.1', 'pytest==8.4.0', 'six==1.17.0']
    assert report['unresolved_entries'] == 3 and report['conditional_entries'] == 1
    assert report['scope'] == 'DECLARED_VERSIONS_ONLY'


@pytest.mark.parametrize('body', ['[project', '[project]\ndependencies="bad"',
    '[project]\noptional-dependencies=[]', '[project]\ndependencies=[42]'])
def test_invalid_manifest_fails_without_echoing_contents(tmp_path, body):
    p = tmp_path / 'pyproject.toml'; p.write_text(body, encoding='utf-8')
    with pytest.raises(ValueError):
        declarations(p)


def test_dynamic_and_unsupported_groups_remain_unknown(tmp_path):
    p = tmp_path / 'pyproject.toml'
    p.write_text('[project]\ndynamic=["dependencies"]\n[dependency-groups]\ntest=["pytest>=8"]\n[tool.poetry.dependencies]\npython="^3.12"', encoding='utf-8')
    assert declarations(p)[1]['unresolved_entries'] == 3


def test_generation_is_private_and_does_not_overwrite_requirements(tmp_path):
    (tmp_path / 'pyproject.toml').write_text('[project]\ndependencies=["six==1.17.0"]')
    (tmp_path / 'requirements.txt').write_text('original')
    aliases, _ = stage_python_manifests(tmp_path, ['pyproject.toml'])
    generated, original = next(iter(aliases.items()))
    assert original == 'pyproject.toml' and generated.endswith('/requirements.txt')
    assert (tmp_path / 'requirements.txt').read_text() == 'original'
    assert manifest_target(str(tmp_path / generated), tmp_path, aliases) == original
    with pytest.raises(ValueError):
        manifest_target('../outside/requirements.txt', tmp_path, aliases)


def manager_fixture(tmp_path):
    manager = ToolManager(root=tmp_path / 'managed')
    manager.ensure = lambda name, **kw: ResolvedTool(name, 'fixture', name, None, ToolStatus.READY)
    manager.prepare_trivy_database = lambda *a, **kw: ToolStatus.READY
    manager.database_freshness = lambda: {'status': 'FRESH'}
    return manager


def test_trivy_extracts_pyproject_and_maps_vulnerability_to_original(tmp_path):
    p = tmp_path / 'pyproject.toml'
    original = '[project]\ndependencies=["PyYAML==5.3.1"]'
    p.write_text(original)
    context = ScanContext(str(tmp_path), ScanMode.QUICK, ('pyproject.toml',))
    def execute(args, cwd, timeout):
        scoped = Path(cwd)
        generated = next(scoped.glob('.runtime-python-*/requirements.txt'))
        assert generated.read_text() == 'PyYAML==5.3.1\n'
        assert '--offline-scan' in args and '--skip-db-update' in args
        return ProcessResult(0, json.dumps({'Results': [{'Target': str(generated), 'Type': 'pip',
            'Packages': [{'Name': 'PyYAML', 'Version': '5.3.1'}],
            'Vulnerabilities': [{'PkgName': 'PyYAML', 'InstalledVersion': '5.3.1',
                'VulnerabilityID': 'CVE-2020-14343', 'Severity': 'HIGH'}]}]}), '', 1)
    with patch('security_runtime.scanners._execute', side_effect=execute):
        found, run = TrivyAdapter(manager_fixture(tmp_path)).scan(context, FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert run.dependency_inventory['per_manifest'] == {'pyproject.toml': 1}
    assert run.dependency_inventory['unconfirmed_manifests'] == []
    assert len(found) == 1
    assert found[0].file_path == 'pyproject.toml'
    assert found[0].technical_details['manifest'] == 'pyproject.toml'
    assert p.read_text() == original


def test_successful_but_unconfirmed_inventory_uses_fallback_only_for_real_gap():
    run = ScannerRun('trivy-vuln', 'fixture', 'SUCCESS', 1, coverage_contract='PARTIAL',
        dependency_inventory={'planned_manifests': 1, 'confirmed_manifests': 0})
    assert should_fallback(run)
    run.dependency_inventory['confirmed_manifests'] = 1
    assert not should_fallback(run)  # Partial graph/freshness is not failed extraction.
    run.dependency_inventory['confirmed_manifests'] = 0
    run.error_code = 'TLS_ERROR'
    assert not should_fallback(run)


def test_osv_pyproject_uses_generated_requirements_and_retains_source_identity(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '0')
    (tmp_path / 'pyproject.toml').write_text('[project]\ndependencies=["six==1.17.0"]')
    context = ScanContext(str(tmp_path), ScanMode.RELEASE, ('pyproject.toml',))
    def execute(args, **kwargs):
        scoped = Path(kwargs['cwd'])
        generated = next(scoped.glob('.runtime-python-*/requirements.txt'))
        assert generated.read_text() == 'six==1.17.0\n'
        return ProcessResult(0, json.dumps({'results': [{'source': {'path': str(generated)},
            'packages': [{'package': {'name': 'six', 'version': '1.17.0', 'ecosystem': 'PyPI'},
                          'vulnerabilities': []}]}]}), '', 1)
    with patch('security_runtime.osv.run_process', side_effect=execute):
        _, run = OSVDependencyAdapter(manager_fixture(tmp_path)).scan(context, FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert run.dependency_inventory['per_manifest'] == {'pyproject.toml': 1}
