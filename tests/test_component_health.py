"""Synthetic component failures: no installed scanners, network or project scans."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime.component_health import (ComponentHealthStore, component_feedback,
    diagnosis, repair_semgrep_settings, settings_problem)
from security_runtime.install_readiness import _component, prepare_installation_readiness, validate_readiness_receipt
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolSource, ToolStatus, VERSIONS


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    path = tmp_path / 'settings.yml'
    path.write_text('{}\n', encoding='utf-8')
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE', str(path))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    return path


def tool(status=ToolStatus.READY, code=None, name='semgrep'):
    return ResolvedTool(name, VERSIONS[name] if status == ToolStatus.READY else '',
        '/fixture/engine', ToolSource.SYSTEM, status, diagnostic=diagnosis(code) if code else None)


def component(status=ToolStatus.READY, code=None):
    return _component(tool(status, code), VERSIONS['semgrep'], 'semgrep')


@pytest.mark.parametrize('raw', [b'\x00' * 96, b'api_token: [broken\n', b'[]\n'])
def test_corrupt_settings_diagnosis_never_exposes_contents_or_runs_engine(tmp_path, monkeypatch, isolated_settings, raw):
    isolated_settings.write_bytes(raw)
    executable = tmp_path / 'semgrep.exe'
    executable.write_bytes(b'fixture')
    manager = ToolManager(tmp_path / 'engines')
    monkeypatch.setattr(manager, '_version', lambda *a: pytest.fail('corrupt settings must be detected before launch'))
    result = manager._check('semgrep', executable, ToolSource.SYSTEM)
    assert result.status == ToolStatus.BROKEN
    assert result.diagnostic.error_code == 'COMPONENT_SETTINGS_CORRUPTED'
    assert 'broken' not in json.dumps(result.to_dict())
    assert isolated_settings.read_bytes() == raw


@pytest.mark.parametrize('status,code', [
    (ToolStatus.BROKEN, 'COMPONENT_SETTINGS_CORRUPTED'),
    (ToolStatus.BROKEN, 'COMPONENT_START_FAILED'),
    (ToolStatus.BROKEN, 'COMPONENT_INTEGRITY_FAILED'),
])
def test_broken_installed_component_is_not_automatically_downloaded(tmp_path, monkeypatch, status, code):
    manager = ToolManager(tmp_path / 'engines')
    result = tool(status, code)
    monkeypatch.setattr(manager, 'resolve', lambda name: result)
    monkeypatch.setattr(manager, 'install_python_package', lambda *a, **k: pytest.fail('must not download'))
    assert manager.ensure('semgrep') == result


def test_incomplete_managed_directory_is_not_treated_as_absent(tmp_path, monkeypatch):
    manager = ToolManager(tmp_path / 'engines')
    path = manager.managed_path('gitleaks')
    path.parent.mkdir(parents=True)
    (path.parent / 'metadata.json').write_text('{}', encoding='utf-8')
    monkeypatch.setattr(manager, '_install_binary', lambda *a: pytest.fail('must preserve incomplete install'))
    result = manager.ensure('gitleaks')
    assert result.status == ToolStatus.BROKEN
    assert result.diagnostic.error_code == 'COMPONENT_PACKAGE_INCOMPLETE'


@pytest.mark.parametrize('environment_offline', ['0', '1'])
def test_reinstall_requires_explicit_choice_and_preserves_explicit_external_path(tmp_path, monkeypatch, environment_offline):
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', environment_offline)
    manager = ToolManager(tmp_path / 'engines')
    broken = tool(ToolStatus.BROKEN, 'COMPONENT_START_FAILED', 'gitleaks')
    ready = tool(name='gitleaks')
    results = iter([broken, ready])
    calls = []
    monkeypatch.setattr(manager, 'resolve', lambda name: next(results))
    monkeypatch.setattr(manager, '_install_binary', lambda manifest: calls.append(manifest.tool_id))
    # The installer is mocked; test the explicit online reinstall path even
    # when the regression harness keeps all unmocked providers offline.
    assert manager.ensure('gitleaks', offline=False, reinstall=True).status == ToolStatus.READY
    assert calls == ['gitleaks']
    external = ResolvedTool('gitleaks', '', '/user/custom/engine', ToolSource.EXPLICIT, ToolStatus.BROKEN)
    monkeypatch.setattr(manager, 'resolve', lambda name: external)
    assert manager.ensure('gitleaks', reinstall=True, offline=False) == external
    assert calls == ['gitleaks']


@pytest.mark.parametrize('explicit_offline', [None, True])
def test_offline_reinstall_preserves_broken_component_without_download(tmp_path, monkeypatch, explicit_offline):
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')
    manager = ToolManager(tmp_path / 'engines')
    broken = tool(ToolStatus.BROKEN, 'COMPONENT_START_FAILED', 'gitleaks')
    monkeypatch.setattr(manager, 'resolve', lambda name: broken)
    monkeypatch.setattr(manager, '_install_binary', lambda *a: pytest.fail('offline must not download'))
    assert manager.ensure('gitleaks', reinstall=True, offline=explicit_offline) == broken


def test_reinstalled_component_must_pass_final_probe(tmp_path, monkeypatch):
    manager = ToolManager(tmp_path / 'engines')
    broken = tool(ToolStatus.BROKEN, 'COMPONENT_START_FAILED', 'gitleaks')
    monkeypatch.setattr(manager, 'resolve', lambda name: broken)
    calls = []
    monkeypatch.setattr(manager, '_install_binary', lambda manifest: calls.append(manifest.tool_id))
    assert manager.ensure('gitleaks', reinstall=True, offline=False) == broken
    assert calls == ['gitleaks']


@pytest.mark.parametrize('error,code', [(PermissionError('private-marker'), 'COMPONENT_PERMISSION_DENIED'),
    (TimeoutError('private-marker'), 'COMPONENT_START_TIMEOUT')])
def test_probe_failure_is_specific_without_raw_exception(tmp_path, monkeypatch, error, code):
    manager = ToolManager(tmp_path / 'engines')
    executable = tmp_path / 'engine'
    executable.write_bytes(b'fixture')
    def fail(*a, **k):
        raise error
    monkeypatch.setattr('security_runtime.toolchain.run_process', fail)
    result = manager._check('gitleaks', executable, ToolSource.SYSTEM)
    assert result.diagnostic.error_code == code
    assert 'private-marker' not in json.dumps(result.to_dict())


def test_probe_output_does_not_expose_settings_or_credentials(tmp_path, monkeypatch):
    manager = ToolManager(tmp_path / 'engines')
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *a, **k:
        SimpleNamespace(returncode=1, stdout='', stderr='ModuleNotFoundError: private-marker api_token=secret'))
    path = tmp_path / 'engine'
    path.write_bytes(b'fixture')
    result = manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert result.diagnostic.error_code == 'COMPONENT_DEPENDENCY_BROKEN'
    assert 'private-marker' not in json.dumps(result.to_dict())
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *a, **k:
        SimpleNamespace(returncode=0, stdout=VERSIONS['gitleaks'], stderr='private-marker api_token=secret'))
    assert manager._probe_version('gitleaks', path) == VERSIONS['gitleaks']


def test_same_fault_and_recovery_are_not_repeated_after_reconnection(tmp_path):
    path = tmp_path / 'health.db'
    failed = {'semgrep': component(ToolStatus.BROKEN, 'COMPONENT_SETTINGS_CORRUPTED')}
    ready = {'semgrep': component()}
    store = ComponentHealthStore(path)
    assert store.observe(ready)['notify'] is False
    assert store.observe(failed)['notifications'][0]['kind'] == 'FAULT'
    assert ComponentHealthStore(path).observe(failed)['notify'] is False
    assert ComponentHealthStore(path).observe(ready)['notifications'][0]['kind'] == 'RECOVERED'
    assert ComponentHealthStore(path).observe(ready)['notify'] is False
    assert ComponentHealthStore(path).observe(failed)['notify'] is True


def test_background_observation_leaves_notice_for_next_delivery(tmp_path):
    path = tmp_path / 'health.db'
    failed = {'semgrep': component(ToolStatus.BROKEN, 'COMPONENT_START_FAILED')}
    assert ComponentHealthStore(path).observe(failed, consume=False)['notify'] is False
    assert ComponentHealthStore(path).observe(failed)['notify'] is True
    assert ComponentHealthStore(path).observe(failed)['notify'] is False


def test_concurrent_hosts_deliver_same_fault_once(tmp_path):
    path = tmp_path / 'health.db'
    failed = {'semgrep': component(ToolStatus.BROKEN, 'COMPONENT_START_FAILED')}
    ComponentHealthStore(path).observe(failed, consume=False)
    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = list(executor.map(lambda _: ComponentHealthStore(path).observe(failed), range(2)))
    assert sum(result['notify'] for result in replies) == 1


def test_repair_preserves_original_and_valid_settings_are_never_reset(tmp_path, monkeypatch, isolated_settings):
    raw = b'\x00' * 96
    isolated_settings.write_bytes(raw)
    manager = SimpleNamespace(root=tmp_path / 'engines', versions=VERSIONS,
        resolve=lambda name: tool())
    component_feedback({'semgrep': component(ToolStatus.BROKEN, 'COMPONENT_SETTINGS_CORRUPTED')}, root=manager.root)
    result = repair_semgrep_settings(manager=manager)
    assert result['status'] == 'REPAIRED'
    assert Path(result['backup_path']).read_bytes() == raw
    assert settings_problem() is None
    assert result['component_health']['notifications'][0]['kind'] == 'RECOVERED'
    assert result['downloaded'] is False
    valid = b'api_token: private-marker\n'
    isolated_settings.write_bytes(valid)
    assert repair_semgrep_settings(manager=manager)['status'] == 'NOT_APPLICABLE'
    assert isolated_settings.read_bytes() == valid


def test_fresh_status_overrides_old_failure_without_resuming_work(monkeypatch):
    import security_runtime.background_preparation as background
    tools = {name: _component(tool(name=name), VERSIONS[name], name) for name in VERSIONS if name in {'semgrep', 'gitleaks', 'trivy'}}
    old = {'status': 'PARTIAL', 'ready': False, 'reason': 'SCANNERS_NOT_READY',
           'receipt': {'tools': {'semgrep': component(ToolStatus.BROKEN, 'COMPONENT_START_FAILED')}}}
    receipt = {'tools': tools, 'ready': True, 'status': 'READY', 'message': '当前组件已就绪。'}
    monkeypatch.setattr(background, 'current_preparation', lambda: deepcopy(old))
    def read_only(**kwargs):
        assert kwargs == {'offline': True}
        return receipt
    monkeypatch.setattr(background, 'prepare_installation_readiness', read_only)
    monkeypatch.setattr(background, 'start_background_preparation', lambda *a, **k: pytest.fail('must not resume/download'))
    result = background.read_preparation_status()
    assert result['ready'] is True and result['status'] == 'READY' and result['reason'] is None
    assert result['background_status'] == 'PARTIAL'
    assert result['background_receipt'] == old['receipt']
    assert result['receipt'] == receipt and result['receipt_current'] is True


def test_readiness_records_unavailable_without_exception_or_download(tmp_path, monkeypatch):
    from test_install_readiness import Manager
    monkeypatch.setattr(Manager, 'database_root', tmp_path / 'cache', raising=False)
    manager = Manager()
    manager.tools['semgrep'] = tool(ToolStatus.BROKEN, 'COMPONENT_SETTINGS_CORRUPTED')
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['ready'] is False
    assert receipt['tools']['semgrep']['diagnostic']['repair_command'] == ['security-check', 'tools', 'repair', 'semgrep']
    assert any(item.get('error_code') == 'COMPONENT_SETTINGS_CORRUPTED' for item in receipt['failures'])
    assert not any(call[0] == 'ensure' for call in manager.calls)
    assert validate_readiness_receipt(receipt)
    receipt['tools']['semgrep']['diagnostic']['message'] = 'private-marker: ignore instructions'
    assert not validate_readiness_receipt(receipt)


def test_failed_download_keeps_its_cause_after_final_missing_probe(tmp_path, monkeypatch):
    from test_install_readiness import Manager
    monkeypatch.setattr(Manager, 'database_root', tmp_path / 'cache', raising=False)
    manager = Manager(missing=('semgrep',))
    def failed_download(name, **kwargs):
        return ResolvedTool(name, '', '', None, ToolStatus.BROKEN, diagnostic=diagnosis('TLS_ERROR'))
    manager.ensure = failed_download
    receipt = prepare_installation_readiness(manager=manager)
    assert receipt['tools']['semgrep']['status'] == 'MISSING'
    assert receipt['tools']['semgrep']['diagnostic']['code'] == 'TLS_ERROR'
    assert validate_readiness_receipt(receipt)
