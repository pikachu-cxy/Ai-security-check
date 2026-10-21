"""Probe faults are product faults, not proof that a scanner is broken."""
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace

import pytest

from security_runtime.component_probe import capture_probe_failure, valid_probe
from security_runtime.install_readiness import _component, prepare_installation_readiness, validate_readiness_receipt
from security_runtime.progress import ScanCancelled
from security_runtime.toolchain import ToolManager, ToolSource, ToolStatus, VERSIONS


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE', str(tmp_path / 'settings.yml'))
    monkeypatch.setattr('security_runtime.toolchain.discover_plugin_directory', lambda *a: None)
    return ToolManager(tmp_path / 'engines')


def broken_cache(monkeypatch):
    # Reproduce an actual AttributeError inside product cache lookup. This
    # fixture is not a claim about the historical connection's unknown cause.
    bucket = SimpleNamespace(values=[], lock=threading.RLock())
    monkeypatch.setattr('security_runtime.scanner_cache.preparation_bucket', lambda *a: bucket)
    return bucket


def test_cache_attribute_error_uses_one_version_child_and_preserves_provenance(manager, tmp_path, monkeypatch):
    path = tmp_path / 'gitleaks'
    path.write_bytes(b'fixture')
    bucket = broken_cache(monkeypatch)
    calls = []
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda args, **kw:
        calls.append((args, kw)) or SimpleNamespace(returncode=0, stdout=VERSIONS['gitleaks'], stderr=''))
    result = manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert result.status == ToolStatus.READY
    assert result.probe['exception_type'] == 'AttributeError'
    assert result.probe['attribute'] == 'get'
    assert result.probe['recovery'] == 'READY'
    assert valid_probe(result.probe)
    assert any(frame['module'] == 'security_runtime.toolchain' and frame['function'] == '_version'
               for frame in result.probe['frames'])
    assert len(calls) == 1 and calls[0][0] == [str(path.resolve()), '--version']
    assert calls[0][1]['timeout'] == 8 and calls[0][1]['max_output'] == 16_000
    assert bucket.values == []  # No resetting or writing a false positive cache.
    assert _component(result, VERSIONS['gitleaks'])['probe'] == result.probe


@pytest.mark.parametrize('outcome', ['exception', 'bad_exit', 'mismatch', 'changed'])
def test_failed_recovery_does_not_hide_original_fault_or_start_install(manager, tmp_path, monkeypatch, outcome):
    path = tmp_path / 'engine'
    path.write_bytes(b'fixture')
    broken_cache(monkeypatch)
    calls = []
    def run(*a, **kw):
        calls.append(a)
        if outcome == 'exception':
            raise AttributeError('private-secret-marker')
        if outcome == 'changed':
            path.write_bytes(b'changed')
        return SimpleNamespace(returncode=1 if outcome == 'bad_exit' else 0,
            stdout='9.99.99' if outcome == 'mismatch' else VERSIONS['gitleaks'], stderr='private-secret-marker')
    monkeypatch.setattr('security_runtime.toolchain.run_process', run)
    monkeypatch.setattr(manager, '_install_binary', lambda *a: pytest.fail('must not install'))
    result = manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert len(calls) == 1
    assert result.status == (ToolStatus.VERSION_MISMATCH if outcome == 'mismatch' else ToolStatus.BROKEN)
    assert result.probe['recovery'] == {'exception': 'FAILED', 'bad_exit': 'FAILED',
        'mismatch': 'VERSION_MISMATCH', 'changed': 'IDENTITY_CHANGED'}[outcome]
    if outcome != 'mismatch':
        assert result.diagnostic.error_code == 'RUNTIME_PROBE_FAILED'
        assert '组件已安装，但启动检查失败' not in result.diagnostic.error_summary
    assert 'private-secret-marker' not in json.dumps(result.to_dict())


def test_known_startup_failure_and_cancellation_do_not_trigger_runtime_recovery(manager, tmp_path, monkeypatch):
    path = tmp_path / 'engine'
    path.write_bytes(b'fixture')
    calls = []
    def fail(*a, **kw):
        calls.append(a)
        raise PermissionError('private-secret-marker')
    monkeypatch.setattr('security_runtime.toolchain.run_process', fail)
    result = manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert result.diagnostic.error_code == 'COMPONENT_PERMISSION_DENIED'
    assert result.probe is None and len(calls) == 1
    monkeypatch.setattr(manager, '_version', lambda *a: (_ for _ in ()).throw(ScanCancelled()))
    with pytest.raises(ScanCancelled):
        manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert len(calls) == 1


def test_resolve_exception_is_not_component_damage_and_never_downloads(manager, monkeypatch):
    def fail(*a):
        raise AttributeError('private-secret-marker')
    monkeypatch.setattr(manager, 'resolve', fail)
    monkeypatch.setattr(manager, 'ensure', lambda *a, **kw: pytest.fail('must not install'))
    receipt = prepare_installation_readiness(manager=manager)
    assert validate_readiness_receipt(receipt)
    for component in receipt['tools'].values():
        assert component['diagnostic']['code'] == 'RUNTIME_PROBE_FAILED'
        assert component['diagnostic']['automatic_download'] is False
        assert component['probe']['operation'] == 'RESOLVE'
        assert valid_probe(component['probe'])
        assert component['probe']['fault_id'] in receipt['message']
    assert 'private-secret-marker' not in json.dumps(receipt)
    assert not receipt['ready']


def test_diagnostic_omits_raw_attribute_source_locals_and_exception_text():
    marker = 'private_secret_marker'
    try:
        getattr(None, marker)
    except AttributeError as exc:
        value = capture_probe_failure(exc, 'RESOLVE')
    assert valid_probe(value)
    assert value['attribute'] == '' and value['frames'] == []
    assert marker not in json.dumps(value)
    assert 'NoneType' not in json.dumps(value)
    forged = deepcopy(value)
    forged['frames'] = [{'module': '/private/path.py', 'function': 'x', 'line': 1}]
    assert not valid_probe(forged)
    forged = deepcopy(value)
    forged['exception_text'] = marker
    assert not valid_probe(forged)
    assert not valid_probe(value | {'operation': []})


def test_same_probe_fault_is_quiet_but_new_fault_is_delivered(tmp_path):
    from security_runtime.component_health import ComponentHealthStore
    from security_runtime.install_readiness import _probe_failed
    store = ComponentHealthStore(tmp_path / 'health.db')
    first = {'gitleaks': _component(_probe_failed('gitleaks', AttributeError('private-marker'), 'RESOLVE'), VERSIONS['gitleaks'])}
    another = {'gitleaks': _component(_probe_failed('gitleaks', TypeError('private-marker'), 'RESOLVE'), VERSIONS['gitleaks'])}
    notification = store.observe(first)
    assert notification['notify'] and first['gitleaks']['probe']['fault_id'] in notification['message']
    assert not store.observe(first)['notify']
    assert store.observe(another)['notify']
    assert 'private-marker' not in json.dumps(notification)


def test_known_configuration_error_keeps_its_diagnosis(manager, monkeypatch):
    from security_runtime.component_health import diagnosis
    from security_runtime.diagnostics import DiagnosticError
    def fail(*a):
        raise DiagnosticError(diagnosis('CONFIG_CORRUPTED'))
    monkeypatch.setattr(manager, 'resolve', fail)
    receipt = prepare_installation_readiness(manager=manager, offline=True)
    assert validate_readiness_receipt(receipt)
    assert all(component['diagnostic']['code'] == 'CONFIG_CORRUPTED' and 'probe' not in component
        for component in receipt['tools'].values())


def test_recovery_uses_normal_environment_without_saving_it(manager, tmp_path, monkeypatch):
    path = tmp_path / 'engine'
    path.write_bytes(b'fixture')
    broken_cache(monkeypatch)
    marker = 'private_environment_marker'
    environment = {'APP_TOKEN': marker}
    calls = []
    monkeypatch.setattr('security_runtime.toolchain.tool_environment', lambda path: environment.copy())
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda args, **kw:
        calls.append(kw) or SimpleNamespace(returncode=0, stdout=VERSIONS['gitleaks'], stderr=''))
    result = manager._check('gitleaks', path, ToolSource.SYSTEM)
    assert result.status == ToolStatus.READY and calls[0]['env'] == environment
    assert marker not in json.dumps(result.to_dict())


def test_long_lived_real_mcp_status_recovers_transient_probe_without_scanning(tmp_path):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    script = tmp_path / 'probe_server.py'
    script.write_text('''
import sys, threading
from pathlib import Path
from types import SimpleNamespace
from security_runtime import toolchain as t, scanner_cache
from security_runtime import engine_probe
# Python stands in for every engine here; test cache recovery, not native scans.
engine_probe.probe_semgrep = lambda *a: None
original_init = t.ToolManager.__init__
original_bucket = scanner_cache.preparation_bucket
injected = False
def init(self, *a, **kw):
    original_init(self, *a, **kw)
    self.versions = {name: '.'.join(map(str, sys.version_info[:3])) for name in t.VERSIONS}
def resolve(self, name):
    return self._check(name, Path(sys.executable), t.ToolSource.EXPLICIT)
def bucket(kind, scope=''):
    global injected
    if kind == 'version:gitleaks' and not injected:
        injected = True
        return SimpleNamespace(values=[], lock=threading.RLock())
    return original_bucket(kind, scope)
t.ToolManager.__init__ = init
t.ToolManager.resolve = resolve
t.ToolManager._probe_identity = lambda self, name, path, **kwargs: (name, str(path), path.stat().st_mtime_ns)
scanner_cache.preparation_bucket = bucket
from security_runtime.cli import main
main(['mcp'])
''', encoding='utf-8')
    env = dict(os.environ, SECURITY_RUNTIME_DATA_DIR=str(tmp_path / 'data'),
        SECURITY_RUNTIME_STATE_DIR=str(tmp_path / 'state'), SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_MCP_SELF_TEST='1', SECURITY_RUNTIME_WORKSPACE=str(tmp_path),
        SEMGREP_SETTINGS_FILE=str(tmp_path / 'settings.yml'), PYTHONUTF8='1',
        SECURITY_RUNTIME_TRIVY_CACHE_DIR=str(tmp_path / 'trivy'), TRIVY_CACHE_DIR=str(tmp_path / 'trivy'))
    async def run():
        params = StdioServerParameters(command=sys.executable, args=[str(script)], env=env, cwd=tmp_path)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await asyncio.wait_for(client.initialize(), 25)
                    receipts = []
                    for _ in range(4):
                        value = await asyncio.wait_for(client.call_tool('get_scan_preparation_status', {}), 30)
                        assert not value.isError
                        data = value.structuredContent or json.loads(value.content[0].text)
                        receipt = data['current_readiness']
                        assert all(component['ready'] for component in receipt['tools'].values())
                        assert validate_readiness_receipt(receipt)
                        assert not data.get('scanner_run')
                        receipts.append(receipt)
                        info = await client.call_tool('get_runtime_info', {})
                        assert not info.isError
                    diagnostic = receipts[0]['tools']['gitleaks']['probe']
                    assert diagnostic['attribute'] == 'get' and diagnostic['recovery'] == 'READY'
                    assert all('probe' not in receipt['tools']['gitleaks'] for receipt in receipts[1:])
            errors.seek(0)
            assert 'Traceback' not in errors.read()
    asyncio.run(run())
