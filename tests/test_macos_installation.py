"""Mac installer defaults and failed-update recovery; no system changes."""
import os
from pathlib import Path
import ssl
import subprocess
import sys

import pytest

from security_runtime import install_platform, toolchain
from security_runtime.diagnostics import classify_network_error


def test_macos_ca_defaults_are_child_only(tmp_path, monkeypatch):
    ca = tmp_path / 'system-ca.pem'
    ca.touch()
    monkeypatch.setattr(install_platform, 'MACOS', True)
    monkeypatch.setattr(install_platform, 'SYSTEM_CA', ca)
    original = {'HTTPS_PROXY': 'http://proxy.invalid:8080'}
    child = install_platform.network_environment(original)
    assert child['SSL_CERT_FILE'] == child['PIP_CERT'] == child['REQUESTS_CA_BUNDLE'] == str(ca)
    assert child['HTTPS_PROXY'] == original['HTTPS_PROXY']
    assert 'SSL_CERT_FILE' not in original


@pytest.mark.parametrize('explicit', [
    {'SSL_CERT_FILE': '/explicit/missing.pem', 'PIP_CERT': '/pip/custom.pem'},
    {'SSL_CERT_DIR': '/custom/ca-directory'},
    {'REQUESTS_CA_BUNDLE': '/requests/custom.pem'},
])
def test_explicit_trust_policy_preserved(explicit, monkeypatch):
    monkeypatch.setattr(install_platform, 'MACOS', True)
    child = install_platform.network_environment(explicit)
    assert all(child[k] == v for k, v in explicit.items())
    if 'SSL_CERT_DIR' in explicit:
        assert 'SSL_CERT_FILE' not in child


def test_system_proxy_passed_to_external_children_without_global_mutation(monkeypatch):
    monkeypatch.setattr(install_platform, 'MACOS', True)
    for key in ('HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(install_platform.urllib.request, 'getproxies',
        lambda: {'https': 'http://system-proxy.invalid:8080', 'no': 'localhost'})
    child = install_platform.network_environment()
    assert child['HTTPS_PROXY'] == 'http://system-proxy.invalid:8080'
    assert child['NO_PROXY'] == 'localhost'
    assert 'HTTPS_PROXY' not in os.environ


def test_other_platform_environment_unchanged(monkeypatch):
    monkeypatch.setattr(install_platform, 'MACOS', False)
    assert install_platform.network_environment({'EXAMPLE': 'value'}) == {'EXAMPLE': 'value'}


@pytest.mark.skipif(os.name == 'nt', reason='POSIX directory aliases')
def test_default_temporary_parent_rejects_arbitrary_links(tmp_path, monkeypatch):
    actual = tmp_path / 'actual'
    actual.mkdir()
    alias = tmp_path / 'untrusted-alias'
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(install_platform.tempfile, 'gettempdir', lambda: str(alias))
    with pytest.raises(ValueError, match='links'):
        install_platform.temporary_parent()


def test_https_verifies_certificates(monkeypatch):
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    context = install_platform.download_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_ensurepip_dyld_failure_is_reported_without_raw_paths_or_secrets(monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'darwin')
    error = subprocess.CalledProcessError(-6, ['python', '-m', 'ensurepip'],
        output=b'Library not loaded: @rpath/libpython3.12.dylib\nprivate/path token=PRIVATE_VALUE')
    result = classify_network_error(error, fallback='ENGINE_PREPARATION_FAILED')
    assert result.error_code == 'PYTHON_VENV_DYLIB_MISSING'
    assert '-6' in result.diagnostic_detail
    assert 'PRIVATE_VALUE' not in str(result.to_dict())
    assert 'private/path' not in str(result.to_dict())


def test_gatekeeper_error_has_local_signing_diagnosis(monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'darwin')
    diagnostic = classify_network_error(stderr='code signature not valid for use in process: library load disallowed by system policy')
    assert diagnostic.error_code == 'MACOS_SIGNATURE_BLOCKED'


@pytest.mark.parametrize('platform,engine,timeout', [
    ('darwin', 'semgrep', 30), ('darwin', 'gitleaks', 8), ('win32', 'semgrep', 8),
])
def test_macos_semgrep_first_start_has_bounded_loading_allowance(tmp_path, monkeypatch, platform, engine, timeout):
    from security_runtime.processes import ProcessResult
    manager = toolchain.ToolManager(tmp_path)
    calls = []
    def process(args, **kwargs):
        calls.append(kwargs['timeout'])
        return ProcessResult(0, manager.versions[engine], '', 1)
    monkeypatch.setattr(toolchain.sys, 'platform', platform)
    monkeypatch.setattr(toolchain, 'run_process', process)
    monkeypatch.setattr('security_runtime.engine_probe.probe_semgrep', lambda *_args, **_kwargs: None)
    assert manager._probe_version(engine, tmp_path / engine) == manager.versions[engine]
    assert calls == [timeout]


def test_failed_python_update_preserves_existing_component(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'darwin')
    manager = toolchain.ToolManager(tmp_path / 'managed')
    final = manager.root / 'tools/fake-engine/0.1'
    final.mkdir(parents=True)
    (final / 'old-component').write_bytes(b'previous working bytes')
    def fail(*_a, **_kw):
        final.mkdir()
        (final / 'partial').write_bytes(b'partial')
        raise ValueError('synthetic installation failure')
    monkeypatch.setattr(manager, '_install_python_package', fail)
    with pytest.raises(ValueError, match='synthetic'):
        manager.install_python_package('fake-engine', '0.1', 'fake-engine==0.1')
    assert (final / 'old-component').read_bytes() == b'previous working bytes'
    assert not (final / 'partial').exists()
    assert not list(final.parent.glob('.previous-*'))


@pytest.mark.skipif(os.name == 'nt', reason='POSIX directory aliases')
def test_delivery_probe_resolves_only_its_private_temporary_directory(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from security_runtime.delivery import StableDelivery
    from security_runtime.hook_state import no_links
    monkeypatch.setattr(sys, 'platform', 'darwin')
    actual = tmp_path / 'actual'
    actual.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(actual, target_is_directory=True)
    @contextmanager
    def temporary(**_kwargs):
        yield str(alias)
    def probe(runtime, home, environment):
        no_links(home)
        assert home.is_relative_to(actual)
        return {'status': 'OK'}
    monkeypatch.setattr('security_runtime.delivery.tempfile.TemporaryDirectory', temporary)
    monkeypatch.setattr('security_runtime.codex_integration.probe_runtime', probe)
    assert StableDelivery(tmp_path / 'delivery')._probe(tmp_path / 'bundle')['status'] == 'OK'


def test_windows_python_install_keeps_original_path_without_transaction(tmp_path, monkeypatch):
    manager = toolchain.ToolManager(tmp_path / 'managed')
    final = manager.root / 'engines/semgrep/1.178.0'
    final.mkdir(parents=True)
    marker = final / 'existing'
    marker.write_text('old component')
    calls = []
    def original(tool, version, requirement, **kwargs):
        assert marker.read_text() == 'old component'
        assert not list(final.parent.glob('.previous-*'))
        calls.append((tool, version, requirement, kwargs))
        return final
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr(manager, '_install_python_package', original)
    assert manager.install_python_package('semgrep', '1.178.0', 'semgrep==1.178.0') == final
    assert len(calls) == 1
    assert not (manager.root / '.python-install-locks').exists()


def test_windows_children_keep_existing_environment_without_macos_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'win32')
    for key in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'PIP_CERT'):
        monkeypatch.delenv(key, raising=False)
    def forbidden():
        raise AssertionError('macOS defaults must not run on Windows')
    monkeypatch.setattr(toolchain, 'network_environment', forbidden)
    original = dict(os.environ)
    executable = tmp_path / 'python.exe'
    child = toolchain.tool_environment(executable)
    expected = dict(original, PATH=str(executable.resolve().parent) + os.pathsep + original.get('PATH', ''))
    expected.pop('PYTHONHOME', None)
    expected.pop('PYTHONPATH', None)
    assert child == expected
    assert dict(os.environ) == original


@pytest.mark.parametrize('stderr', [
    'code signature not valid for use in process: library load disallowed by system policy',
    'Library not loaded: @rpath/libpython3.12.dylib',
])
def test_windows_error_classification_keeps_original_fallback(monkeypatch, stderr):
    monkeypatch.setattr(sys, 'platform', 'win32')
    result = classify_network_error(stderr=stderr, fallback='ENGINE_PREPARATION_FAILED')
    assert result.error_code == 'ENGINE_PREPARATION_FAILED'


@pytest.mark.skipif(os.name == 'nt', reason='POSIX links used to test platform dispatch')
def test_windows_delivery_probe_keeps_strict_temporary_path_validation(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from security_runtime.delivery import StableDelivery
    actual = tmp_path / 'actual'
    actual.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(actual, target_is_directory=True)
    @contextmanager
    def temporary(**_kwargs):
        yield str(alias)
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr('security_runtime.delivery.tempfile.TemporaryDirectory', temporary)
    with pytest.raises(ValueError, match='links'):
        StableDelivery(tmp_path / 'delivery')._probe(tmp_path / 'bundle')
