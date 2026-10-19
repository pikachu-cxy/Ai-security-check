"""Native scratch space and startup proof: no project execution or network."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from security_runtime import engine_environment as module
from security_runtime.diagnostics import DiagnosticError, classify_network_error
from security_runtime.engine_environment import engine_environment
from security_runtime.engine_probe import probe_semgrep


def test_other_engines_and_non_windows_keep_their_environment(monkeypatch):
    original = {'TEMP': 'original', 'TMPDIR': 'original-other'}
    for engine in ('gitleaks', 'trivy', 'osv-scanner'):
        with engine_environment(engine, original) as child:
            assert child == original and child is not original
    monkeypatch.setattr(module, 'WINDOWS', False)
    with engine_environment('semgrep', original) as child:
        assert child == original and child is not original


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch contract')
def test_long_unicode_temp_is_replaced_only_in_child_and_cleaned(tmp_path, monkeypatch):
    old = str(tmp_path / ('长临时目录' * 12))
    for name in ('TEMP', 'TMP', 'TMPDIR'):
        monkeypatch.setenv(name, old)
    original = dict(os.environ)
    original.pop('SECURITY_RUNTIME_ENGINE_TEMP_ROOT', None)
    with engine_environment('semgrep', original, workspace=tmp_path) as child:
        directory = Path(child['TEMP'])
        assert directory.is_dir()
        assert len(str(directory).encode('utf-8')) <= module.SEMGREP_TEMP_PATH_BYTES
        assert child['TEMP'] == child['TMP'] == child['TMPDIR']
        assert not directory.resolve().is_relative_to(tmp_path.resolve())
        (directory / 'private.txt').write_text('synthetic')
        assert all(os.environ[name] == old for name in ('TEMP', 'TMP', 'TMPDIR'))
    assert not directory.exists()
    assert original['TEMP'] == old


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch contract')
def test_concurrent_invocations_have_independent_directories(tmp_path):
    from threading import Barrier
    barrier = Barrier(4)
    def invoke(_):
        with engine_environment('semgrep', {}, workspace=tmp_path) as child:
            directory = Path(child['TEMP'])
            (directory / 'owned.txt').write_text(directory.name)
            barrier.wait(timeout=10)
            assert (directory / 'owned.txt').read_text() == directory.name
            return directory
    with ThreadPoolExecutor(max_workers=4) as pool:
        directories = list(pool.map(invoke, range(4)))
    assert len(set(directories)) == 4
    assert not any(path.exists() for path in directories)


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch contract')
def test_scratch_cleanup_on_engine_failure(tmp_path):
    with pytest.raises(RuntimeError, match='synthetic failure'):
        with engine_environment('semgrep', {}, workspace=tmp_path) as child:
            directory = Path(child['TEMP'])
            raise RuntimeError('synthetic failure')
    assert not directory.exists()


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch identity')
def test_cleanup_rejects_replaced_directory_without_removing_either(tmp_path):
    directory = moved = None
    try:
        with pytest.raises(DiagnosticError):
            with engine_environment('semgrep', {}, workspace=tmp_path) as child:
                directory = Path(child['TEMP'])
                moved = directory.with_name(directory.name + '-held')
                directory.rename(moved)
                module.windows_private_directory(directory)
        assert directory.is_dir() and moved.is_dir()
    finally:
        # Both are empty, test-created directories; never recurse into a root.
        if directory is not None and directory.exists():
            directory.rmdir()
        if moved is not None and moved.exists():
            moved.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch contract')
@pytest.mark.parametrize('kind', ['relative', 'workspace', 'missing', 'long', 'linked'])
def test_invalid_parent_fails_closed_without_creation(tmp_path, monkeypatch, kind):
    parent = tmp_path
    workspace = tmp_path if kind == 'workspace' else None
    environment = {'SECURITY_RUNTIME_ENGINE_TEMP_ROOT': str(parent)}
    if kind == 'relative':
        environment['SECURITY_RUNTIME_ENGINE_TEMP_ROOT'] = 'relative'
    elif kind == 'missing':
        environment['SECURITY_RUNTIME_ENGINE_TEMP_ROOT'] = str(parent / 'absent')
    elif kind == 'linked':
        def reject(_):
            raise ValueError('PRIVATE_PATH_MUST_NOT_ESCAPE')
        monkeypatch.setattr(module, 'no_links', reject)
    else:
        monkeypatch.setattr(module, 'SEMGREP_TEMP_PATH_BYTES', 1)
        monkeypatch.setattr(module, '_short_path', lambda path: path)
    monkeypatch.setattr(module, 'windows_private_directory',
        lambda _: pytest.fail('invalid parent must not create scratch'))
    with pytest.raises(DiagnosticError) as caught:
        with engine_environment('semgrep', environment, workspace=workspace):
            pytest.fail('invalid parent was accepted')
    assert caught.value.diagnostic.error_code in {'ENGINE_TEMP_PATH_TOO_LONG', 'ENGINE_TEMP_DIRECTORY_UNAVAILABLE'}
    assert 'PRIVATE_' not in json.dumps(caught.value.diagnostic.to_dict())


@pytest.mark.skipif(os.name != 'nt', reason='Windows native scratch contract')
def test_denied_creation_has_safe_actionable_diagnostic(tmp_path, monkeypatch):
    def denied(_):
        raise PermissionError('PRIVATE_OS_TEXT')
    monkeypatch.setattr(module, 'windows_private_directory', denied)
    with pytest.raises(DiagnosticError) as caught:
        with engine_environment('semgrep', {}, workspace=tmp_path):
            pytest.fail('denied creation was accepted')
    assert caught.value.diagnostic.error_code == 'ENGINE_TEMP_DIRECTORY_UNAVAILABLE'
    assert 'PRIVATE_' not in str(caught.value)


@pytest.mark.parametrize('text,code', [
    ('Unix.EACCES socketpair', 'ENGINE_LOCAL_IPC_DENIED'),
    ('socketpair: Access is denied', 'ENGINE_LOCAL_IPC_DENIED'),
    ('socketpair: 传递给系统调用的数据区域太小。', 'ENGINE_LOCAL_IPC_PATH_LIMIT'),
    ('socketpair: The data area passed to a system call is too small.', 'ENGINE_LOCAL_IPC_PATH_LIMIT'),
    ('socketpair: unknown native failure', 'ENGINE_LOCAL_IPC_FAILED'),
])
def test_local_ipc_diagnosis_does_not_become_proxy_or_download_error(text, code):
    result = classify_network_error(stderr=text + '\nProxy configured; failed api_token=PRIVATE_CANARY', return_code=2)
    assert result.error_code == code
    assert result.source == '' and 'PRIVATE_CANARY' not in json.dumps(result.to_dict())
    assert 'reinstall' in result.remediation and 'HTTPS_PROXY' not in result.remediation


@pytest.fixture
def synthetic_probe(tmp_path, monkeypatch):
    import security_runtime.engine_probe as probe
    @contextmanager
    def environment(*args, **kwargs):
        yield {'TEMP': str(tmp_path), 'SEMGREP_SEND_METRICS': 'off'}
    monkeypatch.setattr(probe, 'engine_environment', environment)
    return probe


def test_probe_requires_real_native_output_and_uses_only_synthetic_inputs(synthetic_probe, tmp_path, monkeypatch):
    def run(args, **kwargs):
        assert kwargs['cwd'] == str(tmp_path) and kwargs['timeout'] == 8
        assert '--metrics' in args and 'off' in args
        assert (tmp_path / 'probe.py').read_text() == 'runtime_engine_probe()\n'
        return SimpleNamespace(return_code=0, stdout=json.dumps({'results': [
            {'check_id': 'runtime-engine-probe', 'path': 'probe.py', 'start': {'line': 1}}], 'errors': []}), stderr='')
    monkeypatch.setattr(synthetic_probe, 'run_process', run)
    probe_semgrep('synthetic-engine', {})


@pytest.mark.parametrize('output', ['not json', '{}', '[]', '{"results":[]}',
    '{"results":[{"check_id":"wrong"}]}'])
def test_version_or_exit_zero_alone_cannot_pass_execution_probe(synthetic_probe, monkeypatch, output):
    monkeypatch.setattr(synthetic_probe, 'run_process', lambda *a, **k:
        SimpleNamespace(return_code=0, stdout=output, stderr='PRIVATE_RAW_OUTPUT'))
    with pytest.raises(DiagnosticError) as caught:
        probe_semgrep('synthetic-engine', {})
    assert caught.value.diagnostic.error_code == 'ENGINE_EXECUTION_PROBE_FAILED'
    assert 'PRIVATE_' not in str(caught.value)


def test_failed_native_probe_keeps_ipc_reason(synthetic_probe, monkeypatch):
    monkeypatch.setattr(synthetic_probe, 'run_process', lambda *a, **k:
        SimpleNamespace(return_code=2, stdout='', stderr='Unix.EACCES socketpair PRIVATE_RAW_OUTPUT'))
    with pytest.raises(DiagnosticError) as caught:
        probe_semgrep('synthetic-engine', {})
    assert caught.value.diagnostic.error_code == 'ENGINE_LOCAL_IPC_DENIED'


def test_socketpair_filename_does_not_hide_a_real_network_error():
    result = classify_network_error(stderr='socketpair.py: HTTP 403 Forbidden', return_code=2)
    assert result.error_code == 'HTTP_403'


@pytest.mark.skipif(os.name != 'nt', reason='Windows engine startup gate')
def test_successful_version_cannot_hide_failed_native_probe(tmp_path, monkeypatch):
    from security_runtime.toolchain import ToolManager, ToolStatus, ToolSource, VERSIONS
    from security_runtime.component_health import component_issue, diagnosis
    path = tmp_path / 'synthetic-engine.exe'
    path.write_bytes(b'fixture only')
    manager = ToolManager(tmp_path / 'engines')
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE', str(tmp_path / 'absent-settings.yml'))
    monkeypatch.setattr('security_runtime.toolchain.run_process', lambda *a, **k:
        SimpleNamespace(returncode=0, stdout=VERSIONS['semgrep'], stderr=''))
    def denied(*args):
        raise DiagnosticError(diagnosis('ENGINE_LOCAL_IPC_DENIED'))
    monkeypatch.setattr('security_runtime.engine_probe.probe_semgrep', denied)
    result = manager._check('semgrep', path, ToolSource.SYSTEM)
    assert result.status == ToolStatus.BROKEN
    assert result.diagnostic.error_code == 'ENGINE_LOCAL_IPC_DENIED'
    assert component_issue('semgrep', result.status, result.diagnostic)['automatic_download'] is False


@pytest.mark.skipif(os.name != 'nt', reason='Windows native engine integration')
@pytest.mark.parametrize('segment', ['long-temp-' * 8, '长临时目录-' * 8])
def test_installed_semgrep_probe_succeeds_with_inherited_long_temp(tmp_path, monkeypatch, segment):
    from security_runtime.toolchain import ToolManager, ToolStatus
    if not shutil.which('semgrep'):
        pytest.skip('optional Semgrep engine is absent')
    long = tmp_path / segment
    long.mkdir()
    for name in ('TEMP', 'TMP', 'TMPDIR'):
        monkeypatch.setenv(name, str(long))
    manager = ToolManager()
    result = manager.resolve('semgrep')
    assert result.status == ToolStatus.READY, result.diagnostic
    assert os.environ['TEMP'] == str(long)
