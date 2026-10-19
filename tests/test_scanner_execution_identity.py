"""Actual bytes determine execution identity; probe invalidation stays stricter."""
import ctypes
import json
import os
import venv
from pathlib import Path

import pytest

from security_runtime.component_health import settings_fingerprint
from security_runtime.findings import FindingNormalizer
from security_runtime.capabilities import Capability
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scan_input import capture_scan_input
from security_runtime.scan_request import ScanRequest, SourceKind
from security_runtime.scanners import BaseScanner, _snapshot
from security_runtime.toolchain import ResolvedTool, ToolManager, ToolStatus, platform_key, sha256_file
from security_runtime import toolchain
from link_fixture import linked_directory


@pytest.fixture
def identity(tmp_path,monkeypatch):
    root=tmp_path/'project'
    root.mkdir()
    (root/'source.py').write_bytes(b'original = 1\n')
    environment=tmp_path/'managed-python'
    binary=environment/'Scripts/semgrep.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'not-executed-launcher-fixture')
    package=environment/'Lib/site-packages/semgrep'
    package.mkdir(parents=True)
    (package/'entry.py').write_bytes(b'not-executed-package-fixture')
    settings=tmp_path/'settings.yml'
    settings.write_bytes(b'anonymous_user_id: fixture\n')
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE',str(settings))
    manager=ToolManager(tmp_path/'tool-state')
    manager.ensure=lambda *_a,**_kw:ResolvedTool('semgrep',manager.versions['semgrep'],str(binary),None,ToolStatus.READY)
    return root,binary,settings,manager


def rewrite(path,raw):
    replacement=path.with_suffix('.replacement')
    replacement.write_bytes(raw)
    replacement.replace(path)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX virtual environment interpreter layout')
@pytest.mark.parametrize('symlinks', [False, True])
def test_posix_venv_identity_requires_copied_interpreter(tmp_path, monkeypatch, symlinks):
    environment = tmp_path / 'runtime'
    venv.EnvBuilder(with_pip=False, symlinks=symlinks).create(environment)
    binary = environment / 'bin/semgrep'
    binary.write_bytes(b'not-executed-launcher-fixture')
    package = environment / 'lib/python3.12/site-packages/semgrep'
    package.mkdir(parents=True, exist_ok=True)
    (package / '__init__.py').write_bytes(b'not-executed-package-fixture')
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE', str(tmp_path / 'settings.yml'))
    manager = ToolManager(tmp_path / 'tool-state')
    assert (manager.execution_identity('semgrep', binary) is None) is symlinks
    if not symlinks:
        before = manager.execution_identity('semgrep', binary)
        python = environment / 'bin/python'
        assert not python.is_symlink()
        rewrite(python, b'changed-interpreter-fixture')
        assert manager.execution_identity('semgrep', binary) != before


@pytest.fixture
def managed_posix_interpreter(tmp_path, monkeypatch):
    manager = ToolManager(tmp_path / 'managed')
    binary = manager.managed_path('semgrep')
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'not-executed-launcher-fixture')
    package = binary.parent.parent / 'lib/python3.12/site-packages/semgrep'
    package.mkdir(parents=True)
    (package / '__init__.py').write_bytes(b'not-executed-package-fixture')
    key = '-'.join(platform_key())
    entry = json.loads(Path(toolchain.__file__).with_name('python_downloads.json').read_text())[key]
    home = manager.root / 'python' / (entry['version'] + '-' + entry['build']) / key
    python = home / 'bin/python3.12'
    python.parent.mkdir(parents=True)
    python.write_bytes(b'not-executed-bootstrap-fixture')
    metadata = home / 'metadata.json'
    metadata.write_text(json.dumps(dict(engine_id='cpython-bootstrap', version=entry['version'],
        build=entry['build'], sha256=entry['sha256'], binary_sha256=sha256_file(python))))
    interpreter = binary.parent / 'python'
    interpreter.symlink_to(python)
    monkeypatch.setenv('SEMGREP_SETTINGS_FILE', str(tmp_path / 'settings.yml'))
    return manager, binary, interpreter, python, metadata


@pytest.mark.skipif(os.name == 'nt', reason='POSIX managed interpreter symlink layout')
def test_managed_bootstrap_link_binds_target_and_metadata(managed_posix_interpreter):
    manager, binary, _, python, metadata = managed_posix_interpreter
    original = manager.execution_identity('semgrep', binary)
    assert original is not None
    record = json.loads(metadata.read_text())
    record['installed_at'] = 'changed-metadata-fixture'
    metadata.write_text(json.dumps(record))
    assert manager.execution_identity('semgrep', binary) != original
    python.write_bytes(b'changed-bootstrap-fixture')
    assert manager.execution_identity('semgrep', binary) is None


@pytest.mark.skipif(os.name == 'nt', reason='POSIX managed interpreter symlink layout')
@pytest.mark.parametrize('changed', ['external', 'metadata', 'launcher', 'package'])
def test_managed_bootstrap_link_rejects_unbound_layout(managed_posix_interpreter, changed, tmp_path):
    manager, binary, interpreter, python, metadata = managed_posix_interpreter
    if changed == 'external':
        external = tmp_path / 'external-python'
        external.write_bytes(python.read_bytes())
        interpreter.unlink()
        interpreter.symlink_to(external)
    elif changed == 'metadata':
        record = json.loads(metadata.read_text())
        record['sha256'] = 'unreviewed-bootstrap'
        metadata.write_text(json.dumps(record))
    else:
        selected = binary if changed == 'launcher' else next((binary.parent.parent / 'lib').rglob('__init__.py'))
        replacement = selected.with_suffix('.original')
        selected.rename(replacement)
        selected.symlink_to(replacement)
    assert manager.execution_identity('semgrep', binary) is None


def test_same_settings_bytes_replacement_expires_health_but_preserves_content_identities(identity):
    _,binary,settings,manager=identity
    probe=manager._probe_identity('semgrep',binary)
    execution=manager.execution_identity('semgrep',binary)
    fingerprint=settings_fingerprint()
    before=settings.stat()
    rewrite(settings,settings.read_bytes())
    assert settings.stat().st_ino!=before.st_ino
    assert settings_fingerprint()!=fingerprint
    assert manager._probe_identity('semgrep',binary)==probe
    assert manager.execution_identity('semgrep',binary)==execution


def test_actual_settings_change_expires_version_cache(identity,monkeypatch):
    _,binary,settings,manager=identity
    calls=[]
    def probe(tool,path):
        calls.append((tool,path))
        rewrite(settings,settings.read_bytes())
        return manager.versions['semgrep']
    monkeypatch.setattr(manager,'_probe_version',probe)
    assert manager._version('semgrep',binary)==manager.versions['semgrep']
    assert manager._version('semgrep',binary)==manager.versions['semgrep']
    assert len(calls)==1
    settings.write_bytes(b'changed: true\n')
    assert manager._version('semgrep',binary)==manager.versions['semgrep']
    assert len(calls)==2


def test_missing_settings_and_present_empty_settings_have_distinct_execution_identity(identity):
    _,binary,settings,manager=identity
    settings.unlink()
    absent=manager.execution_identity('semgrep',binary)
    settings.write_bytes(b'')
    assert manager.execution_identity('semgrep',binary)!=absent


@pytest.mark.parametrize('changed',[False,True])
def test_provider_accepts_same_settings_bytes_and_rejects_actual_change(identity,changed):
    root,_,settings,manager=identity
    original=settings.read_bytes()
    class Provider(BaseScanner):
        name=scanner_id=engine_id='semgrep'
        capabilities=frozenset({Capability.CODE_SAST})
        def _scan(self,binary,context,normalizer):
            rewrite(settings,original+b'changed: true\n' if changed else original)
            return []
    provider=Provider(manager)
    request=ScanRequest(root,ScanMode.QUICK,SourceKind.WORKTREE,('source.py',))
    with capture_scan_input(request) as view:
        context=ScanContext(str(view.execution_root),ScanMode.QUICK,('source.py',),
            logical_root=str(root),input_view=view)
        _,run=provider.scan(context,FindingNormalizer(view.execution_root,identity_root=root))
    assert run.scanner_diagnostics['execution_binding']['verified'] is (not changed)
    assert run.status==('FAILED' if changed else 'SUCCESS')
    assert run.error_code==('SCAN_EXECUTION_IDENTITY_CHANGED' if changed else '')


@pytest.mark.skipif(os.name!='nt',reason='Windows DOS path alias boundary')
def test_standalone_snapshot_canonicalizes_real_short_path_without_live_fallback(tmp_path):
    root=tmp_path/'long-project-name'
    root.mkdir()
    expected=b'original bytes\n'
    (root/'source.py').write_bytes(expected)
    call=ctypes.windll.kernel32.GetShortPathNameW
    call.argtypes=(ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32)
    call.restype=ctypes.c_uint32
    buffer=ctypes.create_unicode_buffer(32768)
    assert call(str(root),buffer,len(buffer))
    alias=Path(buffer.value)
    if str(alias)==str(root.resolve()): pytest.skip('Filesystem has no DOS alias for this path')
    assert alias.resolve()==root.resolve()
    context=ScanContext(str(alias),ScanMode.QUICK,('source.py',))
    with _snapshot(context) as scoped:
        assert scoped.resolve()!=root.resolve()
        (root/'source.py').write_bytes(b'live changed\n')
        assert (scoped/'source.py').read_bytes()==expected
    assert not scoped.exists()


def test_standalone_snapshot_still_rejects_real_junction_before_resolve(tmp_path):
    original=tmp_path/'outside'
    original.mkdir()
    (original/'source.py').write_bytes(b'not admitted\n')
    link=linked_directory(tmp_path/'linked-project',original)
    with pytest.raises(ValueError):
        with _snapshot(ScanContext(str(link),ScanMode.QUICK,('source.py',))):
            pytest.fail('A linked source root must not be admitted')
