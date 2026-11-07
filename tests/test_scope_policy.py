"""Development scope keeps text inputs while excluding installed/build output."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime.scope_policy import INSTALLATION_DIRS, is_compiled_artifact
from security_runtime.target import TargetDetector, DiscoveryLimitError
from security_runtime.development_check import clean_paths
from security_runtime.development_file_watch import _Window
from test_development_check import check, execute


@pytest.mark.parametrize('name,magic', [
    ('module.so', b'\x7fELF'), ('lib.so.1.2', b'\x7fELF'),
    ('mac.dylib', b'\xcf\xfa\xed\xfe'), ('mac.so', b'\xca\xfe\xba\xbe'),
    ('module.pyd', b'MZ'), ('app.exe', b'MZ'), ('lib.dll', b'MZ'),
    ('code.o', b'\x7fELF'), ('code.obj', b'\x64\x86'),
    ('lib.a', b'!<arch>\n'), ('lib.lib', b'!<arch>\n'),
    ('App.class', b'\xca\xfe\xba\xbe'), ('code.wasm', b'\x00asm'),
    ('module.pyc', importlib.util.MAGIC_NUMBER),
])
def test_large_compiled_outputs_excluded_before_size_cap(tmp_path, name, magic):
    path = tmp_path/name
    path.write_bytes(magic + bytes(1_000_001))
    profile = TargetDetector().detect(tmp_path, [name], select_scan_targets=True)
    assert profile.files == []
    assert profile.skipped_files[0]['reason'] == 'COMPILED_ARTIFACT'
    assert profile.skipped_files[0]['size_bytes'] == path.stat().st_size
    path.write_text('TOKEN=plain-text-must-remain\n')
    assert TargetDetector().detect(tmp_path, [name], select_scan_targets=True).files == [name]


def test_shared_directory_policy_keeps_project_inputs_and_nested_worktrees(tmp_path):
    kept = ['src/app.py', 'config/settings.yaml', '.env', 'requirements.txt',
            'poetry.lock', 'uv.lock', 'package.json', 'package-lock.json',
            'pnpm-lock.yaml', 'Cargo.lock', 'src/runtime/app.py', 'tests/test_app.py']
    omitted = [f'worktrees/feature/{folder}/pkg/native.so' for folder in INSTALLATION_DIRS]
    for name in kept + omitted:
        p = tmp_path/name; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b'\x7fELF'+bytes(1_000_001) if name in omitted else b'value=1\n')
    names, unknown = clean_paths(kept + omitted)
    assert names == sorted(kept) and not unknown
    detector = TargetDetector()
    assert detector.detect(tmp_path, kept+omitted, select_scan_targets=True).files == sorted(kept)
    assert detector.detect(tmp_path, select_scan_targets=True).files == sorted(kept)
    window = object.__new__(_Window)
    window.store = SimpleNamespace(root=tmp_path)
    window.private, window.ignored = tmp_path/'private', detector.ignored
    selected, unknown = window.paths([(2, str(tmp_path/n)) for n in kept+omitted])
    assert selected == sorted(kept) and not unknown


def test_ordinary_source_does_not_add_content_io(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('normal source must not be opened by compiled-output filter')
    monkeypatch.setattr(Path, 'open', forbidden)
    for name in ('app.py', '.env', 'settings.yaml', 'requirements.txt', 'uv.lock', 'package-lock.json'):
        assert not is_compiled_artifact(tmp_path/name)


def test_missing_unrecognized_and_large_text_are_not_silently_dropped(tmp_path):
    assert not is_compiled_artifact(tmp_path/'absent.so')
    (tmp_path/'text.so').write_bytes(b'TOKEN='+b'x'*1_000_001)
    with pytest.raises(DiscoveryLimitError):
        TargetDetector().detect(tmp_path, ['text.so'], select_scan_targets=True)


def test_compiled_filter_does_not_follow_links_or_escape_workspace(tmp_path):
    root = tmp_path/'project'; root.mkdir()
    outside = tmp_path/'external.so'; outside.write_bytes(b'\x7fELF')
    (root/'linked.so').symlink_to(outside)
    for name in ('../external.so', 'linked.so'):
        with pytest.raises(ValueError):
            TargetDetector().detect(root, [name], select_scan_targets=True)


def test_normal_development_and_installation_publish_only_source(check, monkeypatch):
    root, service, runtime, state = check
    inputs = {'app.ts': b'eval(input())\n', '.env': b'SETTING=fixture\n',
              'requirements.txt': b'', 'uv.lock': b'version = 1\n',
              '.runtime/lib/site-packages/pkg/native.so': b'\x7fELF'+bytes(1_000_001),
              'native.so': b'\xcf\xfa\xed\xfe'+bytes(1_000_001)}
    for name, content in inputs.items():
        p=root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(content)
    ref = service.begin(root, 'source-and-install')['check_ref']
    service.record(root, ref, list(inputs))
    assert execute(check, monkeypatch) == 0
    saved = service.get(root, ref)
    assert saved['scanned_seq'] == saved['dirty_seq'] and saved['scan_id']
    assert state['calls'] == 1
    assert set(state['inputs'][0]) == {'app.ts', '.env', 'requirements.txt', 'uv.lock'}
    assert service.store(root).read(ref)['excluded_compiled_paths'] == ['native.so']
    assert runtime.store.get_scan(saved['scan_id'])['findings']


def test_install_or_compile_only_does_not_launch_a_scan(check):
    root, service, runtime, state = check
    (root/'native.so').write_bytes(b'\x7fELF'+bytes(1_000_001))
    ref=service.begin(root, 'install-only')['check_ref']
    service.record(root, ref, ['.runtime/lib/site-packages/pkg.py', 'native.so'])
    done=service.finish(root, ref)
    assert done['status']=='NO_OBSERVED_CHANGES' and done['scope']['paths']==[]
    assert state['calls']==0
