"""Managed delivery identities preserve old routes and fail closed on changes."""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import zipfile

import pytest

from security_runtime import build_identity as identity_module
from security_runtime._version import __version__
from security_runtime.managed_identity import (
    MARKER_NAME, METADATA_NAME, canonical_json, managed_build_identity,
    marker_content,
)

SCRIPT_PATH = Path(__file__).resolve().parents[1] / 'scripts/build_managed_wheel.py'
SPEC = importlib.util.spec_from_file_location('build_managed_wheel', SCRIPT_PATH)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
SOURCE_COMMIT = 'c' * 40
DIST_INFO = f'ai_security_runtime-{__version__}.dist-info'


def write_wheel(path: Path, contents: dict[str, bytes], *, bad_record=False):
    record_name = DIST_INFO + '/RECORD'
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    for name, value in contents.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip('=')
        writer.writerow([name, 'sha256=' + digest, len(value)])
    writer.writerow([record_name, '', ''])
    with zipfile.ZipFile(path, 'w') as archive:
        for name, value in contents.items():
            archive.writestr(name, value)
        archive.writestr(record_name, b'invalid' if bad_record else stream.getvalue().encode())


@pytest.fixture
def source_wheel(tmp_path):
    wheel = tmp_path / f'ai_security_runtime-{__version__}-py3-none-any.whl'
    contents = {
        'security_runtime/__init__.py': b'',
        'security_runtime/_version.py': f'__version__ = "{__version__}"\n'.encode(),
        'security_runtime/build_identity.py': b'# identity fixture\n',
        'security_runtime/managed_identity.py': b'# managed fixture\n',
        'security_runtime/rules/LICENSE': b'fixture license\n',
        'security_runtime/assets/check.mjs': b'export const fixture = true;\n',
        DIST_INFO + '/METADATA': f'Metadata-Version: 2.4\nName: ai-security-runtime\nVersion: {__version__}\n'.encode(),
        DIST_INFO + '/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    write_wheel(wheel, contents)
    return wheel


@pytest.fixture
def managed_install(tmp_path, source_wheel):
    result = builder.annotate_wheel(source_wheel, tmp_path / 'managed', source_commit=SOURCE_COMMIT)
    site = tmp_path / 'site-packages'
    with zipfile.ZipFile(result['wheel']) as archive:
        archive.extractall(site)
    return site / 'security_runtime', result


def test_managed_wheel_has_deterministic_identity_and_complete_record(tmp_path, source_wheel, managed_install):
    package, result = managed_install
    repeated = builder.annotate_wheel(source_wheel, tmp_path / 'repeated', source_commit=SOURCE_COMMIT)
    assert repeated['sha256'] == result['sha256']
    assert Path(repeated['wheel']).read_bytes() == Path(result['wheel']).read_bytes()
    identity = managed_build_identity(package, version=__version__)
    assert identity == {
        'status': 'IDENTIFIED', 'version': __version__, 'build_id': result['build_id'],
        'source_commit': SOURCE_COMMIT, 'source_dirty': False,
        'experience_contract': 'upgrade-and-scan-v1', 'state_schema': 'runtime-state-v1',
        'delivery_kind': 'managed-wheel', 'integrity': 'PACKAGE_CONTENT_HASHES_VERIFIED',
    }
    with zipfile.ZipFile(result['wheel']) as archive:
        record_name = DIST_INFO + '/RECORD'
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        assert {row[0] for row in rows} == set(archive.namelist())
        for name, checksum, size in rows:
            if name == record_name:
                assert not checksum and not size
            else:
                assert checksum == builder._record_hash(archive.read(name))
                assert int(size) == len(archive.read(name))


@pytest.mark.parametrize('change', ['changed_source', 'missing_resource', 'extra_source', 'extra_pyc'])
def test_managed_runtime_rejects_changed_missing_or_extra_content(managed_install, change):
    package, _ = managed_install
    if change == 'changed_source':
        (package / 'build_identity.py').write_bytes(b'# replaced\n')
    elif change == 'missing_resource':
        (package / 'rules/LICENSE').unlink()
    else:
        (package / ('unexpected.pyc' if change == 'extra_pyc' else 'unexpected.py')).write_bytes(b'new content')
    identity = managed_build_identity(package, version=__version__)
    assert identity['status'] == 'UNVERIFIABLE_MANAGED_RELEASE'
    assert 'build_id' not in identity


def test_installer_generated_bytecode_cache_does_not_change_source_identity(managed_install):
    package, result = managed_install
    cache = package / '__pycache__'
    cache.mkdir()
    (cache / 'build_identity.cpython-312.pyc').write_bytes(b'generated bytecode')
    assert managed_build_identity(package, version=__version__)['build_id'] == result['build_id']


@pytest.mark.parametrize('missing', ['metadata', 'marker', 'both'])
def test_deleted_delivery_metadata_does_not_fall_back_to_development(managed_install, monkeypatch, missing):
    package, _ = managed_install
    if missing in {'metadata', 'both'}:
        (package / METADATA_NAME).unlink()
    if missing in {'marker', 'both'}:
        (package.parent / DIST_INFO / MARKER_NAME).unlink()
    monkeypatch.setattr(identity_module, '__file__', str(package / 'build_identity.py'))
    monkeypatch.setattr(identity_module.sys, 'frozen', False, raising=False)
    monkeypatch.setattr(identity_module, 'git_provenance', lambda *a, **kw: pytest.fail('Must not enter DEV path'))
    assert identity_module.build_identity()['status'] == 'UNVERIFIABLE_MANAGED_RELEASE'


@pytest.mark.parametrize('invalid', ['null', 'duplicate', 'version', 'commit', 'dirty', 'path', 'checksum'])
def test_invalid_metadata_is_unknown_even_with_a_matching_marker(managed_install, invalid):
    package, _ = managed_install
    metadata = package / METADATA_NAME
    value = json.loads(metadata.read_bytes())
    if invalid == 'null':
        raw = b'null'
    elif invalid == 'duplicate':
        raw = b'{"schema":"managed-wheel-v1","schema":"managed-wheel-v1"}'
    else:
        if invalid == 'version':
            value['version'] = '99.99'
        elif invalid == 'commit':
            value['source_commit'] = 'main'
        elif invalid == 'dirty':
            value['source_dirty'] = 0
        elif invalid == 'path':
            value['package_files']['../outside.py'] = '0' * 64
        else:
            value['package_files']['_version.py'] = 'g' * 64
        payload = {key: item for key, item in value.items() if key != 'build_id'}
        value['build_id'] = hashlib.sha256(canonical_json(payload)).hexdigest()
        raw = canonical_json(value)
    metadata.write_bytes(raw)
    marker = package.parent / DIST_INFO / MARKER_NAME
    marker.write_bytes(marker_content(raw, value['build_id']))
    assert managed_build_identity(package, version=__version__)['status'] == 'UNVERIFIABLE_MANAGED_RELEASE'


def test_plain_source_route_and_build_hash_remain_unchanged(tmp_path, monkeypatch):
    package = tmp_path / 'src/security_runtime'
    package.mkdir(parents=True)
    (package / 'build_identity.py').write_bytes(b'fixture\n')
    (package / 'rules.json').write_bytes(b'{}\n')
    monkeypatch.setattr(identity_module, '__file__', str(package / 'build_identity.py'))
    monkeypatch.setattr(identity_module.sys, 'frozen', False, raising=False)
    monkeypatch.setattr(identity_module, 'git_provenance',
                        lambda root, *args: SOURCE_COMMIT if args[0] == 'rev-parse' else '')
    assert managed_build_identity(package, version=__version__) is None
    digest = hashlib.sha256(b'runtime-source-build-v1')
    for name in ['build_identity.py', 'rules.json']:
        digest.update(name.encode())
        digest.update((package / name).read_bytes())
    assert identity_module.build_identity() == {
        'status': 'DEV', 'build_id': digest.hexdigest(), 'version': __version__,
        'source_commit': SOURCE_COMMIT, 'source_dirty': False,
        'experience_contract': 'upgrade-and-scan-v1', 'state_schema': 'runtime-state-v1',
    }


def test_original_unmarked_wheel_keeps_development_route(tmp_path, source_wheel, monkeypatch):
    site = tmp_path / 'original-site-packages'
    with zipfile.ZipFile(source_wheel) as archive:
        archive.extractall(site)
    package = site / 'security_runtime'
    assert managed_build_identity(package, version=__version__) is None
    monkeypatch.setattr(identity_module, '__file__', str(package / 'build_identity.py'))
    monkeypatch.setattr(identity_module.sys, 'frozen', False, raising=False)
    monkeypatch.setattr(identity_module, 'git_provenance',
                        lambda root, *args: SOURCE_COMMIT if args[0] == 'rev-parse' else '')
    assert identity_module.build_identity()['status'] == 'DEV'


def test_frozen_bundle_identity_keeps_priority_and_existing_contract(tmp_path, managed_install, monkeypatch):
    package, _ = managed_install
    (package / METADATA_NAME).write_bytes(b'invalid')
    expected = {'build_id': 'b' * 64, 'version': __version__, 'source_commit': SOURCE_COMMIT,
                'source_dirty': False, 'experience_contract': 'upgrade-and-scan-v1',
                'state_schema': 'runtime-state-v1'}
    (tmp_path / 'version.json').write_text(json.dumps(expected))
    monkeypatch.setattr(identity_module, '__file__', str(package / 'build_identity.py'))
    monkeypatch.setattr(identity_module.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(identity_module.sys, 'executable', str(tmp_path / 'security-check'))
    assert identity_module.build_identity() == {'status': 'IDENTIFIED', **expected}


def test_symlinked_package_resource_is_rejected_but_interpreter_link_is_irrelevant(managed_install, tmp_path, monkeypatch):
    package, result = managed_install
    executable = tmp_path / 'python-link'
    try:
        executable.symlink_to(tmp_path / 'real-python')
    except OSError:
        pytest.skip('Creating symlinks is unavailable on this host')
    monkeypatch.setattr(identity_module, '__file__', str(package / 'build_identity.py'))
    monkeypatch.setattr(identity_module.sys, 'frozen', False, raising=False)
    monkeypatch.setattr(identity_module.sys, 'executable', str(executable))
    assert identity_module.build_identity()['build_id'] == result['build_id']
    license_path = package / 'rules/LICENSE'
    external = tmp_path / 'license-original'
    external.write_bytes(license_path.read_bytes())
    license_path.unlink()
    license_path.symlink_to(external)
    assert identity_module.build_identity()['status'] == 'UNVERIFIABLE_MANAGED_RELEASE'


@pytest.mark.parametrize('extra', ['../escape.py', '/escape.py', 'security_runtime/../../escape.py'])
def test_builder_rejects_traversal_before_creating_output(tmp_path, source_wheel, extra):
    with zipfile.ZipFile(source_wheel, 'a') as archive:
        archive.writestr(extra, b'bad')
    with pytest.raises(ValueError, match='unsupported entry'):
        builder.annotate_wheel(source_wheel, tmp_path / 'output', source_commit=SOURCE_COMMIT)
    assert not (tmp_path / 'output').exists()


def test_builder_rejects_symlink_archive_entries(tmp_path, source_wheel):
    with zipfile.ZipFile(source_wheel, 'a') as archive:
        entry = zipfile.ZipInfo('security_runtime/link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, b'outside')
    with pytest.raises(ValueError, match='unsupported entry'):
        builder.annotate_wheel(source_wheel, tmp_path / 'output', source_commit=SOURCE_COMMIT)


def test_builder_requires_original_wheel_record_integrity(tmp_path, source_wheel):
    with zipfile.ZipFile(source_wheel) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()
                    if not name.endswith('/RECORD')}
    write_wheel(source_wheel, contents, bad_record=True)
    with pytest.raises(ValueError, match='RECORD'):
        builder.annotate_wheel(source_wheel, tmp_path / 'output', source_commit=SOURCE_COMMIT)


def test_builder_rejects_unknown_source_and_reannotating_wheel(tmp_path, source_wheel, managed_install):
    with pytest.raises(ValueError, match='full lowercase Git commit SHA'):
        builder.annotate_wheel(source_wheel, tmp_path / 'output', source_commit='main')
    _, result = managed_install
    with pytest.raises(ValueError, match='fresh source wheel'):
        builder.annotate_wheel(Path(result['wheel']), tmp_path / 'output', source_commit=SOURCE_COMMIT)
