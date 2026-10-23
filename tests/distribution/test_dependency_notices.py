"""Unknown license metadata needs the exact reviewed release and full text."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def notices():
    path = Path(__file__).resolve().parents[2] / 'scripts/build/dependency_notices.py'
    spec = importlib.util.spec_from_file_location('dependency_notices_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def distribution(tmp_path, *, version='0.13.0', label='UNKNOWN', text=None):
    source = Path(__file__).resolve().parents[2] / 'src/security_runtime/licenses/javalang/LICENSE'
    license_file = tmp_path / 'javalang.dist-info/LICENSE.txt'
    license_file.parent.mkdir(exist_ok=True)
    license_file.write_bytes(source.read_bytes() if text is None else text)
    return SimpleNamespace(version=version, metadata={'License': label},
        files=['javalang.dist-info/LICENSE.txt'], locate_file=lambda entry: tmp_path / entry)


def test_pinned_unknown_metadata_uses_complete_reviewed_mit_text(notices, tmp_path):
    label, texts = notices.dependency_license(distribution(tmp_path), 'javalang')
    assert label == 'MIT' and texts == ['javalang.dist-info/LICENSE.txt']


def test_newline_normalization_does_not_change_license_identity(notices, tmp_path):
    dist = distribution(tmp_path)
    p = dist.locate_file(dist.files[0])
    p.write_bytes(p.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    assert notices.dependency_license(dist, 'javalang')[0] == 'MIT'


@pytest.mark.parametrize('version,key', [('0.13.1', 'javalang'), ('0.13.0', 'other-package')])
def test_unknown_other_release_or_package_remains_blocked(notices, tmp_path, version, key):
    with pytest.raises(ValueError, match='Unreviewed'):
        notices.dependency_license(distribution(tmp_path, version=version), key)


def test_changed_or_missing_original_text_stays_blocked(notices, tmp_path):
    dist = distribution(tmp_path, text=b'Not the reviewed license')
    with pytest.raises(ValueError, match='does not match'):
        notices.dependency_license(dist, 'javalang')
    dist.files = []
    with pytest.raises(ValueError, match='does not match'):
        notices.dependency_license(dist, 'javalang')


def test_conflicting_explicit_license_does_not_use_metadata_exception(notices, tmp_path):
    with pytest.raises(ValueError, match='Unreviewed'):
        notices.dependency_license(distribution(tmp_path, label='Unreviewed-Proprietary'), 'javalang')
