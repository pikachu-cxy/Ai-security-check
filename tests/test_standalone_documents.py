"""Standalone packaging resolves migrated sources without changing bundle names."""
from pathlib import Path
import runpy
import shutil

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_NAMES = {
    'PILOT_INSTALL_AND_USE.zh-CN.md',
    'WINDOWS_EXPERIENCE.md',
    'WINDOWS_EXPERIENCE.zh-CN.md',
    'PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md',
    'INSTALL_FLOW_ACCEPTANCE.zh-CN.md',
    'BACKGROUND_PREPARATION_ACCEPTANCE.zh-CN.md',
    'SCAN_TARGET_SELECTION.md',
    'RULE_FOUNDATION.md',
    'RULE_SOURCE_INVENTORY.md',
}


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts'))
    return runpy.run_path(str(ROOT / 'scripts/build_standalone.py'))


def test_repository_documents_copy_to_stable_bundle_names(builder, tmp_path):
    builder['copy_standalone_documents'](ROOT, tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == EXPECTED_NAMES
    for relative_path in builder['STANDALONE_DOCUMENTS']:
        source = ROOT / relative_path
        assert (tmp_path / source.name).read_bytes() == source.read_bytes()


@pytest.mark.parametrize('missing_name', sorted(EXPECTED_NAMES))
def test_missing_document_stops_packaging(builder, tmp_path, missing_name):
    root = tmp_path / 'repository'
    bundle = tmp_path / 'bundle'
    bundle.mkdir()
    for relative_path in builder['STANDALONE_DOCUMENTS']:
        source = root / relative_path
        source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative_path, source)
        if source.name == missing_name:
            source.unlink()
    with pytest.raises(FileNotFoundError):
        builder['copy_standalone_documents'](root, bundle)
    assert not (bundle / missing_name).exists()
