"""A scoped release requires fresh WorkBuddy evidence, never a fabricated full pass."""
import hashlib
import json
import pytest
from scripts.release import make_release_metadata as metadata


@pytest.mark.parametrize('missing', [None, 'bounded-stop', 'owner-bound-mcp'])
def test_workbuddy_scope_requires_each_changed_contract(tmp_path, monkeypatch, missing):
    release=tmp_path/'dist/release';release.mkdir(parents=True)
    monkeypatch.setattr(metadata,'__file__',str(tmp_path/'scripts/release/make_release_metadata.py'))
    monkeypatch.setattr(metadata.subprocess,'check_output',lambda *a,**k:'a'*40)
    checked=['frozen-install','settings-preservation','native-edit-record','owner-bound-mcp','bounded-stop','owned-uninstall']
    if missing: checked.remove(missing)
    for platform in metadata.PLATFORMS:
        name=f'ai-security-runtime-v{metadata.__version__}-{platform}'+('.zip' if platform.startswith('windows') else '.tar.gz')
        (release/name).write_bytes(b'fixture')
        proof=dict(version=metadata.__version__,source_commit='a'*40,platform=platform,smoke=True,
            archive_sha256=hashlib.sha256(b'fixture').hexdigest(),validation_scope='workbuddy-adapter',
            workbuddy_connector=True,checked=checked,managed_engines=False)
        (release/(name+'.verification.json')).write_text(json.dumps(proof))
    if missing:
        with pytest.raises(ValueError,match='Incomplete'):metadata.main(workbuddy=True)
    else:
        metadata.main(workbuddy=True)
        assert json.loads((release/'release-manifest.json').read_text())['validation_scope']=='workbuddy-adapter'
