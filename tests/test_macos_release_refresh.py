"""Mac release replacement must preserve the published Windows bytes and identity."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from scripts import refresh_macos_release as refresh

SOURCE = 'a' * 40
OLD_SOURCE = 'b' * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def refresh_case(tmp_path, monkeypatch):
    original_files = tmp_path / 'original'
    original_files.mkdir()
    manifest = dict(version='0.3.6', source_commit=OLD_SOURCE, artifacts={})
    for platform in ('windows-x64', *refresh.MACS):
        name = (f'ai-security-runtime-v0.3.6-{platform}.zip' if platform == 'windows-x64'
                else refresh.archive_name(platform))
        content = ('original-' + platform).encode()
        (original_files / name).write_bytes(content)
        (original_files / (name + '.sha256')).write_text(sha(content) + '  ' + name + '\n')
        manifest['artifacts'][platform] = dict(url=f'https://github.com/{refresh.REPOSITORY}/releases/download/{refresh.TAG}/{name}', sha256=sha(content))
    with zipfile.ZipFile(original_files / refresh.EVIDENCE, 'w') as archive:
        archive.writestr('release/windows-verification.json', b'original Windows evidence')
        for platform in refresh.MACS:
            archive.writestr('release/' + refresh.archive_name(platform) + '.verification.json', b'old Mac evidence')
        archive.writestr('distribution/homebrew/Formula/ai-security-runtime.rb', 'old formula')
    (original_files / 'release-manifest.json').write_text(json.dumps(manifest))
    (original_files / 'SHA256SUMS.txt').write_text(''.join(
        f'{refresh.digest(path)}  {path.name}\n' for path in original_files.iterdir()
        if path.name.endswith(('.zip', '.tar.gz'))))
    original = dict(id=123, tag_name=refresh.TAG, draft=False, immutable=False,
        html_url='https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.6',
        body='Original release notes', assets=[dict(id=i, name=path.name, digest='sha256:' + refresh.digest(path))
            for i, path in enumerate(sorted(original_files.iterdir()), start=1)])
    approval = dict(release_id=123, original_source_commit=OLD_SOURCE,
        assets={asset['name']:dict(id=asset['id'], sha256=asset['digest'][7:]) for asset in original['assets']})
    inputs = tmp_path / 'dist/release'
    inputs.mkdir(parents=True)
    for platform in refresh.MACS:
        path = inputs / refresh.archive_name(platform)
        metadata = dict(version='0.3.6', source_commit=SOURCE, source_dirty=False, build_id=sha(platform.encode()))
        raw = json.dumps(metadata).encode()
        with tarfile.open(path, 'w:gz') as archive:
            member = tarfile.TarInfo('security-check/version.json')
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        (inputs / (path.name + '.sha256')).write_text(refresh.digest(path) + '  ' + path.name + '\n')
        record = dict(version='0.3.6', source_commit=SOURCE, platform=platform, archive_sha256=refresh.digest(path))
        record.update(dict.fromkeys(('smoke', 'managed_engines', 'plugin_discovery', 'osv_offline_fallback',
            'fix_verify_offline_synthetic', 'hooks_offline_synthetic', 'remediation_offline_synthetic',
            'codex_integration_offline_synthetic'), True))
        (inputs / (path.name + '.verification.json')).write_text(json.dumps(record))
    state, uploads = copy.deepcopy(original), []
    def command(args, **kwargs):
        if args[:3] == ['gh', 'release', 'download']:
            name = args[args.index('--pattern') + 1]
            destination = Path(args[args.index('--dir') + 1]) / name
            destination.write_bytes((original_files / name).read_bytes())
        elif args[:3] == ['gh', 'release', 'upload']:
            path = Path(args[4])
            assert 'windows-x64' not in path.name
            uploads.append(path.name)
            state['assets'] = [asset for asset in state['assets'] if asset['name'] != path.name]
            state['assets'].append(dict(name=path.name, id=100 + len(uploads), digest='sha256:' + refresh.digest(path)))
        elif args[:3] == ['gh', 'release', 'edit']:
            state['body'] = Path(args[args.index('--notes-file') + 1]).read_text()
        else:
            raise AssertionError(args)
    monkeypatch.setattr(refresh, 'release', lambda: copy.deepcopy(state))
    monkeypatch.setattr(refresh, 'wait_for_tests', lambda source: 'https://github.com/example/tests')
    monkeypatch.setattr(refresh.subprocess, 'run', command)
    return tmp_path, approval, state, uploads


def test_refresh_preserves_windows_and_uses_both_clean_native_packages(refresh_case):
    root, approval, state, uploads = refresh_case
    windows_before = [asset for asset in state['assets'] if 'windows-x64' in asset['name']]
    refresh.prepare(root, SOURCE, approval)
    staged = root / 'dist/macos-refresh/staged'
    manifest = json.loads((staged / 'release-manifest.json').read_text())
    assert manifest['source_commit'] == OLD_SOURCE
    assert manifest['artifact_source_commits'] == {'windows-x64':OLD_SOURCE, **dict.fromkeys(refresh.MACS, SOURCE)}
    assert not list(staged.glob('*windows*'))
    with zipfile.ZipFile(staged / refresh.EVIDENCE) as evidence:
        assert evidence.read('release/windows-verification.json') == b'original Windows evidence'
        for platform in refresh.MACS:
            record = json.loads(evidence.read('release/' + refresh.archive_name(platform) + '.verification.json'))
            assert record['source_commit'] == SOURCE
    refresh.publish(root, SOURCE, approval)
    assert len(uploads) == 8
    assert [asset for asset in state['assets'] if 'windows-x64' in asset['name']] == windows_before
    assert state['body'].startswith('Original release notes')
    refresh.publish(root, SOURCE, approval)
    assert len(uploads) == 8, 'Retry must reuse identical staged files'


@pytest.mark.parametrize('damage', ('windows_id', 'windows_checksum', 'mac_checksum'))
def test_concurrent_release_change_prevents_any_upload(refresh_case, damage):
    root, approval, state, uploads = refresh_case
    refresh.prepare(root, SOURCE, approval)
    wanted = 'windows-x64' if damage.startswith('windows') else 'macos-arm64'
    asset = next(asset for asset in state['assets'] if wanted in asset['name'])
    asset['id' if damage.endswith('_id') else 'digest'] = 999 if damage.endswith('_id') else 'sha256:' + 'f' * 64
    with pytest.raises(ValueError, match='Concurrent release change'):
        refresh.publish(root, SOURCE, approval)
    assert not uploads


def test_stale_native_receipt_cannot_be_published(refresh_case):
    root, approval, state, uploads = refresh_case
    path = root / 'dist/release' / (refresh.archive_name('macos-x64') + '.verification.json')
    record = json.loads(path.read_text())
    record['source_commit'] = OLD_SOURCE
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='Incomplete native verification'):
        refresh.prepare(root, SOURCE, approval)
    assert not uploads


def test_changed_staging_cannot_be_uploaded(refresh_case):
    root, approval, state, uploads = refresh_case
    refresh.prepare(root, SOURCE, approval)
    (root / 'dist/macos-refresh/staged' / refresh.archive_name('macos-x64')).write_bytes(b'tampered')
    with pytest.raises(ValueError, match='Staged publication changed'):
        refresh.publish(root, SOURCE, approval)
    assert not uploads


def test_retry_recovers_an_approved_mac_asset_missing_after_failed_upload(refresh_case):
    root, approval, state, uploads = refresh_case
    refresh.prepare(root, SOURCE, approval)
    missing = refresh.archive_name('macos-x64')
    state['assets'] = [asset for asset in state['assets'] if asset['name'] != missing]
    refresh.publish(root, SOURCE, approval)
    assert missing in uploads
    assert all('windows-x64' not in name for name in uploads)
