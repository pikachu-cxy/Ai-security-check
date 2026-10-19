"""Explicit v0.3.6 Mac-only refresh; preserve the published Windows delivery."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import time
import zipfile

REPOSITORY = 'pikachu-cxy/Ai-security-check'
TAG = 'v0.3.6'
MACS = ('macos-arm64', 'macos-x64')
EVIDENCE = f'ai-security-runtime-{TAG}-release-evidence.zip'
RECEIPT = 'macos-refresh.json'
SHARED = (EVIDENCE, RECEIPT, 'release-manifest.json', 'SHA256SUMS.txt')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def archive_name(platform):
    return f'ai-security-runtime-{TAG}-{platform}.tar.gz'


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}'], text=True))


def release():
    return api(f'releases/tags/{TAG}')


def asset_index(value):
    result = {asset['name']: asset for asset in value['assets']}
    if len(result) != len(value['assets']):
        raise ValueError('Duplicate release assets')
    return result


def require_original(value, approval):
    if value['id'] != approval['release_id'] or value['tag_name'] != TAG or value['draft'] or value.get('immutable'):
        raise ValueError('Release identity or mutability changed')
    assets = asset_index(value)
    for name, expected in approval['assets'].items():
        actual = assets.get(name, {})
        if actual.get('id') != expected['id'] or actual.get('digest') != 'sha256:' + expected['sha256']:
            raise ValueError('Published asset changed since approval: ' + name)


def require_native(archive, platform, source):
    record = json.loads(archive.with_name(archive.name + '.verification.json').read_text())
    required = ('smoke', 'managed_engines', 'plugin_discovery', 'osv_offline_fallback',
                'fix_verify_offline_synthetic', 'hooks_offline_synthetic',
                'remediation_offline_synthetic', 'codex_integration_offline_synthetic')
    if (record.get('version') != '0.3.6' or record.get('source_commit') != source
            or record.get('platform') != platform or record.get('archive_sha256') != digest(archive)
            or not all(record.get(key) is True for key in required)):
        raise ValueError('Incomplete native verification: ' + platform)
    if archive.with_name(archive.name + '.sha256').read_text().strip() != digest(archive) + '  ' + archive.name:
        raise ValueError('Archive sidecar mismatch')
    with tarfile.open(archive) as tar:
        members = [item for item in tar.getmembers() if item.name == 'security-check/version.json']
        if len(members) != 1 or not members[0].isfile() or members[0].size > 128_000:
            raise ValueError('Invalid package provenance')
        metadata = json.load(tar.extractfile(members[0]))
    if (metadata.get('source_commit') != source or metadata.get('source_dirty') is not False
            or metadata.get('version') != '0.3.6' or not re.fullmatch(r'[0-9a-f]{64}', metadata.get('build_id', ''))):
        raise ValueError('Package was not built from the clean requested commit')
    return metadata['build_id']


def wait_for_tests(source):
    for _ in range(60):
        runs = api(f'actions/workflows/tests.yml/runs?head_sha={source}&event=push')['workflow_runs']
        matching = [run for run in runs if run['head_sha'] == source and run['head_branch'] == 'feature/runtime-mvp']
        if matching and matching[0]['status'] == 'completed':
            if matching[0]['conclusion'] != 'success':
                raise ValueError('Runtime regression gate did not pass')
            return matching[0]['html_url']
        time.sleep(20)
    raise ValueError('Runtime regression gate has not completed')


def prepare(root, source, approval):
    original = release()
    require_original(original, approval)
    test_url = wait_for_tests(source)
    inputs = root / 'dist/release'
    builds = {platform: require_native(inputs / archive_name(platform), platform, source) for platform in MACS}
    work = root / 'dist/macos-refresh'
    work.mkdir(exist_ok=False)
    previous, staged = work / 'previous', work / 'staged'
    previous.mkdir()
    staged.mkdir()
    (previous / 'release.json').write_text(json.dumps(original, ensure_ascii=False, indent=2))
    (work / 'approval.json').write_text(json.dumps(approval, indent=2))
    for name in approval['assets']:
        if 'windows-x64' in name:
            continue
        subprocess.run(['gh', 'release', 'download', TAG, '--repo', REPOSITORY,
                        '--pattern', name, '--dir', str(previous)], check=True)
        if digest(previous / name) != approval['assets'][name]['sha256']:
            raise ValueError('Original download checksum mismatch: ' + name)
    manifest = json.loads((previous / 'release-manifest.json').read_text())
    if manifest['version'] != '0.3.6' or manifest['source_commit'] != approval['original_source_commit']:
        raise ValueError('Original manifest provenance changed')
    windows = copy.deepcopy(manifest['artifacts']['windows-x64'])
    windows_name = f'ai-security-runtime-{TAG}-windows-x64.zip'
    if windows['sha256'] != approval['assets'][windows_name]['sha256']:
        raise ValueError('Windows manifest checksum mismatch')
    for platform in MACS:
        name = archive_name(platform)
        for suffix in ('', '.sha256'):
            shutil.copyfile(inputs / (name + suffix), staged / (name + suffix))
        manifest['artifacts'][platform]['sha256'] = digest(staged / name)
    manifest['artifact_source_commits'] = {'windows-x64': approval['original_source_commit'], **dict.fromkeys(MACS, source)}
    manifest['macos_refresh'] = {'source_commit': source, 'receipt': RECEIPT}
    (staged / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    receipt = dict(version='0.3.6', source_commit=source, platforms=list(MACS), build_ids=builds,
        runtime_tests=test_url, windows='UNCHANGED', original_source_commit=approval['original_source_commit'],
        artifacts={key: manifest['artifacts'][key] for key in MACS},
        apple_developer_id_and_notarization='NOT_CONFIGURED; NATIVE_CI_IS_NOT_GATEKEEPER_ACCEPTANCE')
    (staged / RECEIPT).write_text(json.dumps(receipt, indent=2) + '\n')
    from scripts.update_homebrew_formula import generate
    formula = work / 'ai-security-runtime.rb'
    generate(staged / 'release-manifest.json', formula)
    with zipfile.ZipFile(previous / EVIDENCE) as old, zipfile.ZipFile(staged / EVIDENCE, 'w', zipfile.ZIP_DEFLATED) as new:
        names = old.namelist()
        if len(names) != len(set(names)) or sum(item.file_size for item in old.infolist()) > 64_000_000:
            raise ValueError('Invalid previous evidence archive')
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe evidence path')
            if any(path.name.startswith(archive_name(platform)) for platform in MACS) or name.endswith('.rb'):
                continue
            new.writestr(name, old.read(name))
        for platform in MACS:
            for path in sorted(inputs.glob(archive_name(platform) + '.*.json')):
                new.write(path, 'release/' + path.name)
        new.write(formula, 'distribution/homebrew/Formula/ai-security-runtime.rb')
        new.write(staged / RECEIPT, 'release/' + RECEIPT)
    sums = {}
    for line in (previous / 'SHA256SUMS.txt').read_text().splitlines():
        sha, name = line.split('  ')
        sums[name] = sha
    if sums[windows_name] != windows['sha256']:
        raise ValueError('Windows aggregate checksum mismatch')
    for name in [*(archive_name(platform) for platform in MACS), EVIDENCE, RECEIPT]:
        sums[name] = digest(staged / name)
    (staged / 'SHA256SUMS.txt').write_text(''.join(f'{sha}  {name}\n' for name, sha in sums.items()))
    plan = dict(source_commit=source, files={path.name: digest(path) for path in staged.iterdir()})
    (work / 'plan.json').write_text(json.dumps(plan, indent=2))
    print('Prepared both Mac replacements and a complete pre-publication backup.')


def publish(root, source, approval):
    work = root / 'dist/macos-refresh'
    staged = work / 'staged'
    plan = json.loads((work / 'plan.json').read_text())
    expected = {*(archive_name(platform) + suffix for platform in MACS for suffix in ('', '.sha256')), *SHARED}
    if plan['source_commit'] != source or set(plan['files']) != expected:
        raise ValueError('Unexpected publication scope')
    for name, checksum in plan['files'].items():
        if (staged / name).is_symlink() or digest(staged / name) != checksum:
            raise ValueError('Staged publication changed: ' + name)
    current = release()
    if current['id'] != approval['release_id'] or current['tag_name'] != TAG or current['draft'] or current.get('immutable'):
        raise ValueError('Release identity changed')
    assets = asset_index(current)
    if RECEIPT in assets and assets[RECEIPT].get('digest') != 'sha256:' + plan['files'][RECEIPT]:
        raise ValueError('Concurrent Mac refresh receipt')
    # A retry may encounter some already replaced assets. Only the exact old
    # approved bytes or this run's staged bytes are accepted; Windows IDs stay fixed.
    for name, old in approval['assets'].items():
        actual = assets.get(name, {})
        allowed = {'sha256:' + old['sha256']}
        if name in plan['files']:
            allowed.add('sha256:' + plan['files'][name])
        if actual.get('digest') not in allowed or ('windows-x64' in name and actual.get('id') != old['id']):
            raise ValueError('Concurrent release change: ' + name)
    for name in [*(archive_name(platform) + suffix for platform in MACS for suffix in ('', '.sha256')), *SHARED]:
        if assets.get(name, {}).get('digest') == 'sha256:' + plan['files'][name]:
            continue
        subprocess.run(['gh', 'release', 'upload', TAG, str(staged / name), '--repo', REPOSITORY, '--clobber'], check=True)
    current = release()
    assets = asset_index(current)
    for name, checksum in plan['files'].items():
        if assets.get(name, {}).get('digest') != 'sha256:' + checksum:
            raise ValueError('Published checksum mismatch: ' + name)
    for name, old in approval['assets'].items():
        if 'windows-x64' in name and (assets[name]['id'] != old['id'] or assets[name]['digest'] != 'sha256:' + old['sha256']):
            raise ValueError('Windows delivery changed')
    marker = f'<!-- macos-refresh:{source} -->'
    body = current.get('body') or ''
    if marker not in body:
        notes = work / 'release-notes.md'
        notes.write_text(body + '\n\n' + marker + '\n## macOS 安装兼容修订\n\n'
            f'Intel 与 Apple Silicon 包已从提交 [{source[:7]}](https://github.com/{REPOSITORY}/commit/{source}) 重新构建并通过原生验收。'
            'Windows 包及其 SHA256 保持不变，版本标签仍对应原始发行源码。'
            '请重新下载 Mac 完整包及配套校验文件；平台源码身份见发行清单的 artifact_source_commits 和 macos-refresh.json。'
            '本次不提供 Apple Developer ID 签名、公证或浏览器下载后 Gatekeeper 放行保证。\n')
        subprocess.run(['gh', 'release', 'edit', TAG, '--repo', REPOSITORY, '--notes-file', str(notes)], check=True)
    (work / 'publication.json').write_text(json.dumps(dict(source_commit=source, release_url=current['html_url'],
        files=plan['files'], windows_assets_unchanged=True), indent=2))
    print('Published both Mac replacements; Windows asset IDs and checksums are unchanged.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'publish'))
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit):
        raise ValueError('A complete source commit is required')
    root = Path(__file__).resolve().parents[1]
    approval = json.loads((root / 'distribution/releases/v0.3.6-macos-refresh.json').read_text())
    if approval['tag'] != TAG or approval['repository'] != REPOSITORY:
        raise ValueError('Unexpected refresh approval')
    {'prepare': prepare, 'publish': publish}[args.action](root, args.source_commit, approval)
