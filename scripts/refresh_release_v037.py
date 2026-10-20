"""Refresh the explicitly pinned v0.3.7 release from verified native CI assets."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

REPOSITORY = 'pikachu-cxy/Ai-security-check'
TAG = 'v0.3.7'
SOURCE = '699851ea94bcce8d21cd27fdc40cff315ecf815d'
PLATFORMS = ('windows-x64', 'macos-arm64', 'macos-x64')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}'], text=True, encoding='utf-8'))


def command(*args, **kwargs):
    subprocess.run(list(args), check=True, **kwargs)


def names():
    archives = [f'ai-security-runtime-{TAG}-{p}' + ('.zip' if p == 'windows-x64' else '.tar.gz') for p in PLATFORMS]
    return {*archives, *(name + '.sha256' for name in archives),
            f'ai-security-runtime-{TAG}-release-evidence.zip', 'release-manifest.json', 'SHA256SUMS.txt'}


def validate_approval(value):
    if (value['repository'] != REPOSITORY or value['tag'] != TAG or value['source_commit'] != SOURCE
            or set(value['assets']) != names() or type(value['release_id']) is not int
            or not re.fullmatch('[0-9a-f]{40}', value['original_tag_commit'])
            or any(type(v['id']) is not int or not re.fullmatch('[0-9a-f]{64}', v['sha256']) for v in value['assets'].values())):
        raise ValueError('Unexpected refresh scope')


def check_runs(approval, *, wait=False):
    for attempt in range(80 if wait else 1):
        runs = [api(f'actions/runs/{approval[key]}') for key in ('build_run_id', 'test_run_id')]
        if any(run['head_sha'] != SOURCE or (run['status'] == 'completed' and run['conclusion'] != 'success') for run in runs):
            raise ValueError('Pinned native build or Runtime regression failed')
        if all(run['status'] == 'completed' for run in runs):
            return
        if wait:
            print('Waiting for pinned native CI and Runtime regressions.', flush=True)
            time.sleep(30)
    raise ValueError('Pinned verification has not completed')


def check_release(value, approval, staged=None):
    if (value['id'] != approval['release_id'] or value['tag_name'] != TAG
            or value['draft'] or value.get('immutable')):
        raise ValueError('Release identity changed')
    assets = {row['name']: row for row in value['assets']}
    if len(assets) != len(value['assets']) or set(assets) - names():
        raise ValueError('Concurrent release scope changed')
    for name, old in approval['assets'].items():
        row = assets.get(name)
        if staged is not None and (not row or row.get('digest') == 'sha256:' + staged[name]):
            continue  # Exact resumable upload, including --clobber's delete/upload gap.
        if not row or row['id'] != old['id'] or row.get('digest') != 'sha256:' + old['sha256']:
            raise ValueError('Concurrent release asset changed: ' + name)
    return assets


def tag_commit():
    tag = api(f'git/ref/tags/{TAG}')['object']
    if tag['type'] != 'commit':
        raise ValueError('Unexpected tag object type')
    return tag['sha']


def prepare(root, approval):
    check_runs(approval)
    current = api(f'releases/tags/{TAG}')
    check_release(current, approval)
    if tag_commit() != approval['original_tag_commit']:
        raise ValueError('Original tag changed')
    public = root / 'dist/public-release'
    if {p.name for p in public.iterdir()} != names() or any(not p.is_file() or p.is_symlink() for p in public.iterdir()):
        raise ValueError('Unexpected staged files')
    manifest = json.loads((public / 'release-manifest.json').read_text(encoding='utf-8'))
    if manifest['source_commit'] != SOURCE or manifest['version'] != '0.3.7':
        raise ValueError('Wrong source provenance')
    for platform in PLATFORMS:
        name = f'ai-security-runtime-{TAG}-{platform}' + ('.zip' if platform == 'windows-x64' else '.tar.gz')
        receipt = json.loads((root / 'dist/release' / (name + '.verification.json')).read_text(encoding='utf-8'))
        flags = ('smoke', 'managed_engines', 'plugin_discovery', 'osv_offline_fallback',
                 'fix_verify_offline_synthetic', 'hooks_offline_synthetic',
                 'remediation_offline_synthetic', 'codex_integration_offline_synthetic')
        if (receipt['source_commit'] != SOURCE or receipt['archive_sha256'] != digest(public / name)
                or receipt['platform'] != platform or receipt['version'] != '0.3.7'
                or not all(receipt.get(key) is True for key in flags)):
            raise ValueError('Incomplete native acceptance: ' + platform)
    work = root / 'dist/refresh-v037'
    work.mkdir(exist_ok=False)
    previous = work / 'previous'
    previous.mkdir()
    (work / 'previous-release.json').write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding='utf-8')
    for name, old in approval['assets'].items():
        command('gh', 'release', 'download', TAG, '--repo', REPOSITORY, '--pattern', name, '--dir', str(previous))
        if digest(previous / name) != old['sha256']:
            raise ValueError('Original backup checksum mismatch')
    shutil.copytree(public, work / 'staged')
    notes = (root / 'dist/release-notes.md').read_text(encoding='utf-8')
    notes += (f'\n## 本次安装包更新\n\n安装包基于提交 [{SOURCE[:7]}](https://github.com/{REPOSITORY}/commit/{SOURCE}) 重新构建。'
              '包含文档与编辑器使用说明、Cursor 常规调用和安装提示修订，以及保守的失联任务归属判定。'
              'Windows、Apple Silicon 和 Intel Mac 均已执行原生包验收；完整证据见验收 ZIP。\n')
    (work / 'release-notes.md').write_text(notes, encoding='utf-8')
    plan = dict(source_commit=SOURCE, files={p.name: digest(p) for p in (work / 'staged').iterdir()}, notes_sha256=digest(work / 'release-notes.md'))
    (work / 'plan.json').write_text(json.dumps(plan, indent=2), encoding='utf-8')


def publish(root, approval):
    check_runs(approval)
    work = root / 'dist/refresh-v037'
    plan = json.loads((work / 'plan.json').read_text(encoding='utf-8'))
    if plan['source_commit'] != SOURCE or set(plan['files']) != names() or digest(work / 'release-notes.md') != plan['notes_sha256']:
        raise ValueError('Staged publication scope changed')
    for name, sha in plan['files'].items():
        path = work / 'staged' / name
        if not path.is_file() or path.is_symlink() or digest(path) != sha:
            raise ValueError('Staged content changed')
    for name, old in approval['assets'].items():
        if digest(work / 'previous' / name) != old['sha256']:
            raise ValueError('Recovery backup changed')
    current = api(f'releases/tags/{TAG}')
    assets = check_release(current, approval, plan['files'])
    original = json.loads((work / 'previous-release.json').read_text(encoding='utf-8'))
    notes = (work / 'release-notes.md').read_text(encoding='utf-8')
    if current.get('body') not in (original.get('body'), notes):
        raise ValueError('Concurrent release notes changed')
    tag = tag_commit()
    if tag not in (approval['original_tag_commit'], SOURCE):
        raise ValueError('Concurrent tag change')
    for name in sorted(names()):
        if assets.get(name, {}).get('digest') != 'sha256:' + plan['files'][name]:
            command('gh', 'release', 'upload', TAG, str(work / 'staged' / name), '--repo', REPOSITORY, '--clobber')
    actual = check_release(api(f'releases/tags/{TAG}'), approval, plan['files'])
    if set(actual) != names() or any(actual[name].get('digest') != 'sha256:' + sha for name, sha in plan['files'].items()):
        raise ValueError('Published download checksum mismatch')
    if tag != SOURCE:
        command('git', 'push', 'origin', f'{SOURCE}:refs/tags/{TAG}',
                f'--force-with-lease=refs/tags/{TAG}:{approval["original_tag_commit"]}', cwd=root)
    command('gh', 'release', 'edit', TAG, '--repo', REPOSITORY, '--notes-file', str(work / 'release-notes.md'))
    if tag_commit() != SOURCE or api(f'releases/tags/{TAG}').get('body') != notes:
        raise ValueError('Final publication identity mismatch')
    (work / 'publication.json').write_text(json.dumps(dict(status='PUBLISHED', source_commit=SOURCE, files=plan['files']), indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('wait', 'prepare', 'publish'))
    parser.add_argument('--root', type=Path, default=Path.cwd())
    args = parser.parse_args()
    approval = json.loads((Path(__file__).resolve().parents[1] / 'distribution/releases/v0.3.7-refresh.json').read_text(encoding='utf-8'))
    validate_approval(approval)
    if args.action == 'wait':
        check_runs(approval, wait=True)
    else:
        {'prepare': prepare, 'publish': publish}[args.action](args.root.resolve(), approval)
