"""Read-only inventory and copies of baseline JSON; no Hook dispatch or secrets."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
from security_runtime.hook_state import native_io_path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'artifacts/workspace-root-fix-20261012'
FLY = Path(r'C:\Users\24170\Downloads\FlyCRM-AI-feat-ai-chat')
STATE = Path(os.environ['LOCALAPPDATA']) / 'AI Security Runtime'
OLD = Path(os.environ['LOCALAPPDATA']) / 'AI-Security-Runtime-install/versions/1f85f7cdfecd0a9ade42e23452b23d034cb2e2561cf8ca5333ca77e61082c5b5/bundle'


def digest(path):
    return hashlib.sha256(native_io_path(path).read_bytes()).hexdigest()


def main(phase):
    BASE.mkdir(parents=True, exist_ok=True)
    docs = {}
    for root in (FLY / 'FlyCRM-AI-feat-ai-chat', FLY / 'hook-experience-r6'):
        path = root / 'docs/20260904/CRM人工测试（20260904）.docx'
        docs[str(path)] = {'exists': path.is_file(), 'bytes': path.stat().st_size if path.is_file() else None,
                           'sha256': digest(path) if path.is_file() else None}
    files = {}
    for directory in (STATE / 'global-workspaces', STATE / 'hooks', STATE / 'baselines'):
        if not directory.is_dir():
            continue
        for path in directory.rglob('*.json'):
            io_path = native_io_path(path)
            if io_path.is_symlink() or io_path.stat().st_size > 4_000_000:
                continue
            name = path.relative_to(STATE).as_posix()
            files[name] = {'bytes': io_path.stat().st_size, 'sha256': digest(path)}
            if phase == 'before':
                destination = BASE / 'preserved-baselines' / name
                io_destination = native_io_path(destination)
                if io_destination.exists():
                    if digest(destination) != files[name]['sha256']:
                        raise ValueError('Do not overwrite earlier preservation evidence')
                else:
                    io_destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(io_path, io_destination)
    git = subprocess.run(['git', '-C', str(FLY / 'hook-experience-r6'), 'branch', '--show-current'],
                         capture_output=True, text=True, check=True)
    status = subprocess.run(['git', '-C', str(FLY / 'hook-experience-r6'), 'status', '--short'],
                            capture_output=True, text=True, check=True)
    result = {'phase': phase, 'state_root': str(STATE), 'baseline_json': files,
              'word_documents': docs, 'fly_test_branch': git.stdout.strip(),
              'fly_test_git_status': status.stdout.splitlines(),
              'old_install_exists': OLD.is_dir(), 'old_exe_sha256': digest(OLD / 'security-check.exe'),
              'old_launcher_sha256': digest(OLD / '_launcher/security-launcher.exe'),
              'secrets_read': False, 'hook_handlers_called': False}
    if phase != 'before':
        original = json.loads((BASE / 'preservation-before.json').read_text(encoding='utf-8'))
        result['word_documents_unchanged'] = original['word_documents'] == docs
        result['old_install_unchanged'] = result['old_exe_sha256'] == original['old_exe_sha256']
        result['all_original_baseline_json_still_exist'] = all(name in files for name in original['baseline_json'])
        result['original_baseline_json_changes'] = [name for name, record in original['baseline_json'].items()
            if files.get(name) != record]
        result['preserved_baseline_copy_hashes_match'] = all(digest(BASE / 'preserved-baselines' / name) == record['sha256']
            for name, record in original['baseline_json'].items())
        result['fly_branch_and_existing_git_changes_preserved'] = (
            git.stdout.strip() == original['fly_test_branch'] and status.stdout.splitlines() == original['fly_test_git_status'])
    destination = BASE / f'preservation-{phase}.json'
    if destination.exists():
        raise ValueError('Preservation output already exists')
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key not in {'baseline_json', 'fly_test_git_status'}}, ensure_ascii=False))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in {'before', 'after', 'after-final'}:
        raise ValueError('Expected before, after or after-final')
    main(sys.argv[1])
