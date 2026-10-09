import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_runtime.git import GitService, GitError
from security_runtime.staged import index_projection
from security_runtime.hooks import GitHookManager, gate_exit
from security_runtime.models import ScanResult, TargetProfile
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from git_gate_fixture import Registry


def git(root, *args, check=True):
    return subprocess.run(['git', '-C', str(root), *args], capture_output=True, check=check)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / 'repo with space'
    root.mkdir()
    git(root, 'init', '-b', 'main')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    return root


def test_partial_stage_and_missing_worktree_reads_index_bytes_and_context(repo):
    path = repo / '空 格.py'
    path.write_text('RISK\n')
    git(repo, 'add', '--', path.name)
    path.write_text('SAFE\n')
    before = git(repo, 'ls-files', '--stage', '-z').stdout
    with index_projection(GitService(repo)) as root:
        assert (root / path.name).read_bytes() == b'RISK\n'
    result = SecurityRuntime(Registry(), SQLiteStore(repo.parent / 'state/scans.db')).scan(repo, staged=True)
    assert result.release_status == 'BLOCKED' and result.findings[0].file_path == path.name
    assert result.target_profile.path == str(repo)
    assert path.read_text() == 'SAFE\n'
    path.unlink()
    assert SecurityRuntime(Registry(), SQLiteStore(repo.parent / 'state/scans.db')).scan(repo, staged=True).release_status == 'BLOCKED'
    assert git(repo, 'ls-files', '--stage', '-z').stdout == before


def test_context_manifest_comes_from_same_index_revision(repo):
    (repo / 'a.py').write_text('SAFE\n')
    (repo / 'requirements.txt').write_text('index-package==1\n')
    git(repo, 'add', '.')
    (repo / 'requirements.txt').write_text('working-package==2\n')
    with index_projection(GitService(repo)) as snapshot:
        assert (snapshot / 'requirements.txt').read_text() == 'index-package==1\n'


def test_index_concurrent_mutation_fails_closed(repo):
    path = repo / 'a.py'
    path.write_text('SAFE\n')
    git(repo, 'add', '.')
    with pytest.raises(GitError, match='INDEX_CHANGED_DURING_SCAN'):
        with index_projection(GitService(repo)):
            path.write_text('changed\n')
            git(repo, 'add', '.')


def test_rename_delete_and_initial_commit(repo):
    (repo / 'old.py').write_text('SAFE\n')
    git(repo, 'add', '.')
    assert GitService(repo).changed_files('quick', staged=True) == ['old.py']
    git(repo, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'initial')
    git(repo, 'mv', 'old.py', 'new.py')
    assert GitService(repo).changed_files('quick', staged=True) == ['new.py']
    with index_projection(GitService(repo)) as root:
        assert (root / 'new.py').read_bytes() == b'SAFE\n' and not (root / 'old.py').exists()
    git(repo, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'rename')
    git(repo, 'rm', 'new.py')
    assert GitService(repo).changed_files('quick', staged=True) == []


@pytest.mark.skipif(os.name == 'nt', reason='Windows filenames cannot contain newline')
def test_nul_safe_newline_filename(repo):
    name = 'line\nname.py'
    (repo / name).write_text('SAFE\n')
    git(repo, 'add', '.')
    assert GitService(repo).changed_files('quick', staged=True) == [name]


@pytest.mark.parametrize('status,execution,release,policy,expected', [
    ('COMPLETED','EXECUTED','SAFE','strict',0), ('COMPLETED','EXECUTED','BLOCKED','report',1),
    ('PARTIAL','UNAVAILABLE','REVIEW','strict',2), ('PARTIAL','UNAVAILABLE','REVIEW','report',0),
    ('NO_CHANGES','NO_CHANGES','NOT_ASSESSED','strict',0)])
def test_gate_exit_contract(status, execution, release, policy, expected):
    result = ScanResult('fixture','quick',TargetProfile('.'),status,[],[],'',release,0,
                        coverage='FULL' if status=='COMPLETED' else 'MINIMAL',execution_state=execution)
    assert gate_exit(result, policy) == expected


def test_real_git_commit_fixed_provider_blocks_risk_and_incomplete_allows_safe_index(repo):
    fixture = Path(__file__).with_name('git_gate_fixture.py')
    manager = GitHookManager(repo, discover=lambda: {'command': sys.executable, 'prefix': [str(fixture)], 'kind': 'FIXTURE'})
    assert manager.execute('install')['status'] == 'INSTALLED'
    path = repo / 'a.py'
    for index, working, allowed in [('RISK', 'SAFE', False), ('INCOMPLETE', 'SAFE', False), ('SAFE', 'RISK', True)]:
        path.write_text(index + '\n')
        git(repo, 'add', '.')
        path.write_text(working + '\n')
        committed = git(repo, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', index, check=False)
        assert (committed.returncode == 0) == allowed, committed.stderr.decode(errors='replace')
    assert manager.execute('status')['status'] == 'INSTALLED'
    assert manager.execute('repair')['status'] == 'INSTALLED'
    assert manager.execute('remove')['status'] == 'REMOVED'


def test_unknown_and_modified_hook_preserved(repo):
    manager = GitHookManager(repo)
    manager.path.parent.mkdir(exist_ok=True)
    raw = b'#!/bin/sh\nexit 7\n'
    manager.path.write_bytes(raw)
    for action in ('install', 'repair', 'remove'):
        with pytest.raises(ValueError, match='GIT_HOOK_USER_CONTENT_PRESERVED'):
            manager.execute(action)
        assert manager.path.read_bytes() == raw


def test_worktree_uses_its_own_index_not_the_main_checkout(repo):
    (repo / 'a.py').write_text('SAFE\n')
    git(repo, 'add', '.')
    git(repo, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'initial')
    worktree = repo.parent / 'isolated worktree'
    main_bytes = (repo / 'a.py').read_bytes()
    git(repo, 'worktree', 'add', '-b', 'fixture-worktree', str(worktree))
    (worktree / 'a.py').write_text('RISK\n')
    git(worktree, 'add', '.')
    with index_projection(GitService(worktree)) as snapshot:
        assert (snapshot / 'a.py').read_bytes() == b'RISK\n'
    assert (repo / 'a.py').read_bytes() == main_bytes
