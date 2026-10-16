"""Real Git fixtures for the narrow Codex managed-worktree admission exception."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.global_workspace import resolve_workspace


def git(*args):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith('GIT_')}
    return subprocess.run(['git', *map(str, args)], env=env, check=True,
                          capture_output=True, text=True, timeout=15).stdout.strip()


def initialize_repository(path):
    path.mkdir(parents=True, exist_ok=True)
    git('init', '-q', path)
    (path / 'src').mkdir()
    (path / 'src' / 'app.py').write_text('value = 1\n', encoding='utf-8')
    git('-C', path, 'add', '.')
    git('-C', path, '-c', 'user.name=fixture', '-c',
        'user.email=fixture@example.invalid', 'commit', '-qm', 'initial')
    return path.resolve()


def linked_worktree(repository, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    git('-C', repository, 'worktree', 'add', '--detach', path, 'HEAD')
    return path.resolve()


@pytest.fixture
def managed(tmp_path, monkeypatch):
    home = tmp_path / 'codex-home'
    user = tmp_path / 'user-home'
    user.mkdir()
    home.mkdir()
    monkeypatch.setattr(Path, 'home', staticmethod(lambda: user))
    monkeypatch.setenv('CODEX_HOME', str(home))
    monkeypatch.delenv('SECURITY_RUNTIME_CODEX_HOME', raising=False)
    state = tmp_path / 'runtime-state'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(state))
    repository = initialize_repository(tmp_path / 'external-repository')
    root = linked_worktree(repository, home / 'worktrees' / 'managed-id' / 'project')
    gitfile = root / '.git'
    admin = Path(gitfile.read_text(encoding='utf-8').strip().split(':', 1)[1].strip())
    if not admin.is_absolute():
        admin = root / admin
    admin = admin.resolve()
    return SimpleNamespace(home=home, user=user, state=state, repository=repository,
                           root=root, gitfile=gitfile, admin=admin,
                           common=(repository / '.git').resolve())


def rejected(path, **kwargs):
    with pytest.raises((ValueError, OSError)):
        resolve_workspace(path, **kwargs)


def test_real_managed_worktree_and_source_subdirectory_are_admitted(managed):
    assert resolve_workspace(managed.root) == managed.root
    assert resolve_workspace(managed.root / 'src') == managed.root


def test_external_repository_and_source_subdirectory_still_resolve(managed):
    assert resolve_workspace(managed.repository) == managed.repository
    assert resolve_workspace(managed.repository / 'src') == managed.repository


def test_trusted_codex_home_parameter_supports_actual_managed_layout(managed, tmp_path):
    alternate = tmp_path / 'trusted-codex-home'
    root = linked_worktree(managed.repository, alternate / 'worktrees' / 'id' / 'repo')
    assert resolve_workspace(root, codex_home=alternate) == root
    rejected(alternate, codex_home=alternate)


@pytest.mark.parametrize('relative', ['', 'worktrees', 'worktrees/managed-id', 'sessions',
                                     'memories', 'worktrees/not-a-worktree/project'])
def test_codex_state_containers_and_plain_source_directories_remain_rejected(managed, relative):
    path = managed.home / relative
    path.mkdir(parents=True, exist_ok=True)
    (path / 'package.json').write_text('{}\n', encoding='utf-8')
    rejected(path)


def test_default_codex_home_remains_protected_with_custom_home_configured(managed):
    default_home = managed.user / '.codex'
    repository = initialize_repository(default_home / 'sessions' / 'pretend-project')
    rejected(repository)
    rejected(repository / 'src')


def test_default_codex_home_valid_worktree_is_supported_with_custom_home_configured(managed):
    root = linked_worktree(managed.repository,
                           managed.user / '.codex' / 'worktrees' / 'default-id' / 'project')
    assert resolve_workspace(root) == root


def test_plain_git_repository_at_managed_layout_does_not_get_exception(managed):
    root = initialize_repository(managed.home / 'worktrees' / 'fake-id' / 'project')
    rejected(root)
    rejected(root / 'src')


@pytest.mark.parametrize('relative', ['worktrees/shallow', 'worktrees/deep/group/repository',
                                     'sessions/id/project'])
def test_real_linked_worktree_outside_exact_managed_layout_is_rejected(managed, relative):
    root = linked_worktree(managed.repository, managed.home / relative)
    rejected(root)
    rejected(root / 'src')


@pytest.mark.parametrize('location', ['home', 'root', 'source', 'external-metadata'])
def test_explicit_exclusions_take_priority_over_managed_worktree_exception(managed, location):
    excluded = {'home': managed.home, 'root': managed.root,
                'source': managed.root / 'src', 'external-metadata': managed.common}[location]
    rejected(managed.root, excluded=(excluded,))


def test_nested_git_repository_cannot_borrow_outer_worktree_exception(managed):
    nested = initialize_repository(managed.root / 'nested')
    rejected(nested)
    rejected(nested / 'src')


def test_gitfile_cannot_point_to_another_worktrees_administration(managed):
    other = managed.home / 'worktrees' / 'different-id' / 'project'
    other.mkdir(parents=True)
    (other / '.git').write_bytes(managed.gitfile.read_bytes())
    (other / 'src').mkdir()
    rejected(other)
    rejected(other / 'src')


def test_backlink_must_identify_this_exact_gitfile(managed, tmp_path):
    (managed.admin / 'gitdir').write_text(str(tmp_path / 'foreign' / '.git') + '\n',
                                        encoding='utf-8')
    rejected(managed.root)


def test_commondir_must_contain_the_worktree_administration(managed, tmp_path):
    other = initialize_repository(tmp_path / 'different-repository')
    (managed.admin / 'commondir').write_text(str(other / '.git') + '\n', encoding='utf-8')
    rejected(managed.root)


@pytest.mark.parametrize('placement', ['codex-state', 'runtime-state', 'explicit-excluded'])
def test_common_git_directory_must_not_live_in_protected_state(managed, tmp_path, placement):
    directory = {'codex-state': managed.home / 'state-repository',
                 'runtime-state': managed.state / 'state-repository',
                 'explicit-excluded': tmp_path / 'excluded' / 'repository'}[placement]
    repository = initialize_repository(directory)
    root = linked_worktree(repository, managed.home / 'worktrees' / placement / 'project')
    exclusions = (tmp_path / 'excluded',) if placement == 'explicit-excluded' else ()
    rejected(root, excluded=exclusions)


@pytest.mark.parametrize('metadata', ['gitdir', 'commondir', 'worktree-head', 'common-head',
                                     'common-config', 'common-objects'])
def test_missing_required_git_metadata_is_rejected(managed, metadata):
    path = {'gitdir': managed.admin / 'gitdir', 'commondir': managed.admin / 'commondir',
            'worktree-head': managed.admin / 'HEAD', 'common-head': managed.common / 'HEAD',
            'common-config': managed.common / 'config',
            'common-objects': managed.common / 'objects'}[metadata]
    path.rename(path.with_name(path.name + '.removed'))
    rejected(managed.root)


@pytest.mark.parametrize('contents', ['', 'not a gitfile\n', 'gitdir: \n',
                                     'gitdir: missing\n', 'gitdir: missing\nextra\n',
                                     'gitdir: missing\x00\n', 'gitdir: ' + 'x' * 8192],
                         ids=['empty', 'prefix', 'empty-target', 'missing', 'multiple-lines',
                              'nul-target', 'oversized'])
def test_malformed_or_unbounded_gitfile_is_rejected(managed, contents):
    # Git for Windows marks .git hidden; reopening with CREATE_ALWAYS fails.
    # Updating an existing file avoids changing the fixture's metadata flags.
    with managed.gitfile.open('r+b') as stream:
        stream.write(contents.encode('utf-8'))
        stream.truncate()
    rejected(managed.root)


def test_ambient_git_directory_cannot_admit_a_fake_managed_project(managed, monkeypatch):
    fake = managed.home / 'worktrees' / 'ambient-id' / 'project'
    fake.mkdir(parents=True)
    (fake / 'src').mkdir()
    monkeypatch.setenv('GIT_DIR', str(managed.common))
    monkeypatch.setenv('GIT_WORK_TREE', str(fake))
    rejected(fake)


def directory_link(link, target):
    if os.name == 'nt':
        result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            pytest.skip('Host does not permit fixture junctions')
    else:
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip('Host does not permit fixture symlinks')


def test_linked_alias_to_managed_workspace_is_rejected(managed, tmp_path):
    alias = tmp_path / 'workspace-alias'
    directory_link(alias, managed.root)
    rejected(alias)
    rejected(alias / 'src')


def test_linked_worktree_administration_directory_is_rejected(managed, tmp_path):
    original = managed.admin
    moved = tmp_path / 'real-administration'
    original.rename(moved)
    directory_link(original, moved)
    rejected(managed.root)


@pytest.mark.parametrize('metadata', ['gitfile', 'commondir', 'backlink'])
def test_linked_git_metadata_file_is_rejected(managed, metadata):
    path = {'gitfile': managed.gitfile, 'commondir': managed.admin / 'commondir',
            'backlink': managed.admin / 'gitdir'}[metadata]
    target = path.with_name(path.name + '.real')
    path.rename(target)
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip('Host does not permit fixture file symlinks')
    rejected(managed.root)
