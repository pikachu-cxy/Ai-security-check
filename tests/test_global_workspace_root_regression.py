"""Source-only root resolution tests; they are not desktop Hook acceptance."""
import subprocess

import pytest

from security_runtime.global_workspace import resolve_workspace


def source_file(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / 'main.ts').write_text('export const value = 1;\n', encoding='utf-8')
    return root


def test_wrapper_without_project_evidence_rejects_unrelated_ancestor_src(tmp_path):
    ancestor = tmp_path / 'container'
    (ancestor / 'src').mkdir(parents=True)
    wrapper = ancestor / 'download-wrapper' / 'unidentified-folder'
    wrapper.mkdir(parents=True)
    with pytest.raises(ValueError, match='No project detected'):
        resolve_workspace(wrapper)


def test_non_git_project_with_own_src_is_recognized(tmp_path):
    root = tmp_path / 'project'
    (root / 'src').mkdir(parents=True)
    assert resolve_workspace(root) == root.resolve()


def test_candidate_inside_own_src_resolves_to_project_root(tmp_path):
    root = tmp_path / 'project'
    nested = root / 'src' / 'services'
    nested.mkdir(parents=True)
    assert resolve_workspace(nested) == root.resolve()


def test_plain_non_git_source_directory_is_not_swallowed_by_unrelated_ancestor_src(tmp_path):
    ancestor = tmp_path / 'container'
    (ancestor / 'src').mkdir(parents=True)
    root = source_file(ancestor / 'separate-download' / 'project')
    assert resolve_workspace(root) == root.resolve()


def test_manifest_project_keeps_existing_root_priority(tmp_path):
    ancestor = tmp_path / 'container'
    (ancestor / 'src').mkdir(parents=True)
    root = ancestor / 'project'
    nested = root / 'lib' / 'submodule'
    nested.mkdir(parents=True)
    (root / 'package.json').write_text('{}\n', encoding='utf-8')
    assert resolve_workspace(nested) == root.resolve()


def test_git_root_keeps_priority_over_layout_markers(tmp_path):
    root = tmp_path / 'repository'
    nested = root / 'module' / 'src' / 'services'
    nested.mkdir(parents=True)
    (root / 'module' / 'package.json').write_text('{}\n', encoding='utf-8')
    subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
    assert resolve_workspace(nested) == root.resolve()


def test_wrapper_is_not_guessed_from_a_child_project(tmp_path):
    wrapper = tmp_path / 'download-wrapper'
    child = wrapper / 'project'
    (child / 'src').mkdir(parents=True)
    with pytest.raises(ValueError, match='No project detected'):
        resolve_workspace(wrapper)
