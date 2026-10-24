"""Narrow linked-worktree admission; no host/session attestation is implied."""
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.global_mcp import GlobalWorkspaces
from security_runtime.global_workspace import resolve_workspace


def git(root, *arguments):
    subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.hooksPath=",
         "-c", "core.fsmonitor=false", "-c", "user.name=L0 fixture",
         "-c", "user.email=l0@example.invalid", "-C", str(root), *arguments],
        check=True, capture_output=True, timeout=20,
    )


@pytest.fixture
def layout(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    home = base / "codex-home"
    home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setenv("SECURITY_RUNTIME_CODEX_HOME", str(home))
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(base / "runtime-state"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_CONFIG", "GIT_CONFIG_COUNT"):
        monkeypatch.delenv(key, raising=False)
    origin = base / "origin"
    origin.mkdir()
    git(origin, "init", "-q")
    (origin / "src").mkdir()
    (origin / "src" / "main.py").write_text("value = 1\n", encoding="utf-8")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "L0 fixture")
    return base, home, origin


def linked_worktree(origin, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    git(origin, "worktree", "add", "--detach", str(target), "HEAD")
    assert (target / ".git").is_file()
    assert (target / "src" / "main.py").read_text(encoding="utf-8") == "value = 1\n"
    return target


@pytest.fixture
def pool(layout):
    base, home, _ = layout
    workspaces = GlobalWorkspaces(base=base / "routing-state",
                                  integration=SimpleNamespace(home=home))
    try:
        yield workspaces
    finally:
        workspaces.close()


def test_external_linked_worktree_resolves_its_own_root(layout, pool):
    base, _, origin = layout
    target = linked_worktree(origin, base / "external-worktree")
    assert resolve_workspace(target) == target
    assert resolve_workspace(target / "src") == target
    assert pool.root(target / "src") == target
    assert not pool.children and not pool.sessions and not pool.jobs


def test_codex_home_admits_only_verified_linked_worktree_root(layout, pool):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    for resolve in (resolve_workspace, pool.root):
        for candidate in (target, target / "src"):
            assert resolve(candidate) == target
    assert not pool.children and not pool.sessions and not pool.jobs


def test_worktree_validation_does_not_write_metadata_or_register_runtime_state(layout, pool):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    marker = target / ".git"
    admin = Path(marker.read_text(encoding="utf-8").removeprefix("gitdir: ").strip())
    paths = [marker, admin / "commondir", admin / "gitdir", origin / ".git" / "config"]
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    for _ in range(3):
        assert pool.root(target / "src") == target
    assert before == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    assert not pool.base.exists()
    assert not pool.children and not pool.sessions and not pool.jobs


@pytest.mark.parametrize("name", ["project with spaces", "项目",
    pytest.param('project "quoted"', marks=pytest.mark.skipif(os.name == "nt", reason="Windows filename restriction")),
    pytest.param("project\\backslash", marks=pytest.mark.skipif(os.name == "nt", reason="Windows separator"))])
def test_git_porcelain_path_representation_preserves_exact_target(layout, pool, name):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / name)
    assert pool.root(target) == target


def test_pool_codex_home_policy_remains_when_environment_home_differs(layout, pool, monkeypatch):
    base, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    other_home = base / "other-codex-home"
    other_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(other_home))
    monkeypatch.setenv("SECURITY_RUNTIME_CODEX_HOME", str(other_home))
    assert resolve_workspace(target) == target
    assert pool.root(target) == target
    assert not pool.children and not pool.sessions and not pool.jobs


def test_default_codex_home_uses_the_same_narrow_admission(layout, monkeypatch):
    base, _, origin = layout
    fake_user = base / "user-home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_user))
    monkeypatch.delenv("CODEX_HOME")
    monkeypatch.delenv("SECURITY_RUNTIME_CODEX_HOME")
    target = linked_worktree(origin, fake_user / ".codex" / "worktrees" / "fixture" / "project")
    assert resolve_workspace(target) == target
    with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
        resolve_workspace(fake_user / ".codex")


@pytest.mark.parametrize("relative", [".", "worktrees", "config", "credentials", "runtime-state"])
def test_codex_home_containers_and_internal_directories_stay_protected(layout, pool, relative):
    _, home, _ = layout
    candidate = home / relative
    candidate.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
        pool.root(candidate)


def test_linked_worktree_does_not_override_state_or_explicit_exclusions(layout, pool, monkeypatch):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
        resolve_workspace(target, excluded=(home,))
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(home / "worktrees"))
    with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
        pool.root(target)


def configuration_alias(base, target, spelling):
    if spelling == "parent_component":
        intermediate = base / "configuration-hop"
        intermediate.mkdir()
        return intermediate / ".." / target.relative_to(base)
    alias = base / "configuration-alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable")
    return alias


@pytest.mark.parametrize("spelling", ["parent_component", "symlink"])
@pytest.mark.parametrize("boundary", ["runtime_state", "excluded", "pool_state"])
def test_configuration_alias_cannot_bypass_protected_boundary(layout, pool, monkeypatch, spelling, boundary):
    base, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    protected = configuration_alias(base, home / "worktrees", spelling)
    if boundary == "runtime_state":
        monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(protected))
        resolve = lambda: pool.root(target)
    elif boundary == "excluded":
        resolve = lambda: resolve_workspace(target, excluded=(protected,))
    else:
        pool.base = protected
        resolve = lambda: pool.root(target)
    with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
        resolve()
    assert not pool.children and not pool.sessions and not pool.jobs


@pytest.mark.parametrize("spelling", ["parent_component", "symlink"])
def test_codex_home_configuration_alias_keeps_real_home_narrowly_protected(layout, pool, monkeypatch, spelling):
    base, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    alias = configuration_alias(base, home, spelling)
    monkeypatch.setenv("CODEX_HOME", str(alias))
    monkeypatch.setenv("SECURITY_RUNTIME_CODEX_HOME", str(alias))
    pool.integration.home = alias
    assert resolve_workspace(target) == target
    assert pool.root(target / "src") == target
    for protected in (home, home / "worktrees", home / "credentials"):
        protected.mkdir(exist_ok=True)
        with pytest.raises(ValueError, match="^RUNTIME_STATE_IS_NOT_A_WORKSPACE$"):
            pool.root(protected)
    assert not pool.children and not pool.sessions and not pool.jobs


@pytest.mark.parametrize("defect", ["marker", "back_pointer", "commondir", "ordinary_repository"])
def test_codex_home_rejects_fake_or_broken_worktree_metadata(layout, pool, defect):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    marker = target / ".git"
    admin = Path(marker.read_text(encoding="utf-8").removeprefix("gitdir: ").strip())
    if defect == "marker":
        marker.write_text("gitdir: " + str(origin / ".git") + "\n", encoding="utf-8")
    elif defect == "back_pointer":
        (admin / "gitdir").write_text(str(origin / ".git") + "\n", encoding="utf-8")
    elif defect == "commondir":
        (admin / "commondir").write_text(str(home) + "\n", encoding="utf-8")
    else:
        marker.unlink()
        git(target, "init", "-q")
    with pytest.raises(ValueError, match="^WORKSPACE_WORKTREE_INVALID$"):
        pool.root(target)
    assert not pool.children and not pool.sessions and not pool.jobs


@pytest.mark.parametrize("link", ["project", "marker", "commondir"])
def test_codex_home_rejects_linked_paths_and_metadata(layout, pool, link):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")
    if link == "project":
        alias = target.parent / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("Directory symlinks are unavailable")
        target = alias
    else:
        marker = target / ".git"
        admin = Path(marker.read_text(encoding="utf-8").removeprefix("gitdir: ").strip())
        path = marker if link == "marker" else admin / "commondir"
        saved = path.with_name(path.name + ".saved")
        path.rename(saved)
        try:
            path.symlink_to(saved)
        except OSError:
            pytest.skip("File symlinks are unavailable")
    with pytest.raises(ValueError):
        pool.root(target)


def test_git_listing_must_confirm_the_reciprocal_registration(layout, pool, monkeypatch):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")

    def unrelated_listing(command, **arguments):
        assert command[-3:] == ["worktree", "list", "--porcelain"]
        arguments["stdout"].write(b"worktree /unrelated\nHEAD " + b"a" * 40 + b"\n\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("security_runtime.worktree_admission.subprocess.run", unrelated_listing)
    with pytest.raises(ValueError, match="^WORKSPACE_WORKTREE_INVALID$"):
        pool.root(target)


def test_replacement_during_verification_does_not_gain_admission(layout, pool, monkeypatch):
    _, home, origin = layout
    target = linked_worktree(origin, home / "worktrees" / "fixture" / "project")

    def replace_directory(common, root):
        marker = (root / ".git").read_bytes()
        root.rename(root.with_name("replaced-project"))
        root.mkdir()
        (root / ".git").write_bytes(marker)

    monkeypatch.setattr("security_runtime.worktree_admission._registered", replace_directory)
    with pytest.raises(ValueError, match="^WORKSPACE_WORKTREE_INVALID$"):
        pool.root(target)


def test_current_session_binding_reuses_same_root_and_rejects_cross_root(layout, pool):
    base, _, origin = layout
    target = linked_worktree(origin, base / "external-worktree")
    key = pool.bind_session("session-a", origin)
    assert pool.bind_session("session-a", origin) == key
    before = dict(pool.sessions)
    with pytest.raises(ValueError, match="^SESSION_WORKSPACE_MISMATCH$"):
        pool.bind_session("session-a", target)
    assert pool.sessions == before == {key: origin}
    assert not pool.children and not pool.jobs
