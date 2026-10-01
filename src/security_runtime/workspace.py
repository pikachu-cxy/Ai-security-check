"""Resolve and validate project workspaces for every entry point."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .git import GitError, GitService


NO_PROJECT = (
    "No project detected.\n"
    "Run Security Runtime inside a Git repository\n"
    "or specify a project explicitly:\n"
    "security-check doctor --path <project>"
)
UNSAFE_WORKSPACE = (
    "The requested path does not appear to be a project workspace. "
    "Security Runtime will not scan the entire user home or system drive."
)


class WorkspaceError(ValueError):
    pass


@dataclass(frozen=True)
class Workspace:
    path: Path
    is_git: bool


class WorkspaceResolver:
    def resolve(self, path: str | Path | None = None, *, allow_non_git_explicit: bool = False,
                allow_non_git_source: bool = False) -> Workspace:
        explicit = path is not None
        candidate = Path(path) if explicit else Path.cwd()
        if any(item.is_symlink() or item.is_junction() for item in (candidate.absolute(), *candidate.absolute().parents)):
            raise WorkspaceError("Workspace symlinks and junctions are not supported")
        if self._unsafe(candidate.absolute()):
            raise WorkspaceError(UNSAFE_WORKSPACE if explicit else NO_PROJECT)
        try:
            candidate = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise WorkspaceError(f"Project path does not exist: {candidate}") from exc
        if not candidate.is_dir():
            raise WorkspaceError("Project path must be a directory")
        if self._unsafe(candidate):
            raise WorkspaceError(UNSAFE_WORKSPACE)
        try:
            root = GitService(candidate).top_level()
        except GitError as exc:
            if (explicit and allow_non_git_explicit) or (allow_non_git_source and self._source_directory(candidate)):
                return Workspace(candidate, False)
            raise WorkspaceError(NO_PROJECT) from exc
        if self._unsafe(root):
            raise WorkspaceError(UNSAFE_WORKSPACE)
        return Workspace(root, True)

    @staticmethod
    def _source_directory(path: Path) -> bool:
        # Bounded name-only recognition; never walk an arbitrary default directory.
        from .target import DEPENDENCIES, EXTENSIONS, IGNORED
        for index, item in enumerate(path.iterdir()):
            if index >= 1000:
                return False
            if item.name in IGNORED or item.is_symlink() or item.is_junction():
                continue
            if item.is_file() and (item.name in DEPENDENCIES or item.suffix.lower() in EXTENSIONS):
                return True
            if item.is_dir() and item.name == "src":
                return True
        return False

    @staticmethod
    def _unsafe(path: Path) -> bool:
        home = Path.home()
        system_root = os.environ.get("SystemRoot")
        protected = {home, home.parent, Path(path.anchor)}
        normalized = os.path.normcase(os.path.abspath(path))
        if any(normalized == os.path.normcase(os.path.abspath(item)) for item in protected):
            return True
        system_directories = [system_root, os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramData")]
        for directory in filter(None, system_directories):
            system_path = os.path.normcase(os.path.abspath(directory))
            if normalized == system_path or normalized.startswith(system_path + os.sep):
                return True
        return False
