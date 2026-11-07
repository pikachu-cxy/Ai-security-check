"""Local repository grouping without executing Git on the closeout path."""
import os
from pathlib import Path
from .hook_state import identity


def describe(workspace):
    root = Path(workspace).resolve()
    work_id = identity(os.path.normcase(str(root)))
    common = root
    kind = 'DIRECTORY'
    try:
        git = root / '.git'
        if git.is_file() and git.stat().st_size <= 4096:
            text = git.read_text().strip()
            if not text.startswith('gitdir: '):
                raise ValueError('Invalid Git pointer')
            git = (root / text[8:]).resolve()
        if git.is_dir():
            shared = git / 'commondir'
            if shared.is_file() and shared.stat().st_size <= 4096:
                git = (git / shared.read_text().strip()).resolve()
            common, kind = git, 'GIT_COMMON_DIRECTORY'
    except (OSError, ValueError, UnicodeError):
        pass
    return dict(project_id=identity(os.path.normcase(str(common))), workspace_id=work_id,
                workspace=str(root), identity_kind=kind)
