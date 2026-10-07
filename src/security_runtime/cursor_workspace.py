"""Cursor ingress diagnostics around the unchanged canonical workspace resolver.

No cwd routing or Git ownership override. All exception projections are enums;
raw claims, probe output and paths stay ephemeral.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path, PureWindowsPath

from .global_workspace import resolve_workspace
from .hook_state import no_links
from .storage import SQLiteStore
from .workspace import WorkspaceResolver

REJECTIONS = {'RAW_PATH_NOT_ABSOLUTE', 'PATH_NOT_FOUND', 'PATH_NOT_DIRECTORY',
    'WINDOWS_PATH_NORMALIZATION', 'URI_STYLE_PATH', 'GIT_ROOT_LOOKUP_FAILED',
    'GIT_DUBIOUS_OWNERSHIP', 'ROOT_NOT_REPOSITORY', 'NESTED_REPO_CONFLICT',
    'LINK_OR_JUNCTION_REJECTED', 'CURSOR_PROJECT_DIR_MISMATCH',
    'REGISTERED_WORKSPACE_MISMATCH', 'WORKSPACE_PATH_INVALID'}


def path_shape(raw):
    text = raw if isinstance(raw, str) else ''
    windows = PureWindowsPath(text)
    style = ('FILE_URI' if text.lower().startswith('file:') else
        'WINDOWS_NATIVE' if windows.drive else 'POSIX' if text.startswith('/') else 'UNKNOWN')
    return dict(is_absolute=Path(text).is_absolute(), drive_present=bool(windows.drive), path_style=style)


def git_probe(candidate):
    """Read-only, bounded probe; never add safe.directory or echo Git stderr."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.run(['git', '--no-optional-locks', '-C', str(candidate),
                'rev-parse', '--show-toplevel'], stdin=subprocess.DEVNULL, stdout=out,
                stderr=err, env=env, timeout=10, check=False)
            if out.tell() > 16384 or err.tell() > 16384:
                return 'FAILED', None
            out.seek(0); err.seek(0)
            output = out.read().decode('utf-8', errors='strict').strip()
            error = err.read().decode('utf-8', errors='replace').lower()
        if process.returncode:
            if 'dubious ownership' in error or 'unsafe repository' in error:
                return 'DUBIOUS_OWNERSHIP', None
            if 'not a git repository' in error:
                return 'NOT_REPOSITORY', None
            return 'FAILED', None
        root = Path(output)
        if not root.is_absolute():
            return 'FAILED', None
        no_links(root)
        return 'OK', root.resolve(strict=True)
    except subprocess.TimeoutExpired:
        return 'TIMEOUT', None
    except FileNotFoundError:
        return 'UNAVAILABLE', None
    except (OSError, ValueError, UnicodeError):
        return 'FAILED', None


def resolve_cursor_workspace(raw, *, excluded=(), diagnostics=None, prefix='workspace_root'):
    diag = diagnostics if diagnostics is not None else {}
    def mark(**fields):
        diag.update({prefix+'_'+key: value for key, value in fields.items()})
    def reject(reason):
        mark(resolution_reason=reason)
        raise ValueError(reason)
    shape = path_shape(raw)
    mark(**shape, exists=None, canonicalized=False, git_probe_status='NOT_RUN',
         git_repo_detected=None, resolution_step='PATH_SHAPE', resolution_reason=None)
    if shape['path_style'] == 'FILE_URI':
        reject('URI_STYLE_PATH')  # Official path strings: no URI decoding/guessing.
    if shape['path_style'] == 'WINDOWS_NATIVE' and not shape['is_absolute']:
        reject('WINDOWS_PATH_NORMALIZATION')
    if not shape['is_absolute']:
        reject('RAW_PATH_NOT_ABSOLUTE')
    if (not isinstance(raw, str) or len(raw) > 4096 or '${' in raw
            or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in raw)
            or '..' in Path(raw).parts):
        reject('WORKSPACE_PATH_INVALID')
    if raw.startswith(('\\\\', '//')):
        reject('WORKSPACE_OUTSIDE_ALLOWED_ROOT')
    candidate = Path(raw)
    mark(resolution_step='FILESYSTEM')
    try:
        no_links(candidate)
        mark(exists=candidate.exists())
        candidate = candidate.resolve(strict=True)
        no_links(candidate)
    except FileNotFoundError:
        mark(exists=False)
        reject('PATH_NOT_FOUND')
    except ValueError:
        reject('LINK_OR_JUNCTION_REJECTED')
    except (OSError, RuntimeError):
        reject('WINDOWS_PATH_NORMALIZATION' if os.name == 'nt' else 'WORKSPACE_PATH_INVALID')
    if not candidate.is_dir():
        reject('PATH_NOT_DIRECTORY')
    # Preserve the canonical resolver's protected-root policy before any probe.
    mark(resolution_step='BOUNDARY')
    home = os.getenv('SECURITY_RUNTIME_CODEX_HOME') or os.getenv('CODEX_HOME')
    forbidden = [SQLiteStore.default_path().parent.absolute(),
        Path(home).absolute() if home else Path.home()/'.codex',
        *(Path(p).absolute() for p in excluded)]
    if WorkspaceResolver._unsafe(candidate) or any(candidate == p or candidate.is_relative_to(p) for p in forbidden):
        reject('WORKSPACE_OUTSIDE_ALLOWED_ROOT')
    mark(resolution_step='GIT_PROBE')
    status, git_root = git_probe(candidate)
    mark(git_probe_status=status, git_repo_detected=status == 'OK' if status in {'OK', 'NOT_REPOSITORY'} else None)
    if status == 'DUBIOUS_OWNERSHIP':
        reject('GIT_DUBIOUS_OWNERSHIP')
    if status not in {'OK', 'NOT_REPOSITORY'}:
        reject('GIT_ROOT_LOOKUP_FAILED')
    mark(resolution_step='CANONICAL_RESOLVER')
    try:
        root = resolve_workspace(str(candidate), excluded=excluded)
    except ValueError as exc:
        from .global_workspace import workspace_rejection
        reason = workspace_rejection(exc, 'RESOLVING_ROOT')
        if reason == 'WORKSPACE_LINK_REJECTED':
            reason = 'LINK_OR_JUNCTION_REJECTED'
        elif reason in {'WORKSPACE_RESOLUTION_FAILED', 'WORKSPACE_CANONICALIZATION_MISMATCH'}:
            reason = 'ROOT_NOT_REPOSITORY' if status == 'NOT_REPOSITORY' else 'GIT_ROOT_LOOKUP_FAILED'
        reject(reason)
    except (FileNotFoundError, OSError):
        reject('PATH_NOT_FOUND')
    # The shared resolver must not silently fall back after an admitted Git probe.
    if git_root is not None and root != git_root:
        reject('REGISTERED_WORKSPACE_MISMATCH')
    mark(canonicalized=True, resolution_step='COMPLETE', resolution_reason=None)
    return root
