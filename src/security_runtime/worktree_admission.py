"""Narrow, read-only admission of registered linked worktrees in Codex home.

An explicit workspace request and reciprocal Git registration authorize this
directory only. They do not attest the caller's host, session or execution cwd.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .hook_state import no_links


def _canonical(path):
    no_links(path)
    result = path.resolve(strict=True)
    no_links(result)
    return result


def _pointer(path, *, prefix=''):
    no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4096:
        raise ValueError()
    with path.open('rb') as stream:
        raw = stream.read(4097)
    after = path.stat()
    if (len(raw) != before.st_size or len(raw) > 4096 or
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError()
    text = os.fsdecode(raw).rstrip('\r\n')
    if not text.startswith(prefix):
        raise ValueError()
    value = text[len(prefix):]
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError()
    target = Path(value)
    return _canonical(target if target.is_absolute() else path.parent / target), raw


def _listing_path(value):
    """Decode Git's C-quoted porcelain paths on Git versions without -z."""
    if value.startswith(b'"'):
        if not value.endswith(b'"'):
            raise ValueError()
        value = value[1:-1]
        decoded = bytearray()
        index = 0
        escapes = {ord('\\'): 92, ord('"'): 34, ord('a'): 7, ord('b'): 8,
                   ord('t'): 9, ord('n'): 10, ord('v'): 11, ord('f'): 12, ord('r'): 13}
        while index < len(value):
            char = value[index]
            index += 1
            if char != 92:
                decoded.append(char)
                continue
            if index == len(value):
                raise ValueError()
            char = value[index]
            index += 1
            if char in escapes:
                decoded.append(escapes[char])
            elif ord('0') <= char <= ord('7'):
                octal = bytes([char])
                while index < len(value) and len(octal) < 3 and ord('0') <= value[index] <= ord('7'):
                    octal += bytes([value[index]])
                    index += 1
                decoded.append(int(octal, 8))
            else:
                raise ValueError()
        value = bytes(decoded)
    return os.path.normcase(os.path.normpath(os.fsdecode(value)))


def _registered(common, root):
    # Ignore inherited repository/config overrides and avoid optional Git writes.
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT='0')
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            ['git', '--no-optional-locks', '-c', 'core.hooksPath=', '-c', 'core.fsmonitor=false',
             '-c', 'core.quotePath=false', '--git-dir=' + str(common),
             'worktree', 'list', '--porcelain'],
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
            env=environment, timeout=10, check=False,
        )
        if result.returncode or output.tell() > 1_000_000:
            raise ValueError()
        output.seek(0)
        records = output.read().replace(b'\r\n', b'\n').split(b'\n\n')
    matches = []
    for record in records:
        fields = record.split(b'\n')
        if fields and fields[0].startswith(b'worktree '):
            if _listing_path(fields[0][9:]) == os.path.normcase(str(root)):
                matches.append(fields)
    if len(matches) != 1 or any(field.startswith(b'prunable') or field == b'bare' for field in matches[0]):
        raise ValueError()


def codex_linked_worktree(candidate, home, *, protected=()):
    """Validate one project under home/worktrees without admitting containers."""
    try:
        container = home / 'worktrees'
        if candidate == container or not candidate.is_relative_to(container):
            raise ValueError()
        root = candidate
        while root != container:
            marker = root / '.git'
            if marker.exists() or marker.is_symlink():
                break
            root = root.parent
        else:
            raise ValueError()
        directory = root.stat()
        gitdir, marker_raw = _pointer(root / '.git', prefix='gitdir: ')
        common, common_raw = _pointer(gitdir / 'commondir')
        back, back_raw = _pointer(gitdir / 'gitdir')
        if (not gitdir.is_dir() or not common.is_dir() or back != root / '.git'
                or gitdir.parent != common / 'worktrees'
                or any(path == boundary or path.is_relative_to(boundary)
                       for path in (root, gitdir, common) for boundary in protected)):
            raise ValueError()
        _registered(common, root)
        # Reject a concurrent replacement instead of accepting mixed metadata.
        after = root.stat()
        if ((directory.st_dev, directory.st_ino) != (after.st_dev, after.st_ino)
                or _pointer(root / '.git', prefix='gitdir: ') != (gitdir, marker_raw)
                or _pointer(gitdir / 'commondir') != (common, common_raw)
                or _pointer(gitdir / 'gitdir') != (back, back_raw)):
            raise ValueError()
        return root
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        raise ValueError('WORKSPACE_WORKTREE_INVALID') from None
