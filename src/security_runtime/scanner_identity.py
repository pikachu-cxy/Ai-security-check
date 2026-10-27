"""Bounded actual tool-data identities. No content or arbitrary errors escape."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .hook_state import no_links
from .progress import checkpoint

MAX_FILES = 2_000
MAX_BYTES = 2_000_000_000
MAX_FILE_BYTES = 1_500_000_000


def database_content_fingerprint_disabled(tool, *, kind=None):
    """Vulnerability DB content hashing is disabled; policy bundles still bind."""
    return tool == 'osv-scanner' or tool == 'trivy' and kind != 'misconfig'


def _inventory(roots):
    entries = []
    visited = 0
    for label, root in roots:
        no_links(root)
        if not root.exists():
            entries.append((label, None))
            continue
        if root.is_file():
            entries.append((label, root))
            continue
        if not root.is_dir():
            raise ValueError()
        entries.append((label + '/', None))
        for directory, directories, files in os.walk(root, followlinks=False):
            checkpoint()
            visited += 1 + len(directories) + len(files)
            if visited > MAX_FILES * 4:
                raise ValueError()
            for name in directories:
                no_links(Path(directory) / name)
            for name in files:
                path = Path(directory) / name
                no_links(path)
                entries.append((label + '/' + path.relative_to(root).as_posix(), path))
                if len(entries) > MAX_FILES:
                    raise ValueError()
    if len(entries) > MAX_FILES:
        raise ValueError()
    return tuple(sorted(entries, key=lambda row: row[0]))


def content_identity(roots):
    """Digest real files and absence inventory; None is an explicit proof gap."""
    try:
        roots = tuple((label, Path(root)) for label, root in roots)
        if not roots:
            return None
        before = _inventory(roots)
        digest = hashlib.sha256(b'scanner-content-identity-v1')
        total = 0
        for label, path in before:
            checkpoint()
            digest.update(label.encode())
            digest.update(b'\0ABSENT_OR_DIRECTORY\0' if path is None else b'\0FILE\0')
            if path is None:
                continue
            first = path.stat()
            if not stat.S_ISREG(first.st_mode) or first.st_size > MAX_FILE_BYTES:
                return None
            total += first.st_size
            if total > MAX_BYTES:
                return None
            content = hashlib.sha256()
            consumed = 0
            with path.open('rb') as stream:
                opened = os.fstat(stream.fileno())
                signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                if signature(first) != signature(opened):
                    return None
                while raw := stream.read(1_000_000):
                    checkpoint()
                    consumed += len(raw)
                    if consumed > first.st_size:
                        return None
                    content.update(raw)
                if signature(first) != signature(os.fstat(stream.fileno())):
                    return None
            no_links(path)
            if consumed != first.st_size or signature(first) != signature(path.stat()):
                return None
            digest.update(content.digest())
        if _inventory(roots) != before:
            return None
        return digest.hexdigest()
    except (OSError, ValueError, RuntimeError):
        return None
