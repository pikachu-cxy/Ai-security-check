"""Comparable delivery identity, independent of the marketing version."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import contextmanager
from contextvars import ContextVar
import subprocess
import sys
import tempfile
from pathlib import Path

from ._version import __version__
from .hook_state import no_links

STATE_SCHEMA = 'runtime-state-v1'
_SOURCE_SUFFIXES = {'.py', '.yaml', '.yml', '.md', '.json'}
_stop_sources = ContextVar('stop_source_digests', default=None)


@contextmanager
def stop_identity_session():
    token = _stop_sources.set({})
    try:
        yield
    finally:
        _stop_sources.reset(token)



def git_provenance(root, *arguments, timeout=5):
    # In a Windows stdio MCP process, inherited protocol handles and PIPE
    # reader joins can outlive a Git timeout. Use no protocol stdin and bounded
    # file output; also avoid optional index writes and executable fsmonitors.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['git', '--no-optional-locks', '-c', f'safe.directory={root.as_posix()}',
                                 '-c', 'core.fsmonitor=false', '-C', str(root), *arguments],
                                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
        if result.returncode or output.tell() > 262_144:
            raise ValueError('DEV_PROVENANCE_UNAVAILABLE')
        output.seek(0)
        return output.read().decode('utf-8').strip()


def build_identity():
    if getattr(sys, 'frozen', False):
        path = Path(sys.executable).absolute().parent / 'version.json'
        try:
            no_links(path)
            if path.stat().st_size > 2_000_000:
                raise ValueError()
            value = json.loads(path.read_bytes())
            if not isinstance(value, dict):
                raise ValueError()
            build_id = value.get('build_id')
            if not isinstance(build_id, str) or len(build_id) != 64 or any(c not in '0123456789abcdef' for c in build_id):
                raise ValueError()
            return {'status': 'IDENTIFIED', 'build_id': build_id, 'version': value['version'],
                    'source_commit': value['source_commit'], 'source_dirty': value['source_dirty'],
                    'experience_contract': value['experience_contract'], 'state_schema': value['state_schema']}
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            return {'status': 'UNVERIFIABLE_LEGACY_BUNDLE', 'version': __version__, 'state_schema': STATE_SCHEMA}
    source = Path(__file__).parent
    from .managed_identity import managed_build_identity
    managed = managed_build_identity(source, version=__version__)
    if managed is not None:
        return managed
    digest = _source_digest(source)
    if digest is None:
        return {'status': 'DEV_IDENTITY_UNAVAILABLE', 'version': __version__, 'state_schema': STATE_SCHEMA}
    root = source.parents[1]
    try:
        commit = git_provenance(root, 'rev-parse', 'HEAD')
        if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
            raise ValueError('DEV_PROVENANCE_UNAVAILABLE')
        dirty = bool(git_provenance(root, 'status', '--porcelain'))
    except (OSError, ValueError, subprocess.SubprocessError):
        commit, dirty = 'UNKNOWN', True
    return {'status': 'DEV', 'build_id': digest, 'version': __version__, 'source_commit': commit,
            'source_dirty': dirty, 'experience_contract': 'upgrade-and-scan-v1', 'state_schema': STATE_SCHEMA}


def _source_inventory(source):
    from .delivery import package_inventory
    return tuple(row for row in package_inventory(source)
                 if stat.S_ISREG(row[1]) and Path(row[0]).suffix in _SOURCE_SUFFIXES
                 and '__pycache__' not in Path(row[0]).parts)


def _verified_source_digest(source, inventory):
    from .delivery import _parallel_map
    if sum(row[4] for row in inventory) > 20_000_000:
        return None

    def read_file(row):
        name, mode, device, inode, size, mtime, ctime, _ = row
        fd = os.open(source / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (info.st_mode, info.st_dev, info.st_ino, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns) != (mode, device, inode, size, mtime, ctime):
                raise ValueError('Development source changed during verification')
            content = os.read(fd, size + 1)
            if len(content) != size:
                raise ValueError('Development source size changed during verification')
            return name, content
        finally:
            os.close(fd)

    files = _parallel_map(read_file, inventory)
    digest = hashlib.sha256(b'runtime-source-build-v1')
    # Concurrent reads must retain the original path-component digest order.
    for name, content in sorted(files, key=lambda item: Path(item[0]).parts):
        digest.update(name.encode())
        digest.update(content)
    return digest.hexdigest()


def _source_digest(source):
    cache = _stop_sources.get()
    if cache is not None and os.name == 'posix':
        from .integration_lifecycle import IntegrationDiagnostic
        from .performance_trace import span
        try:
            inventory = _source_inventory(source)
            previous = cache.get(source)
            if previous is not None and previous[0] == inventory:
                with span('build.source_digest_reused'):
                    return previous[1]
            with span('build.source_digest_verify'):
                digest = _verified_source_digest(source, inventory)
            if digest is not None and _source_inventory(source) == inventory:
                cache[source] = (inventory, digest)
                return digest
        except (IntegrationDiagnostic, OSError, ValueError):
            pass  # Nonstandard or changing checkout: use the full uncached verifier.
        cache.pop(source, None)
    digest = hashlib.sha256(b'runtime-source-build-v1')
    total = 0
    for path in sorted(source.rglob('*')):
        if path.is_file() and path.suffix in _SOURCE_SUFFIXES and '__pycache__' not in path.parts:
            no_links(path)
            total += path.stat().st_size
            if total > 20_000_000:
                return None
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()
