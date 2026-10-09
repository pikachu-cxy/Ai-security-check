"""Comparable delivery identity, independent of the marketing version."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ._version import __version__
from .hook_state import no_links

STATE_SCHEMA = 'runtime-state-v1'


def git_provenance(root, *arguments):
    # In a Windows stdio MCP process, inherited protocol handles and PIPE
    # reader joins can outlive a Git timeout. Use no protocol stdin and bounded
    # file output; also avoid optional index writes and executable fsmonitors.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['git', '--no-optional-locks', '-c', f'safe.directory={root.as_posix()}',
                                 '-c', 'core.fsmonitor=false', '-C', str(root), *arguments],
                                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
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
    digest = hashlib.sha256(b'runtime-source-build-v1')
    total = 0
    for path in sorted(source.rglob('*')):
        if path.is_file() and path.suffix in {'.py', '.yaml', '.yml', '.md', '.json'} and '__pycache__' not in path.parts:
            no_links(path)
            total += path.stat().st_size
            if total > 20_000_000:
                return {'status': 'DEV_IDENTITY_UNAVAILABLE', 'version': __version__, 'state_schema': STATE_SCHEMA}
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(path.read_bytes())
    root = source.parents[1]
    try:
        commit = git_provenance(root, 'rev-parse', 'HEAD')
        if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
            raise ValueError('DEV_PROVENANCE_UNAVAILABLE')
        dirty = bool(git_provenance(root, 'status', '--porcelain'))
    except (OSError, ValueError, subprocess.SubprocessError):
        commit, dirty = 'UNKNOWN', True
    return {'status': 'DEV', 'build_id': digest.hexdigest(), 'version': __version__, 'source_commit': commit,
            'source_dirty': dirty, 'experience_contract': 'upgrade-and-scan-v1', 'state_schema': STATE_SCHEMA}
