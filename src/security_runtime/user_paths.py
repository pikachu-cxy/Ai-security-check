"""Shared Windows defaults outside packaged hosts' AppData overlays.

Pure path selection: no probing, migration, process inventory or directory creation
on the runtime/Hook path. Explicit caller overrides remain authoritative.
"""
from __future__ import annotations

import os
import json
from pathlib import Path


def windows_home() -> Path:
    home = Path(os.environ.get('USERPROFILE', str(Path.home())))
    if not home.is_absolute():
        raise ValueError('USER_PROFILE_MUST_BE_ABSOLUTE')
    return home


def windows_root() -> Path:
    return windows_home() / '.asr'


def windows_directory(kind: str) -> Path:
    if kind not in {'state', 'data', 'config'}:
        raise ValueError('USER_DIRECTORY_KIND_INVALID')
    return windows_root() / kind


def relocated_scan_path(path: Path) -> Path:
    """Resolve a migrated legacy scan-store reference without rewriting evidence.

    Only old default scan filenames consult the migration receipt. New/default
    stores and arbitrary custom databases do not pay for a metadata read.
    """
    path = Path(path)
    if os.name != 'nt' or path.name.lower() != 'scans.db' or path.parent.name.lower() != 'ai security runtime':
        return path
    configured = os.getenv('SECURITY_RUNTIME_STATE_DIR')
    if configured and os.path.normcase(str(Path(configured).absolute() / 'scans.db')) == os.path.normcase(str(path.absolute())):
        return path
    from .hook_state import no_links
    marker = windows_root() / 'user-directories.json'
    no_links(marker)
    if not marker.is_file():
        return path
    if marker.stat().st_size > 16384:
        raise ValueError('USER_DIRECTORY_MIGRATION_INVALID')
    receipt = json.loads(marker.read_bytes())
    if receipt.get('contract') != 'windows-user-directories-v1' or receipt.get('status') != 'COMPLETE':
        raise ValueError('USER_DIRECTORY_MIGRATION_INVALID')
    sources = receipt.get('scan_store_sources', [])
    if str(path.absolute()).casefold() in {str(value).casefold() for value in sources}:
        target = windows_directory('state') / 'scans.db'
        no_links(target)
        return target
    return path
