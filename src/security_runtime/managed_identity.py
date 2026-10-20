"""Content identity for managed wheels; checksums are not publisher signatures."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from .hook_state import no_links

SCHEMA = 'managed-wheel-v1'
METADATA_NAME = 'managed_release.json'
MARKER_NAME = 'MANAGED_RELEASE'
STATE_SCHEMA = 'runtime-state-v1'
EXPERIENCE_CONTRACT = 'upgrade-and-scan-v1'
MAX_METADATA_BYTES = 2_000_000
MAX_PACKAGE_BYTES = 32_000_000
MAX_PACKAGE_FILES = 4096


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate managed release metadata key')
        result[key] = value
    return result


def read_json(data: bytes):
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError('Managed release metadata is too large')
    return json.loads(data, object_pairs_hook=_unique_object)


def valid_relative_path(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 1024:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and path.as_posix() == value
            and all(part not in {'', '.', '..', '__pycache__'} for part in path.parts)
            and not any(character in value for character in ('\\', ':', '\x00')))


def validate_metadata(value: object, *, version: str) -> dict:
    required = {'schema', 'version', 'source_commit', 'source_dirty', 'experience_contract',
                'state_schema', 'package_files', 'build_id'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('Invalid managed release metadata fields')
    if (value['schema'] != SCHEMA or value['version'] != version
            or value['source_dirty'] is not False
            or value['experience_contract'] != EXPERIENCE_CONTRACT
            or value['state_schema'] != STATE_SCHEMA
            or not isinstance(value['source_commit'], str)
            or re.fullmatch('[0-9a-f]{40}', value['source_commit']) is None):
        raise ValueError('Invalid managed release provenance')
    files = value['package_files']
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_PACKAGE_FILES:
        raise ValueError('Invalid managed release file inventory')
    if not {'__init__.py', '_version.py', 'build_identity.py', 'managed_identity.py'} <= set(files):
        raise ValueError('Managed release identity sources are missing')
    for name, checksum in files.items():
        if (not valid_relative_path(name) or name == METADATA_NAME
                or not isinstance(checksum, str) or re.fullmatch('[0-9a-f]{64}', checksum) is None):
            raise ValueError('Invalid managed release file entry')
    payload = {key: item for key, item in value.items() if key != 'build_id'}
    if value['build_id'] != hashlib.sha256(canonical_json(payload)).hexdigest():
        raise ValueError('Managed release build identity does not match its metadata')
    return value


def create_metadata(files: dict[str, str], *, version: str, source_commit: str) -> dict:
    value = {'schema': SCHEMA, 'version': version, 'source_commit': source_commit,
             'source_dirty': False, 'experience_contract': EXPERIENCE_CONTRACT,
             'state_schema': STATE_SCHEMA, 'package_files': dict(sorted(files.items()))}
    value['build_id'] = hashlib.sha256(canonical_json(value)).hexdigest()
    return validate_metadata(value, version=version)


def marker_content(metadata_bytes: bytes, build_id: str) -> bytes:
    return canonical_json({'schema': SCHEMA, 'build_id': build_id,
                           'metadata_sha256': hashlib.sha256(metadata_bytes).hexdigest()})


def _unlinked_stat(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Managed release links are not supported')
    return info


def _regular_bytes(path: Path, *, limit: int, parents_checked: bool = False) -> bytes:
    if not parents_checked:
        no_links(path)
    info = _unlinked_stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError('Invalid managed release file')
    with path.open('rb') as stream:
        data = stream.read(info.st_size + 1)
    if len(data) != info.st_size:
        raise ValueError('Managed release file changed while it was being read')
    return data


def _inventory(source: Path) -> dict[str, str]:
    no_links(source)
    result = {}
    total_bytes = 0
    visited = 0
    for directory, directories, filenames in os.walk(source, followlinks=False):
        directory_path = Path(directory)
        for name in directories:
            if not stat.S_ISDIR(_unlinked_stat(directory_path / name).st_mode):
                raise ValueError('Managed release directory is invalid')
        directories[:] = [name for name in directories if name != '__pycache__']
        visited += len(directories) + len(filenames)
        if visited > MAX_PACKAGE_FILES * 2:
            raise ValueError('Managed package contains too many entries')
        for filename in filenames:
            path = directory_path / filename
            relative = path.relative_to(source).as_posix()
            if relative == METADATA_NAME:
                continue
            if not valid_relative_path(relative):
                raise ValueError('Invalid managed package path')
            # Root ancestors were checked once, and each traversed directory is
            # checked above. Rechecking every ancestor for every resource adds
            # seconds to routine status calls on some filesystems.
            data = _regular_bytes(path, limit=MAX_PACKAGE_BYTES - total_bytes, parents_checked=True)
            total_bytes += len(data)
            result[relative] = hashlib.sha256(data).hexdigest()
            if len(result) > MAX_PACKAGE_FILES:
                raise ValueError('Managed package contains too many files')
    return result


def managed_build_identity(source: Path, *, version: str) -> dict | None:
    """Return None only for an ordinary source/editable or unmarked wheel install.

    The venv interpreter may itself be a symlink. Only the package and its
    metadata are checked here; existing state/configuration link rules stay intact.
    """
    metadata = source / METADATA_NAME
    dist_info = f'ai_security_runtime-{version}.dist-info'
    marker = source.parent / dist_info / MARKER_NAME
    # lexists sees dangling links too, so malformed markers cannot fall back to DEV.
    if not os.path.lexists(metadata) and not os.path.lexists(marker):
        # pip retains the wheel's RECORD. It also distinguishes a damaged
        # managed install if both dedicated metadata files have been removed.
        record = source.parent / dist_info / 'RECORD'
        if not os.path.lexists(record):
            return None
        try:
            rows = csv.reader(io.StringIO(_regular_bytes(record, limit=MAX_METADATA_BYTES).decode('utf-8')))
            recorded = any(row and row[0] in {f'security_runtime/{METADATA_NAME}',
                                              f'{dist_info}/{MARKER_NAME}'} for row in rows)
        except (OSError, ValueError, csv.Error):
            recorded = False
        if not recorded:
            return None
    unavailable = {'status': 'UNVERIFIABLE_MANAGED_RELEASE', 'version': version,
                   'state_schema': STATE_SCHEMA, 'delivery_kind': 'managed-wheel'}
    try:
        raw = _regular_bytes(metadata, limit=MAX_METADATA_BYTES)
        value = validate_metadata(read_json(raw), version=version)
        if _regular_bytes(marker, limit=4096) != marker_content(raw, value['build_id']):
            raise ValueError('Managed release marker does not match its metadata')
        if _inventory(source) != value['package_files']:
            raise ValueError('Managed package content differs from its release inventory')
        return {'status': 'IDENTIFIED', 'version': version, 'build_id': value['build_id'],
                'source_commit': value['source_commit'], 'source_dirty': False,
                'experience_contract': EXPERIENCE_CONTRACT, 'state_schema': STATE_SCHEMA,
                'delivery_kind': 'managed-wheel', 'integrity': 'PACKAGE_CONTENT_HASHES_VERIFIED'}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return unavailable
