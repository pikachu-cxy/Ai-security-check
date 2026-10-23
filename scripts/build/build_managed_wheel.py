"""Annotate an already built wheel with reproducible managed-release identity.

Run ``python -m build --wheel`` in a clean checkout of the chosen source commit
first, then pass its single wheel and that full commit SHA to this script.
The resulting hashes establish content consistency, not publisher signatures.
"""
from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

# Permit running this repository-owned build script before installing the wheel.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))

from security_runtime.hook_state import no_links
from security_runtime.managed_identity import (
    MARKER_NAME, MAX_PACKAGE_BYTES, MAX_PACKAGE_FILES, METADATA_NAME,
    canonical_json, create_metadata, marker_content, valid_relative_path,
)

MAX_WHEEL_BYTES = 128_000_000


def _record_hash(data: bytes) -> str:
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')


def annotate_wheel(wheel: Path, output: Path, *, source_commit: str) -> dict:
    if re.fullmatch('[0-9a-f]{40}', source_commit) is None:
        raise ValueError('Source commit must be a full lowercase Git commit SHA')
    wheel = wheel.absolute()
    output = output.absolute()
    no_links(wheel)
    no_links(output)
    if wheel.suffix != '.whl' or not wheel.is_file() or wheel.stat().st_size > MAX_WHEEL_BYTES:
        raise ValueError('Expected one bounded wheel file')
    destination = output / wheel.name
    if destination == wheel or destination.exists():
        raise ValueError('Managed wheel output must be a new file')
    contents = {}
    modes = {}
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_PACKAGE_FILES * 2:
            raise ValueError('Wheel contains too many entries')
        total = 0
        for item in infos:
            if item.is_dir():
                continue
            mode = item.external_attr >> 16
            if (not valid_relative_path(item.filename) or item.filename in contents
                    or stat.S_ISLNK(mode) or item.flag_bits & 1):
                raise ValueError('Wheel contains an unsupported entry')
            total += item.file_size
            if total > MAX_WHEEL_BYTES:
                raise ValueError('Wheel content exceeds the size limit')
            contents[item.filename] = archive.read(item)
            modes[item.filename] = mode
    metadata_paths = [name for name in contents if re.fullmatch(
        r'ai_security_runtime-[^/]+\.dist-info/METADATA', name)]
    if len(metadata_paths) != 1:
        raise ValueError('Wheel must contain exactly one Runtime distribution')
    metadata_path = metadata_paths[0]
    dist_info = metadata_path.rsplit('/', 1)[0]
    parsed = BytesParser().parsebytes(contents[metadata_path])
    version = parsed.get('Version')
    if (parsed.get('Name') != 'ai-security-runtime' or not isinstance(version, str)
            or not version or dist_info != f'ai_security_runtime-{version}.dist-info'):
        raise ValueError('Wheel distribution identity is invalid')
    record_path = f'{dist_info}/RECORD'
    if record_path not in contents:
        raise ValueError('Wheel RECORD is missing')
    record = {}
    for row in csv.reader(io.StringIO(contents[record_path].decode('utf-8'), newline='')):
        if len(row) != 3 or row[0] in record:
            raise ValueError('Invalid or duplicate wheel RECORD entry')
        record[row[0]] = row[1:]
    if set(record) != set(contents):
        raise ValueError('Wheel RECORD does not cover its exact contents')
    for name, data in contents.items():
        expected = ['', ''] if name == record_path else [_record_hash(data), str(len(data))]
        if record[name] != expected:
            raise ValueError(f'Wheel RECORD mismatch: {name}')
    package_prefix = 'security_runtime/'
    package_files = {name[len(package_prefix):]: hashlib.sha256(data).hexdigest()
                     for name, data in contents.items() if name.startswith(package_prefix)}
    if (METADATA_NAME in package_files or f'{dist_info}/{MARKER_NAME}' in contents
            or any(name.endswith(('.pyc', '.pyo')) for name in package_files)
            or sum(len(data) for name, data in contents.items()
                   if name.startswith(package_prefix)) > MAX_PACKAGE_BYTES):
        raise ValueError('Expected a fresh source wheel without managed metadata or bytecode')
    version_source = contents.get(package_prefix + '_version.py', b'').decode('utf-8')
    if re.search(r'(?m)^__version__\s*=\s*([\'"])' + re.escape(version) + r'\1\s*$', version_source) is None:
        raise ValueError('Wheel metadata version differs from Runtime version')
    identity = create_metadata(package_files, version=version, source_commit=source_commit)
    raw = canonical_json(identity)
    contents[package_prefix + METADATA_NAME] = raw
    contents[f'{dist_info}/{MARKER_NAME}'] = marker_content(raw, identity['build_id'])
    rows = [[name, _record_hash(data), str(len(data))]
            for name, data in sorted(contents.items()) if name != record_path]
    rows.append([record_path, '', ''])
    buffer = io.StringIO(newline='')
    csv.writer(buffer, lineterminator='\n').writerows(rows)
    contents[record_path] = buffer.getvalue().encode('utf-8')
    output.mkdir(parents=True, exist_ok=True)
    no_links(destination)
    # Exclusive creation prevents overwriting another build; fixed ZIP metadata
    # makes the same input wheel/source commit produce the same output bytes.
    with destination.open('xb') as stream, zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(contents.items()):
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = ((modes.get(name, stat.S_IFREG | 0o644) or
                                  (stat.S_IFREG | 0o644)) << 16)
            archive.writestr(item, data)
    return {'wheel': str(destination), 'filename': destination.name, 'version': version,
            'source_commit': source_commit, 'build_id': identity['build_id'],
            'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
            'size': destination.stat().st_size, 'package_files': len(package_files)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = annotate_wheel(args.wheel, args.output, source_commit=args.source_commit)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
