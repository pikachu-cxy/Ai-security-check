"""Verify a local ZIP against its exact manifest and checksum sidecar."""
from pathlib import Path
import argparse
import hashlib
import json
import zipfile
from security_runtime.delivery import encode

parser = argparse.ArgumentParser()
parser.add_argument('archive', type=Path)
args = parser.parse_args()
digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
assert args.archive.with_suffix(args.archive.suffix + '.sha256').read_text().split()[0] == digest
with zipfile.ZipFile(args.archive) as archive:
    assert archive.testzip() is None
    metadata = json.loads(archive.read('security-check/version.json'))
    identity = metadata.pop('build_id')
    assert hashlib.sha256(encode(metadata)).hexdigest() == identity
    expected = {'security-check/version.json', *('security-check/' + name for name in metadata['files'])}
    assert set(archive.namelist()) == expected
    for name, expected_digest in metadata['files'].items():
        assert hashlib.sha256(archive.read('security-check/' + name)).hexdigest() == expected_digest
print(json.dumps({'status': 'PASS', 'build_id': identity, 'sha256': digest,
    'archive_bytes': args.archive.stat().st_size, 'files': len(expected)}))
