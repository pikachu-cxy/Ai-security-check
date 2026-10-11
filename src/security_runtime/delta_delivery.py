"""Bounded local delta packages; no arbitrary archive extraction or remote fetch."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import shutil
import stat
import tempfile
import zipfile

from .delivery import package_metadata, encode, is_digest, EXE
from .hook_state import no_links
from .integration_lifecycle import IntegrationDiagnostic
from .install_progress import report_progress

CONTRACT = 'local-delta-v1'


def make_update(base, bundle, output):
    old, new = package_metadata(base), package_metadata(bundle)
    if old['build_id'] == new['build_id']:
        raise IntegrationDiagnostic('DELTA_ALREADY_CURRENT')
    output = Path(output).absolute()
    no_links(output)
    if output.exists() or output.is_relative_to(Path(base).absolute()) or output.is_relative_to(Path(bundle).absolute()):
        raise IntegrationDiagnostic('DELTA_OUTPUT_CONFLICT')
    changed = sorted(name for name, digest in new['files'].items() if old['files'].get(name) != digest)
    descriptor = {'contract': CONTRACT, 'base_build_id': old['build_id'], 'build_id': new['build_id'], 'changed': changed}
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('delta.json', encode(descriptor))
            archive.write(Path(bundle) / 'version.json', 'version.json')
            for name in changed:
                archive.write(Path(bundle) / name, 'files/' + name)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {'status': 'CREATED', 'contract': CONTRACT, 'changed_files': len(changed),
            'reused_files': len(new['files']) - len(changed), 'bytes': output.stat().st_size,
            'base_build_id': old['build_id'], 'build_id': new['build_id'],
            'publisher_authenticity': 'USER_SUPPLIED_PACKAGE_NOT_ATTESTED'}


@contextmanager
def materialized_update(delivery, archive_path, *, progress=None):
    report_progress(progress, 'DELTA_VERIFY')
    path = Path(archive_path).absolute()
    no_links(path)
    if not path.is_file() or path.stat().st_size > 2_000_000_000:
        raise IntegrationDiagnostic('DELTA_PACKAGE_INVALID')
    pointer = delivery.pointer()
    if not pointer:
        raise IntegrationDiagnostic('DELTA_BASE_NOT_INSTALLED')
    base = delivery.slot(pointer['active'])
    old = package_metadata(base)
    try:
        with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix='runtime-delta-') as temporary:
            infos = archive.infolist()
            names = [i.filename for i in infos]
            if (len(infos) > 10_002 or len(names) != len(set(names))
                    or sum(i.file_size for i in infos) > 2_000_000_000
                    or any(i.is_dir() or stat.S_ISLNK(i.external_attr >> 16) for i in infos)):
                raise ValueError()
            if any(archive.getinfo(name).file_size > 2_000_000 for name in ('delta.json', 'version.json')):
                raise ValueError()
            descriptor = json.loads(archive.read('delta.json'))
            metadata_raw = archive.read('version.json')
            new = json.loads(metadata_raw)
            identity = new.pop('build_id')
            if (descriptor['contract'] != CONTRACT or descriptor['base_build_id'] != old['build_id']):
                raise IntegrationDiagnostic('DELTA_BASE_MISMATCH')
            if (not is_digest(identity) or identity != descriptor['build_id']
                    or hashlib.sha256(encode(new)).hexdigest() != identity or not isinstance(new['files'], dict)):
                raise ValueError()
            changed = sorted(name for name, digest in new['files'].items() if old['files'].get(name) != digest)
            if descriptor['changed'] != changed or set(names) != {'delta.json', 'version.json', *('files/' + n for n in changed)}:
                raise ValueError()
            report_progress(progress, 'DELTA_APPLY')
            bundle = Path(temporary) / 'bundle'
            bundle.mkdir()
            for name, expected in new['files'].items():
                relative = Path(name)
                if (not isinstance(name, str) or not is_digest(expected) or relative.is_absolute()
                        or '..' in relative.parts or ':' in name or '\\' in name or relative.as_posix() != name):
                    raise ValueError()
                target = bundle / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if name in changed:
                    with archive.open('files/' + name) as source, target.open('xb') as destination:
                        shutil.copyfileobj(source, destination)
                else:
                    shutil.copy2(base / relative, target)
            (bundle / 'version.json').write_bytes(metadata_raw)
            package_metadata(bundle)
            if delivery.pointer() != pointer:
                raise IntegrationDiagnostic('DELTA_BASE_CHANGED')
            yield bundle
    except (zipfile.BadZipFile, KeyError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, IntegrationDiagnostic):
            raise
        raise IntegrationDiagnostic('DELTA_PACKAGE_INVALID') from None
