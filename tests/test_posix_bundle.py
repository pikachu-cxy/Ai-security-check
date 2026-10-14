"""Frozen POSIX links must survive delivery without permitting path escape."""
import hashlib
import json
import os
import tarfile
from pathlib import Path

import pytest

from scripts import verify_artifact
from security_runtime.build_identity import STATE_SCHEMA
from security_runtime.delivery import (
    CONTRACT, EXE, StableDelivery, bundle_link_name, encode, package_inventory,
    package_metadata, verification_session,
)
from security_runtime.integration_lifecycle import IntegrationDiagnostic


def make_bundle(root):
    root.mkdir()
    contents = {EXE: b'fixture executable', 'LICENSE': b'license',
                'THIRD_PARTY_NOTICES.md': b'notice', 'SOURCE_OFFER.md': b'offer',
                '_internal/framework/Versions/3.12/Python': b'python library'}
    for name, raw in contents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    links = {'_internal/framework/Versions/Current': '3.12',
             '_internal/framework/Python': 'Versions/Current/Python',
             '_internal/Python': 'framework/Python'}
    for name, target in links.items():
        (root / name).symlink_to(target, target_is_directory=name.endswith('/Current'))
    metadata = {'version': '0.3.2', 'format': 'pyinstaller-onedir', 'source_commit': 'a' * 40,
                'source_dirty': False, 'experience_contract': 'upgrade-and-scan-v1',
                'state_schema': STATE_SCHEMA, 'capability_contract': 'developer-guidance-v0.3',
                'launcher_contract': CONTRACT, 'bundle_link_contract': 'internal-relative-v1',
                'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
                'links': links}
    write_metadata(root, metadata)
    return root


def write_metadata(root, value):
    value = {k: v for k, v in value.items() if k != 'build_id'}
    value['build_id'] = hashlib.sha256(encode(value)).hexdigest()
    (root / 'version.json').write_text(json.dumps(value), encoding='utf-8')


@pytest.mark.parametrize('name,target', [
    ('_internal/link', '/etc/passwd'), ('_internal/link', '../../outside'),
    ('_internal/a/link', '../../LICENSE'), ('LICENSE', '_internal/Python'),
    ('_internal/../link', 'Python'), ('_internal/link', 'C:/outside'),
    ('_internal/link', '..\\outside'), ('_internal/link', ''),
])
def test_link_target_escape_rejected(name, target):
    with pytest.raises(IntegrationDiagnostic, match='DELIVERY_PACKAGE_INVALID'):
        bundle_link_name(name, target)


def test_relative_parent_within_internal_allowed():
    assert bundle_link_name('_internal/a/link', '../Python') == '_internal/Python'


posix_only = pytest.mark.skipif(os.name == 'nt', reason='POSIX native bundle links')


@posix_only
def test_native_link_chain_preserved_in_archive_install_and_launcher(tmp_path):
    bundle = make_bundle(tmp_path / 'bundle')
    before = package_metadata(bundle)
    rows = package_inventory(bundle, allow_internal_links=True)
    assert len(rows) < 20
    archive = tmp_path / 'bundle.tar.gz'
    with tarfile.open(archive, 'w:gz', dereference=False) as output:
        for row in rows:
            output.add(bundle / row[0], arcname='security-check/' + row[0], recursive=False)
    extracted = tmp_path / 'extracted'
    extracted.mkdir()
    verify_artifact.extract(archive, extracted)
    restored = extracted / 'security-check'
    assert package_metadata(restored) == before
    delivery = StableDelivery(tmp_path / 'install', probe=lambda _: {'status': 'OK'})
    result = delivery.activate(restored)
    for directory in (delivery.slot(result['active_build']), delivery.root / 'launcher'):
        assert (directory / '_internal/framework/Versions/Current').is_symlink()
        assert os.readlink(directory / '_internal/Python') == 'framework/Python'
        assert (directory / '_internal/Python').read_bytes() == b'python library'
        assert package_metadata(directory) == before


@posix_only
@pytest.mark.parametrize('change', ['unlisted', 'target', 'bytes', 'contract', 'dangling', 'cycle', 'external_chain'])
def test_tampered_or_invalid_links_rejected(tmp_path, change):
    bundle = make_bundle(tmp_path / 'bundle')
    metadata = package_metadata(bundle)
    link = bundle / '_internal/Python'
    if change == 'unlisted':
        (bundle / '_internal/extra').symlink_to('Python')
    elif change == 'bytes':
        (bundle / '_internal/framework/Versions/3.12/Python').write_bytes(b'tampered')
    elif change == 'contract':
        metadata.pop('bundle_link_contract')
        write_metadata(bundle, metadata)
    else:
        link.unlink()
        target = {'target': 'framework/Versions/3.12/Python', 'dangling': 'missing',
                  'cycle': 'Python', 'external_chain': 'external'}[change]
        link.symlink_to(target)
        if change == 'external_chain':
            (bundle / '_internal/external').symlink_to(tmp_path)
            metadata['links']['_internal/external'] = str(tmp_path)
            metadata['links']['_internal/Python'] = target
            write_metadata(bundle, metadata)
    with pytest.raises(IntegrationDiagnostic, match='DELIVERY_PACKAGE_INVALID'):
        package_metadata(bundle)


@posix_only
def test_cached_verification_detects_link_target_change(tmp_path):
    bundle = make_bundle(tmp_path / 'bundle')
    with verification_session():
        package_metadata(bundle)
        link = bundle / '_internal/Python'
        link.unlink()
        link.symlink_to('framework/Versions/3.12/Python')
        with pytest.raises(IntegrationDiagnostic):
            package_metadata(bundle)


@pytest.mark.parametrize('name,target,kind', [
    ('security-check/_internal/link', '/tmp/outside', tarfile.SYMTYPE),
    ('security-check/_internal/link', '../../outside', tarfile.SYMTYPE),
    ('security-check/LICENSE', '_internal/Python', tarfile.SYMTYPE),
    ('../outside', '', tarfile.REGTYPE),
    ('security-check/_internal/link', 'security-check/LICENSE', tarfile.LNKTYPE),
])
def test_unsafe_archive_rejected_before_extract(tmp_path, name, target, kind):
    archive = tmp_path / 'bad.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = target
        output.addfile(member)
    destination = tmp_path / 'extracted'
    destination.mkdir()
    with pytest.raises((ValueError, IntegrationDiagnostic)):
        verify_artifact.extract(archive, destination)
    assert not list(destination.iterdir())
