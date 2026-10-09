import hashlib
import json

import pytest

from security_runtime.delivery import StableDelivery, package_metadata, encode, CONTRACT, EXE, stable_command
from security_runtime.build_identity import STATE_SCHEMA
from security_runtime.integration_lifecycle import IntegrationDiagnostic


def bundle(root, content=b'fixture-executable'):
    root.mkdir()
    files = {EXE: content, 'LICENSE': b'fixture license', 'THIRD_PARTY_NOTICES.md': b'fixture notice', 'SOURCE_OFFER.md': b'fixture source offer'}
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    metadata = {'version': '0.3.1', 'format': 'pyinstaller-onedir', 'source_commit': 'a' * 40,
                'source_dirty': True, 'experience_contract': 'upgrade-and-scan-v1', 'state_schema': STATE_SCHEMA,
                'capability_contract': 'developer-guidance-v0.3', 'launcher_contract': CONTRACT,
                'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
    metadata['build_id'] = hashlib.sha256(encode(metadata)).hexdigest()
    (root / 'version.json').write_text(json.dumps(metadata))
    return root


def test_continuous_same_version_upgrade_stable_launcher_and_rollback(tmp_path):
    delivery = StableDelivery(tmp_path / 'installation', probe=lambda _: {'status': 'OK'})
    identities = []
    original_launcher = None
    for i in range(3):
        result = delivery.activate(bundle(tmp_path / f'package-{i}', f'build-{i}'.encode()))
        identities.append(result['active_build'])
        launcher = delivery.root / 'launcher' / EXE
        if original_launcher is None:
            original_launcher = launcher.read_bytes()
        assert launcher.read_bytes() == original_launcher
        assert stable_command(delivery.slot(identities[-1]) / EXE) == str(launcher)
    assert len(set(identities)) == 3
    key = delivery.store.workspace_directory(delivery.root) / 'snapshot.key'
    prior = key.read_bytes()
    assert delivery.rollback()['active_build'] == identities[-2]
    assert key.read_bytes() == prior
    assert delivery.status()['version'] == '0.3.1'


@pytest.mark.parametrize('change', ['bytes', 'extra', 'traversal', 'identity'])
def test_invalid_package_is_not_executed(tmp_path, change):
    package = bundle(tmp_path / 'package')
    if change == 'bytes':
        (package / EXE).write_bytes(b'tampered')
    elif change == 'extra':
        (package / 'foreign').write_bytes(b'foreign')
    else:
        metadata = json.loads((package / 'version.json').read_bytes())
        if change == 'traversal':
            metadata['files']['../foreign'] = '0' * 64
        else:
            metadata['build_id'] = '0' * 64
        (package / 'version.json').write_text(json.dumps(metadata))
    probes = []
    delivery = StableDelivery(tmp_path / 'installation', probe=lambda p: probes.append(p))
    with pytest.raises(IntegrationDiagnostic, match='DELIVERY_PACKAGE_INVALID'):
        delivery.activate(package)
    assert not probes and not (delivery.root / 'active.json').exists()


def test_failed_activation_preserves_previous_pointer_and_invalid_pointer_fails_closed(tmp_path):
    delivery = StableDelivery(tmp_path / 'installation', probe=lambda _: {'status': 'OK'})
    first = delivery.activate(bundle(tmp_path / 'first'))
    pointer = delivery.root / 'active.json'
    before = pointer.read_bytes()
    delivery.probe = lambda _: {'status': 'MISSING_CAPABILITY'}
    with pytest.raises(IntegrationDiagnostic, match='DELIVERY_CAPABILITY_MISMATCH'):
        delivery.activate(bundle(tmp_path / 'second', b'new'))
    assert pointer.read_bytes() == before and delivery.status()['active_build'] == first['active_build']
    value = json.loads(before)
    value['active'] = '../elsewhere'
    pointer.write_text(json.dumps(value))
    with pytest.raises(IntegrationDiagnostic, match='DELIVERY_POINTER_INVALID'):
        delivery.status()
    with pytest.raises(IntegrationDiagnostic):
        delivery.activate(tmp_path / 'second')
    assert pointer.read_text() == json.dumps(value)
