import hashlib
import json
import os
from pathlib import Path
import zipfile

import pytest

from security_runtime.delivery import StableDelivery, package_metadata, verification_session, encode, EXE, launcher_metadata
from security_runtime.delta_delivery import make_update, materialized_update
from security_runtime.personal_install import setup_personal_codex
from security_runtime.review_skill import ReviewSkillManager
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from test_delivery import bundle
from test_global_integration import installed, projects


def test_verified_session_detects_same_length_change_and_no_persistent_cache(tmp_path):
    package = bundle(tmp_path / 'package', b'first')
    with verification_session():
        original = package_metadata(package)
        assert package_metadata(package) == original
        file = package / EXE
        before = file.stat()
        file.write_bytes(b'other')
        os.utime(file, ns=(before.st_atime_ns, before.st_mtime_ns))
        with pytest.raises(IntegrationDiagnostic):
            package_metadata(package)
    with pytest.raises(IntegrationDiagnostic):
        package_metadata(package)


def test_verified_session_rejects_new_file_and_link(tmp_path):
    package = bundle(tmp_path / 'package')
    with verification_session():
        package_metadata(package)
        (package / 'extra').write_bytes(b'x')
        with pytest.raises(IntegrationDiagnostic):
            package_metadata(package)


def test_personal_setup_runs_one_successful_probe_per_transaction(installed, tmp_path):
    original, calls = installed.probe, []
    def probe(*args):
        calls.append(args)
        return original(*args)
    installed.probe = probe
    skill = ReviewSkillManager(tmp_path / 'skills', tmp_path / 'skill-state')
    for _ in range(2):
        before = len(calls)
        assert setup_personal_codex(installed, skill=skill)['installation']['local_files_ready']
        assert len(calls) - before == 1
    assert installed.probe is probe


def test_cleanup_preserves_live_active_unknown_and_scanner_cache(tmp_path):
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    identities = [delivery.activate(bundle(tmp_path / f'package-{i}', str(i).encode()))['active_build'] for i in range(3)]
    foreign = delivery.root / 'versions/user-content'
    foreign.mkdir()
    (foreign / 'note').write_bytes(b'keep')
    cache = tmp_path / 'scanner-cache'
    cache.mkdir()
    (cache / 'trivy.db').write_bytes(b'cache')
    result = delivery.cleanup(in_use=lambda _: {identities[1]})
    assert result['removed_builds'] == [identities[0]]
    assert result['deferred_builds'] == [identities[1]]
    assert result['preserved_builds'] == ['user-content']
    assert delivery.slot(identities[2]).exists()
    assert (cache / 'trivy.db').read_bytes() == b'cache'
    assert delivery.cleanup(in_use=lambda _: set())['removed_builds'] == [identities[1]]
    assert delivery.pointer()['previous'] is None


def test_cleanup_defers_if_process_inventory_unknown_and_preserves_tampered_slot(tmp_path, monkeypatch):
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    first = delivery.activate(bundle(tmp_path / 'a'))['active_build']
    delivery.activate(bundle(tmp_path / 'b', b'new'))
    import security_runtime.delivery as module
    original, verified = module.package_metadata, []
    def record(path, **kwargs):
        verified.append(path)
        return original(path, **kwargs)
    monkeypatch.setattr(module, 'package_metadata', record)
    assert delivery.cleanup(in_use=lambda _: None)['deferred_builds'] == [first]
    assert delivery.slot(first) not in verified
    (delivery.slot(first) / EXE).write_bytes(b'user modified')
    assert delivery.cleanup(in_use=lambda _: set())['preserved_builds'] == [first]
    assert delivery.slot(first) in verified


def test_delta_contains_only_changed_files_and_reconstructs_exact_bundle(tmp_path):
    base, new = bundle(tmp_path / 'base'), bundle(tmp_path / 'new', b'new executable')
    update = tmp_path / 'update.zip'
    result = make_update(base, new, update)
    assert result['changed_files'] == 1 and result['reused_files'] == 3
    with zipfile.ZipFile(update) as archive:
        assert set(archive.namelist()) == {'delta.json', 'version.json', 'files/' + EXE}
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    delivery.activate(base)
    with materialized_update(delivery, update) as materialized:
        assert package_metadata(materialized) == package_metadata(new)
    assert not materialized.exists()


@pytest.mark.parametrize('change', ['base', 'bytes', 'extra', 'traversal'])
def test_delta_rejects_wrong_base_tampered_bytes_and_foreign_members(tmp_path, change):
    base, new = bundle(tmp_path / 'base'), bundle(tmp_path / 'new', b'new executable')
    update = tmp_path / 'update.zip'
    make_update(base, new, update)
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    delivery.activate(base)
    if change == 'base':
        delivery.activate(bundle(tmp_path / 'other', b'different'))
    else:
        with zipfile.ZipFile(update) as archive:
            members = {n: archive.read(n) for n in archive.namelist()}
        if change == 'bytes':
            members['files/' + EXE] = b'tampered'
        else:
            members['../foreign' if change == 'traversal' else 'foreign'] = b'x'
        with zipfile.ZipFile(update, 'w') as archive:
            for name, value in members.items():
                archive.writestr(name, value)
    before = (delivery.root / 'active.json').read_bytes()
    with pytest.raises(IntegrationDiagnostic):
        with materialized_update(delivery, update):
            pytest.fail('invalid update must never be yielded')
    assert (delivery.root / 'active.json').read_bytes() == before
    assert not (tmp_path / 'foreign').exists()


def test_tiny_launcher_avoids_runtime_duplication_and_legacy_overwrite(tmp_path):
    first = bundle(tmp_path / 'first')
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    delivery.activate(first)
    previous = (delivery.root / 'launcher' / EXE).read_bytes()
    new = bundle(tmp_path / 'new', b'new exe')
    tiny = new / '_launcher/security-launcher.exe'
    tiny.parent.mkdir()
    tiny.write_bytes(b'tiny test launcher')
    metadata = json.loads((new / 'version.json').read_bytes())
    metadata.pop('build_id')
    metadata['files']['_launcher/security-launcher.exe'] = hashlib.sha256(tiny.read_bytes()).hexdigest()
    metadata['build_id'] = hashlib.sha256(encode(metadata)).hexdigest()
    (new / 'version.json').write_text(json.dumps(metadata))
    activated = delivery.activate(new)
    assert Path(activated['launcher']).parent.name == 'launcher-v2'
    assert {p.name for p in Path(activated['launcher']).parent.iterdir()} == {EXE, 'launcher.json'}
    assert (delivery.root / 'launcher' / EXE).read_bytes() == previous
    launcher_metadata(Path(activated['launcher']).parent)
    Path(activated['launcher']).write_bytes(b'tampered')
    with pytest.raises(IntegrationDiagnostic):
        delivery.status()


def test_frozen_probe_reuses_verified_inventory_but_detects_mutation(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import security_runtime.delivery as module
    from security_runtime.install_checks import single_capability_check
    package = bundle(tmp_path / 'package', b'first')
    walks, probes = [], []
    original = module.package_inventory
    def inventory(*args, **kwargs):
        walks.append(args[0])
        return original(*args, **kwargs)
    def probe(*args):
        probes.append(args)
        return {'status': 'OK'}
    monkeypatch.setattr(module, 'package_inventory', inventory)
    integration = SimpleNamespace(probe=probe)
    runtime = {'command': str(package / EXE), 'prefix': [], 'kind': 'FROZEN'}
    with verification_session(), single_capability_check(integration):
        integration.probe(runtime, tmp_path, {})
        assert len(walks) == 2  # Before/after hashing; no third redundant walk.
        integration.probe(runtime, tmp_path, {})
        assert len(walks) == 3 and len(probes) == 1
        integration.probe(runtime, tmp_path, {'changed': '1'})
        assert len(probes) == 2
        target = package / EXE
        before = target.stat()
        target.write_bytes(b'other')
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        integration.probe(runtime, tmp_path, {})
        assert len(probes) == 3  # Invalid identity must not reuse success.
    assert integration.probe is probe


def test_failed_capability_probe_is_never_cached(tmp_path):
    from types import SimpleNamespace
    from security_runtime.install_checks import single_capability_check
    results = iter([{'status': 'FAILED'}, {'status': 'OK'}])
    integration = SimpleNamespace(probe=lambda *args: next(results))
    runtime = {'command': 'fixture', 'prefix': [], 'kind': 'DEV'}
    with single_capability_check(integration):
        assert integration.probe(runtime, tmp_path, {})['status'] == 'FAILED'
        assert integration.probe(runtime, tmp_path, {})['status'] == 'OK'
        assert integration.probe(runtime, tmp_path, {})['status'] == 'OK'


def test_install_probe_directs_only_verified_launcher_to_current_slot(tmp_path):
    from types import SimpleNamespace
    from security_runtime.install_checks import single_capability_check
    delivery = StableDelivery(tmp_path / 'program', probe=lambda _: {'status': 'OK'})
    first = delivery.activate(bundle(tmp_path / 'first'))
    calls = []
    def probe(runtime, home, environment):
        calls.append(runtime.copy())
        return {'status': 'OK'}
    integration = SimpleNamespace(probe=probe)
    runtime = {'command': first['launcher'], 'prefix': [], 'kind': 'FROZEN'}
    with verification_session(), single_capability_check(integration):
        integration.probe(runtime, tmp_path, {})
        integration.probe(runtime, tmp_path, {})
        assert [r['command'] for r in calls] == [str(delivery.slot(first['active_build']) / EXE)]
        second = delivery.activate(bundle(tmp_path / 'second', b'updated executable'))
        integration.probe(runtime, tmp_path, {})
        assert len(calls) == 2
        assert calls[-1]['command'] == str(delivery.slot(second['active_build']) / EXE)
        # A custom command prefix must keep the original launch semantics.
        custom = {**runtime, 'prefix': ['custom-argument']}
        integration.probe(custom, tmp_path, {})
        assert calls[-1] == custom
    assert runtime == {'command': first['launcher'], 'prefix': [], 'kind': 'FROZEN'}
    assert integration.probe is probe
