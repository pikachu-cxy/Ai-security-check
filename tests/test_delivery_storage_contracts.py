"""A package storage floor is independent of global installation layout v1."""
import hashlib
import json
import shutil

import pytest

from security_runtime.build_identity import STATE_SCHEMA
from security_runtime.compatibility import storage_contracts
from security_runtime.delivery import StableDelivery,package_metadata,encode
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from test_delivery import bundle

MISSING=object()


def package(root,capabilities=MISSING):
    bundle(root,root.name.encode())
    path=root/'version.json';value=json.loads(path.read_bytes())
    value.pop('build_id')
    if capabilities is not MISSING:value['storage_contracts']=capabilities
    value['build_id']=hashlib.sha256(encode(value)).hexdigest()
    path.write_text(json.dumps(value),encoding='utf-8')
    return root


def installed(tmp_path,capabilities=MISSING):
    probes=[]
    manager=StableDelivery(tmp_path/'installation',probe=lambda path:probes.append(path) or {'status':'OK'})
    original=package(tmp_path/'original',capabilities)
    manager.activate(original)
    return manager,original,probes


def snapshot(manager):
    return ((manager.root/'active.json').read_bytes(),
            sorted(path.name for path in (manager.root/'versions').iterdir()))


def test_legacy_metadata_is_unknown_and_upgrade_to_new_floor_is_allowed(tmp_path):
    manager,old,probes=installed(tmp_path)
    assert STATE_SCHEMA=='runtime-state-v1'
    assert 'storage_contracts' not in package_metadata(old)
    assert manager.status()['storage_contracts'] is None
    new=package(tmp_path/'new',storage_contracts())
    upgraded=manager.activate(new)
    assert upgraded['storage_contracts']==storage_contracts() and upgraded['state_schema']==STATE_SCHEMA
    assert upgraded['previous_build']==package_metadata(old)['build_id']
    before=snapshot(manager);calls=len(probes)
    # Both explicit reactivation of the already copied legacy slot and rollback
    # must respect the floor, even before any private store is migrated.
    for action in (lambda:manager.activate(old),manager.rollback):
        with pytest.raises(IntegrationDiagnostic,match='DELIVERY_STATE_SCHEMA_INCOMPATIBLE'):action()
        assert snapshot(manager)==before and len(probes)==calls


@pytest.mark.parametrize('target',[MISSING,[],storage_contracts()[:-1],
    [value for value in storage_contracts() if value != 'closeout-persistence-v1']])
def test_same_global_schema_with_missing_floor_cannot_activate(tmp_path,target):
    manager,_,probes=installed(tmp_path,storage_contracts())
    candidate=package(tmp_path/'candidate',target);metadata=package_metadata(candidate)
    before=snapshot(manager);calls=len(probes)
    with pytest.raises(IntegrationDiagnostic,match='DELIVERY_STATE_SCHEMA_INCOMPATIBLE'):
        manager.activate(candidate)
    assert snapshot(manager)==before and len(probes)==calls
    assert not manager.slot(metadata['build_id']).exists()


def test_equal_capability_packages_can_upgrade_and_rollback_without_changing_layout(tmp_path):
    manager,first,_=installed(tmp_path,storage_contracts())
    second=package(tmp_path/'second',list(reversed(storage_contracts())))
    old=manager.status()['active_build'];new=manager.activate(second)['active_build']
    assert old!=new and package_metadata(first)['version']==package_metadata(second)['version']
    result=manager.rollback()
    assert result['active_build']==old and result['previous_build']==new
    assert result['storage_contracts']==storage_contracts() and result['state_schema']=='runtime-state-v1'
    assert result['ephemeral_authorizations_restored'] is False


def test_newer_floor_is_monotonic_across_explicit_reactivation_and_history(tmp_path):
    manager,old,probes=installed(tmp_path,storage_contracts())
    future=storage_contracts()+['future-private-authority-v3']
    manager.activate(package(tmp_path/'future',future))
    before=snapshot(manager);calls=len(probes)
    for action in (manager.rollback,lambda:manager.activate(old)):
        with pytest.raises(IntegrationDiagnostic,match='DELIVERY_STATE_SCHEMA_INCOMPATIBLE'):action()
        assert snapshot(manager)==before and len(probes)==calls


@pytest.mark.parametrize('metadata',[None,{},'task-risk-authority-v2',[True],[{}],['UPPER-v1'],
    ['../private-v1'],['https://private.invalid/v1'],['same-v1','same-v1'],
    ['a'*97+'-v1'],['private-v0'],[f'contract-{i}-v1' for i in range(65)]])
def test_optional_storage_metadata_is_strictly_bounded_and_validated(tmp_path,metadata):
    candidate=package(tmp_path/'invalid',metadata)
    with pytest.raises(IntegrationDiagnostic,match='DELIVERY_PACKAGE_INVALID'):
        package_metadata(candidate)


@pytest.mark.parametrize('action',['status','activate','rollback'])
def test_valid_old_package_copied_over_active_slot_cannot_lower_its_signed_identity(tmp_path,action):
    manager,old,probes=installed(tmp_path)
    current=manager.activate(package(tmp_path/'new',storage_contracts()))['active_build']
    before=snapshot(manager);calls=len(probes)
    shutil.copytree(old,manager.slot(current),dirs_exist_ok=True)
    # Hash-valid alone does not establish the original signed slot identity.
    assert package_metadata(manager.slot(current))['build_id']!=current
    operation={'status':manager.status,'activate':lambda:manager.activate(old),'rollback':manager.rollback}[action]
    with pytest.raises(IntegrationDiagnostic,match='DELIVERY_SLOT_CONFLICT'):operation()
    assert snapshot(manager)==before and len(probes)==calls


def test_replaced_history_package_and_corrupt_pointer_fail_closed(tmp_path):
    manager,first,probes=installed(tmp_path,storage_contracts())
    manager.activate(package(tmp_path/'second',storage_contracts()))
    before=snapshot(manager);calls=len(probes)
    previous=manager.pointer()['previous']
    foreign=package(tmp_path/'foreign')
    shutil.copytree(foreign,manager.slot(previous),dirs_exist_ok=True)
    with pytest.raises(IntegrationDiagnostic,match='DELIVERY_SLOT_CONFLICT'):manager.rollback()
    assert snapshot(manager)==before and len(probes)==calls
    pointer=manager.root/'active.json';value=json.loads(pointer.read_bytes());value['active']=previous
    pointer.write_text(json.dumps(value),encoding='utf-8');corrupt=pointer.read_bytes()
    for operation in (manager.rollback,lambda:manager.activate(first)):
        with pytest.raises(IntegrationDiagnostic,match='DELIVERY_POINTER_INVALID'):operation()
        assert pointer.read_bytes()==corrupt and len(probes)==calls


def test_release_floor_matches_implemented_store_contracts_and_creates_no_state(tmp_path):
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_risk_ledger import TaskRiskLedger
    from security_runtime.risk_closure import RiskClosureService
    from security_runtime.private_authority import FENCE_CONTRACT
    from security_runtime.persistence_effects import CONTRACT as EFFECT
    from security_runtime.task_verification_journal import CONTRACT as VERIFICATION
    from security_runtime.host_event_journal import CONTRACT as EVENT
    from security_runtime.task_delivery_receipts import CONTRACT as DELIVERY
    from security_runtime.closeout_persistence import CONTRACT as CLOSEOUT
    hooks=HookStateStore(tmp_path/'state');root=tmp_path/'workspace';root.mkdir()
    expected={TaskRiskLedger(hooks,root).authority.contract,RiskClosureService(hooks)._authority(root).contract,
              FENCE_CONTRACT,EFFECT,VERIFICATION,EVENT,DELIVERY,CLOSEOUT,'task-risk-partition-v1',
              'native-intent-release-v1','workspace-scan-attempt-v1'}
    assert storage_contracts()==sorted(expected)
    changed=storage_contracts();changed.clear()
    assert storage_contracts()==sorted(expected) and not (tmp_path/'state').exists()
