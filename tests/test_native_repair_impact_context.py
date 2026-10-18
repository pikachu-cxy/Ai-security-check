"""Bound repair retries retain their start without reviving stale analysis."""
from test_repair_impact_service import impact, proof  # noqa: F401


def native(impact):
    service, root, clock, resolved, proposal, _ = impact
    source = dict(kind='HOST_TASK_RISK', task_ref='ts1-' + 'a' * 32,
                  finding_id='tc1-original', origin_review_revision=1)
    resolved['binding'] = dict(source, origin_snapshot_id='native-origin', member_ids=['tc1-original'])
    resolved['member_ids'] = ['tc1-original']
    packet = service.prepare(source, proposal)
    return service, root, clock, proposal, source, packet


def context(service, source, packet):
    basis = service.native_fix_context(packet['assessment_ref'], source)
    assert basis.pop('gate') == 'READY_FOR_EXISTING_AUTH'
    basis.pop('repair_authorized')
    basis.pop('automatic_execution')
    return basis


def test_bound_retry_allows_own_patch_but_rejects_other_policy_changes(impact):
    service, root, _, _, source, packet = native(impact)
    impacts = proof(service, packet)
    (root / 'policy.py').write_text('def can_read(member):\n    return member.active\n')
    service.read(packet['assessment_ref'], 'policy.py', 1, 2,
                 reason='The proposed permission check must preserve this shared membership policy.')
    service.submit(packet['assessment_ref'], impacts, [])
    basis = context(service, source, packet)
    (root / 'app.py').write_text('def read_file(user, file):\n    return file.read_if_permitted(user)\n')
    assert service.bound_native_fix_status(packet['assessment_ref'], basis) == 'READY_FOR_EXISTING_AUTH'
    (root / 'policy.py').write_text('def can_read(member):\n    return False\n')
    assert service.bound_native_fix_status(packet['assessment_ref'], basis) == 'REASSESS_REQUIRED'


def test_expired_or_superseded_analysis_cannot_become_ready_via_bound_history(impact):
    service, _, clock, proposal, source, packet = native(impact)
    service.submit(packet['assessment_ref'], proof(service, packet), [])
    basis = context(service, source, packet)
    original_time = clock[0]
    clock[0] = packet['material_expires_at'] + 1
    assert service.bound_native_fix_status(packet['assessment_ref'], basis) == 'REASSESS_REQUIRED'
    clock[0] = original_time
    service.prepare(source, dict(proposal, summary='A different concrete repair proposal.'))
    assert service.bound_native_fix_status(packet['assessment_ref'], basis) == 'REASSESS_REQUIRED'


def test_clock_rollback_does_not_revive_a_bound_preparation(impact):
    service, _, clock, _, source, packet = native(impact)
    service.submit(packet['assessment_ref'], proof(service, packet), [])
    basis = context(service, source, packet)
    clock[0] = packet['created_at'] - 1
    assert service.bound_native_fix_status(packet['assessment_ref'], basis) == 'REASSESS_REQUIRED'
