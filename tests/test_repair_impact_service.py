"""Impact reasoning has finite evidence, durable history and no repair authority."""
import copy
import json
import sqlite3

import pytest

from security_runtime.repair_impact import RepairImpactService, RepairImpactError
from security_runtime.repair_impact_models import MATERIAL_SECONDS


SOURCE = dict(kind='SCANNER_TASK_GROUP', task_ref='task-v1-fixture')
OWNER = dict(host='codex', session='original-chat')


@pytest.fixture
def impact(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'app.py').write_text('def read_file(user, file):\n    return file.read()\n', encoding='utf8')
    clock = [1000.0]
    binding = dict(kind=SOURCE['kind'], task_ref=SOURCE['task_ref'], scan_id='scan-1', member_ids=['f1'])
    resolved = dict(binding=binding, source_paths=['app.py'], member_ids=['f1'],
                    required_windows=[dict(file_path='app.py', start_line=1, end_line=2)])
    def resolve(source):
        if source['kind'] != resolved['binding']['kind'] or source['task_ref'] != resolved['binding']['task_ref']:
            raise ValueError('not this source')
        return copy.deepcopy(resolved)
    service = RepairImpactService(root, tmp_path/'private', OWNER, resolve, now=lambda:clock[0])
    proposal = dict(security_goal='Enforce file membership', summary='Check existing member policy',
                    changes=[dict(file_path='app.py', start_line=1, end_line=2, reason='Selected risk')],
                    preserve=['Retain member access'])
    return service, root, clock, resolved, proposal, resolve


def prepared(impact):
    service, _, _, _, proposal, _ = impact
    return service.prepare(SOURCE, proposal)


def proof(service, packet, *, kind='NO_ADDITIONAL_CHANGE_IDENTIFIED'):
    ref = packet['assessment_ref']
    evidence = service.read(ref, 'app.py', 1, 2)['evidence_ref']
    return [dict(kind=kind, summary='Member access is preserved within reviewed code', evidence_refs=[evidence])]


def test_prepare_read_submit_and_no_source_storage(impact):
    service, root, _, _, _, _ = impact
    before = (root/'app.py').read_bytes()
    packet = prepared(impact)
    assert packet['gate'] == 'CRITICAL_CONTEXT_MISSING'
    result = service.submit(packet['assessment_ref'], proof(service, packet), [])
    assert result['gate'] == 'READY_FOR_EXISTING_AUTH'
    assert result['analysis_trust'] == 'HOST_ANALYSIS_NOT_SCANNER_PROOF'
    assert result['repair_authorized'] is result['automatic_execution'] is False
    assert service.validate_for_fix(result['assessment_ref'], SOURCE)['gate'] == 'READY_FOR_EXISTING_AUTH'
    with sqlite3.connect(service.store.path) as db:
        saved = db.execute('SELECT record FROM assessments').fetchone()[0]
    assert 'def read_file' not in saved and 'numbered_lines' not in saved
    assert before == (root/'app.py').read_bytes()


def test_unread_requested_range_prevents_ready_even_if_submitted_reviewed(impact):
    service, root, _, resolved, proposal, _ = impact
    (root/'app.py').write_text('\n'.join(f'operation_{n}()' for n in range(240)), encoding='utf8')
    resolved['required_windows'][0]['end_line'] = 240
    packet = service.prepare(SOURCE, proposal)
    first = service.read(packet['assessment_ref'], 'app.py', 1, 240)
    assert first['end_line'] <= 80 and first['next_range']['end_line'] == 240
    result = service.submit(packet['assessment_ref'], [dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED',
        summary='Only the first page was read', evidence_refs=[first['evidence_ref']])], [])
    assert result['lifecycle'] == 'PARTIAL' and result['gate'] == 'CRITICAL_CONTEXT_MISSING'
    assert result['unread_window_count']


def test_new_context_invalidates_previous_analysis_until_resubmitted(impact):
    service, root, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet)
    service.submit(packet['assessment_ref'], impacts, [])
    (root/'policy.py').write_text('def can_read(member):\n    return member.active\n', encoding='utf8')
    service.read(packet['assessment_ref'], 'policy.py', 1, 2, reason='Shared membership policy')
    assert service.validate_for_fix(packet['assessment_ref'], SOURCE)['gate'] == 'CRITICAL_CONTEXT_MISSING'
    assert service.submit(packet['assessment_ref'], impacts, [])['gate'] == 'READY_FOR_EXISTING_AUTH'


def test_choice_is_plan_bound_and_not_edit_authority(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet, kind='BUSINESS_BEHAVIOR_CHANGE')
    first = service.submit(packet['assessment_ref'], impacts, [])
    assert first['gate'] == 'BUSINESS_CHOICE_REQUIRED'
    choice = dict(user_requested=True, proposal_revision=packet['proposal_revision'],
                  decision='ACCEPT_PROPOSED_CHANGE')
    result = service.submit(packet['assessment_ref'], impacts, [], business_choice=choice)
    assert result['gate'] == 'READY_FOR_EXISTING_AUTH' and not result['repair_authorized']
    assert result['business_choice']['trust'].startswith('UNTRUSTED_HOST_REPORT')
    choice['proposal_revision'] = 'other-plan'
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_BUSINESS_CHOICE_INVALID'):
        service.submit(packet['assessment_ref'], impacts, [], business_choice=choice)


def test_critical_unknown_and_undetermined_never_ready(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet)
    out = service.submit(packet['assessment_ref'], impacts, [dict(summary='Tenant rule unknown', critical=True)])
    assert out['gate'] == 'CRITICAL_CONTEXT_MISSING'
    impacts[0]['kind'] = 'UNDETERMINED'
    assert service.submit(packet['assessment_ref'], impacts, [])['gate'] == 'CRITICAL_CONTEXT_MISSING'


def test_stale_partial_is_durable_without_replacing_old_snapshot(impact):
    service, root, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet)
    (root/'app.py').write_text('changed = True\n', encoding='utf8')
    out = service.submit(packet['assessment_ref'], impacts, [dict(summary='Source changed', critical=True)], coverage='PARTIAL')
    assert out['lifecycle'] == 'STALE' and out['gate'] == 'REASSESS_REQUIRED'
    assert service.get(packet['assessment_ref'])['unknown_count'] == 1
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_STALE'):
        service.read(packet['assessment_ref'], 'app.py', 1, 1)


def test_idle_partial_saved_without_renewing_lease_and_resume_keeps_spending(impact):
    service, _, clock, _, proposal, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet)
    old = service.get(packet['assessment_ref'])
    clock[0] = old['activity_expires_at'] + 1
    partial = service.submit(packet['assessment_ref'], impacts, [], coverage='PARTIAL')
    assert partial['activity_expires_at'] == old['activity_expires_at']
    assert partial['gate'] == 'CRITICAL_CONTEXT_MISSING'
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_IDLE_RESUME_REQUIRED'):
        service.submit(packet['assessment_ref'], impacts, [])
    resumed = service.prepare(SOURCE, proposal)
    assert resumed['assessment_ref'] == packet['assessment_ref']
    assert resumed['ledger']['source_bytes'] == old['ledger']['source_bytes']
    assert resumed['material_expires_at'] == old['material_expires_at']


def test_material_ttl_new_revision_does_not_reset_ledger(impact):
    service, _, clock, _, proposal, _ = impact
    packet = prepared(impact)
    proof(service, packet)
    before = service.get(packet['assessment_ref'])
    clock[0] += MATERIAL_SECONDS + 1
    renewed = service.prepare(SOURCE, proposal)
    assert renewed['assessment_ref'] != packet['assessment_ref']
    assert renewed['revision'] == 2
    assert renewed['ledger']['source_bytes'] == before['ledger']['source_bytes']
    assert service.get(packet['assessment_ref'])['lifecycle'] == 'STALE'


def test_owner_cannot_resume_or_edit_but_history_read_is_non_mutating(impact, tmp_path):
    service, root, _, _, _, resolve = impact
    packet = prepared(impact)
    outsider = RepairImpactService(root, tmp_path/'private', dict(host='codex', session='another-chat'), resolve)
    out = outsider.get(packet['assessment_ref'])
    assert out['owner_matches'] is False
    for call in [lambda: outsider.read(packet['assessment_ref'], 'app.py', 1, 2),
                 lambda: outsider.submit(packet['assessment_ref'], [], [], coverage='PARTIAL'),
                 lambda: outsider.validate_for_fix(packet['assessment_ref'], SOURCE)]:
        with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_OWNER_MISMATCH'):
            call()


def test_native_revision_and_source_kind_cannot_cross(impact, tmp_path):
    service, root, clock, _, proposal, _ = impact
    packet = prepared(impact)
    native = dict(kind='HOST_TASK_RISK', task_ref='native-task', finding_id='tc1-risk', origin_review_revision=2)
    resolved = dict(binding=dict(**native, origin_snapshot_id='snapshot-2'),
                    source_paths=['app.py'], required_windows=[dict(file_path='app.py', start_line=1, end_line=2)])
    other = RepairImpactService(root, tmp_path/'private', OWNER, lambda _:copy.deepcopy(resolved), now=lambda:clock[0])
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_SOURCE_BINDING_MISMATCH'):
        other.validate_for_fix(packet['assessment_ref'], native)
    p = other.prepare(native, proposal)
    omitted = dict(native)
    omitted.pop('origin_review_revision')
    q = other.prepare(omitted, proposal)
    assert q['assessment_ref'] == p['assessment_ref']
    native['origin_review_revision'] = 3
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_SOURCE_BINDING_MISMATCH'):
        other.prepare(native, proposal)


@pytest.mark.parametrize('name', ['../escape.py', '.env', '.env.local', '.git/config',
    'node_modules/a.js', 'dist/a.js', 'vendor/a.py', 'x.exe', 'secrets.key', 'a.py:stream'])
def test_untrusted_path_denied(impact, name):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    with pytest.raises(RepairImpactError):
        service.read(packet['assessment_ref'], name, 1, 1, reason='related')


def test_docs_need_reason_and_literals_remain_original(impact):
    service, root, _, _, _, _ = impact
    (root/'rules.md').write_text('Use token = secret-value\nShared members may read files.\n', encoding='utf8')
    packet = prepared(impact)
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_DOCUMENT_REASON_REQUIRED'):
        service.read(packet['assessment_ref'], 'rules.md', 1, 2)
    out = service.read(packet['assessment_ref'], 'rules.md', 1, 2, reason='Business access contract')
    assert 'secret-value' in json.dumps(out)
    assert 'Shared members' in json.dumps(out)


def test_response_is_bytes_and_line_bounded_no_silent_obligation_drop(impact):
    service, root, _, resolved, proposal, _ = impact
    (root/'app.py').write_text('\n'.join('operation_'+str(n)+'('*1+'變'*150+')' for n in range(100)), encoding='utf8')
    resolved['required_windows'][0]['end_line'] = 100
    packet = service.prepare(SOURCE, proposal)
    out = service.read(packet['assessment_ref'], 'app.py', 1, 100)
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= 16_000
    assert len(out['numbered_lines']) <= 80 and out['next_range']
    assert out['next_range']['end_line'] == 100


def test_duplicate_delivery_is_receipt_and_does_not_renew(impact):
    service, _, clock, _, _, _ = impact
    packet = prepared(impact)
    first = service.read(packet['assessment_ref'], 'app.py', 1, 2)
    before = service.get(packet['assessment_ref'])
    clock[0] += 30
    again = service.read(packet['assessment_ref'], 'app.py', 1, 2)
    after = service.get(packet['assessment_ref'])
    assert again['status'] == 'ALREADY_DELIVERED' and 'numbered_lines' not in again
    assert again['evidence_ref'] == first['evidence_ref']
    assert before['activity_expires_at'] == after['activity_expires_at']
    assert before['ledger']['source_bytes'] == after['ledger']['source_bytes']


def test_forged_evidence_does_not_change_saved_analysis(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_EVIDENCE_INVALID'):
        service.submit(packet['assessment_ref'], [dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED',
            summary='made up', evidence_refs=['ri-evidence-forged'])], [])
    assert service.get(packet['assessment_ref'])['impact_count'] == 0


def test_proposal_many_locations_is_complete_and_paginated(impact):
    service, root, _, resolved, proposal, _ = impact
    (root/'app.py').write_text('\n'.join(f'line_{n} = {n}' for n in range(20)), encoding='utf8')
    proposal['changes'] = [dict(file_path='app.py', start_line=n, end_line=n, reason='Selected grouped member')
                           for n in range(1,21)]
    packet = service.prepare(SOURCE, proposal)
    assert packet['proposal_change_count'] == 20 and packet['proposal_changes_truncated']
    ref, offset, changes = packet['assessment_ref'], 0, []
    while True:
        page = service.get(ref, offset=offset, limit=10)
        assert len(json.dumps(page, ensure_ascii=False).encode()) <= 16_000
        changes.extend(page['proposal']['changes'])
        if not page['page']['has_more']:
            break
        offset = page['page']['next_offset']
    assert len(changes) == 20


def test_old_proposal_cannot_be_used_after_a_new_proposal(impact):
    service, _, _, _, proposal, _ = impact
    packet = prepared(impact)
    service.submit(packet['assessment_ref'], proof(service, packet), [])
    proposal['summary'] = 'Another implementation preserving membership'
    new = service.prepare(SOURCE, proposal)
    assert new['revision'] == 2
    assert service.validate_for_fix(packet['assessment_ref'], SOURCE)['gate'] == 'REASSESS_REQUIRED'


def test_get_missing_is_read_only_and_constructor_is_lazy(impact, tmp_path):
    _, root, _, _, _, resolve = impact
    directory = tmp_path/'never-created'
    service = RepairImpactService(root, directory, OWNER, resolve)
    assert not directory.exists()
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_REFERENCE_INVALID'):
        service.get('ria1-'+'a'*32)
    assert not directory.exists()


def test_history_get_does_not_write_or_renew(impact):
    service, _, clock, _, _, _ = impact
    packet = prepared(impact)
    before = service.store.path.read_bytes()
    stamp = service.store.path.stat().st_mtime_ns
    clock[0] += 30
    result = service.get(packet['assessment_ref'])
    assert result['activity_expires_at'] == packet['activity_expires_at']
    assert service.store.path.read_bytes() == before
    assert service.store.path.stat().st_mtime_ns == stamp


def test_private_record_tampering_cannot_forge_ready(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    with sqlite3.connect(service.store.path) as db:
        payload = json.loads(db.execute('SELECT record FROM assessments WHERE id=?',
                                      (packet['assessment_ref'],)).fetchone()[0])
        payload['payload'].update(coverage='REVIEWED', submitted=True, required_windows=[])
        db.execute('UPDATE assessments SET record=? WHERE id=?',
                   (json.dumps(payload), packet['assessment_ref']))
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_STORAGE_INTEGRITY'):
        service.validate_for_fix(packet['assessment_ref'], SOURCE)


def test_linked_source_cannot_be_used_for_related_context(impact, tmp_path):
    service, root, _, _, _, _ = impact
    packet = prepared(impact)
    target = tmp_path/'outside.py'
    target.write_text('private_value = 1\n', encoding='utf8')
    try:
        (root/'linked.py').symlink_to(target)
    except OSError:
        pytest.skip('Host cannot create symlinks')
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_SOURCE_UNAVAILABLE'):
        service.read(packet['assessment_ref'], 'linked.py', 1, 1, reason='claimed related source')


def test_partial_results_save_even_when_control_delivery_is_exhausted(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet)
    with service.store.connect(write=True) as db:
        record, cycle = service._record(db, packet['assessment_ref'])
        cycle['ledger']['category_limits']['control'] = cycle['ledger']['control_bytes']
        service._save(db, record, cycle)
    result = service.submit(packet['assessment_ref'], impacts, [dict(summary='Still reviewing consumers', critical=True)], coverage='PARTIAL')
    assert result['result_saved'] and result['result_details_required']
    assert len(json.dumps(result).encode()) < 2048
    assert service.get(packet['assessment_ref'])['unknown_count'] == 1


def test_known_source_credential_remains_in_proposal_and_stale_analysis(impact):
    service, root, _, resolved, proposal, _ = impact
    secret = 'opaque-business-credential'
    (root/'app.py').write_text('password = "'+secret+'"\noperation()\n', encoding='utf8')
    resolved['secret_ranges'] = {'app.py': [(1, 1)]}
    proposal['summary'] = 'Preserve '+secret+' during configuration migration'
    packet = service.prepare(SOURCE, proposal)
    impacts = proof(service, packet)
    impacts[0]['summary'] = 'Previously used '+secret+'; exact value is unknown'
    (root/'app.py').write_text('changed = True\n', encoding='utf8')
    result = service.submit(packet['assessment_ref'], impacts, [], coverage='PARTIAL')
    assert secret in json.dumps(result)
    with sqlite3.connect(service.store.path) as db:
        saved = db.execute('SELECT record FROM assessments').fetchone()[0]
    assert secret in saved


@pytest.mark.parametrize('bad_source', [dict(kind=[], task_ref='x'), dict(kind='SCANNER_TASK_GROUP', task_ref='x', finding_id='extra')])
def test_invalid_nested_source_has_domain_error(impact, bad_source):
    service, _, _, _, proposal, _ = impact
    with pytest.raises(RepairImpactError):
        service.prepare(bad_source, proposal)


def test_business_choice_does_not_cover_newly_identified_business_effect(impact):
    service, _, _, _, _, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet, kind='BUSINESS_BEHAVIOR_CHANGE')
    choice = dict(user_requested=True, proposal_revision=packet['proposal_revision'],
                  decision='ACCEPT_PROPOSED_CHANGE')
    service.submit(packet['assessment_ref'], impacts, [], business_choice=choice)
    impacts[0]['summary'] = 'Shared members also lose their previously legitimate access'
    result = service.submit(packet['assessment_ref'], impacts, [])
    assert result['gate'] == 'BUSINESS_CHOICE_REQUIRED'


def test_same_business_semantics_reuse_choice_after_material_refresh(impact):
    service, _, clock, _, proposal, _ = impact
    packet = prepared(impact)
    impacts = proof(service, packet, kind='BUSINESS_BEHAVIOR_CHANGE')
    choice = dict(user_requested=True, proposal_revision=packet['proposal_revision'],
                  decision='ACCEPT_PROPOSED_CHANGE')
    service.submit(packet['assessment_ref'], impacts, [], business_choice=choice)
    clock[0] += MATERIAL_SECONDS+1
    renewed = service.prepare(SOURCE, proposal)
    new_impacts = proof(service, renewed, kind='BUSINESS_BEHAVIOR_CHANGE')
    assert new_impacts[0]['evidence_refs'] != impacts[0]['evidence_refs']
    assert service.submit(renewed['assessment_ref'], new_impacts, [])['gate'] == 'READY_FOR_EXISTING_AUTH'


def test_missing_existing_integrity_key_is_not_recreated(impact):
    service, _, _, _, proposal, _ = impact
    prepared(impact)
    service.store.key_path.unlink()
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_STORAGE_INTEGRITY'):
        service.prepare(SOURCE, proposal)
    assert not service.store.key_path.exists()
