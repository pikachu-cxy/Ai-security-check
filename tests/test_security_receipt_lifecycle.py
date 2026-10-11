"""Functional authority uses the exact signed current resolved security proof."""
import copy
import pytest

from security_runtime.functional_verification import FunctionalVerificationService
from security_runtime.remediation import RemediationService
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.triage import TriageService
from test_remediation import setup, args, prepare, FIXED
from test_remediation_episodes import record, resolve, recur
from test_hook_runtime import repo
from test_functional_host import report


def planned(service, values, root):
    functional = FunctionalVerificationService(service)
    out = functional.prepare(values['remediation_ref'], values['task_ref'], root, bound_workspace=root)
    functional._cleanup_rows(functional.plans)
    return out


def mutate(setup, change):
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    change(next(iter(rows.values())))
    service._save(path, rows, key)


def diagnostic(setup, values=None):
    values = values or args(setup)
    return setup[3].functional_receipt_diagnostics(values['remediation_ref'], values['task_ref'], setup[0])


def test_resolved_proof_not_rejected_by_stale_ai_review(setup, monkeypatch):
    root, runtime, provider, service, hook, _ = setup
    references = dict(args(setup))
    scan_id = record(setup)['origin_scan_id']
    triage = TriageService(runtime.store)
    packet = triage.prepare(scan_id)['packets'][0]
    # Model a review of the original source whose publication arrives after
    # the explicitly approved repair has been scanned and closed. Publishing
    # an active review before prepare would correctly invalidate that grant.
    pending_reviews = []
    save_review = runtime.store.save_triage
    with monkeypatch.context() as delayed:
        delayed.setattr(runtime.store, 'save_triage', lambda row, key: pending_reviews.append((row, key)))
        triage.submit(scan_id, [dict(finding_id=packet['finding_id'], context_hash=packet['context_hash'],
            verdict='NEEDS_REVIEW', confidence='HIGH', exploitability='UNKNOWN', reason='Production unknown',
            attack_path='', evidence_refs=[], preconditions_met=[], preconditions_unknown=['Production usage'],
            recommended_action='Review')])
        resolve(setup)
    assert len(pending_reviews) == 1
    for row, key in pending_reviews:
        save_review(row, key)
    assert triage.view(scan_id, persist_stale=False)['findings'][0]['triage_status'] == 'STALE'
    functional = FunctionalVerificationService(service)
    out = functional.prepare(references['remediation_ref'], references['task_ref'], root, bound_workspace=root)
    try:
        assert out.get('status') == 'FUNCTIONAL_VERIFICATION_READY', out
    finally:
        functional._cleanup_rows(functional.plans)


def test_old_scan_cannot_masquerade_as_resolved_receipt(setup):
    resolve(setup)
    service = setup[3]
    path = service.state.path(setup[0], 'codex', 'session')
    key = service.state.key(setup[0])
    rows = service._read(path, key)
    row = next(iter(rows.values()))
    row['resolution']['hook_scan_id'] = row['origin_scan_id']
    service._save(path, rows, key)
    values = args(setup)
    assert service.functional_receipt(values['remediation_ref'], values['task_ref'], setup[0]) is None
    assert diagnostic(setup)['reason_code'] == 'RESOLVED_SCAN_IS_ORIGIN_SCAN'


def test_first_resolution_commits_bound_proof_before_functional_handoff(setup):
    closed = resolve(setup)
    proof = record(setup)['resolution']
    out = planned(setup[3], args(setup), setup[0])
    assert out['status'] == 'FUNCTIONAL_VERIFICATION_READY', out.get('functional_verification')
    public = out['plan']['security_receipt']
    assert public['episode_id'] == record(setup)['episode_id']
    assert public['grant_id'] == setup[-1]['remediation']['grant_id']
    assert public['origin_scan_id'] == record(setup)['origin_scan_id']
    assert public['resolved_scan_id'] == closed['scan_id'] != public['origin_scan_id']
    assert public['verification_id'] == proof['binding']['verification_id']
    assert out['security_verification']['receipt_validation']['status'] == 'VALID'
    assert out['plan']['target_files'] == ['A.java']


def test_current_episode_proof_survives_restart_without_restoring_execution_consent(setup):
    resolve(setup)
    old = record(setup)
    restarted = RemediationService(setup[3].store, registry=setup[3].registry, hooks=setup[3].hooks)
    out = planned(restarted, args(setup), setup[0])
    assert old['authorization_kind'] == 'USER_CONFIRMED'
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert out['functional_verification']['receipt_reason_code'] == 'CONFIRMED_CONNECTION_NOT_AUTHORIZED'
    assert 'plan' not in out and 'handoff' not in out
    values = args(setup)
    verified = restarted.verify(values['remediation_ref'], values['task_ref'], setup[0])
    assert verified['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert verified['security_receipt']['episode_id'] == old['episode_id']
    assert record(setup)['attempt_count'] == old['attempt_count'] == 1
    assert not restarted.prepared and not restarted.authorized


def test_family_recurrence_signs_new_proof_and_rejects_all_old_authority(setup):
    old = dict(args(setup))
    resolve(setup)
    old_record = record(setup)
    old_proof = copy.deepcopy(old_record['resolution'])
    fresh = recur(setup)['remediation']['prepare']['arguments']
    assert diagnostic(setup, old)['reason_code'] == 'REMEDIATION_EPISODE_SUPERSEDED'
    assert setup[3].prepare(fresh['remediation_ref'], fresh['task_ref'], setup[0])['status'] == 'READY_FOR_HOST_FIX'
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    assert setup[4]()['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    current = record(setup)
    assert current['resolution']['binding']['verification_id'] != old_proof['binding']['verification_id']
    assert current['episode_id'] != old_record['episode_id'] and current['episode_number'] == 2
    assert planned(setup[3], fresh, setup[0])['status'] == 'FUNCTIONAL_VERIFICATION_READY'
    mutate(setup, lambda r: r.update(resolution=old_proof))
    assert diagnostic(setup, fresh)['reason_code'] == 'RECEIPT_EPISODE_ID_MISMATCH'
    out = planned(setup[3], fresh, setup[0])
    assert out['functional_verification']['receipt_reason_code'] == 'RECEIPT_EPISODE_ID_MISMATCH'
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert 'plan' not in out


@pytest.mark.parametrize('field,reason', [
    ('workspace_id', 'RECEIPT_WORKSPACE_ID_MISMATCH'), ('episode_id', 'RECEIPT_EPISODE_ID_MISMATCH'),
    ('task_ref_hash', 'RECEIPT_TASK_REF_HASH_MISMATCH'), ('grant_id', 'RECEIPT_GRANT_ID_MISMATCH'),
    ('origin_scan_id', 'RECEIPT_ORIGIN_SCAN_ID_MISMATCH'), ('scope_hash', 'RECEIPT_SCOPE_MISMATCH'),
    ('resolved_scan_hash', 'RECEIPT_RESOLVED_SCAN_MISMATCH')])
def test_signed_but_mismatched_receipt_diagnostics_preserve_security(setup, field, reason):
    resolve(setup)
    mutate(setup, lambda r: r['resolution']['binding'].update({field: 'stale-scan' if field == 'origin_scan_id' else '0' * 64}))
    out = planned(setup[3], args(setup), setup[0])
    assert out['functional_verification']['reason_code'] == 'SECURITY_RECEIPT_REQUIRED_REFRESH'
    assert out['functional_verification']['receipt_reason_code'] == reason
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert out['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
    assert 'plan' not in out and 'handoff' not in out


def test_missing_or_stale_resolved_scan_has_exact_reason(setup):
    resolve(setup)
    mutate(setup, lambda r: r['resolution'].update(hook_scan_id='scan-missing'))
    assert diagnostic(setup)['reason_code'] == 'RESOLVED_SCAN_NOT_FOUND'


def test_wrong_workspace_and_changed_task_are_rejected_without_echo(setup, tmp_path):
    resolve(setup)
    values = args(setup)
    out = setup[3].functional_receipt_diagnostics(values['remediation_ref'], values['task_ref'], tmp_path)
    assert out['reason_code'] == 'TASK_WORKSPACE_MISMATCH' and out['receipt'] is None
    # Same task encoding with a changed character is not reconstructed/accepted.
    assert setup[3].functional_receipt_diagnostics(values['remediation_ref'], 'T01', setup[0])['reason_code'] == 'TASK_REFERENCE_INVALID'
    assert setup[3].functional_receipt_diagnostics('rem-v1.bad', values['task_ref'], setup[0])['reason_code'] == 'REMEDIATION_REFERENCE_INVALID'


@pytest.mark.parametrize('changed,reason', [('scan', 'ORIGIN_SCAN_NOT_FOUND'),
    ('scope', 'ORIGIN_TASK_SCOPE_MISMATCH'), ('detector', 'RECEIPT_SCOPE_MISMATCH')])
def test_origin_scan_and_exact_saved_scope_remain_required(setup, changed, reason):
    resolve(setup)
    scan = setup[1].store.get_scan(record(setup)['origin_scan_id'])
    original = setup[3].store.get_scan
    def read(scan_id):
        if scan_id != scan['scan_id']:
            return original(scan_id)
        if changed == 'scan':
            return None
        altered = copy.deepcopy(scan)
        if changed == 'scope':
            altered['findings'][0]['file_path'] = 'Wrong.java'
        else:
            altered['findings'][0]['technical_details']['rule_pack_checksum'] = 'b' * 64
        return altered
    setup[3].store.get_scan = read
    assert diagnostic(setup)['reason_code'] == reason


def test_source_and_git_snapshot_failures_are_distinct(setup, monkeypatch):
    resolve(setup)
    original = setup[3]._snapshot
    monkeypatch.setattr(setup[3], '_snapshot', lambda root: '0' * 64)
    assert diagnostic(setup)['reason_code'] == 'WORKSPACE_SNAPSHOT_CHANGED'
    def unavailable(root): raise OSError('private diagnostic never echoed')
    monkeypatch.setattr(setup[3], '_snapshot', unavailable)
    assert diagnostic(setup)['reason_code'] == 'WORKSPACE_SNAPSHOT_UNAVAILABLE'
    monkeypatch.setattr(setup[3], '_snapshot', original)
    setup[0].joinpath('A.java').write_text(FIXED.replace('1000', '9999'))
    assert diagnostic(setup)['reason_code'] == 'SOURCE_OR_PRESERVATION_CHANGED'


def test_legacy_proof_requires_actual_recheck_then_ready_and_stable_identity(setup):
    resolve(setup)
    mutate(setup, lambda r: r['resolution'].pop('binding'))
    values = args(setup)
    out = planned(setup[3], values, setup[0])
    assert out['functional_verification']['receipt_reason_code'] == 'RESOLVED_RECEIPT_BINDING_REQUIRED'
    assert out['handoff']['tool'] == 'verify_task_fix'
    assert out['handoff']['arguments']['task_ref'] == values['task_ref']
    assert out['handoff']['arguments']['remediation_ref'] == values['remediation_ref']
    assert setup[3].verify(values['remediation_ref'], values['task_ref'], setup[0])['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    proof = copy.deepcopy(record(setup)['resolution'])
    assert proof['hook_scan_id'] is None  # Explicit scanner recheck, not a forged DB scan.
    assert planned(setup[3], values, setup[0])['status'] == 'FUNCTIONAL_VERIFICATION_READY'
    assert setup[3].verify(values['remediation_ref'], values['task_ref'], setup[0])['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert record(setup)['resolution'] == proof


def test_old_cached_hook_scan_is_not_labeled_as_new_resolution(setup):
    prepare(setup)
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    result = HookCoordinator(setup[1], setup[3].hooks, cooldown_ms=0).handle('FILE_CHANGED', setup[0], 'codex', 'session')
    result.update(status='DEBOUNCED', scan_id=record(setup)['origin_scan_id'])
    out = setup[3].on_hook(result, setup[0], 'session', host='codex')
    assert out['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert record(setup)['resolution']['hook_scan_id'] is None
    assert planned(setup[3], args(setup), setup[0])['status'] == 'FUNCTIONAL_VERIFICATION_READY'


def test_state_commit_contention_is_busy_not_false_refresh(setup):
    resolve(setup)
    values = args(setup)
    functional = FunctionalVerificationService(setup[3])
    with setup[3].state.lock(setup[0]) as acquired:
        assert acquired
        out = functional.prepare(values['remediation_ref'], values['task_ref'], setup[0], bound_workspace=setup[0])
    assert out['functional_verification']['receipt_reason_code'] == 'SECURITY_STATE_BUSY'
    assert out['next_action'] == 'RETRY_PREPARE_AFTER_STATE_COMMIT' and not functional.plans
    assert planned(setup[3], values, setup[0])['status'] == 'FUNCTIONAL_VERIFICATION_READY'


def test_functional_report_and_final_verify_use_same_proof_across_duplicate_recheck(setup):
    resolve(setup)
    values = args(setup)
    functional = FunctionalVerificationService(setup[3])
    out = functional.prepare(values['remediation_ref'], values['task_ref'], setup[0], bound_workspace=setup[0])
    proof_id = out['plan']['security_receipt']['verification_id']
    checked = setup[3].verify(values['remediation_ref'], values['task_ref'], setup[0])
    assert record(setup)['resolution']['binding']['verification_id'] == proof_id
    final = functional.run(out['functional_ref'], execution_result=report(out), bound_workspace=setup[0])
    assert final['status'] == 'FUNCTIONAL_VERIFIED'
    merged = functional.finalize(values['remediation_ref'], values['task_ref'], setup[0], checked)
    assert merged['overall_status'] == 'SECURITY_AND_FUNCTIONALLY_VERIFIED'
    assert merged['security_verification']['receipt_binding']['verification_id'] == proof_id


def test_replaced_proof_cannot_consume_existing_functional_plan(setup):
    resolve(setup)
    values = args(setup)
    functional = FunctionalVerificationService(setup[3])
    out = functional.prepare(values['remediation_ref'], values['task_ref'], setup[0], bound_workspace=setup[0])
    artifact = functional.plans[out['functional_ref']]['artifact_directory']
    mutate(setup, lambda r: r['resolution']['binding'].update(verification_id='0' * 64))
    final = functional.run(out['functional_ref'], execution_result=report(out), bound_workspace=setup[0])
    assert final['functional_verification']['receipt_reason_code'] == 'SECURITY_PROOF_CHANGED'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert not artifact.exists()


def test_verified_scanner_fact_survives_later_receipt_read_failure(setup):
    resolve(setup)
    values = args(setup)
    checked = {'status': 'SCANNER_VERIFIED_RESOLVED', 'verification_status': 'SCANNER_VERIFIED_RESOLVED'}
    mutate(setup, lambda r: r['resolution']['binding'].update(scope_hash='0' * 64))
    final = FunctionalVerificationService(setup[3]).finalize(values['remediation_ref'], values['task_ref'], setup[0], checked)
    assert final['verification_status'] == final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert final['functional_verification']['status'] == 'INCONCLUSIVE'
    assert final['functional_verification']['receipt_reason_code'] == 'RECEIPT_SCOPE_MISMATCH'


@pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)
@pytest.mark.parametrize('changed,reason', [('restart', 'CONFIRMED_CONNECTION_NOT_AUTHORIZED'),
    ('expired', 'CONFIRMATION_EXPIRED')])
def test_confirmed_receipt_does_not_renew_expired_or_connection_authority(setup, changed, reason):
    from test_confirmation import choice
    values = choice(setup)['prepare']['arguments']
    service = setup[3]
    assert service.prepare(values['remediation_ref'], values['task_ref'], setup[0])['status'] == 'READY_FOR_HOST_FIX'
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    assert setup[4]()['remediation']['reason_code'] == 'SCANNER_VERIFIED_RESOLVED'
    assert planned(service, values, setup[0])['status'] == 'FUNCTIONAL_VERIFICATION_READY'
    if changed == 'restart':
        service = RemediationService(service.store, registry=service.registry, hooks=service.hooks, config=service.config)
    else:
        # Expiry is evaluated by the same existing confirmation clock.
        service._confirmation_remaining = lambda row: 0
    out = planned(service, values, setup[0])
    assert out['functional_verification']['receipt_reason_code'] == reason
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert 'plan' not in out


def test_receipt_does_not_bypass_policy_change(setup):
    resolve(setup)
    setup[3].config.write('ask_before_fix')
    out = planned(setup[3], args(setup), setup[0])
    # Writing the same mode changes the bound policy revision, not its name.
    assert out['functional_verification']['receipt_reason_code'] == 'CONFIRMATION_POLICY_OR_DEADLINE_CHANGED'
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert 'plan' not in out
