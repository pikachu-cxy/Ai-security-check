"""Historical target receipts cannot stand in for current risk-row facts."""
import copy

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.risk_ledger import TaskRiskLedger, current_hashes
from summary_fixtures import sample, snapshot  # noqa: F401


def ledger_event(sample, event_id='verification-e'):
    root, scan, store = sample
    hooks = HookStateStore(store.path.parent/'hooks')
    ledger = TaskRiskLedger(hooks,root)
    with hooks.lock(root) as held:
        assert held
        ledger.register(dict(task_ref='origin',static=scan.to_dict(),
            end=dict(hashes=current_hashes(root,[row.file_path for row in scan.findings]))))
    finding_id = scan.findings[0].id
    rows = ledger.read_scan(scan.scan_id)
    event = dict(event_id=event_id,scan_id=scan.scan_id,before=current_hashes(root,['App.java']),
        results=[dict(finding_id=finding_id,verification_status='SCANNER_VERIFIED_RESOLVED',
            reason='Original detector result')],expected_rows={key:ledger.row_version(row)
            for key,row in rows.items() if row['finding_id'] == finding_id})
    return root,hooks,ledger,event


def apply(hooks,root,ledger,event):
    with hooks.lock(root) as held:
        assert held
        return ledger.apply_native_event(event)


def newer_event(ledger,event,*,same_result=False):
    newer = copy.deepcopy(event)
    newer['event_id'] = 'verification-f'
    newer['expected_rows'] = {key:ledger.row_version(row)
        for key,row in ledger.read_scan(event['scan_id']).items() if key in event['expected_rows']}
    if not same_result:
        newer['results'][0].update(verification_status='STILL_PRESENT',reason='New independent observation')
    return newer


def test_old_inbox_replay_does_not_claim_newer_risk_row_is_resolved(sample):
    root,hooks,ledger,event = ledger_event(sample)
    assert apply(hooks,root,ledger,event)['status'] == 'RECORDED'
    assert ledger.effect_current(event)
    assert apply(hooks,root,ledger,newer_event(ledger,event))['status'] == 'RECORDED'
    newer = snapshot(root)
    assert not ledger.effect_current(event)
    assert apply(hooks,root,ledger,event) == dict(
        status='SUPERSEDED',recorded=0,unverified_current=0,already_applied=True)
    assert snapshot(root) == newer
    prior = ledger._stored()['inbox'][event['event_id']+':ledger']
    assert prior['result']['status'] == 'RECORDED'  # Preserve the historical delivery.
    assert all(ledger.read()[key]['status'] == 'STILL_PRESENT' for key in event['expected_rows'])


def test_independent_same_result_changes_watermark_without_leaking_internal_marker(sample):
    root,hooks,ledger,event = ledger_event(sample)
    apply(hooks,root,ledger,event)
    newer = newer_event(ledger,event,same_result=True)
    apply(hooks,root,ledger,newer)
    assert not ledger.effect_current(event) and ledger.effect_current(newer)
    assert apply(hooks,root,ledger,event)['status'] == 'SUPERSEDED'
    assert all('_native_verification' not in row for row in ledger.view('origin')['items'])


def test_unrelated_risk_changes_do_not_invalidate_selected_row_receipt(sample):
    root,hooks,ledger,event = ledger_event(sample)
    apply(hooks,root,ledger,event)
    with hooks.lock(root) as held:
        assert held
        rows = ledger.read('origin')
        key = next(key for key in rows if key not in event['expected_rows'])
        rows[key]['reason'] = 'Independent risk fact'
        ledger.save(rows)
    before = snapshot(root)
    assert ledger.effect_current(event)
    assert apply(hooks,root,ledger,event)['status'] == 'RECORDED'
    assert snapshot(root) == before


def test_legacy_receipt_without_watermark_is_retained_without_current_proof(sample):
    root,hooks,ledger,event = ledger_event(sample)
    with hooks.lock(root) as held:
        assert held
        ledger.save(ledger.read('origin'),receipt=(event['event_id']+':ledger',dict(
            payload_sha256=ledger._native_fingerprint(event),
            result=dict(status='RECORDED',recorded=1,unverified_current=0))))
    before = snapshot(root)
    assert not ledger.effect_current(event)
    assert apply(hooks,root,ledger,event)['status'] == 'SUPERSEDED'
    assert snapshot(root) == before


def test_absent_target_watermark_query_creates_no_authority(sample):
    root,scan,store = sample
    hooks = HookStateStore(store.path.parent/'unused-hooks')
    ledger = TaskRiskLedger(hooks,root)
    before = snapshot(root)
    assert not ledger.effect_current(dict(event_id='missing'))
    assert snapshot(root) == before and not ledger.path.exists()
