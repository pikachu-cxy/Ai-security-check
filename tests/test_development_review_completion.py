"""Versioned review coverage, recovery and Stop integration without real scanners."""
import pytest

from test_development_risks import sample, scanner, observation
from security_runtime.development_risks import DevelopmentRiskError, review_progress
from security_runtime.development_stop import fallback


@pytest.fixture(autouse=True)
def presentation(monkeypatch):
    monkeypatch.setattr('security_runtime.mcp_tools.presentation._agent_result',
                        lambda scan, **kwargs: dict(scan_id='scan-1'))


def review(risks, **changes):
    value = dict(same_issue_as='s1', scan_id='scan-1', decision='DISMISSED',
                 rationale='Context rules out the candidate',
                 evidence_refs=[risks.read('query.py', 1, 2)['evidence_ref']])
    return dict(value, **changes)


def business(risks, **changes):
    return dict(dict(file_path='query.py', rationale='Checked input and caller boundary',
                     evidence_refs=[risks.read('query.py', 1, 2)['evidence_ref']], limitations=[]), **changes)


def progress(risks):
    return review_progress(risks.current_check(), risks.load())


def test_empty_and_partial_submissions_do_not_complete_review(sample, monkeypatch):
    original = scanner(sample, monkeypatch)
    root, service, ref, risks = sample
    second = dict(original, id='s2', fingerprint='other')
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                        lambda *a: dict(target_profile=dict(path=str(root)), findings=[original, second]))
    risks.submit([], 1)
    assert len(progress(risks)['pending_scanner_ids']) == 2
    risks.submit([review(risks)], 1)
    assert len(progress(risks)['pending_scanner_ids']) == 1
    risks.submit([review(risks, same_issue_as='s2')], 1)
    assert progress(risks)['scanner_review'] == 'COMPLETE'
    assert not service.get(root, ref)['host_review_completed']
    risks.submit([], 1, business_reviews=[business(risks)])
    assert service.get(root, ref)['host_review_completed']
    service.record(root, ref, ['query.py'])
    assert not service.get(root, ref)['host_review_completed']


def test_id_review_keeps_original_location_and_related_evidence(sample, monkeypatch):
    original = scanner(sample, monkeypatch)
    root, _, _, risks = sample
    (root/'caller.py').write_text('safe = True\n')
    related = risks.read('caller.py', 1, 1, related=True)['evidence_ref']
    value = review(risks)
    value['evidence_refs'].append(related)
    first = risks.submit([value], 1)['risks'][0]
    again = risks.submit([value], 1)['risks'][0]
    assert first['finding']['line_start'] == original['line_start']
    assert again['assessment_count'] == 1
    assert risks.current_check()['observed_paths'] == ['query.py']
    # Mutable display findings must not become the source of original locations.
    with risks.store.transaction() as db:
        row = risks.load(db)
        row['risks'][first['id']]['finding']['line_start'] = 1
        risks.store._put(db, risks.ref, row)
    risks.submit([value], 1)
    assert risks.load()['risks'][first['id']]['assessment']['finding']['line_start'] == 2


@pytest.mark.parametrize('changes,reason', [
    ({'scan_id': 'old-scan'}, 'SCAN_VERSION_STALE'),
    ({'same_issue_as': 'foreign-risk'}, 'LINK_UNKNOWN'),
    ({'evidence_refs': ['forged']}, 'EVIDENCE_UNKNOWN'),
])
def test_failed_batch_is_atomic_and_has_recovery(sample, monkeypatch, changes, reason):
    scanner(sample, monkeypatch)
    risks = sample[3]
    with pytest.raises(DevelopmentRiskError, match=reason) as raised:
        risks.submit([review(risks), review(risks, **changes)], 1)
    assert raised.value.item_index == 1
    assert raised.value.recovery['arguments']['check_ref'] == risks.ref
    assert risks.load()['reviews'] == []
    assert risks.load()['risks'] == {}
    assert risks.get()['total'] is None and not risks.get()['candidates_ready']


def test_evidence_must_cover_original_alert_not_only_related_file(sample, monkeypatch):
    scanner(sample, monkeypatch)
    root, _, _, risks = sample
    (root/'caller.py').write_text('safe = True\n')
    value = review(risks, evidence_refs=[risks.read('caller.py', 1, 1, related=True)['evidence_ref']])
    with pytest.raises(DevelopmentRiskError, match='LOCATION_UNREAD') as raised:
        risks.submit([value], 1)
    assert raised.value.recovery['arguments']['start_line'] == 2


def test_business_limitations_and_old_receipts_do_not_complete(sample, monkeypatch):
    scanner(sample, monkeypatch)
    risks = sample[3]
    risks.submit([review(risks)], 1, business_reviews=[business(risks, limitations=['caller unknown'])])
    assert progress(risks)['pending_business_paths'] == ['query.py']
    risks.submit([], 1, business_reviews=[business(risks)])
    assert progress(risks)['host_review_completed']
    risks.submit([], 1, business_reviews=[business(risks, limitations=['new uncertainty'])])
    assert not progress(risks)['host_review_completed']
    risks.submit([], 1, business_reviews=[business(risks)])
    assert progress(risks)['host_review_completed']
    with risks.store.transaction() as db:
        row = risks.load(db)
        row['reviews'] = [dict(dirty_seq=1, scan_id='scan-1', risk_ids=list(row['risks']))]
        risks.store._put(db, risks.ref, row)
    assert not progress(risks)['host_review_completed']


def test_inconclusive_candidate_stays_pending(sample, monkeypatch):
    scanner(sample, monkeypatch)
    risks = sample[3]
    risks.submit([review(risks)], 1, business_reviews=[business(risks)])
    assert progress(risks)['host_review_completed']
    risks.submit([review(risks, decision='INCONCLUSIVE')], 1)
    assert progress(risks)['pending_scanner_ids']
    assert not progress(risks)['host_review_completed']


@pytest.mark.parametrize('review_enabled,audit_enabled', [(True, False), (False, True), (False, False)])
def test_disabled_phase_does_not_require_coverage(sample, monkeypatch, review_enabled, audit_enabled):
    scanner(sample, monkeypatch)
    root, service, ref, risks = sample
    with service.store(root).transaction() as db:
        row = service.store(root)._get(db, ref)
        row['effective_config']['values']['agent'].update(
            review_scanner_findings=review_enabled, audit_business_logic=audit_enabled)
        service.store(root)._put(db, ref, row)
    if review_enabled or audit_enabled:
        risks.submit([review(risks)] if review_enabled else [], 1,
                     business_reviews=[business(risks)] if audit_enabled else [])
        assert progress(risks)['host_review_completed']
    else:
        risks.sync_scanner()
        assert progress(risks)['scanner_review'] == 'SKIPPED_BY_CONFIG'
        assert progress(risks)['business_review'] == 'SKIPPED_BY_CONFIG'
        assert not progress(risks)['host_review_completed']


def test_changed_scan_id_invalidates_saved_reviews(sample, monkeypatch):
    scanner(sample, monkeypatch)
    root, service, ref, risks = sample
    risks.submit([review(risks)], 1, business_reviews=[business(risks)])
    with service.store(root).transaction() as db:
        row = service.store(root)._get(db, ref)
        row['scan_id'] = 'scan-2'
        service.store(root)._put(db, ref, row)
    assert not progress(risks)['host_review_completed']
    with pytest.raises(DevelopmentRiskError, match='SCAN_VERSION_STALE'):
        risks.submit([review(risks)], 1)


def test_zero_candidates_still_requires_business_review(sample, monkeypatch):
    scanner(sample, monkeypatch)
    root, _, _, risks = sample
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                        lambda *a: dict(target_profile=dict(path=str(root)), findings=[]))
    risks.sync_scanner()
    risks.submit([], 1)
    assert progress(risks)['scanner_review'] == 'COMPLETE'
    assert not progress(risks)['host_review_completed']
    risks.submit([], 1, business_reviews=[business(risks)])
    assert progress(risks)['host_review_completed']


def test_scan_change_during_evidence_validation_rolls_back(sample, monkeypatch):
    scanner(sample, monkeypatch)
    root, service, ref, risks = sample
    value = review(risks)
    original = risks.evidence
    def changed(row, refs):
        evidence = original(row, refs)
        with service.store(root).transaction() as db:
            check = service.store(root)._get(db, ref)
            check['scan_id'] = 'scan-2'
            service.store(root)._put(db, ref, check)
        return evidence
    monkeypatch.setattr(risks, 'evidence', changed)
    from security_runtime.tasks.durable import TaskOperationError
    with pytest.raises(TaskOperationError, match='BUSY'):
        risks.submit([value], 1)
    assert risks.load()['reviews'] == []


def test_stop_routes_pending_review_once_per_terminal_version(sample, monkeypatch):
    scanner(sample, monkeypatch)
    root, service, ref, risks = sample
    risks.sync_scanner()
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.update(state='RESULTS_READY', finish_requested=True)
        store._put(db, ref, row)
    first = fallback(service.hooks, root, service.owner, service=service)
    assert first['decision'] == 'block'
    assert 'get_development_risks' in first['reason']
    assert first['review_progress']['pending_scanner_ids']
    fallback(service.hooks, root, service.owner, service=service, stop_hook_active=True)
    last = fallback(service.hooks, root, service.owner, service=service, stop_hook_active=True)
    assert last is None  # The same terminal input is offered only once.
    assert store.load(ref, service.owner)['stop_fallback']['count'] == 1
    assert store.load(ref, service.owner)['stop_fallback']['terminal_result'] == [1, 'scan-1', 'RESULTS_READY']
    risks.submit([review(risks)], 1, business_reviews=[business(risks)])
    assert fallback(service.hooks, root, service.owner, service=service, stop_hook_active=True) is None


@pytest.mark.parametrize('batch_id,second_fields,reason', [
    ('old-scan', {}, 'SCAN_VERSION_STALE'),
    ('scan-1', {'scan_id': 'different'}, 'SCAN_VERSION_STALE'),
    ('scan-1', {'evidence_refs': []}, 'EVIDENCE_REQUIRED'),
    (None, {}, 'SCAN_VERSION_STALE'),
])
def test_batch_scan_identity_and_evidence_fail_atomically(sample, monkeypatch, batch_id, second_fields, reason):
    original = scanner(sample, monkeypatch)
    root, _, _, risks = sample
    second = dict(original, id='s2', fingerprint='second')
    monkeypatch.setattr('security_runtime.storage.ReadOnlySQLiteStore.get_scan',
                        lambda *_: dict(target_profile=dict(path=str(root)), findings=[original, second]))
    risks.sync_scanner()
    first = review(risks)
    other = dict(first, same_issue_as='s2')
    del other['scan_id']
    other.update(second_fields)
    with pytest.raises(DevelopmentRiskError, match=reason):
        risks.submit([first, other], 1, scan_id=batch_id)
    assert len(progress(risks)['pending_scanner_ids']) == 2
    assert not risks.load()['reviews']
