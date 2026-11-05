"""Canonical result persistence, rollback and legacy compatibility."""
import threading

import pytest

from test_development_risks import sample, observation, scanner  # noqa: F401
from security_runtime.tasks.durable import SignedRecords


def test_one_result_retains_original_fact_review_and_disposition(sample, monkeypatch):
    root, service, ref, risks = sample
    original = scanner(sample, monkeypatch)
    risks.sync_scanner()
    value = observation(risks, same_issue_as='s1')
    result = risks.submit([value], risks.current_check()['dirty_seq'])
    key = result['risks'][0]['id']
    risks.disposition(key, 'DEFER', True)
    stored = service.store(root).load(ref)['security_result']
    item = stored['risks'][key]
    assert item['observations'][0]['finding'] == original
    assert item['assessment']['decision'] == 'CONFIRMED'
    assert item['disposition'] == 'DEFER'
    assert value['evidence_refs'][0] in stored['evidence']
    assert 'scan-1' in stored['scan_facts']
    assert not risks.store.legacy.path.exists()


def test_legacy_migrates_on_write_preserving_ids_and_no_dual_write(sample):
    root, service, ref, risks = sample
    result = risks.submit([observation(risks)], risks.current_check()['dirty_seq'])
    key = result['risks'][0]['id']
    legacy = SignedRecords(service.hooks, root, 'development-risks.db')
    saved = risks.load()
    with legacy.transaction() as db:
        legacy._put(db, ref, saved)
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, ref)
        check.pop('security_result')
        check.pop('result_storage')
        risks.checks._put(db, ref, check)
    before = legacy.path.read_bytes()
    assert risks.get()['risks'][0]['id'] == key
    assert 'security_result' not in risks.current_check()  # read-only query
    risks.disposition(key, 'DEFER', True)
    assert risks.current_check()['security_result']['risks'][key]['disposition'] == 'DEFER'
    assert legacy.path.read_bytes() == before
    assert risks.load()['evidence'] == saved['evidence']


def test_result_and_check_rollback_together(sample):
    root, service, ref, risks = sample
    before = risks.current_check()
    with pytest.raises(RuntimeError):
        with risks.store.transaction() as db:
            risks.store._put(db, ref, risks.fresh())
            current = risks.checks._get(db, ref)
            risks.checks._put(db, ref, dict(current, state='RESULTS_READY'))
            raise RuntimeError('crash before commit')
    assert risks.current_check() == before
    assert not risks.store.legacy.path.exists()


def test_new_scan_serializes_after_old_import_without_lost_update(sample, monkeypatch):
    root, service, ref, risks = sample
    scanner(sample, monkeypatch)
    entered, started, finished = threading.Event(), threading.Event(), threading.Event()
    original = risks.import_scanner
    def newer():
        assert entered.wait(5)
        started.set()
        with risks.checks.transaction() as db:
            row = risks.checks._get(db, ref)
            risks.checks._put(db, ref, dict(row, scan_id='scan-2', risk_import_status='UNAVAILABLE'))
        finished.set()
    def paused(row, check):
        original(row, check)
        entered.set()
        assert started.wait(5)
        assert not finished.is_set()
    monkeypatch.setattr(risks, 'import_scanner', paused)
    thread = threading.Thread(target=newer)
    thread.start()
    risks.sync_scanner()
    thread.join(5)
    assert finished.is_set()
    assert risks.current_check()['scan_id'] == 'scan-2'
    assert risks.current_check()['risk_import_status'] == 'UNAVAILABLE'
    assert risks.get()['total'] is None
