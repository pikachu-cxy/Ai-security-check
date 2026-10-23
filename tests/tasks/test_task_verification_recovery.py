"""Scanner results survive target/ack faults without reconstructed execution."""
import copy

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.fix import TaskFixService
from security_runtime.tasks.risk_ledger import TaskRiskLedger, current_hashes
from security_runtime.tasks.verification_journal import TaskVerificationJournal
from summary_fixtures import sample, snapshot, SECRET  # noqa: F401
from test_task_fix import LocalProvider
from test_task_triage import task
from security_runtime.scanners import ScannerRegistry


def services(sample):
    root, scan, store = sample
    hooks = HookStateStore(store.path.parent/'hooks')
    provider = LocalProvider()
    fixer = TaskFixService(store,ScannerRegistry([provider]),hooks=hooks)
    return root, hooks, provider, fixer, TaskVerificationJournal(hooks,root)


def test_target_ack_failure_replays_inbox_without_scanner_or_source_changes(sample, monkeypatch):
    root,hooks,provider,fixer,journal = services(sample)
    original = TaskVerificationJournal._ack
    def fail_ack(self, record, target, result):
        if target == 'ledger': raise OSError('fixture ack after target commit')
        return original(self,record,target,result)
    monkeypatch.setattr(TaskVerificationJournal,'_ack',fail_ack)
    result = fixer.verify(task(sample)['task_ref'],root)
    assert result['verification_status'] == 'INCONCLUSIVE'
    assert result['verification_persistence']['pending']
    assert provider.calls == [('App.java',)]
    source = journal.pending()[0]
    assert source['targets'] == {} and source['results'] == result['members']
    ledger = TaskRiskLedger(hooks,root)
    before_target = ledger.path.read_bytes()
    before_read = snapshot(root)
    assert journal.pending() == [source]
    assert snapshot(root) == before_read  # Pure queries neither migrate nor ACK.
    monkeypatch.setattr(TaskVerificationJournal,'_ack',original)
    with hooks.lock(root) as held:
        assert held
        recovered = journal.reconcile()[0]
    assert recovered['state'] == 'APPLIED' and journal.pending() == []
    assert provider.calls == [('App.java',)] and ledger.path.read_bytes() == before_target
    assert sample[2].get_scan(sample[1].scan_id) == sample[1].to_dict()
    assert (root/'App.java').read_text().startswith('class App {')
    with journal.store.connect() as db:
        raw = db.execute('SELECT record FROM task_verifications').fetchone()[0]
    assert 'boolean verify()' not in raw and SECRET not in raw


def test_changed_source_supersedes_pending_delivery_without_replaying_old_proof(sample,monkeypatch):
    root,hooks,provider,fixer,journal = services(sample)
    original = TaskVerificationJournal.drain
    monkeypatch.setattr(TaskVerificationJournal,'drain',lambda *a: (_ for _ in ()).throw(OSError('target unavailable')))
    result = fixer.verify(task(sample)['task_ref'],root)
    assert result['verification_persistence']['pending'] and len(journal.pending()) == 1
    (root/'App.java').write_text('class App { boolean changed() { return false; } }\n')
    monkeypatch.setattr(TaskVerificationJournal,'drain',original)
    with hooks.lock(root) as held:
        assert held
        recovered = journal.reconcile()[0]
    assert recovered['state'] == 'SUPERSEDED'
    assert all(row['status'] == 'SUPERSEDED' for row in recovered['targets'].values())
    assert provider.calls == [('App.java',)]
    assert not TaskRiskLedger(hooks,root).path.exists()


def test_newer_ledger_fact_is_not_overwritten_by_late_delivery(sample,monkeypatch):
    root,hooks,provider,fixer,journal = services(sample)
    ledger = TaskRiskLedger(hooks,root)
    record = dict(task_ref='origin-task', static=sample[1].to_dict(), end=dict(hashes=current_hashes(root,['App.java'])))
    with hooks.lock(root) as held:
        assert held
        ledger.register(record)
    original = TaskVerificationJournal.drain
    monkeypatch.setattr(TaskVerificationJournal,'drain',lambda *a: (_ for _ in ()).throw(OSError('target unavailable')))
    fixer.verify(task(sample)['task_ref'],root)
    with hooks.lock(root) as held:
        assert held
        rows = ledger.read()
        for row in rows.values(): row.update(status='STILL_PRESENT',reason='new independent observation')
        ledger.save(rows)
    newer = copy.deepcopy(ledger.read())
    monkeypatch.setattr(TaskVerificationJournal,'drain',original)
    with hooks.lock(root) as held:
        assert held
        recovered = journal.reconcile()[0]
    assert recovered['state'] == 'SUPERSEDED' and recovered['targets']['ledger']['status'] == 'SUPERSEDED'
    assert ledger.read() == newer and provider.calls == [('App.java',)]


def test_preparation_and_absent_journal_queries_never_create_authority(sample):
    root,hooks,provider,fixer,journal = services(sample)
    before = snapshot(root)
    assert journal.pending() == [] and not journal.store.path.exists()
    fixer.prepare(task(sample)['task_ref'],root)
    assert snapshot(root) == before and provider.calls == []


def test_missing_target_with_registered_rows_keeps_original_risk_and_no_attempt_fact(sample):
    root,hooks,provider,fixer,journal = services(sample)
    ledger = TaskRiskLedger(hooks,root)
    record = dict(task_ref='original-scan-task',static=sample[1].to_dict(),
                  end=dict(hashes=current_hashes(root,['App.java'])))
    with hooks.lock(root) as held:
        assert held
        ledger.register(record)
    original = copy.deepcopy(ledger.read())
    (root/'App.java').unlink()
    result = fixer.verify(task(sample)['task_ref'],root)
    assert result['status'] == result['verification_status'] == 'NOT_VERIFIED'
    assert not result['runtime_observed_execution']['scanner_recheck_attempted']
    assert result['risk_ledger_recording']['status'] == 'STALE'
    assert result['risk_ledger_recording']['recorded'] == 0
    assert result['risk_ledger_recording']['unverified_current'] == 1
    assert provider.calls == [] and ledger.read() == original
    assert all(row['status'] == 'OPEN' for row in ledger.read().values())
