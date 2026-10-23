"""Originating-provider rechecks use one private input and fenced publication."""
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import threading

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScannerRun
from security_runtime.progress import ScanCancelled
from security_runtime.scan_attempt import AttemptLease, ScanAttemptStore, source_binding
from security_runtime.scanners import PatternSASTScanner, ScannerRegistry
from security_runtime.tasks.fix import TaskFixService
from security_runtime.tasks.risk_ledger import TaskRiskLedger, current_hashes
from security_runtime.tasks.verification_journal import TaskVerificationJournal
from summary_fixtures import sample  # noqa: F401
from test_task_fix import LocalProvider
from test_task_triage import task


def setup(sample, provider=None):
    root, scan, store=sample
    hooks=HookStateStore(store.path.parent/'hooks')
    provider=provider or LocalProvider()
    fixer=TaskFixService(store,ScannerRegistry([provider],fallback_adapters=[]),hooks=hooks)
    return root,hooks,provider,fixer,TaskVerificationJournal(hooks,root)


def register(sample,hooks):
    root,scan,_=sample
    ledger=TaskRiskLedger(hooks,root)
    with hooks.lock(root) as held:
        assert held
        ledger.register(dict(task_ref='original-scanner-task',static=scan.to_dict(),
            end=dict(hashes=current_hashes(root,scan.target_profile.files))))
    return ledger,copy.deepcopy(ledger.read())


def worker(fixer,reference,root):
    result=[]
    def run():
        try: result.append(fixer.verify(reference,root))
        except BaseException as error: result.append(error)
    thread=threading.Thread(target=run)
    thread.start()
    return thread,result


def test_private_original_bytes_and_short_lock_do_not_close_changed_live_risk(sample):
    root,hooks,provider,fixer,journal=setup(sample)
    ledger,original=register(sample,hooks)
    expected=(root/'App.java').read_bytes()
    calls=[]
    def scan(context,normalizer):
        assert Path(context.root)!=root and context.logical_root==str(root)
        assert not hooks.lock_held(root)
        with hooks.lock(root) as held: assert held
        assert context.input_view is not None
        assert (Path(context.root)/'App.java').read_bytes()==expected
        (root/'App.java').write_text('class App { boolean unsafeAgain() { return true; } }\n')
        assert (Path(context.root)/'App.java').read_bytes()==expected
        calls.append(context.files)
        return [],ScannerRun('semgrep','fixture','SUCCESS',1)
    provider.scan=scan
    result=fixer.verify(task(sample)['task_ref'],root)
    assert calls==[('App.java',)]
    assert result['status']=='INCONCLUSIVE'
    assert result['verification_input']['applicability']=='STALE'
    assert result['verification_input']['publication']=='SUPERSEDED'
    assert all(row['verification_status']=='SCANNER_VERIFIED_RESOLVED' for row in result['members'])
    assert ledger.read()==original and journal.pending()==[]
    assert sample[2].get_scan(sample[1].scan_id)==sample[1].to_dict()
    attempts=ScanAttemptStore(hooks,root)
    assert attempts.read()['directories']==[]
    assert not list(attempts.private_parent.iterdir())


@pytest.mark.parametrize('path',['App.java','.semgrepignore'])
def test_capture_a_b_a_rejects_other_bytes_before_originating_provider(sample,monkeypatch,path):
    root,hooks,provider,fixer,journal=setup(sample)
    if path!='App.java': (root/path).write_text('original-ignore\n')
    expected=(root/path).read_bytes()
    import security_runtime.scan_input as module
    original=module.capture_scan_input
    @contextmanager
    def changed(request,**kwargs):
        (root/path).write_text('captured-other-input\n')
        with original(request,**kwargs) as view:
            (root/path).write_bytes(expected)
            yield view
    monkeypatch.setattr(module,'capture_scan_input',changed)
    with pytest.raises(ScanCancelled,match='SOURCE_MISMATCH'):
        fixer.verify(task(sample)['task_ref'],root)
    assert provider.calls==[] and journal.pending()==[]
    assert (root/path).read_bytes()==expected
    assert sample[2].get_scan(sample[1].scan_id)==sample[1].to_dict()
    attempts=ScanAttemptStore(hooks,root)
    assert attempts.read()['lane']['state']=='CANCELLED'
    assert attempts.read()['directories']==[]
    assert not list(attempts.private_parent.iterdir())


def test_rule_a_b_a_is_rejected_before_provider_even_when_live_rule_is_restored(sample,monkeypatch,tmp_path):
    from security_runtime.rulepacks import RulePackManager
    root,_,_=sample
    rules=tmp_path/'local-rules'
    rules.mkdir()
    yaml=rules/'rule.yml'
    yaml.write_text('rules:\n- id: fixture.rule\n  languages: [java]\n  severity: WARNING\n  message: fixture\n  pattern: old($X)\n')
    manager=RulePackManager()
    selected=manager.resolve(user_path=rules)
    class SelectedRules:
        resolve=lambda self:selected
        bind_input=lambda self,pack,path:manager.bind_input(pack,path)
    class Origin(PatternSASTScanner):
        name=scanner_id='semgrep'
        verification_offline=verification_scope_complete=True
        calls=[]
        def scan(self,context,normalizer):
            self.calls.append(context.files)
            raise AssertionError('A mismatched rule pack must not execute')
    provider=Origin(rule_packs=SelectedRules())
    root,hooks,_,fixer,journal=setup(sample,provider)
    expected=yaml.read_bytes()
    import security_runtime.scan_input as module
    original=module.capture_scan_input
    @contextmanager
    def changed(request,**kwargs):
        yaml.write_bytes(expected.replace(b'old($X)',b'new($X)'))
        with original(request,**kwargs) as view:
            yaml.write_bytes(expected)
            yield view
    monkeypatch.setattr(module,'capture_scan_input',changed)
    with pytest.raises(ValueError,match='Rule pack changed during input capture'):
        fixer.verify(task(sample)['task_ref'],root)
    assert provider.calls==[] and journal.pending()==[] and yaml.read_bytes()==expected
    assert ScanAttemptStore(hooks,root).read()['directories']==[]


@pytest.mark.parametrize('existed',[True,False])
def test_pending_delivery_checks_auxiliary_input_including_original_absence(sample,monkeypatch,existed):
    root,hooks,provider,fixer,journal=setup(sample)
    config=root/'.semgrepignore'
    if existed: config.write_text('original-ignore\n')
    ledger,original_rows=register(sample,hooks)
    original=TaskVerificationJournal.drain
    monkeypatch.setattr(TaskVerificationJournal,'drain',lambda *a:(_ for _ in ()).throw(OSError('target offline')))
    result=fixer.verify(task(sample)['task_ref'],root)
    assert result['verification_persistence']['pending']
    pending=journal.pending()[0]
    assert pending['input_hashes']['.semgrepignore']==(
        current_hashes(root,['.semgrepignore'])['.semgrepignore'])
    assert pending['input_context']['input_id']==result['verification_input']['input_id']
    assert pending['input_context']['source_revision']==result['verification_input']['source_revision']
    config.write_text('new-config-after-result\n')
    monkeypatch.setattr(TaskVerificationJournal,'drain',original)
    with hooks.lock(root) as held:
        assert held
        recovered=journal.reconcile()[0]
    assert recovered['state']=='SUPERSEDED'
    assert ledger.read()==original_rows and provider.calls==[('App.java',)]
    with journal.store.connect() as db:
        raw=db.execute('SELECT record FROM task_verifications').fetchone()[0]
    assert 'new-config-after-result' not in raw and 'original-ignore' not in raw
    assert 'boolean verify()' not in raw


def test_shared_lane_is_busy_and_cancelled_worker_cannot_publish_over_new_generation(sample):
    entered,release=threading.Event(),threading.Event()
    class Blocked(LocalProvider):
        def scan(self,context,normalizer):
            self.calls.append(context.files)
            entered.set()
            assert release.wait(10)
            return [],ScannerRun(self.name,'fixture','SUCCESS',1)
    root,hooks,provider,fixer,journal=setup(sample,Blocked())
    ledger,original_rows=register(sample,hooks)
    reference=task(sample)['task_ref']
    thread,result=worker(fixer,reference,root)
    attempts=ScanAttemptStore(hooks,root)
    try:
        assert entered.wait(10)
        assert fixer.verify(reference,root)['status']=='BUSY'
        lane=attempts.read()['lane']
        old=AttemptLease(**{key:lane[key] for key in ('attempt_id','generation','lease_owner','cancel_generation')})
        with hooks.lock(root) as held:
            assert held and attempts.cancel(old)
            newer=attempts.claim('HOOK','new-work',source_binding({'hook':2}))
            assert newer is not None
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive() and isinstance(result[0],ScanCancelled)
    assert attempts.is_current(newer)
    assert provider.calls==[('App.java',)] and journal.pending()==[]
    assert ledger.read()==original_rows
    assert sample[2].get_scan(sample[1].scan_id)==sample[1].to_dict()
    assert attempts.read()['directories']==[]


def test_legacy_journal_record_without_input_metadata_is_not_reconstructed(sample,monkeypatch):
    root,hooks,provider,fixer,journal=setup(sample)
    original_append=TaskVerificationJournal.append
    original_drain=TaskVerificationJournal.drain
    def legacy(self,**kwargs):
        kwargs.pop('input_hashes')
        kwargs.pop('input_context')
        return original_append(self,**kwargs)
    monkeypatch.setattr(TaskVerificationJournal,'append',legacy)
    monkeypatch.setattr(TaskVerificationJournal,'drain',lambda *a:(_ for _ in ()).throw(OSError('target offline')))
    fixer.verify(task(sample)['task_ref'],root)
    pending=journal.pending()[0]
    assert 'input_hashes' not in pending and 'input_context' not in pending
    monkeypatch.setattr(TaskVerificationJournal,'drain',original_drain)
    with hooks.lock(root) as held:
        assert held
        recovered=journal.reconcile()[0]
    assert recovered['state']=='APPLIED'
    with journal.store.connect() as db:
        value=json.loads(db.execute('SELECT record FROM task_verifications').fetchone()[0])
    assert 'input_hashes' not in value and 'input_context' not in value
    assert provider.calls==[('App.java',)]


@pytest.mark.parametrize('failed_ack',['ledger','closure'])
def test_pending_old_effect_cannot_be_reported_current_after_new_independent_row(sample,monkeypatch,failed_ack):
    root,hooks,provider,fixer,journal=setup(sample)
    ledger,_=register(sample,hooks)
    ack=TaskVerificationJournal._ack
    def unavailable(self,record,target,result):
        if target==failed_ack: raise OSError('fixture source ACK unavailable')
        return ack(self,record,target,result)
    monkeypatch.setattr(TaskVerificationJournal,'_ack',unavailable)
    old=fixer.verify(task(sample)['task_ref'],root)
    assert old['verification_persistence']['pending']
    pending=journal.pending()[0]
    assert ('ledger' in pending['targets']) is (failed_ack=='closure')
    with hooks.lock(root) as held:
        assert held
        rows=ledger.read_scan(sample[1].scan_id)
        selected={member['finding_id'] for member in old['members']}
        for row in rows.values():
            if row['finding_id'] in selected:
                row.update(status='STILL_PRESENT',reason='new independent scanner fact')
        ledger.save(rows)
    newer=copy.deepcopy(ledger.read())
    monkeypatch.setattr(TaskVerificationJournal,'_ack',ack)
    with hooks.lock(root) as held:
        assert held
        recovered=journal.reconcile()[0]
    assert recovered['state']=='SUPERSEDED'
    assert ledger.read()==newer and provider.calls==[('App.java',)]
    if failed_ack=='closure':
        # The original ACK remains a historical target-commit receipt.
        assert recovered['targets']==pending['targets']
        assert recovered['superseded_reason']=='LEDGER_EFFECT_SUPERSEDED'
    else:
        assert recovered['targets']['ledger']['status']=='SUPERSEDED'
    assert journal.pending()==[]


def test_unrelated_row_change_does_not_invalidate_pending_exact_target_effect(sample,monkeypatch):
    root,hooks,provider,fixer,journal=setup(sample)
    ledger,_=register(sample,hooks)
    ack=TaskVerificationJournal._ack
    def unavailable(self,record,target,result):
        if target=='closure': raise OSError('fixture source ACK unavailable')
        return ack(self,record,target,result)
    monkeypatch.setattr(TaskVerificationJournal,'_ack',unavailable)
    result=fixer.verify(task(sample)['task_ref'],root)
    selected={member['finding_id'] for member in result['members']}
    with hooks.lock(root) as held:
        assert held
        rows=ledger.read_scan(sample[1].scan_id)
        unrelated=next(row for row in rows.values() if row['finding_id'] not in selected)
        unrelated.update(status='STILL_PRESENT',reason='unrelated new technical fact')
        ledger.save(rows)
    newer=copy.deepcopy(ledger.read())
    monkeypatch.setattr(TaskVerificationJournal,'_ack',ack)
    with hooks.lock(root) as held:
        assert held
        recovered=journal.reconcile()[0]
    assert recovered['state']=='APPLIED'
    assert ledger.read()==newer and provider.calls==[('App.java',)]


def test_completed_delivery_remains_historical_after_new_independent_row(sample):
    root,hooks,provider,fixer,journal=setup(sample)
    ledger,_=register(sample,hooks)
    result=fixer.verify(task(sample)['task_ref'],root)
    assert result['verification_persistence']['state']=='APPLIED'
    with journal.store.connect() as db:
        completed=journal._load(db,result['verification_persistence']['event_id'])
    with hooks.lock(root) as held:
        assert held
        rows=ledger.read_scan(sample[1].scan_id)
        for row in rows.values(): row.update(status='STILL_PRESENT',reason='new observation')
        ledger.save(rows)
        newer=copy.deepcopy(ledger.read())
        assert journal.drain(completed)==completed
    assert ledger.read()==newer and provider.calls==[('App.java',)]
